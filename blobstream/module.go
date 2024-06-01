package blobstream

import (
	bytes2 "bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"

	"github.com/celestiaorg/celestia-app/pkg/appconsts"
	pkgproof "github.com/celestiaorg/celestia-app/pkg/proof"
	"github.com/celestiaorg/celestia-app/pkg/shares"
	"github.com/celestiaorg/celestia-node/blob"
	"github.com/celestiaorg/celestia-node/header"
	"github.com/celestiaorg/celestia-node/share"
	"github.com/celestiaorg/nmt"
	"github.com/celestiaorg/rsmt2d"
	"github.com/tendermint/tendermint/crypto/merkle"
	"github.com/tendermint/tendermint/libs/bytes"
	tmbytes "github.com/tendermint/tendermint/libs/bytes"
	"github.com/tendermint/tendermint/types"
)

var _ Module = (*API)(nil)

// Module defines the API related to interacting with the proofs
type Module interface {
	// DataCommitment collects the data roots over a provided ordered range of blocks,
	// and then creates a new Merkle root of those data roots. The range is end exclusive.
	DataCommitment(ctx context.Context, start, end uint64) (*ResultDataCommitment, error)

	// DataRootInclusionProof creates an inclusion proof for the data root of block
	// height `height` in the set of blocks defined by `start` and `end`. The range
	// is end exclusive.
	DataRootInclusionProof(ctx context.Context, height int64, start, end uint64) (*ResultDataRootInclusionProof, error)

	// ProveShares generates a share proof for a share range.
	ProveShares(ctx context.Context, height uint64, start, end uint64) (*ResultShareProof, error)
	// ProveCommitment generates a commitment proof for a share commitment.
	ProveCommitment(ctx context.Context, height uint64, namespace share.Namespace, shareCommitment bytes.HexBytes) (*ResultCommitmentProof, error)
}

type InternalAPI struct {
	GetByHeight func(ctx context.Context, height uint64) (*header.ExtendedHeader, error) `perm:"read"`

	LocalHead   func(ctx context.Context) (*header.ExtendedHeader, error) `perm:"read"`
	NetworkHead func(ctx context.Context) (*header.ExtendedHeader, error) `perm:"read"`

	GetEDS func(
		ctx context.Context,
		header *header.ExtendedHeader,
	) (*rsmt2d.ExtendedDataSquare, error) `perm:"read"`
	GetProof func(ctx context.Context, height uint64, ns share.Namespace, commitment blob.Commitment) (*blob.Proof, error) `perm:"read"`
	GetShare func(
		ctx context.Context,
		header *header.ExtendedHeader,
		row, col int,
	) (share.Share, error) `perm:"read"`
	Get func(ctx context.Context, height uint64, ns share.Namespace, commitment blob.Commitment) (*blob.Blob, error) `perm:"read"`
}
type API struct {
	Internal InternalAPI
}

// DataCommitment collects the data roots over a provided ordered range of blocks,
// and then creates a new Merkle root of those data roots. The range is end exclusive.
func (api API) DataCommitment(ctx context.Context, start, end uint64) (*ResultDataCommitment, error) {
	err := api.validateDataCommitmentRange(ctx, start, end)
	if err != nil {
		return nil, err
	}
	tuples, err := api.fetchDataRootTuples(ctx, start, end)
	if err != nil {
		return nil, err
	}
	root, err := hashDataRootTuples(tuples)
	if err != nil {
		return nil, err
	}
	// Create data commitment
	return &ResultDataCommitment{DataCommitment: root}, nil
}

// DataRootInclusionProof creates an inclusion proof for the data root of block
// height `height` in the set of blocks defined by `start` and `end`. The range
// is end exclusive.
func (api API) DataRootInclusionProof(
	ctx context.Context,
	height int64,
	start,
	end uint64,
) (*ResultDataRootInclusionProof, error) {
	err := api.validateDataRootInclusionProofRequest(ctx, uint64(height), start, end)
	if err != nil {
		return nil, err
	}
	tuples, err := api.fetchDataRootTuples(ctx, start, end)
	if err != nil {
		return nil, err
	}
	proof, err := proveDataRootTuples(tuples, height)
	if err != nil {
		return nil, err
	}
	return &ResultDataRootInclusionProof{Proof: *proof}, nil
}

// padBytes Pad bytes to given length
func padBytes(byt []byte, length int) ([]byte, error) {
	l := len(byt)
	if l > length {
		return nil, fmt.Errorf(
			"cannot pad bytes because length of bytes array: %d is greater than given length: %d",
			l,
			length,
		)
	}
	if l == length {
		return byt, nil
	}
	tmp := make([]byte, length)
	copy(tmp[length-l:], byt)
	return tmp, nil
}

// To32PaddedHexBytes takes a number and returns its hex representation padded to 32 bytes.
// Used to mimic the result of `abi.encode(number)` in Ethereum.
func To32PaddedHexBytes(number uint64) ([]byte, error) {
	hexRepresentation := strconv.FormatUint(number, 16)
	// Make sure hex representation has even length.
	// The `strconv.FormatUint` can return odd length hex encodings.
	// For example, `strconv.FormatUint(10, 16)` returns `a`.
	// Thus, we need to pad it.
	if len(hexRepresentation)%2 == 1 {
		hexRepresentation = "0" + hexRepresentation
	}
	hexBytes, hexErr := hex.DecodeString(hexRepresentation)
	if hexErr != nil {
		return nil, hexErr
	}
	paddedBytes, padErr := padBytes(hexBytes, 32)
	if padErr != nil {
		return nil, padErr
	}
	return paddedBytes, nil
}

// DataRootTuple contains the data that will be used to create the QGB commitments.
// The commitments will be signed by orchestrators and submitted to an EVM chain via a relayer.
// For more information: https://github.com/celestiaorg/quantum-gravity-bridge/blob/master/src/DataRootTuple.sol
type DataRootTuple struct {
	height   uint64
	dataRoot [32]byte
}

// EncodeDataRootTuple takes a height and a data root, and returns the equivalent of
// `abi.encode(...)` in Ethereum.
// The encoded type is a DataRootTuple, which has the following ABI:
//
//	{
//	  "components":[
//	     {
//	        "internalType":"uint256",
//	        "name":"height",
//	        "type":"uint256"
//	     },
//	     {
//	        "internalType":"bytes32",
//	        "name":"dataRoot",
//	        "type":"bytes32"
//	     },
//	     {
//	        "internalType":"structDataRootTuple",
//	        "name":"_tuple",
//	        "type":"tuple"
//	     }
//	  ]
//	}
//
// padding the hex representation of the height padded to 32 bytes concatenated to the data root.
// For more information, refer to:
// https://github.com/celestiaorg/quantum-gravity-bridge/blob/master/src/DataRootTuple.sol
func EncodeDataRootTuple(height uint64, dataRoot [32]byte) ([]byte, error) {
	paddedHeight, err := To32PaddedHexBytes(height)
	if err != nil {
		return nil, err
	}
	return append(paddedHeight, dataRoot[:]...), nil
}

// dataCommitmentBlocksLimit The maximum number of blocks to be used to create a data commitment.
// It's a local parameter to protect the API from creating unnecessarily large commitments.
const dataCommitmentBlocksLimit = 10_000 // ~33 hours of blocks assuming 12-second blocks.

// validateDataCommitmentRange runs basic checks on the asc sorted list of
// heights that will be used subsequently in generating data commitments over
// the defined set of heights.
func (api API) validateDataCommitmentRange(ctx context.Context, start uint64, end uint64) error {
	if start == 0 {
		return fmt.Errorf("the start block is 0")
	}
	if start >= end {
		return fmt.Errorf("end block is smaller or equal to the start block")
	}
	heightsRange := end - start
	if heightsRange > uint64(dataCommitmentBlocksLimit) {
		return fmt.Errorf("the query exceeds the limit of allowed blocks %d", dataCommitmentBlocksLimit)
	}

	currentHeader, err := api.Internal.NetworkHead(ctx)
	if err != nil {
		return err
	}
	// the data commitment range is end exclusive
	if end > uint64(currentHeader.Height())+1 {
		return fmt.Errorf(
			"end block %d is higher than current chain height %d",
			end,
			currentHeader.Height(),
		)
	}

	currentLocalHeader, err := api.Internal.LocalHead(ctx)
	if err != nil {
		return err
	}
	// the data commitment range is end exclusive
	if end > uint64(currentLocalHeader.Height())+1 {
		return fmt.Errorf(
			"end block %d is higher than local chain height %d. Wait for the node until it syncs up to %d",
			end,
			currentLocalHeader.Height(),
			end,
		)
	}
	return nil
}

// hashDataRootTuples hashes a list of blocks data root tuples, i.e., height, data root and square size,
// then returns their merkle root.
func hashDataRootTuples(tuples []DataRootTuple) ([]byte, error) {
	if len(tuples) == 0 {
		return nil, fmt.Errorf("cannot hash an empty list of data root tuples")
	}
	dataRootEncodedTuples := make([][]byte, 0, len(tuples))
	for _, tuple := range tuples {
		encodedTuple, err := EncodeDataRootTuple(
			tuple.height,
			tuple.dataRoot,
		)
		if err != nil {
			return nil, err
		}
		dataRootEncodedTuples = append(dataRootEncodedTuples, encodedTuple)
	}
	root := merkle.HashFromByteSlices(dataRootEncodedTuples)
	return root, nil
}

// validateDataRootInclusionProofRequest validates the request to generate a data root
// inclusion proof.
func (api API) validateDataRootInclusionProofRequest(ctx context.Context, height uint64, start uint64, end uint64) error {
	err := api.validateDataCommitmentRange(ctx, start, end)
	if err != nil {
		return err
	}
	if height < start || height >= end {
		return fmt.Errorf(
			"height %d should be in the end exclusive interval first_block %d last_block %d",
			height,
			start,
			end,
		)
	}
	return nil
}

// proveDataRootTuples returns the merkle inclusion proof for a height.
func proveDataRootTuples(tuples []DataRootTuple, height int64) (*merkle.Proof, error) {
	if len(tuples) == 0 {
		return nil, fmt.Errorf("cannot prove an empty list of tuples")
	}
	if height < 0 {
		return nil, fmt.Errorf("cannot prove a strictly negative height %d", height)
	}
	currentHeight := tuples[0].height - 1
	for _, tuple := range tuples {
		if tuple.height != currentHeight+1 {
			return nil, fmt.Errorf("the provided tuples are not consecutive %d vs %d", currentHeight, tuple.height)
		}
		currentHeight += 1
	}
	dataRootEncodedTuples := make([][]byte, 0, len(tuples))
	for _, tuple := range tuples {
		encodedTuple, err := EncodeDataRootTuple(
			tuple.height,
			tuple.dataRoot,
		)
		if err != nil {
			return nil, err
		}
		dataRootEncodedTuples = append(dataRootEncodedTuples, encodedTuple)
	}
	_, proofs := merkle.ProofsFromByteSlices(dataRootEncodedTuples)
	return proofs[height-int64(tuples[0].height)], nil
}

// fetchDataRootTuples takes an end exclusive range of heights and fetches its
// corresponding data root tuples.
func (api API) fetchDataRootTuples(ctx context.Context, start, end uint64) ([]DataRootTuple, error) {
	tuples := make([]DataRootTuple, 0, end-start)
	for height := start; height < end; height++ {
		block, err := api.Internal.GetByHeight(ctx, height)
		if err != nil {
			return nil, err
		}
		if block == nil {
			return nil, fmt.Errorf("couldn't load block %d", height)
		}
		tuples = append(tuples, DataRootTuple{
			height:   block.Height(),
			dataRoot: *(*[32]byte)(block.DataHash),
		})
	}
	return tuples, nil
}

// ProveShares generates a share proof for a share range.
// Note: queries the whole EDS to generate the proof.
func (api API) ProveShares(ctx context.Context, height uint64, start, end uint64) (*ResultShareProof, error) {
	if height == 0 {
		return nil, fmt.Errorf("height cannot be equal to 0")
	}
	if start == end {
		return nil, fmt.Errorf("start share cannot be equal to end share")
	}
	if start > end {
		return nil, fmt.Errorf("start share %d cannot be greater than end share %d", start, end)
	}
	extendedHeader, err := api.Internal.GetByHeight(ctx, height)
	if err != nil {
		return nil, err
	}
	eds, err := api.Internal.GetEDS(ctx, extendedHeader)
	if err != nil {
		return nil, err
	}

	startInt, err := uint64ToInt(start)
	if err != nil {
		return nil, err
	}
	endInt, err := uint64ToInt(end)
	if err != nil {
		return nil, err
	}
	odsShares, err := shares.FromBytes(eds.FlattenedODS())
	if err != nil {
		return nil, err
	}
	nID, err := pkgproof.ParseNamespace(odsShares, startInt, endInt)
	if err != nil {
		return nil, err
	}
	proof, err := pkgproof.NewShareInclusionProofFromEDS(eds, nID, shares.NewRange(startInt, endInt))
	if err != nil {
		return nil, err
	}
	return &ResultShareProof{ShareProof: proof}, nil
}

// ProveCommitment generates a commitment proof for a share commitment.
func (api API) ProveCommitment(ctx context.Context, height uint64, namespace share.Namespace, shareCommitment bytes.HexBytes) (*ResultCommitmentProof, error) {
	// TODO debug this
	if height == 0 {
		return nil, fmt.Errorf("height cannot be equal to 0")
	}
	// get the share to row root proofs. these proofs coincide with the subtree root to row root proofs.
	shareToRowRootProofs, err := api.Internal.GetProof(ctx, height, namespace, blob.Commitment(shareCommitment))
	if err != nil {
		return nil, err
	}

	// get the blob to compute the subtree roots
	blb, err := api.Internal.Get(ctx, height, namespace, shareCommitment.Bytes())
	if err != nil {
		return nil, err
	}
	blobShares, err := blob.BlobsToShares(blb)
	if err != nil {
		return nil, err
	}

	// compute the subtree roots of the blob shares
	var subtreeRoots [][]byte
	var dataCursor int
	for _, proof := range *shareToRowRootProofs {
		// TODO: do we want directly use the default subtree root threshold or want to allow specifying which version to use?
		ranges, err := nmt.ToLeafRanges(proof.Start(), proof.End(), appconsts.DefaultSubtreeRootThreshold)
		if err != nil {
			return nil, err
		}
		roots, err := computeSubtreeRoots(blobShares[dataCursor:proof.End()-proof.Start()], ranges, proof.Start())
		if err != nil {
			return nil, err
		}
		subtreeRoots = append(subtreeRoots, roots...)
		dataCursor += proof.End() - proof.Start()
	}

	// get the extended header to get the row/column roots
	extendedHeader, err := api.Internal.GetByHeight(ctx, height)
	if err != nil {
		return nil, err
	}

	// rowWidth is the width of the square's rows.
	rowWidth := len(extendedHeader.DAH.ColumnRoots)

	// finding the rows of the square that contain the blob
	startingRowIndex := -1
	for index, row := range extendedHeader.DAH.RowRoots {
		if startingRowIndex >= 0 {
			// we found the starting row of the share data
			break
		}
		if !namespace.IsOutsideRange(row, row) {
			// we found the first row where the namespace data starts
			// we should go over the row shares to find the row where the data lives
			for i := 0; i < rowWidth; i++ {
				sh, err := api.Internal.GetShare(ctx, extendedHeader, index, i)
				if err != nil {
					return nil, err
				}
				if bytes2.Equal(sh, blobShares[0]) {
					// if the queried share is the same as the blob's data first share,
					// then we found the first row of our data.
					startingRowIndex = index
					break
				}
			}
		}
	}

	if startingRowIndex < 0 {
		return nil, fmt.Errorf("couldn't find the blob starting row")
	}

	// the blob's data row roots start at the starting row index, and span over the number of row proofs that we have
	dataRowRoots := func() []tmbytes.HexBytes {
		var tmBytesRowRoots []tmbytes.HexBytes
		for _, rowRoot := range extendedHeader.DAH.RowRoots[startingRowIndex : startingRowIndex+len(*shareToRowRootProofs)] {
			tmBytesRowRoots = append(tmBytesRowRoots, tmbytes.FromBytes(rowRoot)...)
		}
		return tmBytesRowRoots
	}()

	// generate all the row proofs
	_, allRowProofs := merkle.ProofsFromByteSlices(append(extendedHeader.DAH.RowRoots, extendedHeader.DAH.ColumnRoots...))

	commitmentProof := CommitmentProof{
		SubtreeRoots:      subtreeRoots,
		SubtreeRootProofs: *shareToRowRootProofs,
		NamespaceID:       namespace.ID(),
		RowProof: types.RowProof{
			RowRoots: dataRowRoots,
			Proofs:   allRowProofs[startingRowIndex : startingRowIndex+len(*shareToRowRootProofs)],
			StartRow: uint32(startingRowIndex), // these conversions are safe because we return if the startingRowIndex is strictly negative
			EndRow:   uint32(startingRowIndex + len(*shareToRowRootProofs) - 1),
		},
		NamespaceVersion: namespace.Version(),
	}

	return &ResultCommitmentProof{CommitmentProof: commitmentProof}, nil
}

// computeSubtreeRoots takes a set of shares and ranges and returns the corresponding subtree roots.
// the offset is the number of shares that are before the subtree roots we're calculating.
func computeSubtreeRoots(shares []share.Share, ranges []nmt.LeafRange, offset int) ([][]byte, error) {
	if len(shares) == 0 {
		return nil, fmt.Errorf("cannot compute subtree roots for an empty shares list")
	}
	if len(ranges) == 0 {
		return nil, fmt.Errorf("cannot compute subtree roots for an empty ranges list")
	}
	if offset < 0 {
		return nil, fmt.Errorf("the offset %d cannot be stricly negative", offset)
	}
	hasher := nmt.NewNmtHasher(share.NewSHA256Hasher(), share.NamespaceSize, true)
	tree := nmt.New(hasher, nmt.IgnoreMaxNamespace(true), nmt.NamespaceIDSize(share.NamespaceSize))
	for _, sh := range shares {
		var leafData []byte
		leafData = append(append(leafData, share.GetNamespace(sh)...), sh...)
		err := tree.Push(leafData)
		if err != nil {
			return nil, err
		}
	}
	var subtreeRoots [][]byte
	for _, rg := range ranges {
		if rg.End-rg.Start == 1 {
			// means a leaf is a subtree root. so we need to have only the leaf hash and not the root of that subtree
			var leafData []byte
			leafData = append(append(leafData, share.GetNamespace(shares[rg.Start-offset])...), shares[rg.Start-offset]...)
			leafHash, err := hasher.HashLeaf(leafData)
			if err != nil {
				return nil, err
			}
			subtreeRoots = append(subtreeRoots, leafHash)
		} else {
			root, err := tree.ComputeSubtreeRoot(rg.Start-offset, rg.End-offset)
			if err != nil {
				return nil, err
			}
			subtreeRoots = append(subtreeRoots, root)
		}
	}
	return subtreeRoots, nil
}

func uint64ToInt(number uint64) (int, error) {
	if number >= math.MaxInt {
		return 0, fmt.Errorf("number %d is higher than max int %d", number, math.MaxInt)
	}
	return int(number), nil
}
