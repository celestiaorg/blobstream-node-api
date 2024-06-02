package blobstream

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/celestiaorg/celestia-app/test/util/blobfactory"

	"github.com/celestiaorg/celestia-app/app"
	"github.com/celestiaorg/celestia-app/app/encoding"
	"github.com/celestiaorg/celestia-app/pkg/appconsts"
	"github.com/celestiaorg/celestia-app/pkg/da"
	"github.com/celestiaorg/celestia-app/pkg/namespace"
	pkgproof "github.com/celestiaorg/celestia-app/pkg/proof"
	"github.com/celestiaorg/celestia-app/pkg/shares"
	"github.com/celestiaorg/celestia-app/pkg/square"
	"github.com/celestiaorg/celestia-app/test/util/testfactory"
	"github.com/celestiaorg/celestia-app/x/blob/types"
	"github.com/celestiaorg/celestia-node/blob"
	"github.com/celestiaorg/celestia-node/header"
	"github.com/celestiaorg/celestia-node/share"
	"github.com/celestiaorg/nmt"
	"github.com/celestiaorg/rsmt2d"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto/merkle"
	bytes2 "github.com/tendermint/tendermint/libs/bytes"
	coretypes "github.com/tendermint/tendermint/types"
)

func TestPadBytes(t *testing.T) {
	tests := []struct {
		input     []byte
		length    int
		expected  []byte
		expectErr bool
	}{
		{input: []byte{1, 2, 3}, length: 5, expected: []byte{0, 0, 1, 2, 3}},
		{input: []byte{1, 2, 3}, length: 3, expected: []byte{1, 2, 3}},
		{input: []byte{1, 2, 3}, length: 2, expected: nil, expectErr: true},
		{input: []byte{}, length: 3, expected: []byte{0, 0, 0}},
	}

	for _, test := range tests {
		result, err := padBytes(test.input, test.length)
		if test.expectErr {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			assert.Equal(t, test.expected, result)
		}
	}
}

func TestTo32PaddedHexBytes(t *testing.T) {
	tests := []struct {
		number      uint64
		expected    []byte
		expectError bool
	}{
		{
			number: 10,
			expected: func() []byte {
				res, _ := hex.DecodeString("000000000000000000000000000000000000000000000000000000000000000a")
				return res
			}(),
		},
		{
			number: 255,
			expected: func() []byte {
				res, _ := hex.DecodeString("00000000000000000000000000000000000000000000000000000000000000ff")
				return res
			}(),
		},
		{
			number: 255,
			expected: func() []byte {
				res, _ := hex.DecodeString("00000000000000000000000000000000000000000000000000000000000000ff")
				return res
			}(),
		},
		{
			number: 4294967295,
			expected: func() []byte {
				res, _ := hex.DecodeString("00000000000000000000000000000000000000000000000000000000ffffffff")
				return res
			}(),
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("number: %d", test.number), func(t *testing.T) {
			result, err := To32PaddedHexBytes(test.number)
			if test.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, result)
			}
		})
	}
}

func TestEncodeDataRootTuple(t *testing.T) {
	height := uint64(2)
	dataRoot, err := hex.DecodeString("82dc1607d84557d3579ce602a45f5872e821c36dbda7ec926dfa17ebc8d5c013")
	require.NoError(t, err)

	expectedEncoding, err := hex.DecodeString(
		// hex representation of height padded to 32 bytes
		"0000000000000000000000000000000000000000000000000000000000000002" +
			// data root
			"82dc1607d84557d3579ce602a45f5872e821c36dbda7ec926dfa17ebc8d5c013",
	)
	require.NoError(t, err)
	require.NotNil(t, expectedEncoding)

	actualEncoding, err := EncodeDataRootTuple(height, *(*[32]byte)(dataRoot))
	require.NoError(t, err)
	require.NotNil(t, actualEncoding)

	// Check that the length of packed data is correct
	assert.Equal(t, len(actualEncoding), 64)
	assert.Equal(t, expectedEncoding, actualEncoding)
}

func TestHashDataRootTuples(t *testing.T) {
	tests := map[string]struct {
		tuples       []DataRootTuple
		expectedHash []byte
		expectErr    bool
	}{
		"empty tuples list": {tuples: nil, expectErr: true},
		"valid list of data root tuples": {
			tuples: []DataRootTuple{
				{
					height:   1,
					dataRoot: [32]byte{0x1},
				},
				{
					height:   2,
					dataRoot: [32]byte{0x2},
				},
			},
			expectedHash: func() []byte {
				tuple1, _ := EncodeDataRootTuple(1, [32]byte{0x1})
				tuple2, _ := EncodeDataRootTuple(2, [32]byte{0x2})

				return merkle.HashFromByteSlices([][]byte{tuple1, tuple2})
			}(),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := hashDataRootTuples(tc.tuples)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedHash, result)
			}
		})
	}
}

func TestProveDataRootTuples(t *testing.T) {
	tests := map[string]struct {
		tuples        []DataRootTuple
		height        int64
		expectedProof merkle.Proof
		expectErr     bool
	}{
		"empty tuples list": {tuples: nil, expectErr: true},
		"strictly negative height": {
			height: -1,
			tuples: []DataRootTuple{
				{
					height:   1,
					dataRoot: [32]byte{0x1},
				},
			},
			expectErr: true,
		},
		"non consecutive list of tuples at the beginning": {
			tuples: []DataRootTuple{
				{
					height:   1,
					dataRoot: [32]byte{0x1},
				},
				{
					height:   3,
					dataRoot: [32]byte{0x2},
				},
				{
					height:   4,
					dataRoot: [32]byte{0x4},
				},
			},
			expectErr: true,
		},
		"non consecutive list of tuples in the middle": {
			tuples: []DataRootTuple{
				{
					height:   1,
					dataRoot: [32]byte{0x1},
				},
				{
					height:   2,
					dataRoot: [32]byte{0x2},
				},
				{
					height:   3,
					dataRoot: [32]byte{0x2},
				},
				{
					height:   5,
					dataRoot: [32]byte{0x4},
				},
				{
					height:   6,
					dataRoot: [32]byte{0x5},
				},
			},
			expectErr: true,
		},
		"non consecutive list of tuples at the end": {
			tuples: []DataRootTuple{
				{
					height:   1,
					dataRoot: [32]byte{0x1},
				},
				{
					height:   2,
					dataRoot: [32]byte{0x2},
				},
				{
					height:   4,
					dataRoot: [32]byte{0x4},
				},
			},
			expectErr: true,
		},
		"duplicate height at the beginning": {
			tuples: []DataRootTuple{
				{
					height:   1,
					dataRoot: [32]byte{0x1},
				},
				{
					height:   1,
					dataRoot: [32]byte{0x1},
				},
				{
					height:   4,
					dataRoot: [32]byte{0x4},
				},
			},
			expectErr: true,
		},
		"duplicate height in the middle": {
			tuples: []DataRootTuple{
				{
					height:   1,
					dataRoot: [32]byte{0x1},
				},
				{
					height:   2,
					dataRoot: [32]byte{0x2},
				},
				{
					height:   2,
					dataRoot: [32]byte{0x2},
				},
				{
					height:   3,
					dataRoot: [32]byte{0x3},
				},
			},
			expectErr: true,
		},
		"duplicate height at the end": {
			tuples: []DataRootTuple{
				{
					height:   1,
					dataRoot: [32]byte{0x1},
				},
				{
					height:   2,
					dataRoot: [32]byte{0x2},
				},
				{
					height:   2,
					dataRoot: [32]byte{0x2},
				},
			},
			expectErr: true,
		},
		"valid proof": {
			height: 3,
			tuples: []DataRootTuple{
				{
					height:   1,
					dataRoot: [32]byte{0x1},
				},
				{
					height:   2,
					dataRoot: [32]byte{0x2},
				},
				{
					height:   3,
					dataRoot: [32]byte{0x3},
				},
				{
					height:   4,
					dataRoot: [32]byte{0x4},
				},
			},
			expectedProof: func() merkle.Proof {
				encodedTuple1, _ := EncodeDataRootTuple(1, [32]byte{0x1})
				encodedTuple2, _ := EncodeDataRootTuple(2, [32]byte{0x2})
				encodedTuple3, _ := EncodeDataRootTuple(3, [32]byte{0x3})
				encodedTuple4, _ := EncodeDataRootTuple(4, [32]byte{0x4})
				_, proofs := merkle.ProofsFromByteSlices([][]byte{encodedTuple1, encodedTuple2, encodedTuple3, encodedTuple4})
				return *proofs[2]
			}(),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := proveDataRootTuples(tc.tuples, tc.height)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedProof, *result)
			}
		})
	}
}

func TestUint64ToInt(t *testing.T) {
	tests := []struct {
		number    uint64
		expected  int
		expectErr bool
	}{
		{number: 0, expected: 0},
		{number: 10, expected: 10},
		{number: math.MaxInt - 1, expected: math.MaxInt - 1},
		{number: math.MaxInt, expected: 0, expectErr: true},
		{number: math.MaxInt + 1, expected: 0, expectErr: true},
		{number: math.MaxUint64, expected: 0, expectErr: true},
	}

	for _, test := range tests {
		result, err := uint64ToInt(test.number)
		if test.expectErr {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			assert.Equal(t, test.expected, result)
		}
	}
}

func TestDataCommitment(t *testing.T) {
	api := newTestAPI(t, 10, 1000, 10)
	tests := map[string]struct {
		start, end             uint64
		expectedDataCommitment bytes2.HexBytes
		expectErr              bool
	}{
		"start == 0":                                         {start: 0, expectErr: true},
		"start block == end block":                           {start: 2, end: 2, expectErr: true},
		"start block > end block":                            {start: 3, end: 2, expectErr: true},
		"range exceeds data commitment blocks limit":         {start: 3, end: dataCommitmentBlocksLimit + 10, expectErr: true},
		"end block is greater than the network block height": {start: 3, end: 15, expectErr: true},
		"valid case": {
			start: 5,
			end:   9,
			expectedDataCommitment: func() bytes2.HexBytes {
				tuples := []DataRootTuple{
					{
						height:   5,
						dataRoot: [32]byte(api.blocks[5].dataRoot),
					},
					{
						height:   6,
						dataRoot: [32]byte(api.blocks[6].dataRoot),
					},
					{
						height:   7,
						dataRoot: [32]byte(api.blocks[7].dataRoot),
					},
					{
						height:   8,
						dataRoot: [32]byte(api.blocks[8].dataRoot),
					},
				}
				hash, err := hashDataRootTuples(tuples)
				require.NoError(t, err)
				return hash
			}(),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := api.api.DataCommitment(context.Background(), tc.start, tc.end)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedDataCommitment, result.DataCommitment)
			}
		})
	}
}

func TestDataRootInclusionProof(t *testing.T) {
	api := newTestAPI(t, 10, 1000, 10)
	tests := map[string]struct {
		height        int64
		start, end    uint64
		expectedProof merkle.Proof
		expectErr     bool
	}{
		"height < 0":               {height: -1, expectErr: true},
		"height == 0":              {height: 0, expectErr: true},
		"start == 0":               {start: 0, expectErr: true},
		"start block == end block": {start: 2, end: 2, expectErr: true},
		"start block > end block":  {start: 3, end: 2, expectErr: true},
		"height < start":           {height: 2, start: 3, end: 2, expectErr: true},
		"height == end":            {height: 4, start: 3, end: 4, expectErr: true},
		"height > end":             {height: 5, start: 3, end: 4, expectErr: true},
		"range exceeds data commitment blocks limit":            {start: 3, end: dataCommitmentBlocksLimit + 10, expectErr: true},
		"end block is greater than the network block height":    {start: 3, end: 15, expectErr: true},
		"start block is greater than the network block height":  {start: 12, end: 15, height: 14, expectErr: true},
		"height block is greater than the network block height": {start: 1, end: 15, height: 14, expectErr: true},
		"valid case": {
			height: 6,
			start:  5,
			end:    9,
			expectedProof: func() merkle.Proof {
				encodedTuple5, _ := EncodeDataRootTuple(5, [32]byte(api.blocks[5].dataRoot))
				encodedTuple6, _ := EncodeDataRootTuple(6, [32]byte(api.blocks[6].dataRoot))
				encodedTuple7, _ := EncodeDataRootTuple(7, [32]byte(api.blocks[7].dataRoot))
				encodedTuple8, _ := EncodeDataRootTuple(8, [32]byte(api.blocks[8].dataRoot))
				_, proofs := merkle.ProofsFromByteSlices([][]byte{encodedTuple5, encodedTuple6, encodedTuple7, encodedTuple8})
				return *proofs[1]
			}(),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := api.api.DataRootInclusionProof(context.Background(), tc.height, tc.start, tc.end)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedProof, result.Proof)
			}
		})
	}
}

func TestProveShares(t *testing.T) {
	api := newTestAPI(t, 10, 1000, 10)
	tests := map[string]struct {
		height        uint64
		start, end    uint64
		expectedProof ResultShareProof
		expectErr     bool
	}{
		"height == 0":                                 {height: 0, expectErr: true},
		"height > blockchain tip":                     {height: 100, expectErr: true},
		"start share == end share":                    {start: 2, end: 2, expectErr: true},
		"start share > end share":                     {start: 3, end: 2, expectErr: true},
		"start share > number of shares in the block": {start: 200, end: 201, expectErr: true},
		"end share > number of shares in the block":   {start: 1, end: 201, expectErr: true},
		"valid case": {
			height: 6,
			start:  0,
			end:    2,
			expectedProof: func() ResultShareProof {
				proof, err := pkgproof.NewShareInclusionProofFromEDS(&api.blocks[6].eds, namespace.PayForBlobNamespace, shares.NewRange(0, 2))
				require.NoError(t, err)
				require.NoError(t, proof.Validate(api.blocks[6].dataRoot))
				return ResultShareProof{ShareProof: proof}
			}(),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := api.api.ProveShares(context.Background(), tc.height, tc.start, tc.end)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedProof, *result)
				assert.NoError(t, result.ShareProof.Validate(api.blocks[6].dataRoot))
			}
		})
	}
}

// TestProveCommitmentAllCombinations tests proving all the commitments in a block.
// The number of shares per blob increases with each blob to cover proving a large number
// of possibilities.
func TestProveCommitmentAllCombinations(t *testing.T) {
	tests := map[string]struct {
		numberOfBlocks int
		blobSize       int
	}{
		"very small blobs that take less than a share": {numberOfBlocks: 20, blobSize: 350},
		"small blobs that take 2 shares":               {numberOfBlocks: 20, blobSize: 1000},
		"small blobs that take ~10 shares":             {numberOfBlocks: 10, blobSize: 5000},
		"large blobs ~100 shares":                      {numberOfBlocks: 5, blobSize: 50000},
		"very large blobs ~1500 shares":                {numberOfBlocks: 3, blobSize: 750000},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			proveAllCommitments(t, tc.numberOfBlocks, tc.blobSize)
		})
	}
}

func proveAllCommitments(t *testing.T, numberOfBlocks, blobSize int) {
	api := newTestAPI(t, numberOfBlocks, blobSize, 10)
	for blockIndex, block := range api.blocks {
		for msgIndex, msg := range block.msgs {
			t.Run(fmt.Sprintf("height=%d, blobIndex=%d", blockIndex, msgIndex), func(t *testing.T) {
				actualCommitmentProof, err := api.api.ProveCommitment(context.Background(), uint64(blockIndex), msg.Namespaces[0], msg.ShareCommitments[0])
				require.NoError(t, actualCommitmentProof.CommitmentProof.Validate())
				valid, err := actualCommitmentProof.CommitmentProof.Verify(block.dataRoot, appconsts.DefaultSubtreeRootThreshold)
				require.NoError(t, err)
				require.True(t, valid)

				expectedCommitmentProof := generateCommitmentProofFromBlock(t, block, msgIndex)
				require.NoError(t, expectedCommitmentProof.CommitmentProof.Validate())
				valid, err = expectedCommitmentProof.CommitmentProof.Verify(block.dataRoot, appconsts.DefaultSubtreeRootThreshold)
				require.NoError(t, err)
				require.True(t, valid)

				assert.Equal(t, expectedCommitmentProof, *actualCommitmentProof)
			})
		}
	}
}

func TestProveCommitment(t *testing.T) {
	api := newTestAPI(t, 10, 300, 10)

	tests := map[string]struct {
		height        uint64
		commitment    bytes2.HexBytes
		ns            share.Namespace
		expectedProof ResultCommitmentProof
		expectErr     bool
	}{
		"height == 0": {height: 0, expectErr: true},
		"valid case": {
			height:     6,
			ns:         api.blocks[6].msgs[0].Namespaces[0],
			commitment: api.blocks[6].msgs[0].ShareCommitments[0],
			expectedProof: func() ResultCommitmentProof {
				commitmentProof := generateCommitmentProofFromBlock(t, api.blocks[6], 0)

				// make sure we're creating a valid proof for the test
				require.NoError(t, commitmentProof.CommitmentProof.Validate())
				valid, err := commitmentProof.CommitmentProof.Verify(api.blocks[6].dataRoot, appconsts.DefaultSubtreeRootThreshold)
				require.NoError(t, err)
				require.True(t, valid)

				return commitmentProof
			}(),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := api.api.ProveCommitment(context.Background(), tc.height, tc.ns, tc.commitment)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedProof, *result)
				assert.NoError(t, result.CommitmentProof.Validate())
				valid, err := result.CommitmentProof.Verify(api.blocks[tc.height].dataRoot, appconsts.DefaultSubtreeRootThreshold)
				assert.NoError(t, err)
				assert.True(t, valid)
			}
		})
	}
}

// testBlock is a block struct used to keep track of all the information
// needed to mock the API.
type testBlock struct {
	msgs     []types.MsgPayForBlobs
	blobs    []types.Blob
	nss      []namespace.Namespace
	eds      rsmt2d.ExtendedDataSquare
	coreTxs  coretypes.Txs
	dah      da.DataAvailabilityHeader
	dataRoot []byte
}

// testAPI an API that allows mocking all the methods and thoroughly testing them
type testAPI struct {
	api    *API
	blocks []testBlock
}

// newTestAPI creates a new test API that fetches data from a test blockchain that has
// a specific number of blocks. Each block has a number of PFBs. Each PFB has a single blob with
// size blobSize or bigger.
func newTestAPI(t *testing.T, numberOfBlocks int, blobSize int, numberOfPFBs int) *testAPI {
	blocks := []testBlock{{}} // so that the heights match the slice indexes
	blocks = append(blocks, generateTestBlocks(t, numberOfBlocks, blobSize, numberOfPFBs)...)

	api := &testAPI{
		api:    &API{},
		blocks: blocks,
	}

	api.api.Internal = InternalAPI{
		GetByHeight: func(
			ctx context.Context,
			height uint64,
		) (*header.ExtendedHeader, error) {
			if height >= uint64(len(api.blocks)) {
				return nil, errors.New("height greater than the blockchain")
			}
			return &header.ExtendedHeader{
				RawHeader: header.RawHeader{
					Height:   int64(height),
					DataHash: api.blocks[height].dataRoot,
				},
				DAH: &api.blocks[height].dah,
			}, nil
		},
		LocalHead: func(ctx context.Context) (*header.ExtendedHeader, error) {
			return &header.ExtendedHeader{
				RawHeader: header.RawHeader{
					Height:   int64(len(api.blocks) - 1),
					DataHash: api.blocks[len(api.blocks)-1].dataRoot,
				},
				DAH: &api.blocks[len(api.blocks)-1].dah,
			}, nil
		},
		NetworkHead: func(ctx context.Context) (*header.ExtendedHeader, error) {
			return &header.ExtendedHeader{
				RawHeader: header.RawHeader{
					Height:   int64(len(api.blocks) - 1),
					DataHash: api.blocks[len(api.blocks)-1].dataRoot,
				},
				Commit:       nil,
				ValidatorSet: nil,
				DAH:          &api.blocks[len(api.blocks)-1].dah,
			}, nil
		},
		GetEDS: func(ctx context.Context, header *header.ExtendedHeader) (*rsmt2d.ExtendedDataSquare, error) {
			if header.Height() >= uint64(len(api.blocks)) {
				return nil, errors.New("height greater than the blockchain")
			}
			return &api.blocks[header.Height()].eds, nil
		},
		GetProof: func(ctx context.Context, height uint64, ns share.Namespace, commitment blob.Commitment) (*blob.Proof, error) {
			if height >= uint64(len(api.blocks)) {
				return nil, errors.New("height greater than the blockchain")
			}
			for i, msg := range api.blocks[height].msgs {
				if bytes.Equal(msg.ShareCommitments[0], commitment) {
					blobShareRange, err := square.BlobShareRange(api.blocks[height].coreTxs.ToSliceOfBytes(), i, 0, appconsts.LatestVersion)
					require.NoError(t, err)
					proof, err := pkgproof.NewShareInclusionProofFromEDS(&api.blocks[height].eds, api.blocks[height].nss[i], blobShareRange)
					require.NoError(t, err)
					var nmtProofs []*nmt.Proof
					for _, proof := range proof.ShareProofs {
						nmtProof := nmt.NewInclusionProof(int(proof.Start),
							int(proof.End),
							proof.Nodes,
							true)
						nmtProofs = append(
							nmtProofs,
							&nmtProof,
						)
					}
					blobProof := blob.Proof(nmtProofs)
					return &blobProof, nil
				}
			}
			return nil, fmt.Errorf("coudln't find commitment")
		},
		GetShare: func(ctx context.Context, header *header.ExtendedHeader, row, col int) (share.Share, error) {
			if header.Height() > uint64(len(api.blocks)) {
				return nil, errors.New("height greater than the blockchain")
			}
			return api.blocks[header.Height()].eds.GetCell(uint(row), uint(col)), nil
		},
		Get: func(ctx context.Context, height uint64, ns share.Namespace, commitment blob.Commitment) (*blob.Blob, error) {
			if height > uint64(len(api.blocks)) {
				return nil, errors.New("height greater than the blockchain")
			}
			for i, msg := range api.blocks[height].msgs {
				if bytes.Equal(msg.ShareCommitments[0], commitment) {
					blb, err := blob.NewBlob(uint8(api.blocks[height].blobs[i].ShareVersion), ns, api.blocks[height].blobs[i].Data)
					require.NoError(t, err)
					return blb, nil
				}
			}
			return nil, fmt.Errorf("coudln't find commitment")
		},
	}

	return api
}

// addBlock adds a new block the testAPI.
// The added block can be created in the tests and added to the chain
// to test specific cases.
func (api *testAPI) addBlock(t *testing.T, numberOfBlobs, blobSize int) int {
	acc := "blobstream-api-tests"
	kr := testfactory.GenerateKeyring(acc)
	signer := types.NewKeyringSigner(kr, acc, "test")

	var msgs []types.MsgPayForBlobs
	var blobs []types.Blob
	var nss []namespace.Namespace
	var coreTxs coretypes.Txs

	for i := 0; i < numberOfBlobs; i++ {
		ns, msg, blob, coreTx := createTestBlobTransaction(t, signer, blobSize)
		msgs = append(msgs, msg)
		blobs = append(blobs, blob)
		nss = append(nss, ns)
		coreTxs = append(coreTxs, coreTx)
	}

	var txs coretypes.Txs
	txs = append(txs, coreTxs...)
	dataSquare, err := square.Construct(txs.ToSliceOfBytes(), appconsts.LatestVersion, appconsts.SquareSizeUpperBound(appconsts.LatestVersion))
	require.NoError(t, err)

	// erasure the data square which we use to create the data root.
	eds, err := da.ExtendShares(shares.ToBytes(dataSquare))
	require.NoError(t, err)

	// create the new data root by creating the data availability header (merkle
	// roots of each row and col of the erasure data).
	dah, err := da.NewDataAvailabilityHeader(eds)
	require.NoError(t, err)
	dataRoot := dah.Hash()
	api.blocks = append(api.blocks, testBlock{
		msgs:     msgs,
		blobs:    blobs,
		nss:      nss,
		coreTxs:  coreTxs,
		eds:      *eds,
		dah:      dah,
		dataRoot: dataRoot,
	})

	return len(api.blocks) - 1
}

// generateCommitmentProofFromBlock takes a block and a PFB index and generates the commitment proof
// using the traditional way of doing, instead of using the API.
func generateCommitmentProofFromBlock(t *testing.T, block testBlock, blobIndex int) ResultCommitmentProof {
	// parse the namespace
	ns, err := share.NamespaceFromBytes(
		append(
			[]byte{byte(block.blobs[blobIndex].NamespaceVersion)}, block.blobs[blobIndex].NamespaceId...,
		),
	)
	require.NoError(t, err)

	// create the blob from the data
	blb, err := blob.NewBlob(uint8(block.blobs[blobIndex].ShareVersion), ns, block.blobs[blobIndex].Data)
	require.NoError(t, err)

	// convert the blob to a number of shares
	blobShares, err := blob.BlobsToShares(blb)

	// find the first share of the blob in the ODS
	startShareIndex := -1
	for i, sh := range block.eds.FlattenedODS() {
		if bytes.Equal(sh, blobShares[0]) {
			startShareIndex = i
			break
		}
	}
	require.Greater(t, startShareIndex, 0)

	// create an inclusion proof of the blob using the share range instead of the commitment
	sharesProof, err := pkgproof.NewShareInclusionProofFromEDS(&block.eds, ns.ToAppNamespace(), shares.NewRange(startShareIndex, startShareIndex+len(blobShares)))
	require.NoError(t, err)
	require.NoError(t, sharesProof.Validate(block.dataRoot))

	// calculate the subtree roots
	var subtreeRoots [][]byte
	var dataCursor int
	for _, proof := range sharesProof.ShareProofs {
		ranges, err := nmt.ToLeafRanges(int(proof.Start), int(proof.End), nmt.SubtreeRootsWidth(len(blobShares), appconsts.DefaultSubtreeRootThreshold))
		require.NoError(t, err)
		roots, err := computeSubtreeRoots(blobShares[dataCursor:int32(dataCursor)+proof.End-proof.Start], ranges, int(proof.Start))
		require.NoError(t, err)
		subtreeRoots = append(subtreeRoots, roots...)
		dataCursor += int(proof.End - proof.Start)
	}

	// convert the nmt proof to be accepted by the commitment proof
	var nmtProofs []*nmt.Proof
	for _, proof := range sharesProof.ShareProofs {
		nmtProof := nmt.NewInclusionProof(int(proof.Start), int(proof.End), proof.Nodes, true)
		nmtProofs = append(nmtProofs, &nmtProof)
	}

	commitmentProof := CommitmentProof{
		SubtreeRoots:      subtreeRoots,
		SubtreeRootProofs: nmtProofs,
		NamespaceID:       sharesProof.NamespaceID,
		RowProof:          sharesProof.RowProof,
		NamespaceVersion:  uint8(sharesProof.NamespaceVersion),
	}

	return ResultCommitmentProof{CommitmentProof: commitmentProof}
}

// generateTestBlocks generates a set of test blocks with a specific blob size and number of transactions
func generateTestBlocks(t *testing.T, numberOfBlocks int, blobSize int, numberOfTransactions int) []testBlock {
	require.Greater(t, numberOfBlocks, 1)
	var blocks []testBlock
	for i := 1; i <= numberOfBlocks; i++ {
		nss, msgs, blobs, coreTxs := createTestBlobTransactions(t, numberOfTransactions, blobSize)

		var txs coretypes.Txs
		txs = append(txs, coreTxs...)
		dataSquare, err := square.Construct(txs.ToSliceOfBytes(), appconsts.LatestVersion, appconsts.SquareSizeUpperBound(appconsts.LatestVersion))
		require.NoError(t, err)

		// erasure the data square which we use to create the data root.
		eds, err := da.ExtendShares(shares.ToBytes(dataSquare))
		require.NoError(t, err)

		// create the new data root by creating the data availability header (merkle
		// roots of each row and col of the erasure data).
		dah, err := da.NewDataAvailabilityHeader(eds)
		require.NoError(t, err)
		dataRoot := dah.Hash()
		blocks = append(blocks, testBlock{
			msgs:     msgs,
			blobs:    blobs,
			nss:      nss,
			eds:      *eds,
			dah:      dah,
			dataRoot: dataRoot,
			coreTxs:  coreTxs,
		})
	}
	return blocks
}

// createTestBlobTransactions generates a set of transactions that can be added to a blob.
// The number of transactions dictates the number of PFBs that will be returned.
// The size refers to the size of the data contained in the PFBs in bytes.
func createTestBlobTransactions(t *testing.T, numberOfTransactions int, size int) ([]namespace.Namespace, []types.MsgPayForBlobs, []types.Blob, []coretypes.Tx) {
	acc := "blobstream-api-tests"
	kr := testfactory.GenerateKeyring(acc)
	signer := types.NewKeyringSigner(kr, acc, "test")

	var nss []namespace.Namespace
	var msgs []types.MsgPayForBlobs
	var blobs []types.Blob
	var coreTxs []coretypes.Tx
	for i := 0; i < numberOfTransactions; i++ {
		ns, msg, blob, coreTx := createTestBlobTransaction(t, signer, size+i*1000)
		nss = append(nss, ns)
		msgs = append(msgs, msg)
		blobs = append(blobs, blob)
		coreTxs = append(coreTxs, coreTx)
	}

	return nss, msgs, blobs, coreTxs
}

// createTestBlobTransaction creates a test blob transaction using a specific signer and a specific PFB size.
// The size is in bytes.
func createTestBlobTransaction(t *testing.T, signer *types.KeyringSigner, size int) (namespace.Namespace, types.MsgPayForBlobs, types.Blob, coretypes.Tx) {
	addr, err := signer.GetSignerInfo().GetAddress()
	require.NoError(t, err)

	ns := namespace.RandomBlobNamespace()
	msg, blob := blobfactory.RandMsgPayForBlobsWithNamespaceAndSigner(addr.String(), ns, size)
	require.NoError(t, err)

	builder := signer.NewTxBuilder()
	stx, err := signer.BuildSignedTx(builder, msg)
	require.NoError(t, err)
	rawTx, err := encoding.MakeConfig(app.ModuleEncodingRegisters...).TxConfig.TxEncoder()(stx)
	require.NoError(t, err)
	cTx, err := coretypes.MarshalBlobTx(rawTx, blob)
	require.NoError(t, err)
	return ns, *msg, *blob, cTx
}
