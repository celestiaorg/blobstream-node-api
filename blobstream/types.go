package blobstream

import (
	"fmt"

	"github.com/celestiaorg/celestia-node/share"
	"github.com/celestiaorg/nmt"
	"github.com/celestiaorg/nmt/namespace"
	"github.com/tendermint/tendermint/crypto/merkle"

	"github.com/tendermint/tendermint/libs/bytes"
	"github.com/tendermint/tendermint/types"
)

type ResultDataCommitment struct {
	DataCommitment bytes.HexBytes `json:"data_commitment"`
}

type ResultDataRootInclusionProof struct {
	Proof merkle.Proof `json:"proof"`
}

// ResultShareProof is an API response that contains a ShareProof.
type ResultShareProof struct {
	ShareProof types.ShareProof `json:"share_proof"`
}

// ResultCommitmentProof is an API response that contains a CommitmentProof.
type ResultCommitmentProof struct {
	CommitmentProof CommitmentProof `json:"commitment_proof"`
}

// CommitmentProof is an inclusion proof of a commitment to the data root
// TODO add protobuf definitions
type CommitmentProof struct {
	// TODO Data are the raw shares that are being proven.
	SubtreeRoots [][]byte `json:"subtree_roots"`
	// TODO ShareProofs are NMT proofs that the shares in Data exist in a set of
	// rows. There will be one ShareProof per row that the shares occupy.
	SubtreeRootProofs []*nmt.Proof `json:"subtree_root_proofs"`
	// NamespaceID is the namespace id of the shares being proven. This
	// namespace id is used when verifying the proof. If the namespace id doesn't
	// match the namespace of the shares, the proof will fail verification.
	NamespaceID      namespace.ID   `json:"namespace_id"`
	RowProof         types.RowProof `json:"row_proof"`
	NamespaceVersion uint8          `json:"namespace_version"`
}

func (commitmentProof CommitmentProof) Validate() error {
	if len(commitmentProof.SubtreeRoots) < len(commitmentProof.SubtreeRootProofs) {
		return fmt.Errorf(
			"the number of subtree roots %d should be bigger than the number of subtree root proofs %d",
			len(commitmentProof.SubtreeRoots),
			len(commitmentProof.SubtreeRootProofs),
		)
	}
	if len(commitmentProof.SubtreeRootProofs) != len(commitmentProof.RowProof.Proofs) {
		return fmt.Errorf(
			"the number of subtree root proofs %d should be equal to the number of row root proofs %d",
			len(commitmentProof.SubtreeRoots),
			len(commitmentProof.RowProof.Proofs),
		)
	}
	// TODO either this or use root and Validate method
	if int(commitmentProof.RowProof.EndRow-commitmentProof.RowProof.StartRow+1) != len(commitmentProof.RowProof.RowRoots) {
		return fmt.Errorf(
			"the number of rows %d must equal the number of row roots %d",
			int(commitmentProof.RowProof.EndRow-commitmentProof.RowProof.StartRow+1),
			len(commitmentProof.RowProof.RowRoots),
		)
	}
	if len(commitmentProof.RowProof.Proofs) != len(commitmentProof.RowProof.RowRoots) {
		return fmt.Errorf(
			"the number of proofs %d must equal the number of row roots %d",
			len(commitmentProof.RowProof.Proofs),
			len(commitmentProof.RowProof.RowRoots),
		)
	}
	return nil
}

// Verify verifies that a commitment proof is valid.
// Expects the commitment proof to be properly formulated and validated
// using the Validate() function.
func (commitmentProof CommitmentProof) Verify(root []byte, subtreeRootThreshold int) (bool, error) {
	nmtHasher := nmt.NewNmtHasher(share.NewSHA256Hasher(), share.NamespaceSize, true)

	subtreeRootsCursor := 0
	for i, subtreeRootProof := range commitmentProof.SubtreeRootProofs {
		ranges, err := nmt.ToLeafRanges(subtreeRootProof.Start(), subtreeRootProof.End(), subtreeRootThreshold)
		if err != nil {
			return false, err
		}
		valid, err := subtreeRootProof.VerifySubtreeRootInclusion(
			nmtHasher,
			commitmentProof.SubtreeRoots[subtreeRootsCursor:subtreeRootsCursor+len(ranges)],
			subtreeRootThreshold,
			commitmentProof.RowProof.RowRoots[i],
		)
		if err != nil {
			return false, err
		}
		if !valid {
			return false, fmt.Errorf("subtree root proof for range [%d, %d) is invalid", subtreeRootProof.Start(), subtreeRootProof.End())
		}
		subtreeRootsCursor += len(ranges)
	}

	// verify row roots to data root proof
	return commitmentProof.RowProof.VerifyProof(root), nil
}

// GenerateCommitment generates the share commitment of the corresponding subtree roots.
func (commitmentProof CommitmentProof) GenerateCommitment() bytes.HexBytes {
	return merkle.HashFromByteSlices(commitmentProof.SubtreeRoots)
}
