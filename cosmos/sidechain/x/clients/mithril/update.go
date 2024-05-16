package mithril

import (
	"fmt"

	errorsmod "cosmossdk.io/errors"
	storetypes "cosmossdk.io/store/types"
	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	clienttypes "github.com/cosmos/ibc-go/v8/modules/core/02-client/types"
	host "github.com/cosmos/ibc-go/v8/modules/core/24-host"
	"github.com/cosmos/ibc-go/v8/modules/core/exported"
)

// VerifyClientMessage checks if the clientMessage is of type MithrilHeader or Misbehaviour and verifies the message
func (cs *ClientState) VerifyClientMessage(
	ctx sdk.Context, cdc codec.BinaryCodec, clientStore storetypes.KVStore,
	clientMsg exported.ClientMessage,
) error {
	switch msg := clientMsg.(type) {
	case *MithrilHeader:
		return cs.verifyHeader(ctx, clientStore, cdc, msg)
	case *Misbehaviour:
		return cs.verifyMisbehaviour(ctx, clientStore, cdc, msg)
	default:
		return clienttypes.ErrInvalidClientType
	}
}

func (cs *ClientState) verifyHeader(
	_ sdk.Context, clientStore storetypes.KVStore, _ codec.BinaryCodec,
	header *MithrilHeader,
) error {
	nilCertificate := MithrilCertificate{}

	fcMsdInEpoch := getFcMsdInEpoch(clientStore, header.MithrilStakeDistribution.Epoch)
	fcTsInEpoch := getFcTsInEpoch(clientStore, header.TransactionSnapshot.Epoch)
	fcMsdInPrevEpoch := getFcMsdInEpoch(clientStore, header.MithrilStakeDistribution.Epoch-1)
	fcTsInPrevEpoch := getFcTsInEpoch(clientStore, header.TransactionSnapshot.Epoch-1)

	if fcMsdInEpoch != nilCertificate {
		if header.MithrilStakeDistributionCertificate.PreviousHash != fcMsdInEpoch.Hash {
			return errorsmod.Wrapf(ErrInvalidCertificate, "invalid latest mithril state distribution certificate")
		}
	} else {
		if header.MithrilStakeDistributionCertificate.PreviousHash != fcMsdInPrevEpoch.Hash {
			return errorsmod.Wrapf(ErrInvalidCertificate, "invalid first mithril state distribution certificate")
		}
	}

	if fcTsInEpoch != nilCertificate {
		if header.TransactionSnapshotCertificate.PreviousHash != fcTsInEpoch.Hash {
			return errorsmod.Wrapf(ErrInvalidCertificate, "invalid latest mithril state distribution certificate")
		}
	} else {
		if header.TransactionSnapshotCertificate.PreviousHash != fcTsInPrevEpoch.Hash {
			return errorsmod.Wrapf(ErrInvalidCertificate, "invalid first mithril state distribution certificate")
		}
	}

	err := header.MithrilStakeDistributionCertificate.verifyCertificate()
	if err != nil {
		return errorsmod.Wrapf(ErrInvalidCertificate, "mithril state distribution certificate is invalid")
	}

	err = header.TransactionSnapshotCertificate.verifyCertificate()
	if err != nil {
		return errorsmod.Wrapf(ErrInvalidCertificate, "transaction snapshot certificate is invalid")
	}
	return nil
}

func (c *MithrilCertificate) verifyCertificate() error {
	return errorsmod.Wrap(ErrNotImplemented, "this method is not implemented")
}

func (cs ClientState) UpdateState(ctx sdk.Context, cdc codec.BinaryCodec, clientStore storetypes.KVStore, clientMsg exported.ClientMessage) []exported.Height {
	header, ok := clientMsg.(*MithrilHeader)
	if !ok {
		panic(fmt.Errorf("expected type %T, got %T", &MithrilHeader{}, clientMsg))
	}

	cs.pruneOldestConsensusState(ctx, cdc, clientStore)

	// check for duplicate update
	if _, found := GetConsensusState(clientStore, cdc, header.GetHeight()); found {
		// perform no-op
		return []exported.Height{header.GetHeight()}
	}

	height := NewHeight(header.TransactionSnapshot.Height.GetRevisionHeight())
	if height.GT(cs.LatestHeight) {
		cs.LatestHeight = &height
	}

	consensusState := &ConsensusState{}

	epoch := header.TransactionSnapshot.Epoch
	if epoch > cs.CurrentEpoch {
		cs.CurrentEpoch = epoch
		consensusState = &ConsensusState{
			Timestamp:            header.GetTimestamp(),
			FcHashLatestEpochMsd: header.MithrilStakeDistributionCertificate.Hash,
			FcHashLatestEpochTs:  header.TransactionSnapshotCertificate.Hash,
		}
		// set first certificate of mithril stake distribution and transaction snapshot for epoch
		setFcMsdInEpoch(clientStore, *header.MithrilStakeDistributionCertificate, epoch)
		setFcTsInEpoch(clientStore, *header.TransactionSnapshotCertificate, epoch)
	}
	consensusState = &ConsensusState{
		Timestamp:         header.GetTimestamp(),
		LatestCertHashMsd: header.MithrilStakeDistributionCertificate.Hash,
		LatestCertHashTs:  header.TransactionSnapshotCertificate.Hash,
	}

	// set latest certificate of mithril stake distribution and transaction snapshot for epoch
	setLcMsdInEpoch(clientStore, *header.MithrilStakeDistributionCertificate, epoch)
	setLcTsInEpoch(clientStore, *header.TransactionSnapshotCertificate, epoch)

	// set client state, consensus state and associated metadata
	setClientState(clientStore, cdc, &cs)
	setConsensusState(clientStore, cdc, consensusState, header.GetHeight())
	setConsensusMetadata(ctx, clientStore, header.GetHeight())

	return []exported.Height{height}
}

// pruneOldestConsensusState will retrieve the earliest consensus state for this clientID and check if it is expired. If it is,
// that consensus state will be pruned from store along with all associated metadata. This will prevent the client store from
// becoming bloated with expired consensus states that can no longer be used for updates and packet verification.
func (cs ClientState) pruneOldestConsensusState(ctx sdk.Context, cdc codec.BinaryCodec, clientStore storetypes.KVStore) {
	// Check the earliest consensus state to see if it is expired, if so then set the prune height
	// so that we can delete consensus state and all associated metadata.
	var (
		pruneHeight exported.Height
	)

	pruneCb := func(height exported.Height) bool {
		consState, found := GetConsensusState(clientStore, cdc, height)
		// this error should never occur
		if !found {
			panic(errorsmod.Wrapf(clienttypes.ErrConsensusStateNotFound, "failed to retrieve consensus state at height: %s", height))
		}

		if cs.IsExpired(consState.GetTimestamp(), ctx.BlockTime()) {
			pruneHeight = height
		}

		return true
	}

	IterateConsensusStateAscending(clientStore, pruneCb)

	// if pruneHeight is set, delete consensus state and metadata
	if pruneHeight != nil {
		deleteConsensusState(clientStore, pruneHeight)
		deleteConsensusMetadata(clientStore, pruneHeight)
	}
}

// UpdateStateOnMisbehaviour updates state upon misbehaviour, freezing the ClientState. This method should only be called when misbehaviour is detected
// as it does not perform any misbehaviour checks.
func (cs ClientState) UpdateStateOnMisbehaviour(ctx sdk.Context, cdc codec.BinaryCodec, clientStore storetypes.KVStore, _ exported.ClientMessage) {
	cs.FrozenHeight = &FrozenHeight

	clientStore.Set(host.ClientStateKey(), clienttypes.MustMarshalClientState(cdc, &cs))
}