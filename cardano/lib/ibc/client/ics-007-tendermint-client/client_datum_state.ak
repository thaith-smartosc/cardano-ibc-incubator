use ibc/client/ics_007_tendermint_client/client_state.{ClientState}
use ibc/client/ics_007_tendermint_client/height.{Height}
use ibc/client/ics_007_tendermint_client/consensus_state.{ConsensusState}

pub type ClientDatumState {
  client_state: ClientState,
  consensus_states: List<(Height, ConsensusState)>,
}

pub fn new(
  client_state: ClientState,
  consensus_states: List<(Height, ConsensusState)>,
) -> ClientDatumState {
  ClientDatumState { client_state, consensus_states }
}
