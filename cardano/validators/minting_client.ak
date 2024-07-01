use aiken/bytearray
use aiken/dict.{Dict}
use aiken/hash.{Blake2b_224, Hash}
use aiken/interval
use aiken/list
use aiken/transaction.{
  Input, Mint, Redeemer, ScriptContext, ScriptPurpose, Spend, Transaction,
}
use aiken/transaction/credential.{Script}
use aiken/transaction/value.{PolicyId}
use ibc/auth.{AuthToken}
use ibc/client/ics_007_tendermint_client/client_datum.{ClientDatum}
use ibc/client/ics_007_tendermint_client/client_datum_state.{ClientDatumState}
use ibc/client/ics_007_tendermint_client/client_state
use ibc/client/ics_007_tendermint_client/consensus_state.{ConsensusState}
use ibc/client/ics_007_tendermint_client/height
use ibc/client/ics_007_tendermint_client/types/unchecked_rational
use ibc/core/ics_002_client_semantics/types/client.{Active}
use ibc/core/ics_002_client_semantics/types/keys.{client_prefix_with_separator}
use ibc/core/ics_023_vector_commitments/merkle.{MerkleRoot}
use ibc/core/ics_025_handler_interface/handler as handler_state_mod
use ibc/core/ics_025_handler_interface/handler_datum.{HandlerDatum}
use ibc/core/ics_025_handler_interface/handler_redeemer.{
  CreateClient as HandlerCreateClient, HandlerOperator,
}
use ibc/utils/string as string_utils
use ibc/utils/test_utils
use ibc/utils/validator_utils

validator(
  handler_token: AuthToken,
  client_spending_script_hash: Hash<Blake2b_224, Script>,
) {
  fn mint_client(_redeemer: Void, context: ScriptContext) -> Bool {
    let ScriptContext { transaction, purpose } = context
    expect Mint(client_minting_policy_id) = purpose
    let Transaction { inputs, outputs, mint, redeemers, validity_range, .. } =
      transaction

    //========================valid input=======================
    // input contains handler auth token
    expect Some(handler_input) =
      inputs
        |> list.find(
            fn(input) { input.output |> auth.contain_auth_token(handler_token) },
          )

    // spent handler redeemer is CreateClient operator
    expect Some(spent_handler_redeemer) =
      redeemers |> dict.get(Spend(handler_input.output_reference))
    expect handler_operator: HandlerOperator = spent_handler_redeemer
    expect handler_operator == HandlerCreateClient

    //========================valid mint=======================
    let spent_handler_output = handler_input.output
    expect spent_handler_datum: HandlerDatum =
      validator_utils.get_inline_datum(spent_handler_output)

    let client_token_name =
      string_utils.int_to_string(spent_handler_datum.state.next_client_sequence)
        |> bytearray.concat(client_prefix_with_separator, _)

    let client_token =
      AuthToken { policy_id: client_minting_policy_id, name: client_token_name }
    expect auth.mint_auth_token(mint, client_token)

    //========================valid output========================
    expect [client_output] =
      outputs
        |> transaction.find_script_outputs(client_spending_script_hash)

    // client utxo contains auth token
    expect auth.contain_auth_token(client_output, client_token)

    // client utxo datum created valid
    expect client_output_datum: ClientDatum =
      validator_utils.get_inline_datum(client_output)
    expect
      client_output_datum
        |> client_datum.is_initialized_valid(client_token)

    // client status must be Active
    let tx_valid_to = validator_utils.get_tx_valid_to(validity_range)
    expect
      client_state.status(
        client_output_datum.state.client_state,
        // posix time in cardano is millisecond while time of cosmos tendermint is nanosecond
        tx_valid_to * 1_000_000,
        dict.from_list(
          client_output_datum.state.consensus_states,
          height.compare,
        ),
      ) == Active

    True
  }
}

//==========================test==========================

type FakeData {
  handler_token: AuthToken,
  client_spending_script_hash: Hash<Blake2b_224, Script>,
  client_minting_policy_id: PolicyId,
}

fn setup_fake_data() -> FakeData {
  let handler_token = auth.new("fake handler policy_id", "fake handler name")

  let client_spending_script_hash = "fake spend client script hash"

  let client_minting_policy_id = "fake client mint policy id"

  FakeData {
    handler_token,
    client_spending_script_hash,
    client_minting_policy_id,
  }
}

test test_create_valid_client() {
  let fake_data = setup_fake_data()

  //========================arrange input=======================
  let fake_handler_input =
    test_utils.setup_handler(
      fake_data.handler_token,
      handler_state_mod.new(1, 0, 0, []),
    )

  let inputs =
    [fake_handler_input]

  //========================arrange redeemer=======================
  let redeemer: Data = HandlerCreateClient
  let redeemers: Dict<ScriptPurpose, Redeemer> =
    test_utils.create_redeemers(
      [(Spend(fake_handler_input.output_reference), redeemer)],
    )

  //========================arrange mint=======================
  let client_token_name = "ibc_client-1"

  let mint =
    test_utils.setup_mint_auth_token(
      fake_data.client_minting_policy_id,
      client_token_name,
    )

  //========================arrange output=======================
  let fake_latest_height = height.new_height(0, 100)

  let fake_client_state =
    client_state.new_client_state(
      chain_id: "cosmoshub",
      trust_level: unchecked_rational.from_int(1),
      trusting_period: 1_000_000_000_000,
      unbonding_period: 1_000_000_000_001,
      max_clock_drift: 1,
      latest_height: fake_latest_height,
      proof_specs: [],
    )

  let fake_consensus_state =
    ConsensusState {
      timestamp: 1705635096691000000,
      next_validators_hash: #"",
      root: MerkleRoot { hash: #"" },
    }

  let client_token =
    auth.new(fake_data.client_minting_policy_id, client_token_name)

  let client_datum_state =
    client_datum_state.new(
      fake_client_state,
      [(fake_latest_height, fake_consensus_state)],
    )

  let client_datum =
    ClientDatum { state: client_datum_state, token: client_token }

  let client_output =
    test_utils.create_output(
      fake_data.client_spending_script_hash,
      [(fake_data.client_minting_policy_id, client_token_name, 1)],
      client_datum,
    )

  let valid_to = 1

  let context =
    ScriptContext {
      purpose: Mint(fake_data.client_minting_policy_id),
      transaction: Transaction {
        ..transaction.placeholder(),
        inputs: inputs,
        outputs: [client_output],
        mint: mint,
        redeemers: redeemers,
        validity_range: interval.before(valid_to),
      },
    }

  mint_client(
    fake_data.handler_token,
    fake_data.client_spending_script_hash,
    Void,
    context,
  )
}
