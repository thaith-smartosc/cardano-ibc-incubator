# Cardano Validator Script

## Overview

This document contains information about validator scripts that power IBC on Cardano blockchain.

Validator scripts is written in Aiken - a modern programming language and toolchain for developing smart contracts on the Cardano. Aiken is easier than Plutus to get started with for those who are less familiar with functional languages like Haskell. For more information visit [Aiken docs](https://aiken-lang.org/).

## Components

Validators scripts are located in `validators/` directory and implement the following specifications of IBC:
- [ICS-25 Handler Interface](https://github.com/cosmos/ibc/tree/main/spec/core/ics-025-handler-interface): `minting_handler.mint_handler`, `spending_handler.spend_handler`.
- [ICS-02 Client Semantics](https://github.com/cosmos/ibc/tree/main/spec/core/ics-002-client-semantics): `minting_client.mint_client`, `spending_client.spend_client`.
- [ICS-03 Connection Semantics](https://github.com/cosmos/ibc/tree/main/spec/core/ics-003-connection-semantics): `minting_connection.mint_connection`, `spending_connection.spend_connection`.
- [ICS-04 Channel & Packet Semantics](https://github.com/cosmos/ibc/tree/main/spec/core/ics-004-channel-and-packet-semantics): `minting_channel.mint_channel`, `spending_channel.spend_channel`, all validators in `spending_channel/` directory.
- [ICS-05 Port Allocation](https://github.com/cosmos/ibc/tree/main/spec/core/ics-005-port-allocation): `minting_port.mint_port`.
- [ICS-23 Vector Commitments](https://github.com/cosmos/ibc/blob/main/spec/core/ics-023-vector-commitments): `verifying_proof.verify_proof`.
- [ICS-20 Fungible Token Transfer](https://github.com/cosmos/ibc/tree/main/spec/app/ics-020-fungible-token-transfer): `spending_transfer_module.spend_transfer_module`, `minting_voucher.mint_voucher`.

There are also some validator scripts used as utilities and will be explained later.

## Storing IBC states

Cardano uses the eUTXO model, where the states of the blockchain are stored in UTXOs and updated by spending these UTXOs. Unlike other blockchains, where an address can hold almost unlimited data (as long as you can pay the fee for it), transactions in Cardano have a size limit, and the UTXO size, which is also included in the transaction, must be lower than that limit. Therefore, if a DApp has too much data, we must distribute it into multiple UTXOs. In IBC which has a bunch of states, we choose to store states of each client, connection and channel in a sole UTXO and have different validator scripts to manage their spending conditions.

However, distributed states also bring some challenges, one of which is identifying which UTXOs belong to our system. Since anyone can create UTXOs that contain any data and attach them to any address, we need a way to distinguish the ones with the same address. To achieve this goal, we used another type of validator scripts called minting policy which help us manage minting and burning native token on Cardano. With this, beside creating new UTXO for each object of IBC, we also mint a new authentication token and attach it to newly created UTXO. Then the spending validator script of the UTXO will ensure that the spent one must contain the authentication token, and this token will be retained in the updated output UTXO.

By leveraging both the spending validator and minting policy, we can effectively create, update and query states of IBC on Cardano. You can refer to the previous section and notice that all semantic of IBC specs are also implemented with both these types of mentioned validator script.

## Reference scripts

Every time a script is used, the transaction which caused the usage must supply the whole script as part of the transaction. This not only increases the transaction fee but also makes the transaction reach its size limit more frequently. That is why Cardano introduced CIP-33 Reference scripts. This CIP allows scripts to be attached to UTXOs and used to satisfy the requirement of providing the scripts during validation.

In Cardano IBC, which has a large Aiken validator scripts codebase, using reference scripts is a must because transaction size limit is never satisfied with a large amount of IBC states plus a very long Aiken scripts (sometimes it can be 2 to 3 times larger the transaction size limit). While effectively helping reduce the transaction size and cost, using reference scripts also requires some extra steps for setup and use.We will discuss this further in section [Deploying](#deploying)

## Transaction Level Validator Minting Policy

Sometimes the size of a single validator script can be larger than the transaction size limit, so we can't even execute a transaction to attach it to a reference script. This can happen if the validator script handles a lot of operations, as many of our IBC scripts do. To deal with this, instead of implementing all logic for a semantic in a single script, we can use minting policies to extend transaction-level validation. With this solution, the role of the original validator script is simply to check that other minting policies are included in the transaction, while the minting scripts will be responsible for validating the main logic. Despite bringing some downside regarding the cost of cross-validation between scripts and minting unused tokens, this method is very effective in reducing the size of validator scripts. Combined with reference scripts, it allows us to have very complicated logic in our validator scripts.

## Dependencies between validator scripts

Since we have separated validator scripts into multiple smaller ones, they often need to refer and cross-validate each other. This leads to some scripts needing to know about others, making dependencies between them somewhat complex. You can see the graph of script dependencies below or [here](./static/img/scripts_dependecies.png) for more clarity (scripts depend on the ones they point to):

```mermaid
graph TD;
    MINT_CHANNEL(minting_handler.mint_handler)-.->SPEND_CHANNEL(spending_handler.spend_handler);

    SPEND_CHANNEL-.->MINT_CLIENT(minting_client.mint_client);
    SPEND_CHANNEL-.->MINT_CONN(minting_connection.mint_connection);
    SPEND_CHANNEL-.->MINT_CHAN(minting_channel.mint_channel);
    SPEND_CHANNEL-.->MINT_PORT(minting_port.mint_port);

    MINT_CLIENT-.->SPEND_CLIENT(spending_client.spend_client);

    MINT_CONN-.->MINT_CLIENT;
    MINT_CONN-.->SPEND_CONN(spending_connection.spend_connection);
    MINT_CONN-.->VERIFY_PROOF(verifying_proof.verify_proof);

    MINT_CHAN-.->MINT_CLIENT;
    MINT_CHAN-.->MINT_CONN;
    MINT_CHAN-.->MINT_PORT;
    MINT_CHAN-.->VERIFY_PROOF;
    MINT_CHAN-.->SPEND_CHAN(spending_channel.spend_channel);

    SPEND_CONN-.->MINT_CLIENT;
    SPEND_CONN-.->VERIFY_PROOF;

    SPEND_CHAN-.->SPEND_CHAN_MINTING_POLICIES(spending_channel/ minting polices);

    SPEND_CHAN_MINTING_POLICIES-.->MINT_CLIENT;
    SPEND_CHAN_MINTING_POLICIES-.->MINT_CONN;
    SPEND_CHAN_MINTING_POLICIES-.->MINT_PORT;
    SPEND_CHAN_MINTING_POLICIES-.->VERIFY_PROOF;
```

## Deploying

