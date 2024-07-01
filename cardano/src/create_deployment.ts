import {
  Address,
  Data,
  fromText,
  Lucid,
  type MintingPolicy,
  OutRef,
  PolicyId,
  Provider,
  type SpendingValidator,
  UTxO,
} from "npm:@dinhbx/lucid-custom";
import {
  formatTimestamp,
  generateIdentifierTokenName,
  generateTokenName,
  getNonceOutRef,
  readValidator,
  setUp,
} from "./utils.ts";
import {
  EMULATOR_ENV,
  MOCK_MODULE_PORT,
  PORT_PREFIX,
  TRANSFER_MODULE_PORT,
} from "./constants.ts";
import { DeploymentTemplate } from "./template.ts";
import { ensureDir } from "https://deno.land/std@0.212.0/fs/mod.ts";
import { submitTx } from "./utils.ts";
import {
  AuthToken,
  AuthTokenSchema,
} from "../lucid-types/ibc/auth/AuthToken.ts";
import { HandlerDatum } from "../lucid-types/ibc/core/ics_025_handler_interface/handler_datum/HandlerDatum.ts";
import { HandlerOperator } from "../lucid-types/ibc/core/ics_025_handler_interface/handler_redeemer/HandlerOperator.ts";
import {
  OutputReference,
} from "../lucid-types/aiken/transaction/OutputReference.ts";
import { MintPortRedeemer } from "../lucid-types/ibc/core/ics_005/port_redeemer/MintPortRedeemer.ts";
import { MockModuleDatum } from "../lucid-types/ibc/apps/mock/datum/MockModuleDatum.ts";
import { Script } from "npm:@dinhbx/lucid-custom";

// deno-lint-ignore no-explicit-any
(BigInt.prototype as any).toJSON = function () {
  const int = Number.parseInt(this.toString());
  return int ?? this.toString();
};

export const createDeployment = async (
  lucid: Lucid,
  provider: Provider,
  mode?: string,
) => {
  const [authTokenMintingPolicy, authTokenMintingPolicyId] = readValidator(
    "minting_auth_token.mint_auth_token",
    lucid,
  );

  const [handlerNonceUtxo, handlerNonceOutRef] = await getNonceOutRef(lucid);
  const handlerTokenName = generateIdentifierTokenName(handlerNonceOutRef);

  const handlerToken: AuthToken = {
    policy_id: authTokenMintingPolicyId,
    name: handlerTokenName,
  };

  const referredValidators: Map<string, Script> = new Map();

  // setup client validators
  const [
    clientSpendingValidator,
    clientSpendingScriptHash,
    clientSpendingAddress,
  ] = readValidator("spending_client.spend_client", lucid);
  referredValidators.set(
    "spending_client.spend_client",
    clientSpendingValidator,
  );

  const [clientMintingPolicy, clientMintingPolicyId] = readValidator(
    "minting_client.mint_client",
    lucid,
    [
      handlerToken,
      clientSpendingScriptHash,
    ],
    Data.Tuple([AuthTokenSchema, Data.Bytes()]) as unknown as [
      AuthToken,
      string,
    ],
  );
  referredValidators.set(
    "minting_client.mint_client",
    clientMintingPolicy,
  );

  // setup verify proof validator
  const [verifyProofMintingPolicy, verifyProofMintingPolicyId] = readValidator(
    "verifying_proof.verify_proof",
    lucid,
  );
  referredValidators.set(
    "verifying_proof.verify_proof",
    verifyProofMintingPolicy,
  );

  // setup connection validators
  const [
    connectionSpendingValidator,
    connectionSpendingScriptHash,
    connectionSpendingAddress,
  ] = readValidator("spending_connection.spend_connection", lucid, [
    clientMintingPolicyId,
    verifyProofMintingPolicyId,
  ]);
  referredValidators.set(
    "spending_connection.spend_connection",
    connectionSpendingValidator,
  );

  const [connectionMintingPolicy, connectionMintingPolicyId] = readValidator(
    "minting_connection.mint_connection",
    lucid,
    [
      clientMintingPolicyId,
      verifyProofMintingPolicyId,
      connectionSpendingScriptHash,
    ],
  );
  referredValidators.set(
    "minting_connection.mint_connection",
    connectionMintingPolicy,
  );

  // setup port validators
  const [portMintingPolicy, portMintingPolicyId] = readValidator(
    "minting_port.mint_port",
    lucid,
  );

  // setup channel validators
  const channelSpendingValidators = await deploySpendChannel(
    lucid,
    clientMintingPolicyId,
    connectionMintingPolicyId,
    portMintingPolicyId,
    verifyProofMintingPolicyId,
  );
  referredValidators.set(
    "spending_channel.spend_channel",
    channelSpendingValidators.base.script,
  );
  Object.entries(channelSpendingValidators.referredValidators).map(
    ([name, val]) => {
      referredValidators.set(
        name,
        val.script,
      );
    },
  );

  const [channelMintingPolicy, channelMintingPolicyId] = readValidator(
    "minting_channel.mint_channel",
    lucid,
    [
      clientMintingPolicyId,
      connectionMintingPolicyId,
      portMintingPolicyId,
      verifyProofMintingPolicyId,
      channelSpendingValidators.base.hash,
    ],
  );
  referredValidators.set(
    "minting_channel.mint_channel",
    channelMintingPolicy,
  );

  // setup handler validators
  const [
    handlerSpendingValidator,
    handlerSpendingScriptHash,
    handlerSpendingAddress,
  ] = readValidator("spending_handler.spend_handler", lucid, [
    clientMintingPolicyId,
    connectionMintingPolicyId,
    channelMintingPolicyId,
    portMintingPolicyId,
  ]);
  referredValidators.set(
    "spending_handler.spend_handler",
    handlerSpendingValidator,
  );

  await deployHandler(
    lucid,
    handlerNonceUtxo,
    handlerNonceOutRef,
    handlerToken,
    handlerSpendingAddress,
    authTokenMintingPolicy,
  );

  // setup transfer module
  const {
    identifierTokenUnit: transferModuleTokenUnit,
    voucherMintingPolicy,
    transferModuleSpendingValidator,
  } = await deployTransferModule(
    lucid,
    handlerToken,
    handlerSpendingValidator,
    portMintingPolicy,
    authTokenMintingPolicy,
    channelMintingPolicyId,
    TRANSFER_MODULE_PORT,
  );
  referredValidators.set(
    "minting_voucher.mint_voucher",
    voucherMintingPolicy.script,
  );
  referredValidators.set(
    "spending_transfer_module.spend_transfer_module",
    transferModuleSpendingValidator.script,
  );

  // setup mock module
  const {
    identifierTokenUnit: mockModuleIdentifier,
    mockModuleSpendingValidator,
  } = await deployMockModule(
    lucid,
    handlerToken,
    handlerSpendingValidator,
    portMintingPolicy,
    authTokenMintingPolicy,
    MOCK_MODULE_PORT,
  );
  referredValidators.set(
    "spending_mock_module.spend_mock_module",
    mockModuleSpendingValidator.script,
  );

  const refUtxosInfo = await createReferenceUtxos(
    lucid,
    provider,
    referredValidators,
  );

  const spendChannelRefValidator = Object.entries(
    channelSpendingValidators.referredValidators,
  ).reduce<
    Record<
      string,
      { script: string; scriptHash: string; refUtxo: UTxO }
    >
  >((acc, [name, val]) => {
    acc[name] = {
      script: val.script.script,
      scriptHash: val.hash,
      refUtxo: refUtxosInfo[val.hash],
    };

    return acc;
  }, {});

  const [mockTokenPolicyId, mockTokenName] = await mintMockToken(lucid);

  console.log("Deployment info created!");

  const deploymentInfo: DeploymentTemplate = {
    validators: {
      spendHandler: {
        title: "spending_handler.spend_handler",
        script: handlerSpendingValidator.script,
        scriptHash: handlerSpendingScriptHash,
        address: handlerSpendingAddress,
        refUtxo: refUtxosInfo[handlerSpendingScriptHash],
      },
      mintClient: {
        title: "minting_client.mint_client",
        script: clientMintingPolicy.script,
        scriptHash: clientMintingPolicyId,
        address: "",
        refUtxo: refUtxosInfo[clientMintingPolicyId],
      },
      spendClient: {
        title: "spending_client.spend_client",
        script: clientSpendingValidator.script,
        scriptHash: clientSpendingScriptHash,
        address: clientSpendingAddress,
        refUtxo: refUtxosInfo[clientSpendingScriptHash],
      },
      mintConnection: {
        title: "minting_connection.mint_connection",
        script: connectionMintingPolicy.script,
        scriptHash: connectionMintingPolicyId,
        address: "",
        refUtxo: refUtxosInfo[connectionMintingPolicyId],
      },
      spendConnection: {
        title: "spending_connection.spend_connection",
        script: connectionSpendingValidator.script,
        scriptHash: connectionSpendingScriptHash,
        address: connectionSpendingAddress,
        refUtxo: refUtxosInfo[connectionSpendingScriptHash],
      },
      mintChannel: {
        title: "minting_channel.mint_channel",
        script: channelMintingPolicy.script,
        scriptHash: channelMintingPolicyId,
        address: "",
        refUtxo: refUtxosInfo[channelMintingPolicyId],
      },
      spendChannel: {
        title: "spending_channel.spend_channel",
        script: channelSpendingValidators.base.script.script,
        scriptHash: channelSpendingValidators.base.hash,
        address: channelSpendingValidators.base.address,
        refUtxo: refUtxosInfo[channelSpendingValidators.base.hash],
        refValidator: spendChannelRefValidator,
      },
      mintPort: {
        title: "minting_port.mint_port",
        script: portMintingPolicy.script,
        scriptHash: portMintingPolicyId,
        address: "",
        refUtxo: refUtxosInfo[portMintingPolicyId],
      },
      mintAuthToken: {
        title: "minting_auth_token.mint_auth_token",
        script: authTokenMintingPolicy.script,
        scriptHash: authTokenMintingPolicyId,
        address: "",
        refUtxo: refUtxosInfo[authTokenMintingPolicyId],
      },
      spendTransferModule: {
        title: "spending_transfer_module.spend_transfer_module",
        script: transferModuleSpendingValidator.script.script,
        scriptHash: transferModuleSpendingValidator.scriptHash,
        address: transferModuleSpendingValidator.address,
        refUtxo: refUtxosInfo[transferModuleSpendingValidator.scriptHash],
      },
      spendMockModule: {
        title: "spending_mock_module.spend_mock_module",
        script: mockModuleSpendingValidator.script.script,
        scriptHash: mockModuleSpendingValidator.scriptHash,
        address: mockModuleSpendingValidator.address,
        refUtxo: refUtxosInfo[mockModuleSpendingValidator.scriptHash],
      },
      mintVoucher: {
        title: "minting_voucher.mint_voucher",
        script: voucherMintingPolicy.script.script,
        scriptHash: voucherMintingPolicy.policyId,
        address: "",
        refUtxo: refUtxosInfo[voucherMintingPolicy.policyId],
      },
      verifyProof: {
        title: "verifying_proof.verify_proof",
        script: verifyProofMintingPolicy.script,
        scriptHash: verifyProofMintingPolicyId,
        address: "",
        refUtxo: refUtxosInfo[verifyProofMintingPolicyId],
      },
    },
    handlerAuthToken: {
      policyId: handlerToken.policy_id,
      name: handlerToken.name,
    },
    modules: {
      handler: {
        identifier: handlerToken.policy_id + handlerToken.name,
        address: handlerSpendingAddress,
      },
      transfer: {
        identifier: transferModuleTokenUnit,
        address: transferModuleSpendingValidator.address,
      },
      mock: {
        identifier: mockModuleIdentifier,
        address: mockModuleSpendingValidator.address,
      },
    },
    tokens: {
      mock: mockTokenPolicyId + mockTokenName,
    },
  };

  if (mode !== undefined && mode != EMULATOR_ENV) {
    const jsonConfig = JSON.stringify(deploymentInfo);

    const folder = "./deployments";
    await ensureDir(folder);

    const filePath = folder + "/handler_" +
      formatTimestamp(new Date().getTime()) + ".json";

    await Deno.writeTextFile(filePath, jsonConfig);
    await Deno.writeTextFile(folder + "/handler.json", jsonConfig);
    console.log("Deploy info saved to:", filePath);
  }

  return deploymentInfo;
};

async function mintMockToken(lucid: Lucid) {
  // load mint mock token validator
  const [mintMockTokenValidator, mintMockTokenPolicyId] = readValidator(
    "minting_mock_token.mint_mock_token",
    lucid,
  );

  const tokenName = fromText("mock");

  const tokenUnit = mintMockTokenPolicyId + tokenName;

  const tx = lucid.newTx().attachMintingPolicy(mintMockTokenValidator)
    .mintAssets({
      [tokenUnit]: 9999999999n,
    }, Data.void()).payToAddress(
      "addr_test1vqj82u9chf7uwf0flum7jatms9ytf4dpyk2cakkzl4zp0wqgsqnql",
      {
        [tokenUnit]: 999999999n,
      },
    );

  await submitTx(tx, lucid, "Mint mock token");

  return [mintMockTokenPolicyId, tokenName];
}

async function createReferenceUtxos(
  lucid: Lucid,
  provider: Provider,
  referredValidators: Map<string, Script>,
) {
  const deployLucids: Lucid[] = await Promise.all(
    Array.from(referredValidators.values()).map(async (_) => {
      const newLucid = await Lucid.new(provider, "Preview");
      const sk = newLucid.utils.generatePrivateKey();
      newLucid.selectWalletFromPrivateKey(sk);
      return newLucid;
    }),
  );

  const fundDeployAccTx = lucid.newTx();
  await Promise.all(
    deployLucids.map(async (inst) => {
      const address = await inst.wallet.address();
      fundDeployAccTx.payToAddress(address, { lovelace: 1000000000n });
    }),
  );
  await submitTx(fundDeployAccTx, lucid, "fundDeployAccTx", false);

  const [, , referenceAddress] = readValidator(
    "reference_validator.refer_only",
    lucid,
  );

  const createRefUtxoTxs = Array.from(referredValidators.entries()).map(
    ([name, validator], index) => {
      const curLucid = deployLucids[index];
      const tx = curLucid.newTx().payToContract(
        referenceAddress,
        {
          inline: Data.void(),
          scriptRef: validator,
        },
        {},
      );

      return submitTx(
        tx,
        curLucid,
        name,
        true,
      );
    },
  );

  const txHash = await Promise.all(createRefUtxoTxs);
  const outRef: OutRef[] = txHash.map((hash) => ({
    txHash: hash,
    outputIndex: 0,
  }));
  const refUtxos = await lucid.utxosByOutRef(outRef);
  const result: { [x: string]: UTxO } = {};
  refUtxos.forEach((utxo) => {
    const scriptHash = lucid.utils.validatorToScriptHash(utxo.scriptRef!);
    result[scriptHash] = { ...utxo, datumHash: "" };
  });

  return result;
}

const deployHandler = async (
  lucid: Lucid,
  handlerNonceUtxo: UTxO,
  handlerNonceOutRef: OutputReference,
  handlerToken: AuthToken,
  handlerSpendingAddress: Address,
  authTokenMintingPolicy: MintingPolicy,
) => {
  const initHandlerDatum: HandlerDatum = {
    state: {
      next_client_sequence: 0n,
      next_connection_sequence: 0n,
      next_channel_sequence: 0n,
      bound_port: [],
    },
    token: handlerToken,
  };

  const handlerTokenUnit = handlerToken.policy_id + handlerToken.name;

  const mintHandlerTx = lucid
    .newTx()
    .collectFrom([handlerNonceUtxo], Data.void())
    .attachMintingPolicy(authTokenMintingPolicy)
    .mintAssets(
      {
        [handlerTokenUnit]: 1n,
      },
      Data.to(handlerNonceOutRef, OutputReference),
    )
    .payToContract(
      handlerSpendingAddress,
      {
        inline: Data.to(initHandlerDatum, HandlerDatum),
      },
      {
        [handlerTokenUnit]: 1n,
      },
    );

  await submitTx(
    mintHandlerTx,
    lucid,
    "mint handler",
  );
};

const deployTransferModule = async (
  lucid: Lucid,
  handlerToken: AuthToken,
  spendHandlerValidator: SpendingValidator,
  mintPortValidator: MintingPolicy,
  mintIdentifierValidator: MintingPolicy,
  mintChannelPolicyId: string,
  portNumber: bigint,
) => {
  console.log("Create Transfer Module");

  // generate identifier token
  const [nonceUtxo, outputReference] = await getNonceOutRef(lucid);
  const mintIdentifierPolicyId = lucid.utils.validatorToScriptHash(
    mintIdentifierValidator,
  );
  const identifierTokenName = generateIdentifierTokenName(outputReference);
  const identifierToken: AuthToken = {
    policy_id: mintIdentifierPolicyId,
    name: identifierTokenName,
  };
  const identifierTokenUnit = mintIdentifierPolicyId + identifierTokenName;
  const [mintVoucherValidator, mintVoucherPolicyId] = readValidator(
    "minting_voucher.mint_voucher",
    lucid,
    [identifierToken],
    Data.Tuple([AuthTokenSchema]) as unknown as [
      AuthToken,
    ],
  );

  const portId = fromText("port-" + portNumber.toString());
  const mintPortPolicyId = lucid.utils.validatorToScriptHash(mintPortValidator);
  const portTokenName = generateTokenName(
    handlerToken,
    PORT_PREFIX,
    portNumber,
  );
  const portTokenUnit = mintPortPolicyId + portTokenName;
  const portToken: AuthToken = {
    policy_id: mintPortPolicyId,
    name: portTokenName,
  };

  const [
    spendTransferModuleValidator,
    spendTransferModuleScriptHash,
    spendTransferModuleAddress,
  ] = readValidator(
    "spending_transfer_module.spend_transfer_module",
    lucid,
    [
      handlerToken,
      portToken,
      identifierToken,
      portId,
      mintChannelPolicyId,
      mintVoucherPolicyId,
    ],
    Data.Tuple([
      AuthTokenSchema,
      AuthTokenSchema,
      AuthTokenSchema,
      Data.Bytes(),
      Data.Bytes(),
      Data.Bytes(),
    ]) as unknown as [
      AuthToken,
      AuthToken,
      AuthToken,
      string,
      string,
      string,
    ],
  );

  const handlerTokenUnit = handlerToken.policy_id + handlerToken.name;
  const handlerUtxo = await lucid.utxoByUnit(handlerTokenUnit);

  const currentHandlerDatum = Data.from(handlerUtxo.datum!, HandlerDatum);
  const updatedHandlerDatum: HandlerDatum = {
    ...currentHandlerDatum,
    state: {
      ...currentHandlerDatum.state,
      bound_port: [...currentHandlerDatum.state.bound_port, portNumber]
        .toSorted(),
    },
  };
  const spendHandlerRedeemer: HandlerOperator = "HandlerBindPort";

  const mintPortRedeemer: MintPortRedeemer = {
    handler_token: handlerToken,
    spend_module_script_hash: spendTransferModuleScriptHash,
    port_number: portNumber,
  };

  const mintModuleTx = lucid
    .newTx()
    .collectFrom([nonceUtxo], Data.void())
    .collectFrom([handlerUtxo], Data.to(spendHandlerRedeemer, HandlerOperator))
    .attachSpendingValidator(spendHandlerValidator)
    .attachMintingPolicy(mintPortValidator)
    .mintAssets(
      {
        [portTokenUnit]: 1n,
      },
      Data.to(mintPortRedeemer, MintPortRedeemer),
    )
    .attachMintingPolicy(mintIdentifierValidator)
    .mintAssets(
      {
        [identifierTokenUnit]: 1n,
      },
      Data.to(outputReference, OutputReference),
    )
    .payToContract(
      lucid.utils.validatorToAddress(
        spendHandlerValidator,
      ),
      {
        inline: Data.to(updatedHandlerDatum, HandlerDatum),
      },
      {
        [handlerTokenUnit]: 1n,
      },
    )
    .payToContract(
      spendTransferModuleAddress,
      {
        inline: Data.void(),
      },
      {
        [identifierTokenUnit]: 1n,
        [portTokenUnit]: 1n,
      },
    );

  await submitTx(mintModuleTx, lucid, "Mint Transfer Module");

  return {
    identifierTokenUnit,
    voucherMintingPolicy: {
      script: mintVoucherValidator,
      policyId: mintVoucherPolicyId,
    },
    transferModuleSpendingValidator: {
      script: spendTransferModuleValidator,
      scriptHash: spendTransferModuleScriptHash,
      address: spendTransferModuleAddress,
    },
  };
};

const deploySpendChannel = async (
  lucid: Lucid,
  mintClientPolicyId: PolicyId,
  mintConnectionPolicyId: PolicyId,
  mintPortPolicyId: PolicyId,
  verifyProofScriptHash: PolicyId,
) => {
  const knownReferredValidatorsName = [
    "chan_open_ack",
    "chan_open_confirm",
    "chan_close_init",
    "chan_close_confirm",
    "recv_packet",
    "send_packet",
    "timeout_packet",
    "acknowledge_packet",
  ] as const;

  const referredValidatorsName =
    (await Array.fromAsync(Deno.readDir("./validators/spending_channel")))
      .filter((val) => val.isFile)
      .map((val) => {
        const name = val.name.split(".").slice(0, -1).join(".");
        // deno-lint-ignore no-explicit-any
        if (!knownReferredValidatorsName.includes(name as any)) {
          throw new Error(
            `Unknown referred validator of spending_channel, expected ${knownReferredValidatorsName}, found: ${name}`,
          );
        }
        return name;
      });

  const referredValidators = referredValidatorsName.reduce<
    Record<
      string,
      { script: Script; hash: string }
    >
  >((acc, name) => {
    const args = [
      mintClientPolicyId,
      mintConnectionPolicyId,
      mintPortPolicyId,
    ];

    if (name != "send_packet" && name != "chan_close_init") {
      args.push(verifyProofScriptHash);
    }

    const [script, hash] = readValidator(
      `spending_channel/${name}.${name}`,
      lucid,
      args,
    );

    acc[name] = {
      script,
      hash,
    };

    return acc;
  }, {});

  const [script, hash, address] = readValidator(
    "spending_channel.spend_channel",
    lucid,
    knownReferredValidatorsName.map((name) => referredValidators[name].hash),
  );

  return {
    base: {
      script,
      hash,
      address,
    },
    referredValidators,
  };
};

const deployMockModule = async (
  lucid: Lucid,
  handlerToken: AuthToken,
  spendHandlerValidator: SpendingValidator,
  mintPortValidator: MintingPolicy,
  mintIdentifierValidator: MintingPolicy,
  mockModulePort: bigint,
) => {
  console.log("Create Mock Module");

  const [
    spendMockModuleValidator,
    spendMockModuleScriptHash,
    spendMockModuleAddress,
  ] = readValidator(
    "spending_mock_module.spend_mock_module",
    lucid,
  );

  const mintPortPolicyId = lucid.utils.mintingPolicyToId(mintPortValidator);
  const spendHandlerAddress = lucid.utils.validatorToAddress(
    spendHandlerValidator,
  );

  const handlerTokenUnit = handlerToken.policy_id + handlerToken.name;
  const handlerUtxo = await lucid.utxoByUnit(handlerTokenUnit);
  const currentHandlerDatum = Data.from(handlerUtxo.datum!, HandlerDatum);
  const updatedHandlerPorts = [
    ...currentHandlerDatum.state.bound_port,
    mockModulePort,
  ]
    .sort((a, b) => Number(a - b));
  const updatedHandlerDatum: HandlerDatum = {
    ...currentHandlerDatum,
    state: {
      ...currentHandlerDatum.state,
      bound_port: updatedHandlerPorts,
    },
  };
  const spendHandlerRedeemer: HandlerOperator = "HandlerBindPort";

  const portTokenName = generateTokenName(
    handlerToken,
    PORT_PREFIX,
    mockModulePort,
  );
  const portTokenUnit = mintPortPolicyId + portTokenName;
  const mintPortRedeemer: MintPortRedeemer = {
    handler_token: handlerToken,
    spend_module_script_hash: spendMockModuleScriptHash,
    port_number: mockModulePort,
  };

  // load nonce UTXO
  const signerUtxos = await lucid.wallet.getUtxos();
  if (signerUtxos.length < 1) throw new Error("No UTXO founded");
  const NONCE_UTXO = signerUtxos[0];

  const outputReference: OutputReference = {
    transaction_id: {
      hash: NONCE_UTXO.txHash,
    },
    output_index: BigInt(NONCE_UTXO.outputIndex),
  };

  const mintIdentifierPolicyId = lucid.utils.validatorToScriptHash(
    mintIdentifierValidator,
  );
  const identifierTokenName = generateIdentifierTokenName(outputReference);
  const identifierTokenUnit = mintIdentifierPolicyId + identifierTokenName;

  const initModuleDatum: MockModuleDatum = {
    received_packets: [],
  };

  const mintModuleTx = lucid
    .newTx()
    .collectFrom([NONCE_UTXO], Data.void())
    .collectFrom([handlerUtxo], Data.to(spendHandlerRedeemer, HandlerOperator))
    .attachSpendingValidator(spendHandlerValidator)
    .attachMintingPolicy(mintPortValidator)
    .mintAssets(
      {
        [portTokenUnit]: 1n,
      },
      Data.to(mintPortRedeemer, MintPortRedeemer),
    )
    .attachMintingPolicy(mintIdentifierValidator)
    .mintAssets(
      {
        [identifierTokenUnit]: 1n,
      },
      Data.to(outputReference, OutputReference),
    )
    .payToContract(
      spendHandlerAddress,
      {
        inline: Data.to(updatedHandlerDatum, HandlerDatum),
      },
      {
        [handlerTokenUnit]: 1n,
      },
    )
    .payToContract(
      spendMockModuleAddress,
      {
        inline: Data.to(initModuleDatum, MockModuleDatum),
      },
      {
        [identifierTokenUnit]: 1n,
        [portTokenUnit]: 1n,
      },
    );

  await submitTx(mintModuleTx, lucid, "Mint Mock Module");

  return {
    identifierTokenUnit,
    mockModuleSpendingValidator: {
      script: spendMockModuleValidator,
      scriptHash: spendMockModuleScriptHash,
      address: spendHandlerAddress,
    },
  };
};

const main = async () => {
  if (Deno.args.length < 1) throw new Error("Missing script params");

  const MODE = Deno.args[0];

  const { lucid, provider } = await setUp(MODE);

  const deploymentInfo = await createDeployment(lucid, provider, MODE);

  console.log(deploymentInfo);
};

if (import.meta.main) {
  main();
}
