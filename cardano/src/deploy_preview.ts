import { Blockfrost, Lucid } from "npm:@dinhbx/lucid-custom";
import { createDeployment } from "./create_deployment.ts";
import { load } from "https://deno.land/std@0.213.0/dotenv/mod.ts";
import { BLOCKFROST_ENV } from "./constants.ts";

const env = await load();

const deployerMnemonic = env["DEPLOYER_MNEMONIC"];
const url = env["BLOCKFROST_URL"];
const projectId = env["BLOCKFROST_PROJECT_ID"];

if (!deployerMnemonic || !url || !projectId) {
    throw new Error("Unable to load environment variables");
}

const provider = new Blockfrost(url, projectId);

const lucid = await Lucid.new(provider, "Preview");
lucid.selectWalletFromSeed(deployerMnemonic);

console.log("=".repeat(70));
await createDeployment(lucid, provider, "sanchonet");
