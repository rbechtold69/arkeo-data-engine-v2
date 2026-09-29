import { GasPrice, SigningStargateClient, calculateFee, defaultRegistryTypes } from "@cosmjs/stargate";
import { OfflineSigner, Registry as ProtoRegistry } from "@cosmjs/proto-signing";
import { SwapMessage, swapTypeUrl } from "./swap-codec";

declare global {
    interface Window {
        keplr?: any;
        getOfflineSigner?: (chainId: string) => OfflineSigner;
    }
}

type ConnectOptions = {
    chainId?: string;
    rpcEndpoint?: string;
};

type SwapOptions = ConnectOptions & {
    senderAddress?: string;
    tokenInDenom: string;
    tokenOutDenom: string;
    amountInBase: string | number | bigint;
    minOutBase: string | number | bigint;
    memo?: string;
    gas?: number;
    gasPrice?: string;
    poolId?: string | number | bigint;
};

type IbcTransferOptions = ConnectOptions & {
    senderAddress?: string;
    receiver: string;
    denom: string;
    amountBase: string | number | bigint;
    sourceChannel: string;
    sourcePort?: string;
    timeoutSeconds?: number;
    memo?: string;
    gas?: number;
    gasPrice?: string;
};

const DEFAULT_CHAIN_ID = "osmosis-1";
const DEFAULT_POOL_ID = 2977;
const DEFAULT_GAS_PRICE = "0.0025uosmo";
const DEFAULT_SWAP_GAS = 350000;
const DEFAULT_IBC_GAS = 250000;
const DEFAULT_IBC_TIMEOUT_SECONDS = 600;

let cachedChainId = DEFAULT_CHAIN_ID;
let cachedRpc = "";
let cachedSigner: OfflineSigner | null = null;
let cachedClient: SigningStargateClient | null = null;
let cachedAddress = "";

function requireKeplr() {
    if (!window.keplr || !window.getOfflineSigner) {
        throw new Error("Keplr extension is required for signing.");
    }
}

function normalizeAmount(val: string | number | bigint): string {
    if (typeof val === "number" && !Number.isSafeInteger(val)) throw new Error("Amount must be an exact integer");
    const text = String(val);
    if (!/^[0-9]+$/.test(text) || BigInt(text) <= 0n) throw new Error("Amount must be a positive integer in base units");
    return text;
}

function buildRegistry() {
    return new ProtoRegistry([...defaultRegistryTypes, [swapTypeUrl, SwapMessage]]);
}

async function resolveIbcTimeout(client: SigningStargateClient, _chainId: string, timeoutSeconds: number) {
    const block = await client.getBlock();
    const blockTimeMs = Date.parse(String(block.header.time));
    if (!Number.isFinite(blockTimeMs) || Date.now() - blockTimeMs > 60000 || blockTimeMs - Date.now() > 10000) {
        throw new Error("RPC block time is stale or invalid");
    }
    // CosmJS sendIbcTokens expects seconds and converts to protobuf nanoseconds.
    // An IBC timeout height belongs to the destination, not this source chain.
    return { timeoutTimestamp: Math.floor(blockTimeMs / 1000) + timeoutSeconds, timeoutHeight: undefined };
}

async function ensureSigner(chainId: string) {
    requireKeplr();
    cachedClient?.disconnect();
    cachedClient = null;
    cachedSigner = null;
    cachedAddress = "";
    cachedRpc = "";
    await window.keplr.enable(chainId);
    cachedSigner = window.getOfflineSigner!(chainId);
    const accounts = await cachedSigner.getAccounts();
    if (!accounts || !accounts.length) {
        throw new Error("No accounts available in Keplr.");
    }
    cachedAddress = accounts[0].address;
    cachedChainId = chainId;
    return cachedSigner;
}

async function ensureClient(opts: { chainId: string; rpcEndpoint: string }) {
    const chainId = opts.chainId || DEFAULT_CHAIN_ID;
    await ensureSigner(chainId);
    if (!cachedClient || cachedRpc !== opts.rpcEndpoint || cachedChainId !== chainId) {
        const registry = buildRegistry();
        cachedClient = await SigningStargateClient.connectWithSigner(opts.rpcEndpoint, cachedSigner!, { registry });
        if (await cachedClient.getChainId() !== chainId) {
            cachedClient.disconnect(); cachedClient = null;
            throw new Error("RPC network does not match the selected wallet network");
        }
        cachedRpc = opts.rpcEndpoint;
        cachedChainId = chainId;
    }
    return cachedClient;
}

export async function connectKeplr(opts: ConnectOptions = {}) {
    const chainId = opts.chainId || cachedChainId || DEFAULT_CHAIN_ID;
    await ensureSigner(chainId);
    if (opts.rpcEndpoint) {
        await ensureClient({ chainId, rpcEndpoint: opts.rpcEndpoint });
    }
    return cachedAddress;
}

export function onKeplrKeystoreChange(handler?: (address: string) => void, opts: ConnectOptions = {}) {
    window.addEventListener("keplr_keystorechange", async () => {
        try {
            const addr = await connectKeplr(opts);
            handler?.(addr);
        } catch (err) {
            console.error("Keplr keystore change handling failed", err);
        }
    });
}

export function getCachedAddress() {
    return cachedAddress;
}

export async function signAndBroadcastSwap(opts: SwapOptions) {
    const chainId = opts.chainId || cachedChainId || DEFAULT_CHAIN_ID;
    if (!opts.rpcEndpoint) throw new Error("rpcEndpoint is required to sign swap.");
    const client = await ensureClient({ chainId, rpcEndpoint: opts.rpcEndpoint });
    const addr = opts.senderAddress || cachedAddress || (await connectKeplr(opts));
    if (addr !== cachedAddress) throw new Error("Sender does not match the active wallet");
    const poolId = normalizeAmount(opts.poolId ?? DEFAULT_POOL_ID);
    if (BigInt(poolId) > 18446744073709551615n) throw new Error("Pool ID exceeds uint64");
    const msg = { typeUrl: swapTypeUrl, value: {
        sender: addr,
        routes: [{ poolId, tokenOutDenom: opts.tokenOutDenom }],
        tokenIn: { denom: opts.tokenInDenom, amount: normalizeAmount(opts.amountInBase) },
        tokenOutMinAmount: normalizeAmount(opts.minOutBase),
    } };
    const fee = calculateFee(opts.gas || DEFAULT_SWAP_GAS, GasPrice.fromString(opts.gasPrice || DEFAULT_GAS_PRICE));
    const result = await client.signAndBroadcast(addr, [msg], fee, opts.memo || "");
    if (result.code !== 0) {
        throw new Error(result.rawLog || `swap failed (code ${result.code})`);
    }
    return { transactionHash: result.transactionHash, rawLog: result.rawLog };
}

export async function signAndBroadcastIbcTransfer(opts: IbcTransferOptions) {
    const chainId = opts.chainId || cachedChainId || DEFAULT_CHAIN_ID;
    if (!opts.rpcEndpoint) throw new Error("rpcEndpoint is required to sign IBC transfer.");
    const client = await ensureClient({ chainId, rpcEndpoint: opts.rpcEndpoint });
    const addr = opts.senderAddress || cachedAddress || (await connectKeplr(opts));
    if (addr !== cachedAddress) throw new Error("Sender does not match the active wallet");
    const timeoutSeconds = opts.timeoutSeconds ?? DEFAULT_IBC_TIMEOUT_SECONDS;
    if (!Number.isSafeInteger(timeoutSeconds) || timeoutSeconds < 60 || timeoutSeconds > 86400) throw new Error("IBC timeout must be 60–86400 seconds");
    const fee = calculateFee(opts.gas || DEFAULT_IBC_GAS, GasPrice.fromString(opts.gasPrice || DEFAULT_GAS_PRICE));
    const { timeoutTimestamp, timeoutHeight } = await resolveIbcTimeout(client, chainId, timeoutSeconds);
    const result = await client.sendIbcTokens(
        addr,
        opts.receiver,
        { denom: opts.denom, amount: normalizeAmount(opts.amountBase) },
        opts.sourcePort || "transfer",
        opts.sourceChannel,
        timeoutHeight,
        timeoutTimestamp,
        fee,
        opts.memo || "",
    );
    if (result.code !== 0) {
        throw new Error(result.rawLog || `ibc transfer failed (code ${result.code})`);
    }
    return { transactionHash: result.transactionHash, rawLog: result.rawLog };
}
