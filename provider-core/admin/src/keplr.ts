import { GasPrice, SigningStargateClient, calculateFee, defaultRegistryTypes } from "@cosmjs/stargate";
import { OfflineSigner, Registry as ProtoRegistry } from "@cosmjs/proto-signing";
import { osmosis } from "osmojs";

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
    poolId?: number;
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
    if (typeof val === "bigint") return val.toString();
    return String(val ?? "0");
}

function buildRegistry() {
    return new ProtoRegistry([...defaultRegistryTypes, ...(osmosis.gamm.v1beta1.registry || [])]);
}

async function ensureSigner(chainId: string) {
    requireKeplr();
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
    if (!cachedSigner || cachedChainId !== chainId) {
        await ensureSigner(chainId);
    }
    if (!cachedClient || cachedRpc !== opts.rpcEndpoint || cachedChainId !== chainId) {
        const registry = buildRegistry();
        cachedClient = await SigningStargateClient.connectWithSigner(opts.rpcEndpoint, cachedSigner!, { registry });
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
    const poolId = BigInt(opts.poolId ?? DEFAULT_POOL_ID);
    const msg = osmosis.gamm.v1beta1.MessageComposer.withTypeUrl.swapExactAmountIn({
        sender: addr,
        routes: [{ poolId, tokenOutDenom: opts.tokenOutDenom }],
        tokenIn: { denom: opts.tokenInDenom, amount: normalizeAmount(opts.amountInBase) },
        tokenOutMinAmount: normalizeAmount(opts.minOutBase),
    });
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
    const timeoutSeconds = opts.timeoutSeconds ?? 300;
    const fee = calculateFee(opts.gas || DEFAULT_IBC_GAS, GasPrice.fromString(opts.gasPrice || DEFAULT_GAS_PRICE));
    const timeoutTimestamp = BigInt(Date.now()) * 1_000_000n + BigInt(timeoutSeconds) * 1_000_000_000n;
    const result = await client.sendIbcTokens(
        addr,
        opts.receiver,
        { denom: opts.denom, amount: normalizeAmount(opts.amountBase) },
        opts.sourcePort || "transfer",
        opts.sourceChannel,
        undefined,
        timeoutTimestamp,
        fee,
        opts.memo || "",
    );
    if (result.code !== 0) {
        throw new Error(result.rawLog || `ibc transfer failed (code ${result.code})`);
    }
    return { transactionHash: result.transactionHash, rawLog: result.rawLog };
}
