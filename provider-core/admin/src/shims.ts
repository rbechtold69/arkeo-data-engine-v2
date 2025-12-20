import { Buffer } from "buffer";
import process from "process";

// Provide minimal Node globals for browser bundle consumers.
if (typeof globalThis.Buffer === "undefined") {
    (globalThis as any).Buffer = Buffer;
}
if (typeof globalThis.process === "undefined") {
    (globalThis as any).process = process;
} else {
    // ensure env exists
    const p: any = (globalThis as any).process;
    if (!p.env) p.env = {};
}
if (typeof (globalThis as any).global === "undefined") {
    (globalThis as any).global = globalThis;
}
