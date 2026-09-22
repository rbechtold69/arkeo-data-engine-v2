// Wire schema: osmosis/gamm/v1beta1/tx.proto and poolmanager/v1beta1/swap_route.proto.
// Only the swap message used by this wallet flow is registered.
import protobuf from "protobufjs/minimal.js";
const { Writer, Reader } = protobuf;
export const swapTypeUrl = "/osmosis.gamm.v1beta1.MsgSwapExactAmountIn";
export const SwapMessage = {
  encode(message: any, writer = Writer.create()) {
    if (message.sender) writer.uint32(10).string(message.sender);
    for (const route of message.routes || []) {
      writer.uint32(18).fork().uint32(8).uint64(route.poolId.toString());
      writer.uint32(18).string(route.tokenOutDenom).ldelim();
    }
    if (message.tokenIn) {
      writer.uint32(26).fork().uint32(10).string(message.tokenIn.denom);
      writer.uint32(18).string(message.tokenIn.amount).ldelim();
    }
    if (message.tokenOutMinAmount) writer.uint32(34).string(message.tokenOutMinAmount);
    return writer;
  },
  decode(input: Uint8Array) {
    const reader = Reader.create(input);
    const result: any = { sender: "", routes: [], tokenOutMinAmount: "" };
    while (reader.pos < reader.len) {
      const tag = reader.uint32();
      if (tag === 10) result.sender = reader.string();
      else if (tag === 18 || tag === 26) {
        const length = reader.uint32(); const end = reader.pos + length;
        if (end > reader.len) throw new Error("Truncated swap message");
        const row: any = tag === 18 ? { poolId: "0", tokenOutDenom: "" } : { denom: "", amount: "" };
        while (reader.pos < end) {
          const field = reader.uint32();
          if (tag === 18 && field === 8) row.poolId = reader.uint64().toString();
          else if (tag === 18 && field === 18) row.tokenOutDenom = reader.string();
          else if (tag === 26 && field === 10) row.denom = reader.string();
          else if (tag === 26 && field === 18) row.amount = reader.string();
          else reader.skipType(field & 7);
        }
        if (reader.pos !== end) throw new Error("Invalid swap message length");
        if (tag === 18) result.routes.push(row); else result.tokenIn = row;
      } else if (tag === 34) result.tokenOutMinAmount = reader.string();
      else reader.skipType(tag & 7);
    }
    return result;
  },
  fromPartial(value: any) { return value; },
};
