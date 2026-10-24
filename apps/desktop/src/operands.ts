// Operand representation (IDA's H / R / B / M) for the instruction under the cursor.

import type { Instruction } from "./engine/types";
import { useStore } from "./store";

export type OperandKind = "hex" | "dec" | "char" | "bin" | "enum" | "default";

/** Parses a rendered number (`0x40`, `-0x8`, `#12`); null for symbols and chars. */
export function parseNumber(text: string): number | null {
  let t = text.replace(/^#/, "");
  const neg = t.startsWith("-");
  if (neg) t = t.slice(1);
  let v: number;
  if (/^0x[0-9a-f]+$/i.test(t)) v = parseInt(t.slice(2), 16);
  else if (/^0b[01]+$/i.test(t)) v = parseInt(t.slice(2), 2);
  else if (/^\d+$/.test(t)) v = parseInt(t, 10);
  else return null;
  return neg ? -v : v;
}

/** Which number operand a command applies to: the highlighted one, the only one, or all. */
export function pickOperand(ins: Instruction): { n: number | null; text: string | null } {
  const nums = ins.operands.filter((t) => t.k === "number" || (t.k === "symbol" && /^'|\|/.test(t.t)));
  if (nums.length === 0) return { n: null, text: null };
  const hl = useStore.getState().highlight;
  const i = hl == null ? -1 : nums.findIndex((t) => t.t === hl);
  if (i >= 0) return { n: i, text: nums[i].t };
  return { n: nums.length === 1 ? 0 : null, text: nums[0].t };
}

export function hasNumber(ins: Instruction | null | undefined): boolean {
  return ins != null && ins.operands.some((t) => t.k === "number");
}

export async function setOperand(ins: Instruction, kind: OperandKind, enumName?: string) {
  const st = useStore.getState();
  if (!st.session) return;
  const { n } = pickOperand(ins);
  try {
    await st.session.setOperandFormat(ins.address, kind, n, enumName);
    await st.afterEdit(false);
  } catch (e) {
    st.toast(e instanceof Error ? e.message : String(e), "error");
  }
}

/** H: toggle between hexadecimal and decimal. */
export function toggleHex(ins: Instruction) {
  const { text } = pickOperand(ins);
  if (text == null) return;
  return setOperand(ins, /^#?-?0x/i.test(text) ? "dec" : "hex");
}

/** M: choose a symbolic constant. */
export function openEnumDialog(ins: Instruction) {
  const { text } = pickOperand(ins);
  const value = text == null ? null : parseNumber(text);
  if (value == null) {
    useStore.getState().toast("Put the cursor on an instruction with a numeric operand", "info");
    return;
  }
  useStore.getState().set("dialog", { kind: "enum", va: ins.address, initial: "", value, ins });
}
