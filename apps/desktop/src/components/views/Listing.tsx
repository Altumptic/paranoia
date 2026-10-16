import type { Instruction, Token } from "../../engine/types";
import { useStore } from "../../store";

const TOKEN_CLASS: Record<Token["k"], string> = {
  text: "t-text",
  register: "t-reg",
  number: "t-num",
  keyword: "t-kw",
  symbol: "t-sym",
  address: "t-addr",
  punct: "t-punct",
  prefix: "t-kw",
};

export function mnemonicClass(ins: Instruction): string {
  switch (ins.flow) {
    case "call":
      return "m-call";
    case "jump":
    case "condjump":
      return "m-jump";
    case "ret":
      return "m-ret";
    case "interrupt":
      return "m-int";
    default:
      return ["align", "db", "dw", "dd", "dq", "text", "extrn", ".word"].includes(ins.mnemonic) ? "m-data" : "m-plain";
  }
}

/** Mnemonic + operands + comments of one instruction. Clicking a symbol / address follows it. */
export function InstructionText({ ins, onFollow }: { ins: Instruction; onFollow?(va: number): void }) {
  const followable = ins.target != null && onFollow;
  const highlight = useStore((s) => s.highlight);
  // Clicking a register / number / name highlights every occurrence (IDA's yellow marker).
  const mark = (text: string) => useStore.getState().set("highlight", useStore.getState().highlight === text ? null : text);
  return (
    <>
      <span className={`mnem ${mnemonicClass(ins)} ${highlight === ins.mnemonic ? "hl" : ""}`} onClick={() => mark(ins.mnemonic)}>
        {ins.mnemonic}
      </span>
      <span className="ops">
        {ins.operands.map((t, i) => {
          const link = followable && (t.k === "symbol" || t.k === "address");
          return (
            <span
              key={i}
              className={`${TOKEN_CLASS[t.k]} ${link ? "link-tok" : ""} ${highlight != null && t.t === highlight && t.k !== "punct" ? "hl" : ""}`}
              onClick={(e) => {
                if (t.k === "punct") return;
                // Ctrl/Cmd-click or a click on a name follows it; anything else highlights.
                if (link && (e.ctrlKey || e.metaKey || t.k === "symbol")) {
                  e.stopPropagation();
                  onFollow!(ins.target!);
                } else {
                  mark(t.t);
                }
              }}
            >
              {t.t}
            </span>
          );
        })}
      </span>
      {(ins.user_comment || ins.comment) && (
        <span className="cmt">
          {ins.user_comment && <span className="cmt-user">; {ins.user_comment}</span>}
          {ins.comment && <span className={ins.comment.startsWith('"') || ins.comment.startsWith('L"') ? "cmt-str" : "cmt-auto"}>; {ins.comment}</span>}
        </span>
      )}
    </>
  );
}
