import type { Instruction, Token } from "../../engine/types";

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
      return ins.mnemonic === "align" || ins.mnemonic === "db" || ins.mnemonic === ".word" ? "m-data" : "m-plain";
  }
}

/** Mnemonic + operands + comments of one instruction. Clicking a symbol / address follows it. */
export function InstructionText({ ins, onFollow }: { ins: Instruction; onFollow?(va: number): void }) {
  const followable = ins.target != null && onFollow;
  return (
    <>
      <span className={`mnem ${mnemonicClass(ins)}`}>{ins.mnemonic}</span>
      <span className="ops">
        {ins.operands.map((t, i) => {
          const link = followable && (t.k === "symbol" || t.k === "address");
          return (
            <span
              key={i}
              className={`${TOKEN_CLASS[t.k]} ${link ? "link-tok" : ""}`}
              onClick={
                link
                  ? (e) => {
                      e.stopPropagation();
                      onFollow!(ins.target!);
                    }
                  : undefined
              }
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
