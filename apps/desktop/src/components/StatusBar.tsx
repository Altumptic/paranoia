import { Cpu, EyeOff } from "lucide-react";
import { useEffect, useState } from "react";

import type { AddressInfo } from "../engine/types";
import { archLabel, fmtAddr, formatLabel, hex, useStore } from "../store";

export function StatusBar({ native }: { native: boolean }) {
  const info = useStore((s) => s.info);
  const stats = useStore((s) => s.stats);
  const cursor = useStore((s) => s.cursor);
  const session = useStore((s) => s.session);
  const revision = useStore((s) => s.revision);
  const [addr, setAddr] = useState<AddressInfo | null>(null);

  useEffect(() => {
    if (!session || cursor == null) return setAddr(null);
    let live = true;
    session.addressInfo(cursor).then((a) => live && setAddr(a));
    return () => {
      live = false;
    };
  }, [session, cursor, revision]);

  if (!info) return null;
  return (
    <footer className="statusbar">
      <span className="sb-item sb-ready">
        <i className="sb-dot" /> Ready
      </span>
      {addr && (
        <>
          <span className="sb-item mono">{fmtAddr(addr.address, info)}</span>
          {addr.section && <span className="sb-item">{addr.section}</span>}
          {addr.offset != null && <span className="sb-item mono">file +{hex(addr.offset)}</span>}
          {addr.function_name && <span className="sb-item sb-fn">{addr.function_name}</span>}
        </>
      )}
      <span className="sb-spacer" />
      {stats && (
        <span className="sb-item" title={`${stats.blocks.toLocaleString()} blocks · ${stats.xrefs.toLocaleString()} xrefs`}>
          {stats.functions.toLocaleString()} functions · {stats.instructions.toLocaleString()} instructions
          {stats.millis > 0 && ` · ${stats.millis} ms`}
        </span>
      )}
      <span className="sb-item">
        {formatLabel(info.format)} · {archLabel(info.arch)} · {info.endian === "little" ? "LE" : "BE"}
      </span>
      <span className="sb-item" title={native ? "Native Rust engine" : "Rust engine compiled to WebAssembly"}>
        <Cpu size={12} /> {native ? "Native" : "WASM"}
      </span>
      <span className="sb-item sb-private" title="No telemetry, no network access">
        <EyeOff size={12} /> Offline · no telemetry
      </span>
    </footer>
  );
}
