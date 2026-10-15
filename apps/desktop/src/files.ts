import { desktop, type OpenSource } from "./engine/client";

/** Shows the platform file picker. Resolves to null when cancelled. */
export async function pickFile(): Promise<OpenSource | null> {
  if (desktop) {
    const path = await desktop.openDialog();
    return path ? { kind: "path", path } : null;
  }
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.onchange = async () => {
      const f = input.files?.[0];
      resolve(f ? await fromFile(f) : null);
    };
    // No reliable cancel event across browsers; a never-resolved promise is harmless here.
    input.click();
  });
}

/** Desktop: open dropped files by path (no copy through IPC). Browser: read the bytes. */
export async function fromFile(f: File): Promise<OpenSource> {
  const path = desktop?.pathForFile(f);
  if (path) return { kind: "path", path };
  return { kind: "bytes", name: f.name, bytes: await f.arrayBuffer() };
}
