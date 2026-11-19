// Hooks run without a click, so Paranoia only runs them for a version you chose to "Always run":
// run the command once from the Plugins menu (or Ctrl+Alt+R) and pick that option.
// A hook function receives `event`: { name: "open", file, sha256, format, arch } or { name: "rename", address, new_name }.

async function report() {
  const fns = await pn.functions();
  const unnamed = fns.filter((f) => /^sub_/i.test(f.name)).length;
  print(fns.length, "functions,", unnamed, "still have automatic names");
}

async function onOpen(event) {
  print("opened", event.file, "(" + event.arch + ")");
  await report();
}

function onRename(event) {
  print("renamed", pn.hex(event.address), "to", event.new_name);
}
