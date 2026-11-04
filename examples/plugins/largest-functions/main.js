// A Paranoia plugin is a script with the same `pn` API and `print` as the JavaScript console.
// The manifest's `run` names the function to call once this file has been evaluated.

async function show(n) {
  const fns = await pn.functions();
  fns.sort((a, b) => b.size - a.size);
  for (const f of fns.slice(0, n)) print(pn.hex(f.address), f.name, f.size, "bytes");
  print(fns.length, "functions in total");
}

async function top10() {
  await show(10);
}

async function top50() {
  await show(50);
}
