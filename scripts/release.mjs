// Release build: hardened compiler flags, build paths removed from the binary,
// SHA-256 checksums written next to the artifacts.
//
//   npm run release
//
// Produces:
//   src-tauri/target/release/bundle/nsis/Cluent_<ver>_x64-setup.exe  (installer)
//   portable/Cluent-<ver>-portable.exe                                (portable exe)
//   portable/SHA256SUMS.txt
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const tauriDir = join(root, "src-tauri");
const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
const cargoHome = process.env.CARGO_HOME || join(homedir(), ".cargo");
const rustupHome = process.env.RUSTUP_HOME || join(homedir(), ".rustup");

// RUSTFLAGS replaces .cargo/config.toml rustflags, so the hardening flags are repeated here.
const rustflags = [
  "-C", "control-flow-guard",
  // The linker embeds the full .pdb path in the exe; keep only the file name.
  "-C", "link-arg=/PDBALTPATH:%_PDB%",
  `--remap-path-prefix=${cargoHome}=cargo`,
  `--remap-path-prefix=${rustupHome}=rustup`,
  `--remap-path-prefix=${root}=cluent`,
  `--remap-path-prefix=${homedir()}=~`,
];
// CARGO_ENCODED_RUSTFLAGS keeps paths with spaces intact (separator 0x1f).
const env = { ...process.env, CARGO_ENCODED_RUSTFLAGS: rustflags.join("\x1f") };
delete env.RUSTFLAGS;

// A single command string: npm is a .cmd on Windows and needs a shell; there are no
// user-supplied arguments to escape.
const r = spawnSync("npm run tauri build", { cwd: root, env, stdio: "inherit", shell: true });
if (r.status !== 0) process.exit(r.status ?? 1);

const outDir = join(root, "portable");
mkdirSync(outDir, { recursive: true });
const portable = join(outDir, `Cluent-${version}-portable.exe`);
copyFileSync(join(tauriDir, "target", "release", "cluent.exe"), portable);

const files = [portable];
const nsisDir = join(tauriDir, "target", "release", "bundle", "nsis");
if (existsSync(nsisDir)) {
  for (const f of readdirSync(nsisDir)) if (f.endsWith(".exe") && f.includes(version)) files.push(join(nsisDir, f));
}

// Fail the release if the user name or build directories leaked into a binary.
const leaks = [homedir(), root].map((p) => p.toLowerCase());
for (const f of files) {
  const text = readFileSync(f).toString("latin1").toLowerCase();
  const leak = leaks.find((p) => text.includes(p));
  if (leak) {
    console.error(`✕ ${basename(f)} still contains the build path ${leak}`);
    process.exit(1);
  }
}

const lines = files.map((f) => `${createHash("sha256").update(readFileSync(f)).digest("hex")}  ${basename(f)}`);
writeFileSync(join(outDir, "SHA256SUMS.txt"), lines.join("\n") + "\n");
console.log("\nSHA-256:\n" + lines.join("\n"));
