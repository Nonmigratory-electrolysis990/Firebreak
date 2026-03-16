# Command Injection Prevention

## DO

- **Use array-based APIs** that bypass the shell entirely — `subprocess.run(["convert", filename], shell=False)` (Python), `execFile` (Node.js), `Command::new("ls").arg(dir)` (Rust).
- **Allowlist permitted input values** — if the user selects from known options (file types, sort orders), validate against an explicit list.
- **Use language-native libraries** instead of shelling out — `fs.readdir()` instead of `ls`, `shutil.move()` instead of `mv`, image libraries instead of `imagemagick` CLI.
- **Sandbox execution** if shell commands are unavoidable — use Docker containers, seccomp, AppArmor, or chroot jails with minimal permissions.
- **Validate input types strictly** — if a filename is expected, reject inputs containing `;`, `|`, `&`, `$`, `` ` ``, `\n`, `$(`, `>`, `<`.
- **Drop privileges** — run shell-executing processes under a restricted user account with no network access and read-only filesystem where possible.

## DON'T

- Pass user input to `os.system()`, `child_process.exec()`, `Runtime.exec(cmd)` with a single string, or backtick execution in any language.
- Use `shell=True` (Python subprocess) with any user-controlled arguments.
- Use string formatting/concatenation to build commands: `os.system(f"convert {filename} output.png")` — a filename of `; rm -rf /` is catastrophic.
- Rely on escaping/quoting — `shlex.quote()` is a defense-in-depth measure, not a primary defense. Edge cases exist.
- Shell out for tasks that have library equivalents — PDF generation, image processing, file operations all have native packages.
- Allow user-controlled environment variables in shell execution contexts — `PATH` manipulation can redirect commands.

## Common AI Mistakes

- Using `child_process.exec()` (shell) instead of `child_process.execFile()` (no shell) in Node.js.
- Writing `subprocess.run(f"ffmpeg -i {input_file} {output_file}", shell=True)` for media processing.
- Suggesting `shlex.quote()` as the complete solution rather than restructuring to avoid shell execution.
- Generating code that shells out to `curl` instead of using `requests`/`fetch`/`reqwest`.
- Building Docker commands via string concatenation: `exec("docker run " + userImage)`.
- Using `os.popen()` in Python (which invokes a shell) instead of `subprocess.run()` with `shell=False`.
