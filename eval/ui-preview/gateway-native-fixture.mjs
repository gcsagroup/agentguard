/* 原生 App 验收用的真实 stdio 客户端。只写新建的临时目录，令牌不落盘、不输出。 */
import { spawn } from "node:child_process";
import { mkdtempSync, realpathSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";

export async function startNativeGatewayFixture(bundle, timeoutSeconds = 120) {
  const resources = join(bundle, "Contents/Resources/agentguard");
  const directory = realpathSync(mkdtempSync(join(tmpdir(), "ag-native-confirm-")));
  const child = spawn(join(resources, "setup/gateway/agentguard-mcp"), [
    "--rules", join(resources, "rules/p0_rules.yaml"),
    "--shell-policy", join(resources, "setup/gateway/default.yaml"),
    "--confirm-port", "0", "--confirm-timeout-secs", String(timeoutSeconds),
  ], { stdio: ["pipe", "pipe", "pipe"] });
  const responses = new Map();
  let port = 0;
  let token = "";
  let sequence = 0;
  const cases = new Map();
  const stderr = createInterface({ input: child.stderr });
  const stdout = createInterface({ input: child.stdout });
  stdout.on("line", line => { const result = JSON.parse(line); responses.set(result.id, result); });
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("测试网关启动超时")), 5000);
      child.once("error", () => { clearTimeout(timer); reject(new Error("测试网关启动失败")); });
      stderr.on("line", line => {
        const address = line.match(/http:\/\/127\.0\.0\.1:(\d+)/);
        const credential = line.trim().match(/^确认令牌 ([0-9a-f]{32})$/);
        if (address) port = Number(address[1]);
        if (credential) token = credential[1];
        if (port && token) { clearTimeout(timer); resolve(); }
      });
    });
  } catch (error) { child.kill(); throw error; }
  return {
    port, token, directory,
    write(name) {
      if (!["denied", "approved", "timeout", "disconnected"].includes(name) || cases.has(name)) throw new Error("仅允许一次性测试用例");
      const path = join(directory, `${name}.txt`);
      if (existsSync(path)) throw new Error("测试目标已存在");
      const id = ++sequence;
      cases.set(name, { path, id });
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "write_file", arguments: { path, contents: `AgentGuard 本地网关验收 ${name}\n` } } })}\n`);
      return { name, path, id };
    },
    snapshot() {
      return { directory, running: child.exitCode === null && child.signalCode === null, cases: [...cases].map(([name, entry]) => ({ name, exists: existsSync(entry.path), content: existsSync(entry.path) ? readFileSync(entry.path, "utf8") : null, response: responses.get(entry.id) || null })) };
    },
    async stop() {
      token = "";
      this.token = "";
      if (child.exitCode === null && child.signalCode === null) {
        await new Promise(resolve => { child.once("exit", resolve); child.kill(); });
      }
      stderr.close(); stdout.close();
      return this.snapshot();
    },
  };
}
