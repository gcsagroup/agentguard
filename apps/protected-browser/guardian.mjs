// 仅清理父进程显式交付的本次临时目录；父进程 SIGKILL 后 IPC 仍会断开。
import { rm, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, basename } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const suppliedDirectory = process.argv[2];
const directory = await realpath(suppliedDirectory);
if (dirname(directory) !== await realpath(tmpdir()) || !basename(directory).startsWith('agentguard-operator-')) {
  throw new Error('拒绝清理非本次专用临时目录');
}
const exec = promisify(execFile);
async function ownedBrowsers() {
  // 仅匹配本次随机目录的 Chromium 主进程；不输出或处理其他进程信息。
  const { stdout } = await exec('/bin/ps', ['-axo', 'pid=,command='], { cwd: '/' });
  return stdout.split('\n').flatMap((line) => {
    const match = line.match(/^\s*(\d+)\s+(.*)$/);
    if (!match) return [];
    const command = match[2];
    return [suppliedDirectory, directory].some((root) => command.includes(`--user-data-dir=${root}/agentguard-task-`)) ? [Number(match[1])] : [];
  });
}
process.once('disconnect', async () => {
  // 先停止本次浏览器写入，再删除资料；递归删除本身不能阻止浏览器重建目录。
  for (const pid of await ownedBrowsers()) { try { process.kill(pid, 'SIGTERM'); } catch { /* 已退出。 */ } }
  const deadline = Date.now() + 1500;
  while ((await ownedBrowsers()).length && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 100));
  for (const pid of await ownedBrowsers()) { try { process.kill(pid, 'SIGKILL'); } catch { /* 已退出。 */ } }
  await new Promise((resolve) => setTimeout(resolve, 200));
  await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});
process.send({ ready: true });
