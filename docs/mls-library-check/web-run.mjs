// Runs web-entry in headless Chrome (over CDP) or in an Electron renderer and prints the result.
// Usage: node web-run.mjs chrome|electron vectors|bench [default|noble|pure] [--json=out.json]
import { spawn } from "node:child_process"
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync, symlinkSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { fileURLToPath } from "node:url"
import { build } from "esbuild"

const [target, mode, provider = "default"] = process.argv.slice(2).filter((a) => !a.startsWith("--"))
const jsonOut = process.argv.find((a) => a.startsWith("--json="))?.split("=")[1]
const here = fileURLToPath(new URL(".", import.meta.url))
const web = join(here, "web")
await build({ entryPoints: [join(here, "web-entry.mjs")], outfile: join(web, "bundle.js"), bundle: true, format: "iife", target: "es2022", logLevel: "warning" })
writeFileSync(join(web, "index.html"), `<!doctype html><meta charset="utf-8"><title>ts-mls check</title><script src="bundle.js"></script>`)
if (!existsSync(join(web, "vectors"))) symlinkSync(join(here, "vectors"), join(web, "vectors"))

// Chrome refuses fetch() from file://, so serve the folder on a loopback port.
const { createServer } = await import("node:http")
const server = createServer((req, res) => {
  try {
    const path = join(web, decodeURIComponent(new URL(req.url, "http://x").pathname))
    const body = readFileSync(path)
    res.writeHead(200, { "content-type": path.endsWith(".html") ? "text/html" : path.endsWith(".json") ? "application/json" : "text/javascript" })
    res.end(body)
  } catch {
    res.writeHead(404).end()
  }
}).listen(0, "127.0.0.1")
await new Promise((r) => server.on("listening", r))
const url = `http://127.0.0.1:${server.address().port}/index.html#${mode},${provider}`

const profile = mkdtempSync(join(tmpdir(), "ts-mls-check-"))
const chrome = process.env.CHROME ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
// Borrow the desktop client's Electron rather than installing another copy here.
const electron = process.env.ELECTRON ?? join(here, "../../../client/node_modules/electron/dist/Electron.app/Contents/MacOS/Electron")
const child =
  target === "electron"
    ? spawn(electron, [join(here, "electron-main.cjs"), url], { stdio: ["ignore", "pipe", "inherit"] })
    : spawn(chrome, ["--headless=new", `--user-data-dir=${profile}`, "--remote-debugging-port=0", "--no-first-run", "--no-default-browser-check", url], { stdio: "ignore" })

// Never leave the browser behind, whatever happens below.
process.on("exit", () => child.kill())
let result
try {
  if (target === "electron") {
    let out = ""
    child.stdout.on("data", (d) => {
      out += d
      for (const line of String(d).split("\n")) if (line && !line.startsWith("RESULT_JSON")) console.log(line)
    })
    await new Promise((r) => child.on("exit", r))
    result = JSON.parse(out.split("RESULT_JSON ")[1])
  } else {
    const portFile = join(profile, "DevToolsActivePort")
    while (!existsSync(portFile) || !readFileSync(portFile, "utf8").includes("\n")) await new Promise((r) => setTimeout(r, 100))
    const port = readFileSync(portFile, "utf8").split("\n")[0]
    let page
    while (!page) {
      page = (await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()).find((t) => t.type === "page" && t.url.startsWith("http://127.0.0.1"))
      if (!page) await new Promise((r) => setTimeout(r, 100))
    }
    const ws = new WebSocket(page.webSocketDebuggerUrl)
    await new Promise((r) => ws.addEventListener("open", r))
    let id = 0
    const pending = new Map()
    ws.addEventListener("message", (ev) => {
      const msg = JSON.parse(ev.data)
      if (msg.method === "Runtime.consoleAPICalled") console.log(msg.params.args.map((a) => a.value).join(" "))
      if (msg.id && pending.has(msg.id)) pending.get(msg.id)(msg.result)
    })
    const send = (method, params = {}) => new Promise((r) => (pending.set(++id, r), ws.send(JSON.stringify({ id, method, params }))))
    await send("Runtime.enable")
    for (;;) {
      const r = await send("Runtime.evaluate", { expression: "window.__result && JSON.stringify(window.__result)", returnByValue: true })
      if (r.result.value) {
        result = JSON.parse(r.result.value)
        break
      }
      await new Promise((res) => setTimeout(res, 500))
    }
    ws.close()
  }
} finally {
  const exited = child.exitCode !== null || new Promise((r) => child.on("exit", r))
  child.kill()
  await exited
  server.close()
  rmSync(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 })
}
if (result.error) {
  console.error(result.error)
  process.exit(1)
}
console.log(result.runtime)
if (result.report) {
  const failed = result.report.reduce((a, r) => a + r.fail, 0)
  console.log(failed === 0 ? "all vectors passed" : `${failed} vectors failed`)
}
if (jsonOut) writeFileSync(jsonOut, JSON.stringify(result, null, 2))
