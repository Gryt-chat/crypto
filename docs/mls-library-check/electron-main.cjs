// Loads the page in a hidden BrowserWindow, which is where the desktop client's crypto runs.
const { app, BrowserWindow } = require("electron")
app.whenReady().then(async () => {
  const win = new BrowserWindow({ show: false, webPreferences: { backgroundThrottling: false } })
  win.webContents.on("console-message", (e) => process.stdout.write(`${e.message}\n`))
  await win.loadURL(process.argv.at(-1))
  for (;;) {
    const r = await win.webContents.executeJavaScript("window.__result && JSON.stringify(window.__result)")
    if (r) {
      const parsed = JSON.parse(r)
      parsed.runtime = `electron ${process.versions.electron} (chrome ${process.versions.chrome})`
      process.stdout.write(`RESULT_JSON ${JSON.stringify(parsed)}\n`)
      break
    }
    await new Promise((res) => setTimeout(res, 500))
  }
  app.quit()
})
