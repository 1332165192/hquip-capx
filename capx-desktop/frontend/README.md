# Desktop UI

Wails directly embeds `dist/index.html`, `dist/desktop.css` and `dist/app.js`.
There is no frontend build step or runtime dependency. The desktop shell uses
the same light/teal workspace palette as the web console; `embed=1` remains the
iframe integration contract. `dist/style.css` is an unused legacy asset.

The shell keeps one console iframe alive. Navigation and manual/automatic refresh
use `capx:navigate` / `capx:refresh` messages instead of reloading that document.
Both ends check the sender window and exact origin; `parent_origin` in the embed
URL identifies the desktop origin. Intruder/Turbo/Decoder/Comparer drafts are
saved in session storage; Repeater retains its existing per-tab persistence.

## UI regression test

Install Playwright in your preferred development tool directory, then run:

```powershell
$env:PLAYWRIGHT_MODULE = 'C:\path\to\node_modules\playwright'
$env:BROWSER_PATH = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
node frontend/tests/ui-smoke.cjs
# Real embedded-console state and async race regressions
node ../dev/ui-state-regression.cjs
go test ./...
```

If Playwright and its Chromium browser are installed normally, the two
environment variables can be omitted. `UI_SCREENSHOT_DIR` optionally overrides
the screenshot directory (default: `%TEMP%/capx-desktop-ui-qa`).

The test starts an ephemeral localhost static server and replaces the Wails
bridge with fixtures. No capture service, real target, cache cleanup or folder
opening is performed. It checks DOM and navigation compatibility, the local
analysis workflows, iframe integration and 1280×820 / 960×600 layouts.
The state regression additionally embeds the real console and verifies draft
retention, origin/source checks, body search and disk pagination, stale-query
cancellation, selected-detail identity, and concurrent Repeater tabs. Its report
defaults to `%TEMP%/capx-ui-state-regression/ui-state-regression.json`.

## Build and launch the modern desktop alongside the existing version

From `capx-desktop/`:

```powershell
go build -tags production -trimpath -ldflags='-s -w -H=windowsgui' -o capx-desktop-modern.exe .
$env:CAPX_EXE = (Resolve-Path '..\capx\dist\captured-modern.exe').Path
$env:CAPX_DESKTOP_SETTINGS = Join-Path $env:LOCALAPPDATA 'capx-desktop-modern\settings.json'
.\capx-desktop-modern.exe
```

Click **启动 capx** in the new window. The new settings location keeps the
modern desktop separate from the old instance, and unused API/proxy ports are
chosen automatically (unless `CAPX_BASE` / `CAPX_PROXY` were explicitly set).
The embedded console is served by the capture backend: connecting this shell
to an old backend will still display the old console UI. `CAPX_EXE` therefore
points to the separately built modern capture backend above.
