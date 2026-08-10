# DELTA Security IDE

DELTA is a browser-based security code workspace for comparing what an npm
package declares with behaviors visible in its source. It combines a familiar
desktop IDE layout with DELTA's declaration-versus-observation workflow.

## Included

- CodeMirror-based code editor with syntax highlighting, line numbers, folding,
  bracket matching, autocomplete, and in-file search
- File explorer, tabs, dirty-file indicators, new-file creation, and browser
  storage persistence
- Workspace search, command palette, keyboard shortcuts, and a functional
  terminal-style command surface
- DELTA policy scan for credential access, undeclared network calls, process
  execution, download-and-run chains, obfuscation, and persistence changes
- Risk score, decision, behavior diff, evidence details, findings list, and
  event timeline
- Responsive side panels inspired by desktop code editors

## Safety boundary

The hosted editor analyzes source text only. The included package is a safe
fixture using documentation-only TEST-NET addresses and synthetic canary names;
it is never executed. Installing or dynamically observing a package belongs in
DELTA's separate isolated Linux runner.

## Keyboard shortcuts

| Shortcut | Action |
| --- | --- |
| `Ctrl/Cmd + S` | Save the active file to browser storage |
| `Ctrl/Cmd + Shift + P` | Open the command palette |
| `Ctrl/Cmd + Shift + D` | Run DELTA editor analysis |
| `Ctrl/Cmd + F` | Search inside the active file |
| `Ctrl/Cmd + \`` | Toggle the bottom panel |

The built-in terminal accepts `delta scan`, `npm test`, `ls`, `pwd`, `help`,
and `clear`.

## Development

Requires Node.js `>=22.13.0`.

```bash
npm install
npm run dev
```

Production validation:

```bash
npm run lint
npm test
```
