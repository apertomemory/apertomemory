# Getting started: your first portable memory in 5 minutes

This walkthrough takes you from nothing to an AI assistant that
remembers you from an encrypted file **you** own - and shows you how to
carry that memory to another machine.

## 1. Install and create your vault

```bash
pip install apertomemory

export AMEM_PASSPHRASE="choose-a-strong-passphrase"
amem --vault ~/.amem init
amem --vault ~/.amem scope add default
```

Your vault now exists at `~/.amem`. The passphrase is the root of all
your keys - there is no recovery if you lose it, because nobody else
(including any server) can decrypt your memories. That's the point.

## 2. Seal your first memories

```bash
amem --vault ~/.amem seal "prefers formal B2B emails, no emoji" --tags style
amem --vault ~/.amem seal "never deploy to production on Fridays" --tags rules
amem --vault ~/.amem list
```

Each memory is signed with your key and encrypted before it touches the
disk. `amem list` shows only object ids - to read one back:

```bash
amem --vault ~/.amem open <id>
```

## 3. Connect your AI assistant

The MCP adapter lets any MCP client read and write your vault. Add this
block to your client's MCP configuration:

```json
{
  "mcpServers": {
    "amem": {
      "command": "python3",
      "args": ["-m", "amem.mcp_server"],
      "env": {
        "AMEM_VAULT": "/Users/YOUR-USER/.amem",
        "AMEM_PASSPHRASE": "choose-a-strong-passphrase"
      }
    }
  }
}
```

Where that configuration lives:

| Client | Location |
|---|---|
| Claude Desktop (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Desktop (Windows) | `%APPDATA%\Claude\claude_desktop_config.json` |
| Claude Code | `claude mcp add amem -- python3 -m amem.mcp_server` (then set the two env vars) |
| Gemini CLI | `~/.gemini/settings.json`, under `mcpServers` |
| Cursor | Settings -> MCP -> Add server |

Use the absolute path to your vault (`~` is not always expanded by MCP
clients). Restart the client after saving.

## 4. The payoff

Ask your assistant:

> "Check my memory - how do I like my emails written?"

It will call `amem_recall` and answer from your vault: formal, B2B, no
emoji. Then try:

> "Remember that my favourite working hours are early mornings."

It will call `amem_remember`, and the new memory is sealed with your
keys like all the others. You can verify it yourself: `amem list` shows
one more object.

The tools the adapter exposes: `amem_remember`, `amem_recall`,
`amem_export`, `amem_list_scopes`.

## 5. Take it with you

```bash
amem --vault ~/.amem export my-memory.amem
```

That single file (a few KB) is your entire memory: encrypted, signed,
portable. Copy it to another machine - or hand it to the TypeScript
implementation, which is a different codebase in a different language:

```bash
npm install apertomemory
node --input-type=module -e "
import { readAmem } from 'apertomemory';
import { readFileSync } from 'node:fs';
const vault = readAmem(new Uint8Array(readFileSync('my-memory.amem')), process.env.AMEM_PASSPHRASE);
for (const o of vault.objects) console.log('-', o.content, '| signature verified:', o.signatureVerified);
"
```

Every memory comes back, every signature checked. Same file, different
vendors - that's the format working as specified.

To import into a fresh Python vault instead:

```bash
amem --vault ~/new-vault import my-memory.amem
```

## Troubleshooting

- **The assistant doesn't see the tools**: restart the client fully;
  check the config file path above; make sure `python3 -m amem.mcp_server`
  runs without errors in a terminal with the two env vars set.
- **"wrong passphrase" on import**: the passphrase must be identical to
  the one used at `init` - it derives your keys, so a different
  passphrase means different keys.
- **Slow first operation (~1-2s)**: that's Argon2id doing its job
  against brute force. It's a feature.

Questions, bugs, spec feedback: https://github.com/apertomemory/apertomemory/issues
