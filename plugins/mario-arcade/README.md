# Sentinel Jump Arcade

An original, Mario-style, **turn-based platformer** for the Sentinel V5 SSH console. Features three side-scrolling worlds, gravity, jumps, coins, enemies, pits, scoring, lives, and a goal flag. Everything is drawn in ASCII/SML; no external ROMs, copyrighted art, sounds, or Nintendo-owned character assets.

## What is actually playable?

The current Sentinel plugin runtime sends one JSON command at a time to a persistent worker. It **does not expose raw SSH keyboard or mouse events to native code plugins**, so this is a turn-based game, NOT a realtime 60 FPS platformer. The SML view displays each new frame after the command completes. It never claims unsupported arrow-key control.

Run these commands from the Sentinel SSH prompt:

| Command | Effect |
| --- | --- |
| mario-arcade | Display the shared arcade game (default command) |
| mario-arcade play | Show the game without advancing time |
| mario-arcade left | Walk left one tile / one physics tick |
| mario-arcade right | Walk right one tile / one physics tick |
| mario-arcade jump | Jump straight up |
| mario-arcade jump-left | Jump and move left |
| mario-arcade jump-right | Jump and move right |
| mario-arcade wait | Advance gravity without horizontal movement |
| mario-arcade show | Redisplay board without advancing time |
| mario-arcade new | Restart the **shared** game |

The older explicit form, such as plugins run mario-arcade jump-right, works too on supported core versions.

Character key: @ = player, $ = coin, X = enemy, # = platform, = = ground, F = finish.

Coins give 100 points, stomping enemies awards 200, and finishing a world gives 500. You have three lives. When you fall into a pit or touch an enemy from the side, you lose a life.

## Build from reviewed source

On a **Linux** host, from the root of the public community repository:

    go test ./plugins/mario-arcade/...
    go build -trimpath -o plugins/mario-arcade/bin/mario-arcade ./plugins/mario-arcade

On **Windows**:

    go test ./plugins/mario-arcade/...
    go build -trimpath -o plugins/mario-arcade/bin/mario-arcade.exe ./plugins/mario-arcade

Copy the complete plugins/mario-arcade directory, including the appropriate built binary, plugin.yaml and views/arcade.sml, to assets/plugins/mario-arcade inside your installed Sentinel V5 host. The source repository does not commit binaries, and a **signed approved marketplace package has not been published**. Do not expect plugins install mario-arcade to work yet.

In your test installation, opt into trusted local code by setting plugins.trusted_code=true in data/config.json (or SENTINEL_TRUSTED_CODE_PLUGINS=enabled), restart Sentinel, then sign in as an authorized administrator:

    plugins validate
    plugins info mario-arcade
    plugins permissions mario-arcade
    plugins enable mario-arcade
    mario-arcade play
    mario-arcade right
    mario-arcade jump-right

For diagnosis use plugins status mario-arcade, plugins reload mario-arcade and plugins disable mario-arcade.

## Shared state and security

The exec-rpc SDK does not currently include verified player identity in the handler arguments. Therefore the save key arcade-state is **shared among all authorized Sentinel users**. This is a community cooperative game, *not* a per-account save or leaderboard. Anyone permitted by the manifest can act on the same character or reset its state. If you require independent games, the core RPC API needs an authenticated actor identity before per-account storage keys can be implemented safely.

The game performs no network calls, filesystem operations or OS shell commands. It requests only storage.get and storage.put from the Sentinel capability broker; the broker stores bounded JSON under the plugin's namespace. Source-managed native code installed manually still executes with the privileges of the Sentinel OS account. **Host trusted-code opt-in and independent review are required**. Run the host process as an unprivileged OS user, and do not blindly execute third-party compiled binaries.

SML version 3 renders a 37-cell view plus panel chrome, designed around common 80-column terminals. Test the view in your PuTTY / Windows Terminal configuration.

## Testing

The pure-Go engine and its deterministic unit tests live in game/. Run go test ./plugins/mario-arcade/.... In addition to these unit tests, full installation must be checked against a live Sentinel binary: verify SML rendering, permissions, persistence after reconnect/restart, Windows/Linux executable launch and host shutdown. Static validation and unit tests alone are not evidence of a production-approved plugin.

To support true continuous arrow-key movement in the future, Sentinel would need to design and review a new interactive PTY/game-host capability with explicit user input routing, suspension, permissions, cancellation and lifecycle limits. This plugin intentionally stays within the currently supported protocol.
