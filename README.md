<p align="center">
  <img src="Assets/velun.png" width="120" alt="velun icon: a bicycle riding through a tunnel">
</p>

<h1 align="center">velun</h1>

<p align="center">
  <b>A native VPN client for macOS.</b><br>
  Reach your university or company network over AnyConnect (Cisco), Fortinet, GlobalProtect (Palo Alto) or WireGuard, several connections at once, with only internal traffic going through them.
</p>

<p align="center">
  <a href="https://store.manueldeprada.com/velun/download.php"><img alt="Download the disk image" src="https://img.shields.io/badge/download-.dmg-1f6feb?style=flat-square"></a>
  <img alt="macOS 13 or later" src="https://img.shields.io/badge/macOS-13%2B-111111?style=flat-square&logo=apple&logoColor=white">
  <img alt="Universal binary" src="https://img.shields.io/badge/universal-Apple%20Silicon%20%2B%20Intel-555555?style=flat-square">
  <img alt="Written in Swift" src="https://img.shields.io/badge/Swift-F05138?style=flat-square&logo=swift&logoColor=white">
</p>

<p align="center">
  <a href="#install">Install</a> &middot;
  <a href="#set-up-your-first-connection">First connection</a> &middot;
  <a href="#sharing-a-connection">Sharing</a> &middot;
  <a href="#troubleshooting">Troubleshooting</a> &middot;
  <a href="https://store.manueldeprada.com/velun/">Website</a>
</p>

![The velun popover in the macOS menu bar, showing three active connections and the networks each one tunnels](Assets/banner.png)

<!-- Demo video goes here once recorded: drag the .mp4 into a GitHub issue comment,
     copy the URL GitHub gives back, and paste it on its own line. -->

velun is a client app for VPN servers that you already have.

Vendor clients handle one connection at a time, route your entire machine through the VPN by default, ask for a 2FA code every single time, and integrate poorly with OS. Velun fixes all that!

## Features

- **Native implementation of 4 protocols.** AnyConnect (Cisco ASA), Fortinet SSL VPN, GlobalProtect (Palo Alto) and WireGuard, implemented natively in Swift on Apple's NetworkExtension APIs.
- **Partial tunneling, with internal services auto-detected.** velun guesses which internal services to route through the VPN from the server's own hints. Everything else keeps using your normal connection, so video calls and streaming stay off the VPN.
- **Several connections at once.** Connect and transfer data between internal services in different VPNs, each with its own routes and its own DNS, even across different vendors.
- **2FA automated, no more pasting codes.** Store the authenticator seed once and velun fills in the code on every connection.
- **Auto-reconnect and launch at login.** Connections come back after sleep, a Wi-Fi change, or a reboot.
- **Kill switch.** Optional, for full-tunnel connections: if the tunnel drops, traffic stops instead of leaking to the open internet.
- **Scriptable.** `open "velun://connect?name=Work"` from a terminal or a script.

## Install

1. **Download the dmg** from [apps.manueldeprada.com/velun](https://apps.manueldeprada.com/velun/download.php).
2. **Open the dmg and drag velun.app into your Applications folder.**
3. **Open velun.** It lives in the macOS menu bar, so there is no Dock icon and no window, look for the icon at the top right of your screen.
4. **On the first connection, macOS asks twice:** once to allow velun's network extension (a dialog offers to open System Settings for you, see below if you dismiss it), and once for your admin password to add the VPN configuration. Both are one-time.

## Set up your first connection

1. Click the menu bar icon, then **Add Connection**.
2. Pick the **protocol** and give the connection a name.
3. Fill in the **server address** (for example `vpn.example.edu`), the **group** or realm if your organization uses one, and your **username** and **password**.
4. If you use 2FA, paste the **authenticator secret** (the `base32:` string behind the QR code you scanned when you set up your authenticator app). Leave it empty and velun prompts you for a 2FA code on each connection instead.
5. Optional, recommended: turn on **partial routing** and leave the network list blank. velun works out your internal networks on connection and shows you what it picked.
6. **Save**, then **Connect**.

Once connected, the card shows which networks and which DNS names are going through the VPN. If something internal is not reachable, add manually its network or just its hostname to the connection and save. See the troubleshooting section below for more details.

For a WireGuard connection, paste your whole `wg-quick` `.conf` file instead of filling in fields.

## Sharing a connection

velun exports a connection as a single `velun://import?...` link. Send it to a colleague, they click it, and the connection shows up in their app with the server, group and routes already filled in. **Credentials are not included** unless you explicitly pick *Export with credentials*, so the plain link is safe to paste into a group chat.

## Troubleshooting

**The network extension was never approved.** velun cannot connect until macOS lets its extension load. 
- Open System Settings, **General**, **Login Items & Extensions**, scroll down to *Extensions*, click in "By Category", then select **Network Extensions**, and switch velun on. 
- On macOS 13 and 14 the same approval sits in **Privacy & Security** instead, at the bottom of the pane.
- If velun is not listed at all, check that the app really is in `/Applications` and not, say, still in Downloads.
- Some corporate MDM policies block VPNs and third-party network extensions. This is likely the case if you don't see VPNs in System Settings at all next to Bluetooth and Network. 

**A internal server is unreachable while connected in partial mode.** The automatic guess only covers what the server advertises. Expand the connection to full, find the the network address (e.g., using `ping service.com`, might return something like `10.0.0.3`, so you add `10.0.0.0/8`) or the domain of the service, and save.

**An internal name does not resolve.** velun sends the VPN's own DNS suffixes to the corporate resolver and leaves everything else on your normal one. If your organization uses a suffix the server does not advertise, add the hostname to the connection and it gets routed explicitly. Please drop me an email if you find such a case.

**Connections drop after the laptop sleeps on battery.** The Wi-Fi radio sleeps with the machine, so idle sessions get reaped by the far end. velun reconnects on wake, it's all we can do.

**Reading the logs.** Everything the tunnel does goes to the unified log:

```bash
log show --predicate 'subsystem == "com.manueldeprada.velun.PacketTunnel"' --last 10m
```

If something is broken in a way this list does not cover, open an issue with that output attached (check it for hostnames you would rather not publish first).

## Technical details

- **Many tunnels on the same extension.** Every connection activates the same extension instance and shares one virtual interface; velun demultiplexes between them internally. No per-profile VPN configuration proliferation, and no extra admin-password prompts after the first install.
- **Automatic partial tunnel detection.** Routes are derived from the server's own split-tunnel hints, its DNS servers and its search domains, with RFC1918 awareness so your home network does not get swept up by mistake.
- **Kill switch.** A full-tunnel connection fails closed when the tunnel drops, so nothing leaks to the open internet. Opt-in, because it applies at connection time and takes a reconnect to turn on or off.
- **Live routing hot-switch.** Flip a connected profile between full and partial without dropping the session or reauthenticating.
- **IPv6 handled explicitly.** A full tunnel claims IPv6 as well: carried when the server offers it, blocked when it does not, rather than quietly escaping onto your physical interface.
- **Scriptable.** The `velun://` URL scheme drives connect, disconnect and import from the terminal or from other tools. Connections can also save one-off shell commands that run through a scoped, ephemeral tunnel with no system-wide routing change, for cases like `ssh`-ing into a single host.

## Building from source

velun's PacketTunnel component is a macOS system extension, which Apple requires to be signed with a `Developer ID Application` certificate under a paid Apple Developer Program membership. The free "Apple Development" identity Xcode uses by default does not work for system extensions.

You will need:

- An Apple Developer Program membership and a Developer ID Application certificate.
- Two manually created provisioning profiles (from developer.apple.com, not Xcode-managed) granting the `packet-tunnel-provider-systemextension` entitlement to bundle identifiers you control.
- Your own bundle identifiers, entitlements, app group and keychain access group throughout the project. Ours cannot be reused.
- Hardened Runtime and timestamped code signing on both targets, or `sysextd` and the notarization service reject the build with unhelpful errors.
- Notarization of the result (`xcrun notarytool` and `stapler`).

With that in place, open `velun.xcodeproj` and build the `velun` scheme; the PacketTunnel extension is a separate target that gets embedded into the app bundle automatically. The `tests/` directory has protocol-level unit tests (auth parsing, packet framing, the userspace TCP state machine) that compile with `swiftc`.

## Pricing

velun is free to use. If it is useful to you, a [license](https://store.manueldeprada.com/velun/buy.php) supports continued development and covers the Apple Developer Program cost.

## Privacy

A random per-install ID is generated locally to count unique installations. It cannot be linked to you, and no other telemetry is collected or sent anywhere.

---

<p align="center">
  <img src="Assets/velun.png" width="72" alt="">
  <br>
  <em>velo (bicycle) + tunnel. Your packets pedal through.</em>
</p>
