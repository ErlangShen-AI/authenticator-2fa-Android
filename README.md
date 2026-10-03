# Authenticator - 2FA

Browser extension for generating and managing two-factor authentication codes, adapted for extension-capable Android browsers.

This repository is the Android adaptation of [VastBlast/authenticator-2fa](https://github.com/VastBlast/authenticator-2fa): a responsive layout for small screens, touch-friendly interaction fixes, and a `firefox` build that declares Android support. See [Android adaptation](#android-adaptation).

**Privacy:** Authenticator - 2FA does not track users or collect analytics. Accounts stay on your device by default. If you enable Browser Sync, encrypted account data is sent through your browser provider's sync service. Account names and secrets are encrypted before upload; the recovery key stays inside your password-protected local vault.

![Authenticator - 2FA promo](assets/store/promotional/marquee-promo-tile.png)

## Install

Builds from this repository target `chrome`, `edge`, and `firefox`:

- **Firefox for Android** — requires a signed build: submit the `firefox` zip to [AMO](https://addons.mozilla.org/) (listed or unlisted), or load it on a development device with `web-ext`.
- **Chromium-based Android browsers with extension support** — use the `chrome` or `edge` zip.
- **Desktop browsers** — the same zips run as unpacked builds; signed store builds are available from the upstream project.

See [Releases](#releases) for where the built zips are published.

## Features

- Generate TOTP, HOTP, and Steam-style 2FA codes.
- Add accounts from QR images, page QR scans, pasted otpauth text, or manual entry.
- Search, copy, manually reorder accounts, or focus on likely codes for the current site with one-click access to the rest.
- Import by dropping or picking QR images, otpauth text, JSON, or password-protected backups; export the same way.
- Optional local vault password protection.
- Optional encrypted Browser Sync across supported devices using the same browser account.
- Local-first storage with no account service.

**Important: Users are responsible for maintaining their own backups of 2FA codes and recovery methods. We are not responsible for lost, deleted, inaccessible, or unrecoverable 2FA codes.**

## Browser Sync

Open **Settings → Browser Sync**, set a local vault password, choose **Set up sync**, and save the generated recovery key. On another supported device, sign into the same browser account, choose **Connect to existing sync**, and enter that key. Enable extension syncing in your browser settings.

Sync works within one browser provider. Accounts, edits, and deletions sync while the extension is open and unlocked; preferences and ordering stay local. Keep independent backups and use HOTP accounts on one device at a time.

See [sync security, recovery, and limits](docs/browser-sync.md).

## Android adaptation

This repository targets extension-capable Android browsers (for example Firefox for Android).

- The extension surface follows the viewport on touch devices: screens narrower than 400px or shorter than 532px get a fully fitted layout instead of the desktop minimum. Desktop windows keep the original 400x532 minimum.
- The default tap highlight is disabled, so taps and long presses on controls leave no highlight overlay.
- The Android back gesture closes dialogs and panels instead of leaving the page, and scrolling never chains into page-level overscroll.
- Floating controls respect display cutouts and on-screen gesture areas via safe-area insets.
- The `firefox` build declares `browser_specific_settings.gecko_android`, so the add-on can be submitted to AMO for Android.

Known mobile limitations:

- "Select QR on page" needs `tabs.captureVisibleTab`; where a mobile browser does not expose it, use QR image import instead.
- Browser Sync and code auto-paste depend on the level of WebExtension support in each browser.

## Development

```sh
npm install
npm run dev
```

Useful commands:

```sh
npm run check
npm run test
npm run build
npm run package
```

`npm run package` builds extension zips for `chrome`, `edge`, and `firefox` into `artifacts/`. Pushes to `main` run the same checks and packaging in GitHub Actions.

## Store Assets

Project assets are grouped under `assets/` by lifecycle:

- `assets/brand/` source artwork for generated extension icons
- `assets/extension/` static files copied into extension packages
- `assets/store/` store icons, screenshots, and promo tiles kept outside the extension bundle

Regenerate screenshots and promo tiles with:

```sh
npm run store:screenshots
```

This command uses synthetic demo accounts and a local browser to render store-ready images.
Temporary store listing text drafts can live in `.tmp/store-listing/`, which is ignored by git.

## Releases

Pushing a tag like `v1.2.3` runs the release workflow: it applies the tag version, builds all targets, packages the zips, creates the GitHub release, and attaches the extension zips. Pushes to `main` run the Build workflow, which runs checks and tests and uploads the same zips as a build artifact.

## Origins

Authenticator - 2FA was inspired by the open-source [Authenticator browser extension](https://github.com/Authenticator-Extension/Authenticator). After that extension became unmaintained, it was rebuilt from scratch as [VastBlast/authenticator-2fa](https://github.com/VastBlast/authenticator-2fa), keeping a simple local-first authenticator workflow.

This repository adapts that project for extension-capable Android browsers.

## License

MIT — see [LICENSE](LICENSE). The upstream copyright notice is retained.
