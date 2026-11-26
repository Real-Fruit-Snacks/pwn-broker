# pwn-broker

Keeps a box's targets, notes, creds and tools in order

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/panel-dark.svg">
  <img alt="A pwn-broker session beside the box's folder. pwn-broker new creates target dc01 and box forest, and the folder 2026-11-14_htb_forest appears with box.toml, notes.md, creds.toml, lists/ and targets/dc01/; cred add at the forest/dc01 prompt saves a credential and svc-alfresco and s3rvice appear in the lists; finish writes 2026-11-14_htb_forest.finished.tar.gz to wrapped/" src="docs/assets/panel-light.svg" width="100%">
</picture>

```sh
curl -fsSL https://github.com/Real-Fruit-Snacks/pwn-broker/releases/latest/download/install.sh | sh
```

- **Structured box workspaces:** Creates `~/pwn-broker/active/<box>/` with per-target folders (`scans/`, `loot/`, `exploits/`), opens `notes.md` in vim with target folds, and manages box-scoped `/etc/hosts` entries.
- **Built-in session tools:** Tracks credentials and rebuilds `lists/`, records terminals with pinned `asciinema`, runs background `nmap` scans, manages OpenVPN, serves upload files over HTTP, and searches the box.
- **Isolated tools, playbooks & reports:** Installs pinned packages from [pwn-shop](https://github.com/Real-Fruit-Snacks/pwn-shop) (with their own Python runtime), [pwn-playbooks](https://github.com/Real-Fruit-Snacks/pwn-playbooks) (`:Pb <name>`), and [pwn-report](https://github.com/Real-Fruit-Snacks/pwn-report), then removes tools cleanly at `finish`.
- **Clean wrap-up:** `finish` archives the box to `~/pwn-broker/wrapped/<box>.finished.tar.gz`, removes its `/etc/hosts` lines, and optionally writes a private evidence report; `import` reopens any archive.

## Documentation

- [Project Page (pwn handbook)](https://real-fruit-snacks.github.io/pwn-broker/)
- [Walkthrough, Features, Configuration & Known Issues](docs/USAGE.md)
- [Full Command Guide](docs/guide.md) · [Tested Record & Limits](docs/tested.md)
- [Changelog](CHANGELOG.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

## License

[MIT](LICENSE)
