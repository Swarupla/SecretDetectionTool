# Installing 2ms

This guide walks through every supported way to install **2ms (Too Many Secrets)** and verify that it works. For full usage documentation see the [README](README.md).

## Table of Contents
- [Requirements](#requirements)
- [Installation Methods](#installation-methods)
  - [Homebrew (macOS / Linux)](#homebrew-macos--linux)
  - [Prebuilt Binaries](#prebuilt-binaries)
  - [Build from Source](#build-from-source)
  - [Docker](#docker)
- [Verifying the Installation](#verifying-the-installation)
- [Upgrading](#upgrading)
- [Uninstalling](#uninstalling)
- [Troubleshooting](#troubleshooting)

## Requirements

| Method | Requirements |
|--------|--------------|
| Homebrew | [Homebrew](https://brew.sh) installed |
| Prebuilt binary | None — a standalone executable |
| Build from source | [Go](https://go.dev/dl/) **1.26.2 or newer** and `git` (see `go.mod`) |
| Docker | A working [Docker](https://docs.docker.com/get-docker/) installation |

2ms runs on Windows, macOS, and Linux (amd64). Some scan targets (for example `2ms git`) also require `git` to be available on your `PATH`.

## Installation Methods

### Homebrew (macOS / Linux)

The quickest way to install on macOS or Linux:

```bash
brew install 2ms
```

This pulls the [official formula](https://formulae.brew.sh/formula/2ms) and places `2ms` on your `PATH`.

### Prebuilt Binaries

Download the archive for your platform from the [releases page](https://github.com/checkmarx/2ms/releases/latest):

- [Windows (amd64)](https://github.com/checkmarx/2ms/releases/latest/download/windows-amd64.zip)
- [macOS (amd64)](https://github.com/checkmarx/2ms/releases/latest/download/macos-amd64.zip)
- [Linux (amd64)](https://github.com/checkmarx/2ms/releases/latest/download/linux-amd64.zip)

Then unzip it and move the binary somewhere on your `PATH`.

On macOS / Linux:

```bash
unzip linux-amd64.zip
sudo mv 2ms /usr/local/bin/2ms
sudo chmod +x /usr/local/bin/2ms
```

On Windows, extract the `.zip` and add the folder containing `2ms.exe` to your `PATH` environment variable.

### Build from Source

Requires Go **1.26.2+** (the version pinned in `go.mod`) and `git`.

```bash
git clone https://github.com/checkmarx/2ms.git
cd 2ms
go build -o dist/2ms .
./dist/2ms --version
```

Alternatively, use the bundled `Makefile` target to produce a Linux amd64 binary:

```bash
make build-local
./2ms --version
```

To install the binary directly into your Go bin directory (`$(go env GOPATH)/bin`):

```bash
go install github.com/checkmarx/2ms/v5@latest
```

Make sure `$(go env GOPATH)/bin` is on your `PATH`.

### Docker

Run 2ms straight from the published image without installing anything locally:

```bash
docker run --rm checkmarx/2ms --version
```

Mount a workspace to scan it:

```bash
docker run --rm -v "$(pwd)":/repo checkmarx/2ms git /repo --stdout-format json
```

Pass credentials for remote targets through environment variables (for example `-e SLACK_TOKEN=...`) or mounted config files.

You can also build the image locally:

```bash
make build           # builds checkmarx/2ms:latest
# or
docker build -t checkmarx/2ms:latest .
```

## Verifying the Installation

Confirm 2ms is installed and on your `PATH`:

```bash
2ms --version
```

Run a quick scan against the current directory to confirm everything works end to end:

```bash
2ms filesystem --path .
```

2ms prints a YAML summary by default and returns a non-zero exit code when secrets are detected.

## Upgrading

| Method | Command |
|--------|---------|
| Homebrew | `brew upgrade 2ms` |
| Prebuilt binary | Download the latest archive and replace the existing binary |
| Source (`go install`) | `go install github.com/checkmarx/2ms/v5@latest` |
| Docker | `docker pull checkmarx/2ms:latest` |

## Uninstalling

| Method | Command |
|--------|---------|
| Homebrew | `brew uninstall 2ms` |
| Prebuilt binary | `sudo rm /usr/local/bin/2ms` (or remove it from wherever you placed it) |
| Source (`go install`) | `rm "$(go env GOPATH)/bin/2ms"` |
| Docker | `docker rmi checkmarx/2ms:latest` |

## Troubleshooting

- **`command not found: 2ms`** — The binary is not on your `PATH`. Confirm its location and add the directory to `PATH`, or move the binary into `/usr/local/bin`.
- **macOS "cannot be opened because the developer cannot be verified"** — Remove the quarantine attribute: `xattr -d com.apple.quarantine /usr/local/bin/2ms`.
- **Build fails with a Go version error** — Upgrade your Go toolchain to **1.26.2 or newer** (`go version` to check).
- **`2ms git` reports "detected dubious ownership"** — Mark the path as safe: `git config --global --add safe.directory <path>`. The Docker image already does this for `/repo`.
- **Permission denied when running the binary** — Make it executable: `chmod +x 2ms`.

For anything else, [open an issue](https://github.com/Checkmarx/2ms/issues/new).
