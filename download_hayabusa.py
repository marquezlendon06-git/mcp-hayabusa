"""Download the latest Hayabusa release for the current platform into ./hayabusa/."""

import json
import platform
import shutil
import ssl
import sys
import urllib.request
import zipfile
from pathlib import Path

import certifi

API_URL = "https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest"
DEST = Path(__file__).parent / "hayabusa"


def platform_slug() -> str:
    system = sys.platform
    machine = platform.machine().lower()

    if system == "win32":
        if machine in ("amd64", "x86_64"):
            return "win-x64"
        if machine == "aarch64":
            return "win-aarch64"
        return "win-x86"
    if system == "linux":
        if machine == "aarch64":
            return "lin-aarch64-gnu"
        return "lin-x64-gnu"
    if system == "darwin":
        if machine == "arm64":
            return "mac-aarch64"
        return "mac-x64"

    raise RuntimeError(f"Unsupported platform: {system}/{machine}")


SSL_CTX = ssl.create_default_context(cafile=certifi.where())


def fetch_latest_asset(slug: str) -> tuple[str, str]:
    """Return (version_tag, download_url) for the asset matching slug."""
    req = urllib.request.Request(API_URL, headers={"Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, context=SSL_CTX) as resp:
        release = json.load(resp)

    tag = release["tag_name"]
    for asset in release["assets"]:
        name: str = asset["name"]
        if slug in name and name.endswith(".zip") and "live-response" not in name:
            return tag, asset["browser_download_url"]

    raise RuntimeError(f"No asset found for slug '{slug}' in release {tag}")


def download(url: str, dest_path: Path) -> None:
    print(f"Downloading {url} ...")
    with urllib.request.urlopen(url, context=SSL_CTX) as resp, open(dest_path, "wb") as f:
        total = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        chunk = 1024 * 256
        while True:
            block = resp.read(chunk)
            if not block:
                break
            f.write(block)
            downloaded += len(block)
            if total:
                pct = downloaded * 100 // total
                print(f"\r  {pct:3d}%  {downloaded // 1024 // 1024} MB / {total // 1024 // 1024} MB", end="", flush=True)
    print()


def main() -> None:
    slug = platform_slug()
    print(f"Platform: {slug}")

    tag, url = fetch_latest_asset(slug)
    print(f"Latest release: {tag}")

    zip_path = Path(__file__).parent / f"hayabusa-{tag}-{slug}.zip"

    try:
        download(url, zip_path)

        if DEST.exists():
            print(f"Removing existing {DEST} ...")
            shutil.rmtree(DEST)
        DEST.mkdir(parents=True)

        print(f"Extracting to {DEST} ...")
        dest_resolved = DEST.resolve()
        with zipfile.ZipFile(zip_path) as zf:
            for member in zf.namelist():
                extracted = (dest_resolved / member).resolve()
                if extracted != dest_resolved and dest_resolved not in extracted.parents:
                    raise RuntimeError(
                        f"Refusing to extract '{member}': path escapes {dest_resolved}"
                    )
            zf.extractall(dest_resolved)

        # Stable hard link so the MCP server always resolves the same path.
        # Extension is .exe on Windows, no extension on Unix.
        ext = ".exe" if sys.platform == "win32" else ""
        versioned = next(DEST.glob(f"hayabusa-*{slug}*{ext}"))
        stable = DEST / f"hayabusa{ext}"
        if stable.exists():
            stable.unlink()
        stable.hardlink_to(versioned)
        print(f"Linked {stable.name} -> {versioned.name}")

        print(f"Done. Hayabusa extracted to: {DEST}")
    finally:
        if zip_path.exists():
            zip_path.unlink()


if __name__ == "__main__":
    main()
