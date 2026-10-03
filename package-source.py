"""Make a portable, reproducible source bundle without Git/hosting metadata."""
from pathlib import Path
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

root = Path(__file__).resolve().parent.parent
output = root / "dist" / "source.zip"
files = [root / name for name in ("README.md", "LICENSE", "package.json", "package-lock.json", "serve.cjs")]
files += [path for folder in ("dist", "tests", "scripts") for path in (root / folder).rglob("*") if path.is_file() and path != output]
with ZipFile(output, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
    for path in sorted(files):
        member = ZipInfo("sentinel-password-analyzer/" + path.relative_to(root).as_posix(), date_time=(2026, 1, 1, 0, 0, 0))
        member.compress_type = ZIP_DEFLATED
        member.external_attr = 0o644 << 16
        archive.writestr(member, path.read_bytes())
print(f"Source bundle: {output.stat().st_size:,} bytes; {len(files)} files")
