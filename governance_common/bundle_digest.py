"""
Deterministic digest of an agent deployment zip.

sha256 over "\\n".join(f"{arcname}\\t{sha256(bytes)}") for every file entry in
sorted arcname order, excluding governance/ (the gate artifact embedded after
signing). Independent of zip entry order, timestamps and compression.
"""
import hashlib
import zipfile

EXCLUDED_PREFIX = "governance/"


def entry_digests(zip_file) -> dict:
    """{arcname: sha256 hex} for every non-directory entry outside governance/.

    A duplicated arcname is refused: which copy the runtime extracts would be
    ambiguous, so the digest could not describe what actually runs."""
    entries = {}
    with zipfile.ZipFile(zip_file) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = info.filename
            if name.startswith(EXCLUDED_PREFIX):
                continue
            if name in entries:
                raise ValueError(f"duplicate zip entry: {name}")
            entries[name] = hashlib.sha256(zf.read(info)).hexdigest()
    return entries


def bundle_digest(zip_file) -> str:
    """Digest of a zip given as a path or a binary file object."""
    entries = entry_digests(zip_file)
    listing = "\n".join(f"{name}\t{entries[name]}" for name in sorted(entries))
    return hashlib.sha256(listing.encode("utf-8")).hexdigest()
