
import secrets
import subprocess
from pathlib import Path
from urllib.parse import urlparse


# --------------------------------------------------------------------------- #
# classification accessor: works for both a pydantic object and a plain dict   #
# (the agent passes an object, the poc-runner loads classification.json → dict)#
# --------------------------------------------------------------------------- #
def _cls_get(classification, key: str, default: str = "") -> str:
    if classification is None:
        return default
    if isinstance(classification, dict):
        value = classification.get(key, default)
    else:
        value = getattr(classification, key, default)
    return value if value is not None else default


_WEB_DOCROOTS = [
    "/usr/share/nginx/html", "/var/www/html", "/var/www",
    "/srv/http", "/srv/www", "/app/public", "/app/static",
    "/usr/local/apache2/htdocs",
]


def _url_to_candidate_paths(url: str) -> list[str]:
    p = urlparse(url)
    url_path = p.path or "/"
    if url_path.endswith("/"):
        url_path += "index.html"
    rel = url_path.lstrip("/")
    return [f"{root}/{rel}" for root in _WEB_DOCROOTS] + [url_path]


def _exec_root(cid: str, script: str, env_pairs: dict) -> subprocess.CompletedProcess:
    """Run ``sh -c <script>`` as root inside cid, passing values via ``-e`` to
    avoid any shell-quoting/injection issues with the path or the nonce."""
    cmd = ["docker", "exec", "-u", "root"]
    for k, v in env_pairs.items():
        cmd += ["-e", f"{k}={v}"]
    cmd += [cid, "sh", "-c", script]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=15)


def _compose_container_ids(code_dir_path: Path) -> list[str]:
    ps = subprocess.run(
        ["docker", "compose", "ps", "-q"],
        cwd=code_dir_path, capture_output=True, text=True,
    )
    return [c for c in ps.stdout.split() if c]


def _find_served_file(cid: str, candidates: list[str], placeholder: str) -> str | None:
    for path in candidates:
        try:
            if _exec_root(cid, 'test -f "$P"', {"P": path}).returncode == 0:
                return path
        except Exception:
            continue
    try:
        r = _exec_root(
            cid,
            'grep -rlF "$V" $R 2>/dev/null | head -n1',
            {"V": placeholder, "R": "/usr/share/nginx /var/www /srv /app /usr/local/apache2/htdocs"},
        )
        hit = (r.stdout or "").strip()
        return hit or None
    except Exception:
        return None


def _write_flag(cid: str, flag_path: str, nonce: str, owner: str, perms: str) -> bool:
    """Overwrite (or create) the flag file with ``nonce``, then re-apply owner/perms.

    Using redirection (``> "$P"``) truncates the existing inode, preserving its
    owner and mode; we still re-apply the classification's owner/perms so the flag
    keeps the exact readability the exploit chain is expected to overcome."""
    try:
        res = _exec_root(cid, 'printf "%s" "$V" > "$P"',
                         {"P": flag_path, "V": nonce})
        if res.returncode != 0:
            return False
        if owner and owner.upper() != "N/A":
            _exec_root(cid, 'chown "$O" "$P" 2>/dev/null || true',
                       {"P": flag_path, "O": owner})
        if perms and perms.strip().isdigit():
            _exec_root(cid, 'chmod "$M" "$P" 2>/dev/null || true',
                       {"P": flag_path, "M": perms.strip()})
        return True
    except Exception:
        return False


def _resolve_fs_targets(cids: list[str], flag_path: str) -> list[tuple[str, str]]:
    targets = []
    for cid in cids:
        try:
            if _exec_root(cid, 'test -f "$P"', {"P": flag_path}).returncode == 0:
                targets.append(cid)
        except Exception:
            continue
    if not targets:
        parent = str(Path(flag_path).parent)
        for cid in cids:
            try:
                if _exec_root(cid, 'test -d "$D"', {"D": parent}).returncode == 0:
                    targets.append(cid)
            except Exception:
                continue
    return [(cid, flag_path) for cid in targets]


def _served_value_matches(cid: str, url: str, expected: str) -> bool | None:
    p = urlparse(url)
    port = p.port or (443 if p.scheme == "https" else 80)
    path = p.path or "/"
    scheme = p.scheme or "http"
    target = f"{scheme}://127.0.0.1:{port}{path}"
    script = (
        'if command -v curl >/dev/null 2>&1; then curl -sk "$U"; '
        'elif command -v wget >/dev/null 2>&1; then wget -qO- --no-check-certificate "$U"; '
        'else echo __NO_HTTP_CLIENT__; fi'
    )
    try:
        r = _exec_root(cid, script, {"U": target})
    except Exception:
        return None
    body = (r.stdout or "")
    if "__NO_HTTP_CLIENT__" in body:
        return None
    return expected in body


def _is_static_docroot(path: str) -> bool:
    return any(path == r or path.startswith(r + "/") for r in _WEB_DOCROOTS)


def make_placeholder(cve_id: str) -> str:
    """The derivable, pre-nonce flag value the environment ships with."""
    return f"FLAG{{verified_{cve_id}}}"


def make_nonce() -> str:
    """A fresh, unguessable per-run flag value (same shape as the placeholder:
    ``FLAG{...}`` so the same extraction regex works on both)."""
    return "FLAG{" + secrets.token_hex(16) + "}"


def inject_flag_nonce(classification, cve_id, code_dir_path, nonce: str | None = None):
    
    placeholder = make_placeholder(cve_id)
    nonce = nonce or make_nonce()
    flag_path = (_cls_get(classification, "flag_path", "") or "").strip()

    if flag_path.lower().startswith("database:"):
        return placeholder, False, "database flag: nonce injection not supported, using placeholder"

    is_url = flag_path.startswith("http://") or flag_path.startswith("https://")
    is_fs = flag_path.startswith("/")
    if not flag_path or not (is_url or is_fs):
        return placeholder, False, f"unsupported flag_path ('{flag_path or 'N/A'}'); using placeholder"

    owner = (_cls_get(classification, "flag_owner", "") or "").strip()
    perms = (_cls_get(classification, "flag_permissions", "") or "").strip()
    cids = _compose_container_ids(code_dir_path)
    if not cids:
        return placeholder, False, "no running containers found; using placeholder"

    if is_fs:
        targets = _resolve_fs_targets(cids, flag_path)
        injected = [cid[:12] for cid, path in targets
                    if _write_flag(cid, path, nonce, owner, perms)]
        if injected:
            return nonce, True, f"nonce injected into {injected} (filesystem)"
        return placeholder, False, f"could not inject nonce at '{flag_path}'; using placeholder"

    candidates = _url_to_candidate_paths(flag_path)
    verified = []
    for cid in cids:
        hit = _find_served_file(cid, candidates, placeholder)
        if not hit:
            continue
        if not _write_flag(cid, hit, nonce, owner, perms):
            continue
        served = _served_value_matches(cid, flag_path, nonce)
        if served is True:
            verified.append(cid[:12])
        elif served is False:
            return placeholder, False, (
                f"nonce written to '{hit}' but served value differs "
                "(app-cached / non-static serving); using placeholder")
        elif _is_static_docroot(hit):
            verified.append(cid[:12])
    if verified:
        return nonce, True, f"nonce injected & served-check {verified} (url→file)"
    return placeholder, False, f"could not verify served nonce for '{flag_path}'; using placeholder"