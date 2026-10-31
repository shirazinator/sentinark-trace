"""
Sentinark-Trace: Safe HTTP Redirection Chain Tracker
Traces URL redirect chains hop-by-hop without executing untrusted scripts.
"""

import urllib.request
import urllib.parse
import urllib.error
import ssl
from typing import List, Dict, Any


class SafeNoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Custom handler that intercepts redirects instead of following automatically."""
    def http_error_301(self, req, fp, code, msg, headers):
        return fp
    http_error_302 = http_error_301
    http_error_303 = http_error_301
    http_error_307 = http_error_301
    http_error_308 = http_error_301


def trace_redirect_chain(initial_url: str, max_hops: int = 10, timeout: float = 4.0) -> Dict[str, Any]:
    """
    Safely follows and documents all HTTP redirects for a URL.
    Returns: list of hops, final destination URL, and shortener detection flags.
    """
    if not initial_url.startswith(("http://", "https://")):
        current_url = "https://" + initial_url
    else:
        current_url = initial_url

    hops: List[Dict[str, Any]] = []
    visited = set()
    is_cloaked = False

    # SSL context that allows inspection without terminating on self-signed certs
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        SafeNoRedirectHandler()
    )

    for hop_idx in range(max_hops):
        if current_url in visited:
            hops.append({
                "hop": hop_idx + 1,
                "url": current_url,
                "status": "LOOP",
                "notes": "Circular redirect loop detected"
            })
            break

        visited.add(current_url)

        req = urllib.request.Request(
            current_url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Sentinark-Trace/1.0"
            }
        )

        try:
            with opener.open(req, timeout=timeout) as resp:
                status_code = getattr(resp, "status", 200)
                headers = dict(resp.headers)
                next_location = headers.get("Location") or headers.get("location")

                hop_record = {
                    "hop": hop_idx + 1,
                    "url": current_url,
                    "status_code": status_code,
                    "server": headers.get("Server", "Unknown"),
                    "content_type": headers.get("Content-Type", "Unknown")
                }
                hops.append(hop_record)

                if next_location:
                    # Resolve relative redirect paths (e.g. /login)
                    current_url = urllib.parse.urljoin(current_url, next_location)
                else:
                    # Final destination reached
                    break

        except urllib.error.HTTPError as e:
            status_code = e.code
            next_location = e.headers.get("Location") or e.headers.get("location")
            hops.append({
                "hop": hop_idx + 1,
                "url": current_url,
                "status_code": status_code,
                "server": e.headers.get("Server", "Unknown"),
                "notes": f"HTTP {status_code}"
            })
            if next_location:
                current_url = urllib.parse.urljoin(current_url, next_location)
            else:
                break
        except Exception as e:
            hops.append({
                "hop": hop_idx + 1,
                "url": current_url,
                "status_code": "ERROR",
                "notes": f"Network unreachable or blocked: {str(e)}"
            })
            break

    # Check for known shorteners
    shorteners = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "goo.gl", "ow.ly"}
    initial_host = urllib.parse.urlparse(initial_url).netloc.lower()
    final_url = hops[-1]["url"] if hops else current_url

    has_shortener = any(s in initial_host for s in shorteners)
    multiple_hops = len(hops) > 1

    return {
        "initial_url": initial_url,
        "final_url": final_url,
        "total_hops": len(hops),
        "hops": hops,
        "uses_shortener": has_shortener,
        "multiple_redirects": multiple_hops
    }
