import argparse
import sys
from dataclasses import dataclass
from typing import Literal
from rich.console import Console
from rich.table import Table

# =============================================================================
# Confidence type — only three valid values
# =============================================================================
Confidence = Literal["high", "medium", "low"]


# =============================================================================
# Result type — what identify() returns for each guess
# =============================================================================
@dataclass(frozen = True, slots = True)
class HashCandidate:
    algorithm: str
    confidence: Confidence
    reason: str


# =============================================================================
# Prefix rules — strongest signal we have
# =============================================================================
PREFIX_RULES: list[tuple[str, str, str]] = [
    # Argon2 family
    ("$argon2id$", "Argon2id", "modern PHC string, the current standard"),
    ("$argon2i$", "Argon2i", "PHC string, side-channel-resistant variant"),
    ("$argon2d$", "Argon2d", "PHC string, GPU-resistant variant"),

    # bcrypt and its many variants
    ("$2y$", "bcrypt", "bcrypt PHC string, 2y variant (PHP)"),
    ("$2b$", "bcrypt", "bcrypt PHC string, 2b variant (current)"),
    ("$2a$", "bcrypt", "bcrypt PHC string, 2a variant (legacy)"),
    ("$2x$", "bcrypt", "bcrypt PHC string, 2x variant (legacy fix)"),

    # Unix crypt(3) family
    ("$6$", "SHA-512 crypt", "Unix crypt(3) using SHA-512 (default on Linux)"),
    ("$5$", "SHA-256 crypt", "Unix crypt(3) using SHA-256"),
    ("$1$", "MD5 crypt", "Unix crypt(3) using MD5 (legacy, weak)"),

    # Apache htpasswd MD5 variant
    ("$apr1$", "Apache MD5-crypt", "Apache htpasswd MD5 variant (`htpasswd -m`)"),

    # yescrypt
    ("$y$", "yescrypt", "PHC string, modern Linux crypt successor"),

    # phpass
    ("$P$", "phpass", "WordPress / phpBB password hash"),
    ("$H$", "phpass", "phpBB-style phpass variant"),

    # Drupal 7
    ("$S$", "Drupal 7 (SHA-512)", "Drupal 7 PHC-style hash"),

    # scrypt as some implementations encode it
    ("$7$", "scrypt", "scrypt PHC-style hash"),

    # Django's default
    ("pbkdf2_sha256$", "Django PBKDF2-SHA256", "Django default password hash"),
    ("pbkdf2_sha1$", "Django PBKDF2-SHA1", "Django legacy password hash"),
    ("bcrypt_sha256$", "Django bcrypt-SHA256", "Django bcrypt wrapper"),
    ("argon2$", "Django Argon2", "Django Argon2 wrapper"),

    # LDAP password schemes
    ("{SSHA}", "LDAP SSHA", "LDAP salted SHA-1 (base64 payload)"),
    ("{SHA}", "LDAP SHA", "LDAP SHA-1 (base64 payload)"),
    ("{SMD5}", "LDAP SMD5", "LDAP salted MD5 (base64 payload)"),
    ("{MD5}", "LDAP MD5", "LDAP MD5 (base64 payload)"),
    ("{CRYPT}", "LDAP CRYPT", "LDAP wrapping a crypt(3) hash"),
]


# =============================================================================
# Length-and-hex rules — fallback when no prefix matched
# =============================================================================
HEX_CHARSET: frozenset[str] = frozenset("0123456789abcdefABCDEF")
_HEX_UPPER_CHARSET: frozenset[str] = frozenset("0123456789ABCDEF")

# Length-in-hex-chars → list of algorithms, ordered by commonality
HEX_LENGTH_RULES: dict[int, list[str]] = {
    # 16 hex chars = 8 bytes = 64 bits
    16: ["MySQL323", "CRC-64"],
    # 32 hex chars = 16 bytes = 128 bits
    32: ["MD5", "NTLM", "MD4", "RIPEMD-128"],
    # 40 hex chars = 20 bytes = 160 bits
    40: ["SHA-1", "RIPEMD-160"],
    # 48 hex chars = 24 bytes = 192 bits
    48: ["Tiger-192"],
    # 56 hex chars = 28 bytes = 224 bits
    56: ["SHA-224", "SHA3-224"],
    # 64 hex chars = 32 bytes = 256 bits
    64: ["SHA-256", "SHA3-256", "BLAKE2s-256", "RIPEMD-256"],
    # 80 hex chars = 40 bytes = 320 bits (uncommon)
    80: ["RIPEMD-320"],
    # 96 hex chars = 48 bytes = 384 bits
    96: ["SHA-384", "SHA3-384"],
    # 128 hex chars = 64 bytes = 512 bits
    128: ["SHA-512", "SHA3-512", "BLAKE2b-512", "Whirlpool"],
}


# =============================================================================
# Helpers
# =============================================================================
def _is_hex(text: str) -> bool:
    return bool(text) and all(c in HEX_CHARSET for c in text)


_MYSQL5_HEX_BODY_LENGTH = 40
_MYSQL5_TOTAL_LENGTH = _MYSQL5_HEX_BODY_LENGTH + 1

def _is_mysql5(text: str) -> bool:
    if len(text) != _MYSQL5_TOTAL_LENGTH or not text.startswith("*"):
        return False
    body = text[1 :]
    return all(c in _HEX_UPPER_CHARSET for c in body)



_DESCRYPT_CHARSET: frozenset[str] = frozenset(
    "./0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
)
_DESCRYPT_TOTAL_LENGTH = 13

def _is_descrypt(text: str) -> bool:
    return (
        len(text) == _DESCRYPT_TOTAL_LENGTH
        and all(c in _DESCRYPT_CHARSET for c in text)
    )


# =============================================================================
# The actual identifier
# =============================================================================
# pylint: disable=too-many-return-statements,too-many-branches
def identify(raw_input: str) -> list[HashCandidate]:
    text = raw_input.strip()

    if not text:
        return []

    # ----- Step 1: prefix rules -----
    for prefix, algorithm, note in PREFIX_RULES:
        if text.startswith(prefix):
            return [
                HashCandidate(
                    algorithm = algorithm,
                    confidence = "high",
                    reason = f"prefix `{prefix}` — {note}",
                )
            ]

    # ----- Step 2: special non-PHC formats -----
    if "::" in text and text.count(":") >= 4:
        parts = text.split(":")
        # NetNTLMv2 layout:
        #   user :: domain : challenge : hmac(32 hex) : blob(>=32 hex)
        if (len(parts) >= 6 and len(parts[4]) == 32 and _is_hex(parts[4])):
            return [
                HashCandidate(
                    algorithm = "NetNTLMv2",
                    confidence = "high",
                    reason =
                    "user::domain:challenge:hmac(32 hex):blob shape",
                )
            ]
        # NetNTLMv1 layout:
        #   user :: domain : lmhash(48 hex) : nthash(48 hex) : challenge
        if (len(parts) >= 6 and len(parts[3]) == 48 and _is_hex(parts[3])):
            return [
                HashCandidate(
                    algorithm = "NetNTLMv1",
                    confidence = "high",
                    reason =
                    "user::domain:lm(48 hex):nt(48 hex):challenge shape",
                )
            ]

    # MySQL5 — literal `*` + 40 uppercase hex chars
    if _is_mysql5(text):
        return [
            HashCandidate(
                algorithm = "MySQL5",
                confidence = "high",
                reason =
                "starts with `*` followed by 40 uppercase hex chars",
            )
        ]

    # Traditional 13-char DES crypt — legacy /etc/passwd format
    # with no prefix at all. We report MEDIUM (not HIGH) because the
    # 13-char `./0-9A-Za-z` shape isn't fully unique to DES crypt
    if _is_descrypt(text):
        return [
            HashCandidate(
                algorithm = "DES crypt",
                confidence = "medium",
                reason =
                "13 chars in `./0-9A-Za-z` — legacy /etc/passwd format",
            )
        ]

    # ----- Step 3: length + hex charset -----
    if _is_hex(text):
        algorithms = HEX_LENGTH_RULES.get(len(text), [])
        candidates: list[HashCandidate] = []
        for index, algorithm in enumerate(algorithms):
            # The first listed algorithm for each length is the modern
            # default and gets MEDIUM confidence. The rest are still
            # possible but less common in 2026 — LOW confidence
            confidence: Confidence = "medium" if index == 0 else "low"
            label = (
                "most likely candidate at this length"
                if index == 0 else "also possible at this length"
            )
            candidates.append(
                HashCandidate(
                    algorithm = algorithm,
                    confidence = confidence,
                    reason = f"{len(text)} hex chars — {label}",
                )
            )
        return candidates

    # ----- Step 4: generic PHC string fallback -----
    if text.startswith("$"):
        rest = text[1 :]
        if "$" in rest:
            algo_name = rest.split("$", 1)[0]
            if algo_name and all(c.isalnum() or c in "-_"
                                 for c in algo_name):
                return [
                    HashCandidate(
                        algorithm = f"PHC string ({algo_name})",
                        confidence = "low",
                        reason =
                        f"`${algo_name}$...` shape — generic PHC, no specific rule",
                    )
                ]

    # ----- Step 5: not-a-hash shape hints -----
    if text.startswith("eyJ"):
        return [
            HashCandidate(
                algorithm = "JWT (not a hash)",
                confidence = "low",
                reason =
                "leading `eyJ` is base64 of `{\"` — JWT, not a hash",
            )
        ]
    if any(c in text for c in "+/=") and len(text) > 8:
        return [
            HashCandidate(
                algorithm = "Base64 blob (not a hash)",
                confidence = "low",
                reason = "contains base64-only chars (`+`, `/`, `=`)",
            )
        ]

    # ----- Step 6: nothing matched -----
    return []


# =============================================================================
# CLI — argparse + a rich table
# =============================================================================
def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog = "hashid",
        description = (
            "Identify a hash string by prefix, length, and charset. "
            "Returns ranked candidates with confidence and reasoning."
        ),
    )
    parser.add_argument(
        "hash",
        help =
        "The hash string to identify (wrap in single quotes if it contains $).",
    )
    parser.add_argument(
        "--top",
        "-n",
        type = int,
        default = 5,
        help = "Show at most this many candidates (default: 5).",
    )
    return parser


def _render_table(
    raw_input: str,
    candidates: list[HashCandidate],
    console: Console,
) -> None:
    table = Table(
        title = f"Candidates for: {raw_input.strip()}",
        title_style = "bold cyan",
        show_lines = False,
    )
    table.add_column("algorithm", style = "bold white", no_wrap = True)
    table.add_column("confidence", no_wrap = True)
    table.add_column("reason", style = "dim")

    confidence_colors: dict[Confidence,
                            str] = {
                                "high": "green",
                                "medium": "yellow",
                                "low": "cyan",
                            }
    for candidate in candidates:
        color = confidence_colors[candidate.confidence]
        table.add_row(
            candidate.algorithm,
            f"[{color}]{candidate.confidence}[/{color}]",
            candidate.reason,
        )
    console.print(table)


def main() -> int:
    parser = _build_argument_parser()
    args = parser.parse_args()
    console = Console()

    candidates = identify(args.hash)

    if not candidates:
        console.print(
            "[red]No identification possible.[/red] "
            "Input did not match any known prefix, special format, "
            "or hex length."
        )
        return 1

    trimmed = candidates[: args.top]
    _render_table(args.hash, trimmed, console)

    return 0

if __name__ == "__main__":
    sys.exit(main())