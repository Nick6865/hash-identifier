import argparse
import sys
from dataclasses import dataclass
from typing import Literal
from rich.console import Console
from rich.table import Table

"""
architecture

data layer: store prefix rules and hex length rules
    lookup tables

cli layer: this is main, render table and build argument parser
    reads cmd argument
    prints colored table
    returns an exit code

logic layer: identify hash type
    decision making
    takes a string, returns a list of hash candidate

decision making
    prefix rule?
    special shape?
    pure hex?
    "$something$"?
    shape hint?

    give up
"""
Confidence = Literal["high","medium","low"]
@dataclass(frozen = True, slots = True)
class HashCandidate:
    algo: str
    confidence: Confidence
    reason: str

#data layer
#prefix
PREFIX_RULE: list[tuple[str, str, str]] = [
    # Argon2 family
    ("$argon2id$", "Argon2id", "modern PHC string, the current standard"),
    ("$argon2i$", "Argon2i", "PHC string, side-channel-resistant variant"),
    ("$argon2d$", "Argon2d", "PHC string, GPU-resistant variant"),

    # bcrypt
    ("$2y$", "bcrypt", "bcrypt PHC string, 2y variant (PHP)"),
    ("$2b$", "bcrypt", "bcrypt PHC string, 2b variant (current)"),
    ("$2a$", "bcrypt", "bcrypt PHC string, 2a variant (legacy)"),
    ("$2x$", "bcrypt", "bcrypt PHC string, 2x variant (legacy fix)"),

    # Unix crypt(3)
    ("$6$", "SHA-512 crypt", "Unix crypt(3) using SHA-512 (default on Linux)"),
    ("$5$", "SHA-256 crypt", "Unix crypt(3) using SHA-256"),
    ("$1$", "MD5 crypt", "Unix crypt(3) using MD5 (legacy, weak)"),

    # Apache htpasswd
    ("$apr1$", "Apache MD5-crypt", "Apache htpasswd MD5 variant (`htpasswd -m`)"),

    # yescrypt
    ("$y$", "yescrypt", "PHC string, modern Linux crypt successor"),

    # phpass
    ("$P$", "phpass", "WordPress / phpBB password hash"),
    ("$H$", "phpass", "phpBB-style phpass variant"),

    # Drupal 7
    ("$S$", "Drupal 7 (SHA-512)", "Drupal 7 PHC-style hash"),

    # scrypt
    ("$7$", "scrypt", "scrypt PHC-style hash"),

    # Django
    ("pbkdf2_sha256$", "Django PBKDF2-SHA256", "Django default password hash"),
    ("pbkdf2_sha1$", "Django PBKDF2-SHA1", "Django legacy password hash"),
    ("bcrypt_sha256$", "Django bcrypt-SHA256", "Django bcrypt wrapper"),
    ("argon2$", "Django Argon2", "Django Argon2 wrapper"),

    # LDAP
    ("{SSHA}", "LDAP SSHA", "LDAP salted SHA-1 (base64 payload)"),
    ("{SHA}", "LDAP SHA", "LDAP SHA-1 (base64 payload)"),
    ("{SMD5}", "LDAP SMD5", "LDAP salted MD5 (base64 payload)"),
    ("{MD5}", "LDAP MD5", "LDAP MD5 (base64 payload)"),
    ("{CRYPT}", "LDAP CRYPT", "LDAP wrapping a crypt(3) hash"),
]

#hex length 
HEX_CHARSET: frozenset[str] = frozenset("0123456789abcdefABCDEF")
HEX_UPPER_CHARSET: frozenset[str] = frozenset("0123456789ABCDEF")

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

#some helper for logic layer
def _is_hex(txt:str) -> bool:
    return bool(txt) and all(c in HEX_CHARSET for c in txt)


#special shape
 #NetNTLMv2 layout:
    #user :: domain : challenge : hmac(32 hex) : blob(>=32 hex)
# NetNTLMv1 layout:
    #user :: domain : lmhash(48 hex) : nthash(48 hex) : challenge
def _is_NetNTLM(txt: str) -> HashCandidate:
    if "::" in txt and txt.count(":") >=4:
        parts = txt.split(":")
        #["user", "", "domain", "challenge", "hmac", "blob"]
        if (len(parts) >= 6 and len(parts[4]) == 32 and _is_hex(parts[4])):
            return[
                HashCandidate(
                    algo = "NetNTLMv2",
                    confidence = "high",
                    reason = "user::domain:challenge:hmac(32 hex):blob shape",
                )
            ]

        if (len(parts) >= 6 and len(parts[3]) == 48 and _is_hex(parts[3])):
            return[
                HashCandidate(
                    algorithm = "NetNTLMv1",
                    confidence = "high",
                    reason = "user::domain:lmhash(48 hex):nthash(48 hex):challenge",
                )
            ]
    return None

#MySQL
_MYSQL5_HEX_BODY_LENGTH = 40
_MYSQL5_TOTAL_LENGTH = _MYSQL5_HEX_BODY_LENGTH + 1

def _is_mysql5(txt: str) -> HashCandidate:
    if len(txt) != _MYSQL5_TOTAL_LENGTH or not txt.startswith("*"):
        return None
    body = txt[1:]
    if all(c in HEX_UPPER_CHARSET for c in body):
        return [
            HashCandidate(
                algo="MySQL5",
                confidence="high",
                reason="starts with `*` followed by 40 uppercase hex chars",
            )
        ]
    
    return None

#descrypt
_DESCRYPT_CHARSET: frozenset[str] = frozenset(
    "./0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
)
_DESCRYPT_TOTAL_LENGTH = 13

def _is_descrypt(txt: str) -> HashCandidate:
    if len(txt) == _DESCRYPT_TOTAL_LENGTH and all(c in _DESCRYPT_CHARSET for c in txt):
        return[
            HashCandidate(
                algo = "DES crypt",
                confidence = "medium",
                reason = "13 chars in `./0-9A-Za-z`"
            )
        ]

#logic layer

def identifier(raw_input: str) ->list[HashCandidate]:
    txt = raw_input.strip()

    if not txt:
        return []

    #prefix?
    for prefix, algor, note in PREFIX_RULE:
        if txt.startswith(prefix):
            return[
                HashCandidate(
                    algo = algor,
                    confidence = "high",
                    reason = f"prefix `{prefix}` — {note}",
                )
            ]

    #special shape?
    #netNTLM
    result = _is_NetNTLM(txt)
    if result:
        return result
    #MySQL5
    result = _is_mysql5(txt)
    if result:
        return result    
    #DES crypt
    result = _is_descrypt(txt)
    if result:
        return result  
    
    #pure hex?
    if _is_hex(txt):
        algorithms = HEX_LENGTH_RULES.get(len(txt), [])
        candidates: list[HashCandidate] = []
        for index, algor in enumerate(algorithms):
            confidence: Confidence = "medium" if index == 0 else "low"
            label = (
                "most likely candidate at this length"
                if index == 0 else "also possible at this length")
            candidates.append(
                HashCandidate(
                    algo = algor,
                    confidence = confidence,
                    reason = f"{len(txt)} hex chars — {label}",
                )
            )
        return candidates

    #"$something$"?
    if txt.startswith("$"):
        rest = txt[1:]
        if "$" in rest:
            algo_name = rest.split("$", 1)[0]
            if algo_name and all(c.isalnum() or c in "-_" for c in algo_name):
                return [
                    HashCandidate(
                        algo = f"PHC string ({algo_name})",
                        confidence = "low",
                        reason = f"`${algo_name}$...` shape — generic PHC, no specific rule",
                    )
                ]

    #shape hint?
    if txt.startswith("eyJ"):
        # JWTs always begin with `eyJ`
        return [
            HashCandidate(
                algo = "JWT (not a hash)",
                confidence = "low",
                reason = "leading `eyJ` is base64 of `{\"` — JWT, not a hash",
            )
        ]
    if any(c in txt for c in "+/=") and len(txt) > 8:
        # Hex hashes NEVER contain `+`, `/`, or `=`
        return [
            HashCandidate(
                algo = "Base64 blob (not a hash)",
                confidence = "low",
                reason = "contains base64-only chars (`+`, `/`, `=`)",
            )
        ]

    return[]

#cli layer

#build argument
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

#print table 
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
            candidate.algo,
            f"[{color}]{candidate.confidence}[/{color}]",
            candidate.reason,
        )
    console.print(table)


#main
def main() -> int:
    parser = _build_argument_parser()
    args = parser.parse_args()
    console = Console()

    candidates = identifier(args.hash)

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