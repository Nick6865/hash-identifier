# Hash Identifier CLI Tool (Self-Learning Project)

This repository is a personal, hands-on learning project created to understand hash identification algorithms, password storage formats, and encoding schemes from the ground up. It contains a Python implementation that analyzes raw input strings to detect hash types (from legacy MD5/DES to modern bcrypt/Argon2 and NTLM), providing confidence scores and technical reasoning via a terminal UI.

**Disclaimer**: This project is strictly for educational and self-study purposes. It is **not** a production-grade software or intended for commercial use.

---

## Goals

The primary goal of this project is to demystify how password hashing formats and signature structures operate underneath by analyzing prefix rules, length properties, and character sets.

Through this experiment, I aim to gain a deeper practical understanding of:
- Recognizing PHC (Password Hashing Competition) string specifications and Unix shadow hash structures.
- Calculating entropy, hex length constraints, and mapping algorithms to candidate probabilities.
- Filtering false positives (e.g., distinguishing Base64 payloads or JWT tokens from actual cryptographic hashes).
- Implementing CLI utilities in modern Python using strict typing (`dataclass`, `Literal`, `slots`) and rich terminal formatting.

---

## Architecture & Progress

The detection engine follows a 6-stage identification pipeline:

### 1. Explicit Prefix Matching (High Confidence)
- [x] Argon2 variants (`$argon2id$`, `$argon2i$`, `$argon2d$`).
- [x] bcrypt variants (`$2b$`, `$2y$`, `$2a$`, `$2x$`).
- [x] Unix crypt(3) formats (`$6$` SHA-512, `$5$` SHA-256, `$1$` MD5).
- [x] Web framework & service hashes (`phpass`, `Apache MD5`, `Django PBKDF2/bcrypt/argon2`, `Drupal 7`, `LDAP`).

### 2. Special Structural Formats
- [x] NetNTLMv1 / NetNTLMv2 challenge-response layouts (`::` delimiter checks).
- [x] MySQL5 password hashes (`*` followed by 40 uppercase hex chars).
- [x] Legacy DES crypt (`13` character charset checks).

### 3. Hex Length Engine (Fallback)
- [x] Length-to-algorithm mapping for standard hex hashes (MD5, NTLM, SHA-1, SHA-256, SHA-512, BLAKE2, Whirlpool, RIPEMD).
- [x] Candidate ranking into `medium` or `low` confidence based on usage frequency.

### 4. Heuristics & Non-Hash Hints
- [x] Generic PHC string detection (`$algo$...`).
- [x] False positive detection for JWT tokens (`eyJ...`) and Base64 payloads (`+`, `/`, `=`).

All pipeline stages are complete.

---

## Usage

### Prerequisites
- **Python 3.10+**
- `rich` library (`pip install rich`)

>  **Note**: Always wrap hash strings containing `$` in single quotes `'...'` to prevent shell variable expansion in Bash/Zsh.

### Examples

```bash
# Basic usage with a raw hex hash (MD5 candidate)
python main.py 5d41402abc4b2a76b9719d911017c592

# Identifying a bcrypt password hash
python main.py '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeg6Lruj3vjPGga31lW'

# Limit candidate list display
python main.py 5d41402abc4b2a76b9719d911017c592 --top 2
```
## Credits & Acknowledgments

This project is a hands-on learning implementation based on **AngelaMos**'s hash identifier, studied as part of the [CarterPerez-dev/Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/foundations/hash-identifier) learning roadmap.

- Original Code & Logic: [AngelaMos](https://github.com/AngelaMos) (core identification pipeline, PHC rules, format checks).
- Learning Roadmap: [CarterPerez-dev](https://github.com/CarterPerez-dev/Cybersecurity-Projects).
- Terminal UI: [Rich](https://github.com/Textualize/rich).

## License

Feel free to use, modify, or inspect this codebase for your own learning and exploration purposes.
