New-Item -ItemType Directory -Force -Path .\detect_secrets\plugins | Out-Null
@'
from __future__ import annotations
import re
from typing import ClassVar, Iterable, Tuple
from .base import RegexBasedDetector

_B58 = r"[1-9A-HJ-NP-Za-km-z]"
_B32 = r"[A-Z2-7]"
_HEX = r"[0-9a-fA-F]"

class CryptoWalletDetector(RegexBasedDetector):
    """
    Detects common cryptocurrency wallet secrets (regex + targeted JSON cues).
    Avoids duplication with built-in detectors.
    """
    secret_type: ClassVar[str] = "Crypto Wallet Secret"

    # Heuristic BIP-39 mnemonics (12/15/18/21/24 words; lowercase; 3–8 chars/word)
    _BIP39_12 = re.compile(r"\b(?:[a-z]{3,8}\s){11}[a-z]{3,8}\b")
    _BIP39_15 = re.compile(r"\b(?:[a-z]{3,8}\s){14}[a-z]{3,8}\b")
    _BIP39_18 = re.compile(r"\b(?:[a-z]{3,8}\s){17}[a-z]{3,8}\b")
    _BIP39_21 = re.compile(r"\b(?:[a-z]{3,8}\s){20}[a-z]{3,8}\b")
    _BIP39_24 = re.compile(r"\b(?:[a-z]{3,8}\s){23}[a-z]{3,8}\b")

    denylist: ClassVar[Iterable[re.Pattern[str]]] = (
        # BTC WIF: 5... (51), K/L... (52), testnet 9.../c... (52–53)
        re.compile(rf"\b(?:5{_B58}{{50}}|[KL]{_B58}{{51}}|9{_B58}{{50}}|c{_B58}{{51}})\b"),
        # BIP32 extended private keys (xprv/yprv/zprv/tprv ~111 chars)
        re.compile(rf"\b(?:xprv|yprv|zprv|tprv){_B58}{{100,108}}\b"),
        # Ethereum private key (0x + 64 hex)
        re.compile(rf"\b0x{_HEX}{{64}}\b"),
        # Ethereum keystore JSON cues
        re.compile(r'"crypto"\s*:\s*{'),
        re.compile(r'"ciphertext"\s*:\s*"[0-9a-fA-F]+"'),
        # Solana private (base58 ~88 chars; heuristic)
        re.compile(rf"\b{_B58}{{85,95}}\b"),
        # Ripple (XRP) family seed: starts with s, 29–35 base58 chars
        re.compile(rf"\bs{_B58}{{28,34}}\b"),
        # Stellar secret seed: 56 base32, starts with S
        re.compile(rf"\bS{_B32}{{55}}\b"),
        # NEAR: ed25519:<base58 43–44>
        re.compile(rf"\bed25519:{_B58}{{43,44}}\b"),
        # Avalanche: PrivateKey-<base58>
        re.compile(rf"\bPrivateKey-{_B58}{{50,120}}\b"),
        # Tezos secret: edsk... / spsk... / p2sk...
        re.compile(rf"\bedsk{_B58}{{40,100}}\b"),
        re.compile(rf"\bspsk{_B58}{{40,70}}\b"),
        re.compile(rf"\bp2sk{_B58}{{40,70}}\b"),
        # Substrate keystore JSON cue
        re.compile(r'"encoded"\s*:\s*"[A-Za-z0-9+/=]+"'),
    )

    def analyze(self, string: str, line_num: int, filename: str):
        # Base regexes first
        for index, match in enumerate(self.denylist):
            m = match.search(string)
            if m:
                yield m.start(), m.group(0)
        # BIP-39 (order longest→shortest for perf)
        for pat in (self._BIP39_24, self._BIP39_21, self._BIP39_18, self._BIP39_15, self._BIP39_12):
            m = pat.search(string)
            if m:
                yield m.start(), m.group(0)
'@ | Set-Content -Encoding UTF8 .\detect_secrets\plugins\crypto_wallets.py
