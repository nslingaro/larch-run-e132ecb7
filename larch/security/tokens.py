"""Bearer access tokens.

Tokens are JWTs signed with ES256 (ECDSA P-256, SHA-256) and carry iss, aud, sub,
jti, iat, exp and role. Verification pins the algorithm, so "none" and HMAC
algorithm-confusion tokens are rejected. Each token's jti is also recorded server-side
(``sessions`` table) so logout and agent deactivation revoke it at once.

Rotation: set the new private key in LARCH_TOKEN_SIGNING_KEY and keep the old public key
in LARCH_TOKEN_PREVIOUS_PUBLIC_KEYS until the old tokens expire (at most the token TTL).
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from larch.db import new_id, utcnow

ALGORITHM = "ES256"
MAX_TOKEN_LENGTH = 4096
_PEM_BLOCK = re.compile(r"-----BEGIN PUBLIC KEY-----.+?-----END PUBLIC KEY-----", re.S)


class InvalidToken(Exception):
    pass


@dataclass(frozen=True)
class IssuedToken:
    token: str
    jti: str
    expires_at: datetime


@dataclass(frozen=True)
class TokenClaims:
    user_id: str
    role: str
    jti: str


def _key_id(public_key: ec.EllipticCurvePublicKey) -> str:
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()[:12]).decode().rstrip("=")


def _check_curve(key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey) -> None:
    if not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("token keys must be EC P-256 keys")


class TokenService:
    def __init__(
        self,
        signing_key_pem: str,
        previous_public_keys_pem: str | None,
        issuer: str,
        audience: str,
        ttl: timedelta,
    ) -> None:
        private_key = serialization.load_pem_private_key(signing_key_pem.encode(), password=None)
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError("LARCH_TOKEN_SIGNING_KEY must be an EC private key")
        _check_curve(private_key)
        self._private_key = private_key
        self._kid = _key_id(private_key.public_key())
        self._verification_keys: dict[str, ec.EllipticCurvePublicKey] = {
            self._kid: private_key.public_key()
        }
        for block in _PEM_BLOCK.findall(previous_public_keys_pem or ""):
            public_key = serialization.load_pem_public_key(block.encode())
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise ValueError("LARCH_TOKEN_PREVIOUS_PUBLIC_KEYS must hold EC public keys")
            _check_curve(public_key)
            self._verification_keys[_key_id(public_key)] = public_key
        self._issuer = issuer
        self._audience = audience
        self._ttl = ttl

    def issue(self, user_id: str, role: str) -> IssuedToken:
        now = utcnow()
        expires_at = now + self._ttl
        jti = new_id()
        claims = {
            "iss": self._issuer,
            "aud": self._audience,
            "sub": user_id,
            "jti": jti,
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "role": role,
        }
        token = jwt.encode(claims, self._private_key, algorithm=ALGORITHM, headers={"kid": self._kid})
        return IssuedToken(token=token, jti=jti, expires_at=expires_at)

    def verify(self, token: str) -> TokenClaims:
        if not token or len(token) > MAX_TOKEN_LENGTH:
            raise InvalidToken("malformed")
        try:
            header = jwt.get_unverified_header(token)
            key = self._verification_keys.get(str(header.get("kid")))
            if key is None or header.get("alg") != ALGORITHM:
                raise InvalidToken("unknown key or algorithm")
            claims = jwt.decode(
                token,
                key=key,
                algorithms=[ALGORITHM],
                audience=self._audience,
                issuer=self._issuer,
                leeway=30,
                options={"require": ["iss", "aud", "sub", "jti", "iat", "exp", "role"]},
            )
        except jwt.PyJWTError as exc:
            raise InvalidToken(type(exc).__name__) from None
        sub, role, jti = claims.get("sub"), claims.get("role"), claims.get("jti")
        if not all(isinstance(v, str) and v for v in (sub, role, jti)):
            raise InvalidToken("claim types")
        return TokenClaims(user_id=sub, role=role, jti=jti)


def generate_signing_key_pem() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def public_key_pem(signing_key_pem: str) -> str:
    key = serialization.load_pem_private_key(signing_key_pem.encode(), password=None)
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
