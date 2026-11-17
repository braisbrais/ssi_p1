#!/usr/bin/env python3
"""CLI compatible with the requested subset of OpenSSL enc options."""

import argparse
import hashlib
import secrets
import sys
from pathlib import Path
from typing import Callable, Optional

from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

SALT_HEADER = b"Salted__"
SALT_LENGTH = 8
PBKDF2_ITERATIONS = 10_000

CipherFunction = Callable[[bytes, bytes, Optional[bytes], bool], bytes]


def derive_key_and_iv(
    password: bytes,
    salt: bytes,
    key_length: int,
    iv_length: int,
) -> tuple[bytes, bytes]:
    """Derive the key and IV as OpenSSL enc does with -pbkdf2."""
    if len(salt) != SALT_LENGTH:
        raise ValueError(f"El salt debe tener {SALT_LENGTH} bytes.")
    if key_length <= 0 or iv_length < 0:
        raise ValueError("Las longitudes de clave e IV no son válidas.")

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password,
        salt,
        PBKDF2_ITERATIONS,
        dklen=key_length + iv_length,
    )
    return derived[:key_length], derived[key_length:]


def aes_256_ecb(
    data: bytes, key: bytes, iv: Optional[bytes], decrypt: bool
) -> bytes:
    """Encripta o descifra datos usando AES-256-ECB con padding PKCS#7."""
    cipher = AES.new(key, AES.MODE_ECB)  # ECB no usa IV: solo se pasa la clave
    if decrypt:  # rama de descifrado
        padded = cipher.decrypt(data)  # descifra bloque a bloque (16 bytes)
        return unpad(padded, AES.block_size)  # quita el padding PKCS#7
    padded = pad(data, AES.block_size)  # rellena hasta múltiplo de 16 bytes
    return cipher.encrypt(padded)  # cifra cada bloque de forma independiente


def aes_256_cbc(
    data: bytes, key: bytes, iv: Optional[bytes], decrypt: bool
) -> bytes:
    """Encripta o descifra datos usando AES-256-CBC con padding PKCS#7."""
    # Comprueba que el IV tenga la longitud correcta, es decir el tamaño del bloque de AES (16 bytes)
    if iv is None or len(iv) != AES.block_size: 
        raise ValueError(f"IV debe tener {AES.block_size} bytes.")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    if decrypt:  # rama de descifrado
        padded = cipher.decrypt(data)
        return unpad(padded, AES.block_size)
    padded = pad(data, AES.block_size)
    return cipher.encrypt(padded)


def des_ecb(
    data: bytes, key: bytes, iv: Optional[bytes], decrypt: bool
) -> bytes:
    """Encripta o descifra datos usando DES-ECB con padding PKCS#7."""
    cipher = DES.new(key, DES.MODE_ECB)
    if decrypt:  # rama de descifrado
        padded = cipher.decrypt(data)
        return unpad(padded, DES.block_size)
    padded = pad(data, DES.block_size)
    return cipher.encrypt(padded)


def des_cbc(
    data: bytes, key: bytes, iv: Optional[bytes], decrypt: bool
) -> bytes:
    """Encripta o descifra datos usando DES-CBC con padding PKCS#7."""
    if iv is None or len(iv) != DES.block_size:
        raise ValueError(f"IV debe tener {DES.block_size} bytes.")
    cipher = DES.new(key, DES.MODE_CBC, iv)
    if decrypt:  # rama de descifrado
        padded = cipher.decrypt(data)
        return unpad(padded, DES.block_size)
    padded = pad(data, DES.block_size)
    return cipher.encrypt(padded)


ALGORITHMS: dict[str, tuple[CipherFunction, int, int]] = {
    "aes-256-ecb": (aes_256_ecb, 32, 0),
    "aes-256-cbc": (aes_256_cbc, 32, 16),
    "des-ecb": (des_ecb, 8, 0),
    "des-cbc": (des_cbc, 8, 8),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Cifra y descifra archivos con AES-256 y DES (modos ECB y CBC), "
            "simulando el comando OpenSSL enc."
        ),
        epilog=(
            "Con -pass se usa PBKDF2-HMAC-SHA256 (10000 iteraciones) y el "
            "formato de salt de OpenSSL. Ejemplo: -pass pass:secreto. "
            "La entrada y salida estándar se usan si se omiten -in y -out."
        ),
    )
    parser.add_argument("-in", dest="input_file", metavar="ARCHIVO")
    parser.add_argument("-out", dest="output_file", metavar="ARCHIVO")
    credentials = parser.add_mutually_exclusive_group()
    credentials.add_argument(
        "-k", dest="key_hex", metavar="CLAVE_HEX", help="clave en hexadecimal"
    )
    credentials.add_argument(
        "-pass",
        dest="password_source",
        metavar="pass:CONTRASEÑA",
        help="contraseña; formato compatible: pass:CONTRASEÑA",
    )
    parser.add_argument("-iv", dest="iv_hex", metavar="IV_HEX")
    parser.add_argument(
        "-d", dest="decrypt", action="store_true", help="descifrar"
    )

    algorithms = parser.add_mutually_exclusive_group(required=True)
    algorithms.add_argument(
        "-aes-256-ecb", dest="algorithm", action="store_const",
        const="aes-256-ecb", help="usar AES-256-ECB"
    )
    algorithms.add_argument(
        "-aes-256-cbc", dest="algorithm", action="store_const",
        const="aes-256-cbc", help="usar AES-256-CBC"
    )
    algorithms.add_argument(
        "-des-ecb", dest="algorithm", action="store_const",
        const="des-ecb", help="usar DES-ECB"
    )
    algorithms.add_argument(
        "-des-cbc", dest="algorithm", action="store_const",
        const="des-cbc", help="usar DES-CBC"
    )
    return parser


def read_input(filename: Optional[str]) -> bytes:
    if filename is None or filename == "-":  # sin -in (o "-"): se lee de la entrada estándar
        return sys.stdin.buffer.read()  # .buffer da acceso a bytes crudos, no a texto
    return Path(filename).read_bytes()  # lee el archivo completo como bytes (modo binario)


def write_output(filename: Optional[str], data: bytes) -> None:
    if filename is None or filename == "-":
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        return
    Path(filename).write_bytes(data)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    cipher_function, key_length, iv_length = ALGORITHMS[args.algorithm]

    if args.password_source is not None:
        scheme, separator, password_text = args.password_source.partition(":")
        if scheme != "pass" or not separator:
            parser.error("-pass debe tener el formato pass:CONTRASEÑA.")
        if args.iv_hex is not None:
            parser.error("No indiques -iv junto con -pass; el IV se deriva.")
        password = password_text.encode("utf-8")
    elif args.key_hex is not None:
        password = None
    else:
        parser.error("Debes indicar -k CLAVE_HEX o -pass pass:CONTRASEÑA.")

    if iv_length == 0 and args.iv_hex is not None:
        parser.error("-iv no se utiliza con los algoritmos ECB.")
    if password is None and iv_length > 0 and args.iv_hex is None:
        parser.error("-iv es obligatorio para CBC cuando se utiliza -k.")

    try:
        data = read_input(args.input_file)  # contenido íntegro del archivo en bytes

        if password is not None:  # con -pass el formato de OpenSSL lleva cabecera + salt
            if args.decrypt:  # al descifrar, el archivo trae la cabecera que hay que separar
                # comprueba que empieza por "Salted__" y que hay sitio para los 8 bytes de salt
                if not data.startswith(SALT_HEADER) or len(data) < len(SALT_HEADER) + SALT_LENGTH:
                    raise ValueError(
                        "La entrada no contiene la cabecera y el salt de OpenSSL."
                    )
                # bytes 8..16: el salt que se generó al cifrar (necesario para rederivar clave e IV)
                salt = data[len(SALT_HEADER):len(SALT_HEADER) + SALT_LENGTH]
                # desde el byte 16: solo el texto cifrado; esto es lo que recibe la función de descifrado
                data = data[len(SALT_HEADER) + SALT_LENGTH:]
            else:  # al cifrar, data se queda tal cual (el texto plano) y se genera un salt nuevo
                salt = secrets.token_bytes(SALT_LENGTH)  # 8 bytes aleatorios criptográficamente seguros

            key, iv = derive_key_and_iv(
                password, salt, key_length, iv_length
            )
        else:
            try:
                key = bytes.fromhex(args.key_hex)
                iv = bytes.fromhex(args.iv_hex) if args.iv_hex else b""
            except ValueError as error:
                raise ValueError("La clave y el IV deben estar en hexadecimal.") from error

            if len(key) != key_length:
                raise ValueError(
                    f"{args.algorithm} requiere una clave de {key_length} bytes."
                )
            if len(iv) != iv_length:
                raise ValueError(f"El IV debe tener {iv_length} bytes.")

        result = cipher_function(data, key, iv or None, args.decrypt)
        # Al cifrar con -pass, añade la cabecera y el salt al resultado
        if password is not None and not args.decrypt: 
            result = SALT_HEADER + salt + result
        write_output(args.output_file, result)
    except NotImplementedError:
        print(
            f"El algoritmo {args.algorithm} todavía no está implementado.",
            file=sys.stderr,
        )
        return 2
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
