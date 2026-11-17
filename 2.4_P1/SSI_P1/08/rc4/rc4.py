#!/usr/bin/env python3
import sys

try:                      # Windows
    import msvcrt
except ImportError:       # Linux / macOS
    msvcrt = None
    import tty, termios

try:                      # evita errores con "→" en consolas que no usan UTF-8
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

AYUDA = ("Uso del programa:\n"
         "\tCifrar:    python3 rc4.py -c <clave_hex>\n"
         "\tDescifrar: python3 rc4.py -d <clave_hex> <texto_cifrado_hex>\n"
         "\tAyuda:     python3 rc4.py --help\n\n"
         "Notas:\n"
         "\t- La clave y el texto cifrado se indican en hexadecimal (p. ej. 4b6579).\n"
         "\t- Al cifrar, cada carácter se cifra en cuanto se pulsa la tecla;\n"
         "\t  pulsa Enter para finalizar.")


def error(mensaje):
    print(f"Error: {mensaje}\n", file=sys.stderr)
    print(AYUDA, file=sys.stderr)
    sys.exit(1)


def hex_a_bytes(texto, nombre):
    """Convierte una cadena hexadecimal en una lista de enteros (bytes)."""
    try:
        return list(bytes.fromhex(texto))
    except ValueError:
        error(f"{nombre} debe estar en hexadecimal válido (nº par de dígitos, 0-9 a-f).")


def leer_tecla():
    """Lee un solo carácter sin necesidad de presionar Enter."""
    if msvcrt:            # Windows
        while True:
            ch = msvcrt.getwch()
            if ch in ('\x00', '\xe0'):   # tecla especial (flechas, F1...): ignorar
                msvcrt.getwch()
                continue
            break
    else:                 # Linux / macOS (modo raw)
        fd = sys.stdin.fileno()
        estado_anterior = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, estado_anterior)
    if ch == '\x03':      # Ctrl+C: en modo raw no genera la señal por sí solo
        raise KeyboardInterrupt
    return ch


def ksa(clave):
    S = list(range(256))
    print(f"→ Estado inicial de S:\n{S}")
    j = 0
    largo_clave = len(clave)
    for i in range(256):
        j = (j + S[i] + clave[i % largo_clave]) % 256
        S[i], S[j] = S[j], S[i]
    print(f"→ Estado de S tras aplicar KSA:\n{S}")
    return S


def prga(S, mostrar=False):
    i = j = 0
    n = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        n += 1
        if mostrar:
            print(f"\n→ Estado de S tras generar el byte {n} del keystream "
                  f"(i={i}, j={j}):\n{S}")
        k = S[(S[i] + S[j]) % 256]
        yield k


def cifrar(caracter, keystream):
    valor_ascii = ord(caracter)
    k = next(keystream)
    cifrado = valor_ascii ^ k
    print(f"\nCarácter: '{caracter}' → ASCII: {valor_ascii} ({valor_ascii:08b})")
    print(f"Keystream: {k} ({k:08b})")
    print(f"Resultado: binario={cifrado:08b}, hexadecimal={cifrado:02x}")
    return cifrado


def descifrar(texto_cifrado, keystream):
    texto_plano = ''
    for byte in texto_cifrado:
        texto_plano += chr(byte ^ next(keystream))
    return texto_plano


def main():
    args = sys.argv[1:]
    if not args or args[0] in ('--help', '-h'):
        print(AYUDA)
        sys.exit(0)

    modo = args[0]
    if modo == '-c' and len(args) == 2:
        pass
    elif modo == '-d' and len(args) == 3:
        pass
    elif modo in ('-c', '-d'):
        error("número de argumentos incorrecto.")
    else:
        error("opción no válida.")

    clave_bytes = hex_a_bytes(args[1], "La clave")
    if not clave_bytes:
        error("la clave no puede estar vacía.")
    if len(clave_bytes) > 256:
        error("la clave no puede superar los 256 bytes.")

    if modo == '-c':
        S = ksa(clave_bytes)
        flujo_clave = prga(S, mostrar=True)
        print("\nIntroduce el texto a cifrar (pulsa Enter para finalizar):")
        texto_cifrado = []
        try:
            while True:
                tecla = leer_tecla()
                if tecla in ('\r', '\n'):
                    break
                if ord(tecla) > 127:
                    print(f"Carácter '{tecla}' fuera de ASCII, ignorado.")
                    continue
                print(f"Tecla: {tecla}")
                texto_cifrado.append(cifrar(tecla, flujo_clave))
                parcial_hex = ''.join(f"{b:02x}" for b in texto_cifrado)
                print(f"Texto cifrado parcial: {parcial_hex}")
        except KeyboardInterrupt:
            print("\nInterrumpido.")
            sys.exit(130)

        print(f"\nTexto cifrado final (hex): {''.join(f'{b:02x}' for b in texto_cifrado)}")

    else:  # -d
        texto_cifrado_bytes = hex_a_bytes(args[2], "El texto cifrado")
        S = ksa(clave_bytes)
        flujo_clave = prga(S, mostrar=False)
        texto_plano = descifrar(texto_cifrado_bytes, flujo_clave)
        print(f"\nTexto descifrado (ASCII): {texto_plano}")


if __name__ == '__main__':
    main()
