
import argparse
from pathlib import Path

ALFABETO = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Calcular el multiplicador (coprimo de 26 mayor que el) en base a la clave
# La clave se limpia eliminando caracteres que no estén en A-Z y se convierte a mayúsculas
# Se comprueban tres condiciones para asegurar que el multiplicador sea adecuado:
# 1. Debe ser mayor que la longitud del alfabeto (si no lo es, se incrementa en la longitud del alfabeto)
# 2. Debe ser impar (si no lo es, se incrementa en 1)
# 3. No debe ser divisible por 13 (si lo es, se incrementa en 2)
def calcular_multiplicador(clave):
    clave = limpiar_mensaje(clave)
    if not clave:
        raise ValueError("la clave debe contener al menos una letra A-Z")

    multiplicador = sum(ALFABETO.index(letra) + 1 for letra in clave)
    if multiplicador <= len(ALFABETO):
        multiplicador += len(ALFABETO)
    if multiplicador % 2 == 0:
        multiplicador += 1
    if multiplicador % 13 == 0:
        multiplicador += 2

    return multiplicador

# Limpiar el mensaje eliminando caracteres que no estén en A-Z y convirtiendo a mayúsculas
def limpiar_mensaje(mensaje):
    mensaje = mensaje.upper()
    #cambiar Ñ por N
    mensaje = mensaje.replace("Ñ", "N")
    #eliminar caracteres que no estén en el alfabeto
    mensaje = "".join([letra for letra in mensaje if letra in ALFABETO])
    return mensaje

# Cifrar el mensaje usando el alfabeto cifrado generado a partir de la clave
def cifrar_mensaje(mensaje, clave):
    alfabeto_cifrado = generar_alfabeto_cifrado(clave)
    mensaje_limpio = limpiar_mensaje(mensaje)
    mensaje_cifrado = ""

    for letra in mensaje_limpio:
        posicion = ALFABETO.index(letra)
        mensaje_cifrado += alfabeto_cifrado[posicion]

    return mensaje_cifrado


# Descifrar el mensaje usando el alfabeto cifrado generado a partir de la clave
def descifrar_mensaje(mensaje, clave):
    alfabeto_cifrado = generar_alfabeto_cifrado(clave)
    mensaje_limpio = limpiar_mensaje(mensaje)
    mensaje_descifrado = ""

    for letra in mensaje_limpio:
        posicion = alfabeto_cifrado.index(letra)
        mensaje_descifrado += ALFABETO[posicion]

    return mensaje_descifrado

# Altera las posiciones del alfabeto según el multiplicador calculado a partir de la clave
# siguiendo la formula: posicion_cifrada = (posicion_original * multiplicador) % longitud_alfabeto
def generar_alfabeto_cifrado(clave):
    multiplicador = calcular_multiplicador(clave)
    alfabeto_cifrado = ""

    for posicion in range(len(ALFABETO)):
        posicion_cifrada = ((posicion + 1) * multiplicador) % len(ALFABETO)
        alfabeto_cifrado += ALFABETO[posicion_cifrada]

    return alfabeto_cifrado

# Parseo de argumentos y ejecución del programa (escritura asistida por IA)
def main():
    parser = argparse.ArgumentParser(
        description=(
            "Cifra o descifra texto con una sustitucion monoalfabetica fija.\n"
            "El programa convierte el texto a mayusculas, cambia Ñ por N y "
            "elimina espacios, tildes y otros caracteres que no sean A-Z."
        ),
        epilog=(
            "Instrucciones:\n"
            "  1. Elige el modo: cifrar o descifrar.\n"
            "  2. Indica texto con -t o la ruta de un archivo .txt con -a.\n"
            "  3. Al usar un archivo, el resultado se guarda junto al original.\n"
            "     Ejemplos:\n"
            "       python3 monoalfabeto.py -m cifrar -k CLAVE -t 'HOLA MUNDO'\n"
            "       python3 monoalfabeto.py -m cifrar -k CLAVE -a mensaje.txt\n"
            "       python3 monoalfabeto.py -m descifrar -k CLAVE -a mensaje_cifrado.txt"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-m",
        "--modo",
        choices=("cifrar", "descifrar"),
        required=True,
        help="operacion que se realizara",
    )
    parser.add_argument(
        "-k", "--clave", required=True, help="clave (letras) que genera el alfabeto"
    )
    origen = parser.add_mutually_exclusive_group(required=True)
    origen.add_argument("-t", "--texto", help="texto que se procesara")
    origen.add_argument(
        "-a", "--archivo", help="archivo .txt de entrada; crea un archivo de salida"
    )
    argumentos = parser.parse_args()

    funcion = cifrar_mensaje if argumentos.modo == "cifrar" else descifrar_mensaje
    try:
        calcular_multiplicador(argumentos.clave)
    except ValueError as error:
        parser.error(str(error))

    def procesar(texto):
        return funcion(texto, argumentos.clave)

    if argumentos.texto is not None:
        print(procesar(argumentos.texto))
        return

    archivo_entrada = Path(argumentos.archivo)
    if archivo_entrada.suffix.lower() != ".txt":
        parser.error("el archivo de entrada debe tener extension .txt")

    sufijo = "_cifrado" if argumentos.modo == "cifrar" else "_descifrado"
    archivo_salida = archivo_entrada.with_name(
        archivo_entrada.stem + sufijo + ".txt"
    )

    try:
        texto = archivo_entrada.read_text(encoding="utf-8")
        archivo_salida.write_text(procesar(texto), encoding="utf-8")
    except (OSError, UnicodeError) as error:
        parser.error(f"no se pudo procesar el archivo: {error}")

    print(f"Resultado guardado en: {archivo_salida}")


if __name__ == "__main__":
    main()



