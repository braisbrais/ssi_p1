import sys, os

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def info():

    print("""
    Uso: vigenere.py (-c | -d) -k CLAVE -i ENTRADA -o SALIDA

    Cifra o descifra un archivo de texto usando el algoritmo de Vigenère.

    Opciones:
    -c            Cifrar el archivo de entrada
    -d            Descifrar el archivo de entrada
    -k CLAVE      Clave a usar (máximo 7 caracteres)
    -i ENTRADA    Ruta del archivo de entrada
    -o SALIDA     Ruta del archivo de salida
    --help        Muestra este mensaje y termina

    Ejemplos:
    python vigenere.py -c -k CLAVE -i GN_fragmento3.txt -o GN_fragmento3_cif.txt
    python vigenere.py -d -k CLAVE -i GN_fragmento3_cif.txt -o GN_fragmento3_dec.txt
    """)
    sys.exit(0)

def validate_args(args):

    if len(args) == 1:
        if args[0] != "--help":
            print("Error: Opción inválida")
            return 1
        return 1
    if len(args) != 7 :
        print("Error: Numero de argumentos inválido")
        return 1
    if args[0] != "-c" and args[0] != "-d":
        print("Error: Opción inválida")
        return 1    
    if args[1] != "-k": 
        print("Error: Opción inválida")
        return 1
    if len(args[2]) > 7:
        print("Error: La clave es demasiado larga (máximo 7 caracteres)")
        return 1
    if args[3] != "-i": 
        print("Error: Opción inválida")
        return 1
    if not os.path.isfile(args[4]):
        print("Error: El archivo no existe")
        return 1
    if args[5] != "-o": 
        print("Error: Opción inválida") 
        return 1

    return 0

def validate_alpha(texto):
    for c in texto:
        if c not in ALPHA:
            print("El texto incluye caracteres no válidos (", c, ")")
            sys.exit(1)

def code_vigenere(texto, clave):

    resultado = ""

    for i in range(len(texto)):
        letrak = clave[i%len(clave)]
        posk = ALPHA.index(letrak)
        for letrat in texto:
            post = ALPHA.index(letrat)
            texto = texto[1:]
            resultado += ALPHA[(posk + post)%26]
            break
        
    return resultado

def decode_vigenere(texto, clave):

    resultado = ""

    for i in range(len(texto)):
        letrak = clave[i%len(clave)]
        posk = ALPHA.index(letrak)
        for letrat in texto:
            post = ALPHA.index(letrat)
            texto = texto[1:]
            resultado += ALPHA[(post - posk)%26]
            break
        
    return resultado

def main():
    args = sys.argv[1:]

    if validate_args(args):
        info()

    with open(args[4], "r", encoding="utf-8") as f:
        texto = f.read().strip()

    validate_alpha(texto)

    if args[0] == "-c":
        output = code_vigenere(texto, args[2])
    else:
        output = decode_vigenere(texto, args[2])

    with open(args[6], "w", encoding="utf-8") as f:
        f.write(output)

if __name__ == "__main__":
    main()
