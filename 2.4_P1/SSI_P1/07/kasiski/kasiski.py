import sys, os

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LONG_MIN = 3
LONG_MAX = 7
AEOS = "EAOS"

def info():

    print("""
    Uso: kasiski.py -i ENTRADA -o SALIDA

    Criptoanaliza un archivo cifrado con Vigenère usando el método de Kasiski
    para obtener la longitud de la clave y la técnica AEOS para obtener cada
    una de sus letras.

    Opciones:
    -i ENTRADA    Ruta del archivo cifrado
    -o SALIDA     Ruta del archivo donde se guarda el texto descifrado
    --help        Muestra este mensaje y termina

    Ejemplos:
    python kasiski.py -i archivo_cifrado.txt -o archivo_descifrado.txt
    """)
    sys.exit(0)

def validate_args(args):

    if len(args) == 1:
        if args[0] != "--help":
            print("Error: Opción inválida")
            return 1
        return 1
    if len(args) != 4:
        print("Error: Numero de argumentos inválido")
        return 1
    if args[0] != "-i":
        print("Error: Opción inválida")
        return 1
    if not os.path.isfile(args[1]):
        print("Error: El archivo no existe")
        return 1
    if args[2] != "-o":
        print("Error: Opción inválida")
        return 1

    return 0

def validate_alpha(texto):
    for c in texto:
        if c not in ALPHA:
            print("El texto incluye caracteres no válidos (", c, ")")
            sys.exit(1)

def find_distances(texto):
    distancias = []
    vistas = []

    for i in range(len(texto) - LONG_MIN + 1):
        secuencia = texto[i:i+LONG_MIN]
        if secuencia in vistas:
            continue
        vistas.append(secuencia)

        posiciones = []
        for j in range(len(texto) - LONG_MIN + 1):
            if texto[j:j+LONG_MIN] == secuencia:
                posiciones.append(j)

        for a in range(len(posiciones)):
            for b in range(a + 1, len(posiciones)):
                distancias.append(posiciones[b] - posiciones[a])

    return distancias

def key_length_candidates(distancias): #Ayuda de IA
    # Modelo: Claude Sonnet 5.5
    # Prompt: "tengo una lista de distancias de Kasiski, hazme una funcion en python que para cada
    # longitud de clave de 2 a LONG_MAX cuente cuantas distancias son multiplos y las ordene de mas a menos
    candidatos = []

    for longitud in range(2, LONG_MAX + 1):
        cuenta = 0
        for d in distancias:
            if d % longitud == 0:
                cuenta += 1
        candidatos.append((cuenta, longitud))

    # Más divisibles primero; a igualdad, la longitud más corta, así si es divisible entre 5 y 10 se le da preferencia a 5
    candidatos.sort(key=lambda c: (-c[0], c[1]))

    return candidatos

def subcryptograms(texto, longitud):
    subs = []

    for i in range(longitud):
        sub = ""
        for j in range(i, len(texto), longitud):
            sub += texto[j]
        subs.append(sub)

    return subs

def frequencies(texto):
    frec = {}

    for c in ALPHA:
        frec[c] = texto.count(c)

    return frec

def aeos(sub):
    frec = frequencies(sub)
    umbral = len(sub) / 26 

    # Letras del cifrado ordenadas de más a menos frecuente (ayuda de IA)
    # Modelo: Claude Sonnet 5.5
    # Prompt: "En Python, dado un diccionario frec con la frecuencia de cada letra de ALPHA, ¿cómo
    # obtengo una lista de las letras ordenadas de más a menos frecuente?"
    orden = sorted(ALPHA, key=lambda c: -frec[c])

    for letrac in orden[:3]:
        mejor = -1
        mejor_puntos = 0

        for supuesta in AEOS:
            desp = (ALPHA.index(letrac) - ALPHA.index(supuesta)) % 26

            puntos = 0
            cumple = True
            for otra in AEOS:
                if otra == supuesta:
                    continue
                letra_otra = ALPHA[(ALPHA.index(otra) + desp) % 26]
                if frec[letra_otra] < umbral:
                    cumple = False
                    break
                puntos += frec[letra_otra]

            if cumple and puntos > mejor_puntos:
                mejor = desp
                mejor_puntos = puntos

        if mejor != -1:
            return mejor

    return -1

def find_key(texto, longitud):
    clave = ""

    for sub in subcryptograms(texto, longitud):
        desp = aeos(sub)
        if desp == -1:
            return ""
        clave += ALPHA[desp]

    return clave

def score_aeos(texto):
    puntos = 0

    for c in AEOS:
        puntos += texto.count(c)

    return puntos

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

    with open(args[1], "r", encoding="utf-8") as f:
        texto = f.read().strip()

    validate_alpha(texto)

    clave = ""

    distancias = find_distances(texto)
    print("Secuencias repetidas encontradas:", len(distancias), "distancias")
    candidatos = key_length_candidates(distancias)

    print("Longitudes candidatas:")
    for cuenta, longitud in candidatos[:5]:
        print("  longitud", longitud, "->", cuenta, "distancias")

    mejor_puntos = 0
    for cuenta, longitud in candidatos:
        if cuenta == 0:
            break
        prueba = find_key(texto, longitud)
        if prueba == "":
            print("Longitud", longitud, "-> no cumple AEOS")
            continue
        puntos = score_aeos(decode_vigenere(texto, prueba))
        print("Longitud", longitud, "-> cumple AEOS. Clave:", prueba, "- Puntuación:", puntos)
        if puntos > mejor_puntos:
            mejor_puntos = puntos
            clave = prueba

    if clave == "":
        print("Error: No se ha podido obtener la clave con la técnica AEOS")
        sys.exit(1)

    print("Longitud de la clave:", len(clave))
    print("Clave:", clave)

    output = decode_vigenere(texto, clave)

    with open(args[3], "w", encoding="utf-8") as f:
        f.write(output)

if __name__ == "__main__":
    main()
