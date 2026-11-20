import sys, os

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"  # alfabeto válido
LONG_MIN = 3  # tamaño de los grupos repetidos que buscamos
LONG_MAX = 7  # longitud máxima de clave que probamos
AEOS = "EAOS"  # letras más frecuentes del español

# Muestra la ayuda y termina
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

# Comprueba los argumentos. Devuelve 1 si hay que mostrar la ayuda, 0 si todo está bien
def validate_args(args):

    if len(args) == 1:  # un solo argumento: solo vale --help
        if args[0] != "--help":
            print("Error: Opción inválida")
            return 1
        return 1
    if len(args) != 4:  # deben ser: -i ENTRADA -o SALIDA
        print("Error: Numero de argumentos inválido")
        return 1
    if args[0] != "-i":
        print("Error: Opción inválida")
        return 1
    if not os.path.isfile(args[1]):  # el archivo de entrada tiene que existir
        print("Error: El archivo no existe")
        return 1
    if args[2] != "-o":
        print("Error: Opción inválida")
        return 1

    return 0

# Comprueba que el texto solo tenga letras A-Z; si no, termina
def validate_alpha(texto):
    for c in texto:
        if c not in ALPHA:
            print("El texto incluye caracteres no válidos (", c, ")")
            sys.exit(1)

# Paso 1 de Kasiski: busca grupos de 3 letras repetidos y calcula las distancias entre ellos
def find_distances(texto):
    distancias = []
    vistas = []  # grupos ya estudiados, para no repetirlos

    for i in range(len(texto) - LONG_MIN + 1):
        secuencia = texto[i:i+LONG_MIN]  # coge 3 letras desde la posición i
        if secuencia in vistas:
            continue
        vistas.append(secuencia)

        posiciones = []  # todas las posiciones donde aparece este grupo
        for j in range(len(texto) - LONG_MIN + 1):
            if texto[j:j+LONG_MIN] == secuencia:
                posiciones.append(j)

        for a in range(len(posiciones)):  # distancia entre cada par de apariciones
            for b in range(a + 1, len(posiciones)):
                distancias.append(posiciones[b] - posiciones[a])

    return distancias

# Paso 2 de Kasiski: para cada longitud posible cuenta cuántas distancias son múltiplos suyos
def key_length_candidates(distancias): #Ayuda de IA
    # Modelo: Claude Sonnet 5.5
    # Prompt: "tengo una lista de distancias de Kasiski, hazme una funcion en python que para cada
    # longitud de clave de 2 a LONG_MAX cuente cuantas distancias son multiplos y las ordene de mas a menos
    candidatos = []

    for longitud in range(2, LONG_MAX + 1):  # prueba longitudes de 2 a 7
        cuenta = 0
        for d in distancias:
            if d % longitud == 0:  # resto 0 = la distancia es múltiplo
                cuenta += 1
        candidatos.append((cuenta, longitud))  # guarda (cuántas, longitud)

    # Más divisibles primero; a igualdad, la longitud más corta, así si es divisible entre 5 y 10 se le da preferencia a 5
    candidatos.sort(key=lambda c: (-c[0], c[1]))

    return candidatos

# Parte el texto en tantos grupos como letras tiene la clave (cada grupo es un César)
def subcryptograms(texto, longitud):
    subs = []

    for i in range(longitud):
        sub = ""
        for j in range(i, len(texto), longitud):  # posiciones i, i+longitud, i+2*longitud...
            sub += texto[j]
        subs.append(sub)

    return subs

# Cuenta cuántas veces aparece cada letra en el texto
def frequencies(texto):
    frec = {}

    for c in ALPHA:
        frec[c] = texto.count(c)

    return frec

# Técnica AEOS: obtiene el desplazamiento (letra de la clave) de un grupo
def aeos(sub):
    frec = frequencies(sub)
    umbral = len(sub) / 26  # frecuencia media de una letra

    # Letras del cifrado ordenadas de más a menos frecuente (ayuda de IA)
    # Modelo: Claude Sonnet 5.5
    # Prompt: "En Python, dado un diccionario frec con la frecuencia de cada letra de ALPHA, ¿cómo
    # obtengo una lista de las letras ordenadas de más a menos frecuente?"
    orden = sorted(ALPHA, key=lambda c: -frec[c])

    for letrac in orden[:3]:  # probamos con las 3 letras más frecuentes
        mejor = -1
        mejor_puntos = 0

        for supuesta in AEOS:  # suponemos que letrac es la E, la A, la O o la S
            desp = (ALPHA.index(letrac) - ALPHA.index(supuesta)) % 26  # desplazamiento que implica

            puntos = 0
            cumple = True
            for otra in AEOS:  # comprobamos las otras tres letras de AEOS
                if otra == supuesta:
                    continue
                letra_otra = ALPHA[(ALPHA.index(otra) + desp) % 26]  # dónde debería estar cifrada
                if frec[letra_otra] < umbral:  # aparece poco: la hipótesis no vale
                    cumple = False
                    break
                puntos += frec[letra_otra]

            if cumple and puntos > mejor_puntos:  # nos quedamos con la mejor hipótesis válida
                mejor = desp
                mejor_puntos = puntos

        if mejor != -1:  # si alguna hipótesis vale, ese es el desplazamiento
            return mejor

    return -1  # ninguna hipótesis funcionó

# Saca la clave completa para una longitud: aplica AEOS a cada grupo
def find_key(texto, longitud):
    clave = ""

    for sub in subcryptograms(texto, longitud):
        desp = aeos(sub)
        if desp == -1:  # si un grupo falla, esta longitud no sirve
            return ""
        clave += ALPHA[desp]  # el desplazamiento se convierte en letra

    return clave

# Puntúa un texto contando sus A, E, O y S (más = más parecido al español)
def score_aeos(texto):
    puntos = 0

    for c in AEOS:
        puntos += texto.count(c)

    return puntos

# Descifra Vigenère: resta a cada letra la letra de la clave que le toca
def decode_vigenere(texto, clave):

    resultado = ""

    for i in range(len(texto)):
        letrak = clave[i%len(clave)]  # letra de la clave (se repite)
        posk = ALPHA.index(letrak)  # número de la letra de la clave
        for letrat in texto:  # coge la primera letra que queda del texto
            post = ALPHA.index(letrat)  # número de la letra del texto
            texto = texto[1:]  # la quita para la siguiente vuelta
            resultado += ALPHA[(post - posk)%26]  # resta y vuelve a letra
            break

    return resultado

def main():
    args = sys.argv[1:]

    if validate_args(args):  # argumentos incorrectos o --help: muestra la ayuda
        info()

    with open(args[1], "r", encoding="utf-8") as f:  # lee el texto cifrado
        texto = f.read().strip()

    validate_alpha(texto)

    clave = ""

    distancias = find_distances(texto)  # Kasiski: distancias entre repeticiones
    print("Secuencias repetidas encontradas:", len(distancias), "distancias")
    candidatos = key_length_candidates(distancias)  # longitudes ordenadas de mejor a peor

    print("Longitudes candidatas:")
    for cuenta, longitud in candidatos[:5]:
        print("  longitud", longitud, "->", cuenta, "distancias")

    mejor_puntos = 0
    for cuenta, longitud in candidatos:  # prueba cada longitud candidata
        if cuenta == 0:
            break
        prueba = find_key(texto, longitud)  # intenta sacar la clave con AEOS
        if prueba == "":
            print("Longitud", longitud, "-> no cumple AEOS")
            continue
        puntos = score_aeos(decode_vigenere(texto, prueba))  # descifra y puntúa
        print("Longitud", longitud, "-> cumple AEOS. Clave:", prueba, "- Puntuación:", puntos)
        if puntos > mejor_puntos:  # se queda con la clave de más puntuación
            mejor_puntos = puntos
            clave = prueba

    if clave == "":
        print("Error: No se ha podido obtener la clave con la técnica AEOS")
        sys.exit(1)

    print("Longitud de la clave:", len(clave))
    print("Clave:", clave)

    output = decode_vigenere(texto, clave)  # descifra con la mejor clave

    with open(args[3], "w", encoding="utf-8") as f:  # guarda el texto descifrado
        f.write(output)

if __name__ == "__main__":
    main()
