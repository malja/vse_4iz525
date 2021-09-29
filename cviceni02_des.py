# Tento kód je implementací šifry DES podle popisu na stránce 
# http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
# Snažil jsem se doplnit ke všemu potřebné komentáře a kód udržet pokud možno co nejpřehlednější. Vše by určitě šlo
# řešit rychleji a nástroji k tomu určenými. Myslím si ale, že z tohoto kódu je vidět, co se jak dělá lépe, než kdybych
# použil nějakou knihovnu...
# Při běžném použití (má-li DES ještě nějaké) by samozřejmě bylo třeba celý skript přepsat, nebo ideálně použít již
# existující implementace a nevymýšlet kolo.
# https://crypto.stackexchange.com/questions/59190/des-how-does-richard-outerbridges-initial-permutation-operate/59212#59212

import argparse

# Přehled:
# ########
#
# Šifrování pomocí DES jde rozdělit na dvě části:
#
# 1. Vytvoření šestnácti 56-bitových klíčů ze základního 64-bitového klíče.
# 2. Šifrování bloku o 64 bitech pomocí výše popsaných klíčů.
#
# Podle způsobu, jakým se postupuje při šifrování se rozlišují následující módy:
#
# 1. ECB - Electronic Code Book - Každý 64-bitový blok vstupu je zašifrován samostatně, bez závislosti na ostatních 
# datech
# 2. CBC - Chain Block Coding - Každý 64-bitový blok je před zašifrováním XORnutý s výstupem DES šifry pro předchozí
# blok. 
# 3. CFB - Cipher Feedback Block
#
# Dále existují další "okořenění", jako například Triple-DES, kdy jsou použity dva šifrovací klíče. Nejdřív se 
# vstupní text zašifruje jedním klíčem a poté se tento zašifrovaný text zašifruje druhým klíčem. Bohužel ale nemá
# ani toto opatření na "bezpečnost" DES valný vliv.
#
# Permutační tabulky
# ##################
#
# Seznam tabulek včetně obsahu a popisu použití je možné najít na Wiki:
# https://en.wikipedia.org/wiki/DES_supplementary_material
#
# Jinak za tím asi nemá cenu hledat nic složitého, prostě je nějak vybrali při definici algoritmu.
#
# Spuštění:
# #########
# python vypocet_des.py --input 0000000110100011010001010110011110001001101010111100110111101111 --key 0001001100110100010101110111100110011011101111001101111111110001

#######################################################################################################################
## Následují funkce využité při generování pomocných klíčů.

def rotate_left(value, rotate_by):
    """
    Provede rotaci znaků předaného řetězce o 'rotate_by' znaků doleva. Znaky, které by měly přetéct a zmizet jsou
    přidány na konec řetězce.
    
    V podstatě jde o obdobu binární rotace, nicméně protože pro jednoduchost pracuji pouze s řetězci, bylo třeba
    tuto funkci definovat.

    :param value: Vstupní řetězec, reprezentující binární hodnotu, která se má rotovat doleva.
    :param rotate_by: Počet znaků, o které se má rotovat doleva.
    """
    # Vstupní řetězec se rozdělí na dvě části, podle místa řezu
    left = value[:rotate_by] 
    right = value[rotate_by:] 
    
    return right + left

def generate_keys(base_key):
    """
    Vytvoří šestnáct 56-bitových klíčů ze zadaného šifrovacího klíče o délce 64 bitů.

    :param base_key: 64-bitový klíč použitý k šifrování.
    """

    # Vstupní klíč je upraven tak, aby obsahoval pouze 56 bitů - některé bity budou zopakovány.
    permutation_table = [
        57,   49,    41,   33,    25,    17,    9,
        1,   58,    50,   42,    34,    26,   18,
        10,    2,    59,   51,    43,    35,   27,
        19,   11,     3,   60,    52,    44,   36,
        63,   55,    47,   39,    31,    23,   15,
        7,   62,    54,   46,    38,    30,   22,
        14,    6,    61,   53,    45,    37,   29,
        21,   13,     5,   28,    20,    12,    4,
    ]

    # Upravený vstupní klíč
    permuted_key = permutate(base_key, permutation_table)

    # Výsledný permutovaný klíč se rozdělí na dva stejně dlouhé bloky - levý a pravý. Každý o 28 bitech
    left_part =     [ permuted_key[:28] ]
    right_part =    [ permuted_key[28:] ]

    # Provede se 16 iterací, při každé se provede výpočet nové levé a pravé strany.
    # Levá/potažmo pravá strana se vypočítá jako bitová rotace o N pozic, kde N je buď 1 nebo 2. To záleží na dané
    # iteraci. N=1 pro iteraci 1, 2, 9 a 16. Ostatní iterace mají N = 2.
    rotate_by = 1
    for i in range(1,17):
        # Poznámka: Horní index 17 je zde kvůli tomu, že první vygenerovaná levá/pravá část má být uložena na index 1,
        # nikoliv 0, protože tam už je levá a pravá strana ze vstupního šifrovacího klíče
        if i in (1, 2, 9, 16):
            rotate_by = 1
        else:
            rotate_by = 2
        
        # Přidá novou levou část, která vznikla rotací o 'rotate_by' doleva
        left_part.append( rotate_left(left_part[i-1], rotate_by) )

        # Přidá novou pravou část, která vznikne rotací o 'rotate_by' doleva
        right_part.append( rotate_left(right_part[i-1], rotate_by) )

    # Seznam všech 17 klíčů - na indexu 0 je uložen vstupní klíč, na indexech 1 až 16 pak klíče vygenerované
    final_keys = [ base_key ]

    # Výsledné klíče mají mít pouze 48 bitů. Proto se opět provede permutace, která některé bity se nepoužije.
    key_permutation_table = [
        14,    17,   11,    24,     1,    5,
        3,    28,   15,     6,    21,   10,
        23,    19,   12,     4,    26,    8,
        16,     7,   27,    20,    13,    2,
        41,    52,   31,    37,    47,   55,
        30,    40,   51,    45,    33,   48,
        44,    49,   39,    56,    34,   53,
        46,    42,   50,    36,    29,   32,
    ]

    for i in range(1, 17):
        # Sloučí levou a pravou část 
        concated = left_part[i] + right_part[i]

        # Provede nad sloučeninou levé a pravé části výše popsanou permutaci, kterou vznikne klíč, ten si uložíme
        final_keys.append( permutate(concated, key_permutation_table) )

    # Všechny klíče budou vráceny
    return final_keys

#######################################################################################################################
## Odsud dál už probíhá šifrování dané zprávy s vygenerovanými klíči.

def xor(left, right):
    """
    Provede binární XOR. Opět, protože pracuji s řetězci, nejde jednoduše použít pouze operátor ^. Nicméně výsledek
    operace je naprosto stejný. Projde oba řetězce znak po znaku a provede nad nimi binární xor.
    
    :param left: Jeden ze vstupních parametrů pro xor. Musí být řetězec reprezentující binární číslo.
    :param right: Jeden ze vstupních parametrů pro xor. Musí být řetězec reprezentující binární číslo.
    """
    xor_output = ""

    # Projde znak po znaku předaný řetězec. Zde by se hodilo kontrolovat, zda len(left) == len(right), protože jde o
    # požadavek úspěšného dokončení této operace.
    for i in range(0, len(left)):
        # Převede znak na dané pozici na číslo a provede číselnou xor operaci mezi nimi. Tím jsem se vyhnul vytváření
        # podmínek pro XOR operaci nad řetězci.
        xor_output += str(int(left[i],2) ^ int(right[i],2))

    return xor_output

def permutate(value, table):
    """
    Provede nad vstupními daty permutaci danou tabulkou. Permutace v tomto kontextu znamená, že se hodnota n-tého znaku
    ve vstupních datech nahradí table[n]-tou hodnotou. Někdy nemusí být využity všechny znaky/bity vstupu. V takovém
    případě má výstup menší délku (méně bitů) než vstup.

    :param value: Vstupní řetězec reprezentující binární číslo.
    :param table: Tabulka permutací zadaná jako pole čísel. Číslo na daném indexu znamená, na jakém indexu vstupní
    hodnoty se nachází nová hodnota.
    """
    permutation = ""

    for i in range(0, len(table)):
        permutation += value[table[i]-1]

    return permutation

def expand(data):
    """
    Provede rozšíření z 32 bitů předané pravé strany na 48 bitů, které se dále využijí v f-funkci. Šlo by použít funci
    permutate, nicméně jsem chtěl odlišit, že dochází k rozšíření.

    :param data: Vstupní pravá strana, tedy řetězec o 32 znacích reprezentující binární číslo.
    """

    # Stejně  jako permutační tabulky. I zde dochází k nahrazení bitů podle této tabulky. Například první bit výstupu
    # se vezme z 32. bitu vstupu. Druhý bit výstupu je 1. bit vstupu apod.
    expansion_table = [
        32,1,2,3,4,5,
        4,5,6,     7,     8,    9,
        8,9,10,    11,    12,   13,
        12,13,14,    15,    16,   17,
        16,17,18,    19,    20,   21,
        20,21,22,    23,    24,   25,
        24,25,26,    27,    28,   29,
        28,29,30,    31,    32,    1
    ]

    expanded_output = ""

    for i in range(0, len(expansion_table)):
        expanded_output += data[expansion_table[i]-1]

    return expanded_output

def s_boxes(value):
    """
    Provede nahrazení každých 6 bitů vstupní hodnoty za 4 bity výstupu dle tzv. S-boxů. Vstupní hodnota má 48 bitů,
    tedy 8 šestic. Nahrazení probíhá tak, že se vezme první a poslední bit z šestice. Ty se sloučí a vznikne binární
    číslo v rozsahu 00 až 11 (resp. 0 až 3). To udává číslo řádku v rámci S-boxu. Zbylé čtyři bity z šestice se
    použijí jako číslo sloupce (buňky v poli) v S-boxu.
    Pro každou šestici ve vstupních datech je jeden S-box.

    :param value: 48 bitová hodnota, která se má převést pomocí s-boxů na 32 bitů.
    """
    boxes = [
        # Sbox 1
        [
            [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
            [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
            [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
            [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13],
        ],
        # Sbox 2
        [
            [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
            [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
            [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
            [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9],
        ],
        # Sbox 3
        [
            [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
            [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
            [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
            [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12],
        ],
        # Sbox 4
        [
            [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
            [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
            [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
            [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14],
        ],
        # Sbox 5
        [
            [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
            [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
            [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
            [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3],
        ],
        # Sbox 6
        [
            [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
            [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
            [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
            [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13],
        ],
        # Sbox 7
        [
            [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
            [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
            [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
            [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12],
        ],
        # Sbox 8
        [
            [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
            [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
            [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
            [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11],
        ]
    ]

    output = ""
    for i in range(0, 8):
        # Získá z předaných 48 bitů postupně šestice bitů
        sixbits = value[(i)*6:(i+1)*6]

        # Číslo řádku je dáno prvním a posledním bitem šestice, které se sloučí do dvojice
        row = int(sixbits[0] + sixbits[5], 2)
        # Sloupec je dán zbylými 4 bity v šestici
        column = int(sixbits[1:5],2)

        # Získá výstup pro tuto šestici transformací pomocí S-boxů
        # Poznámka: 04b znamená, že chci číslo formátovat jako binární číslo, které bude zleva doplněno nulami na
        # celkem 4 bity
        output += f"{boxes[i][row][column]:04b}"

    return output

def f_function(right_n, key_nplus1):
    """
    Omlouvám se za poněkud debilní název. Bohužel mě nic lepšího při psaní (už je pozdě) nenapadlo. Tato funkce provádí
    transformaci v rámci jedné iterace šifrování.

    :param right_n: Řetězec s binární reprezentací 32 bitů pravé strany na indexu N.
    :param key_nplus1: Řetězec s binární reprezentací 48 bitů klíče s indexem N+1.
    """

    # Rozšíří předanou pravou stranu z 32 na 48 bitů
    right_n_expanded = expand(right_n)

    # Provede XOR mezi pravou stranou a klíčem
    xored = xor(right_n_expanded, key_nplus1)

    # Provede transformaci pomocí S-Boxů
    sboxed = s_boxes(xored)

    # Udělá výstupní permutaci jedné iterace.
    permutation_table = [
        16,7,20,21,
        29,12,28,17,
        1,15,23,26,
        5,18,31,10,
        2,8,24,14,
        32,27,3,9,
        19,13,30,6,
        22,11,4,25,
    ]

    return permutate(sboxed, permutation_table)

if __name__ == "__main__":

    # Jednoduché nastavení pro parser parametrů předaných na příkazovém řádku.
    # Přijímá parametry --input následovaný 64 bity pro zašifrování a --key následovaný 64 bity šifrovacího klíče.
    parser = argparse.ArgumentParser(description='Výpočet DES')
    parser.add_argument('--input', metavar='BINARY', type=str,
                        help='Text pro zašifrování')
    parser.add_argument('--key', metavar="BINARY", type=str,
                        help='Klíč pro šifrování')

    args = parser.parse_args()

    ###################################################################################################################
    # Spuštění šifrování

    print(f"Encrypting with DES...")
    print(f"Input: {args.input}")
    print(f"Key: {args.key}")

    # Vygeneruje 16 pomocných klíčů z hlavního dešifrovacího klíče
    keys = generate_keys(args.key)

    # Na vstupních datech se musí provést permutace popsaná následující tabulkou.
    initial_permutation_table = [
        58,50,42,34,26,18,10,2,
        60,52,44,36,28,20,12,4,
        62,54,46,38,30,22,14,6,
        64,56,48,40,32,24,16,8,
        57,49,41,33,25,17,9,1,
        59,51,43,35,27,19,11,3,
        61,53,45,37,29,21,13,5,
        63,55,47,39,31,23,15,7
    ]

    input_first_permutation = permutate(args.input, initial_permutation_table)
    
    # Data se rozdělí na dvě poloviny.
    left = [ None for i in range(0, 17) ]
    left[0] = input_first_permutation[0:32]

    right = [ None for i in range(0, 17) ]
    right[0] = input_first_permutation[32:]

    # Provede 16 iterací, při každé se vypočítají:
    # leva_(n) = prava_(n-1)
    # prava_(n) = leva_(n-1) ^ f(prava_(n-1), klic_(n))
    for i in range(1, 17):
        # Poznámka: Index 17 je zde z důvodu, že má proběhnout 16 iterací a začíná se ukládat na index 1, nikoliv 0,
        # kde jsou uloženy originální (byť permutovaná) data.
        left[i] = right[i-1]
        right[i] = xor(left[i-1], f_function(right[i-1], keys[i]))

    # Levá a pravá strana se prohodí.
    # Pozor: na pořadí záleží!
    reverse_order = right[16] + left[16]

    # Před výstupem se ještě provede jedna permutace.
    final_permutation_table = [
        40,8,48,16,56,24,64,32,
        39,7,47,15,55,23,63,31,
        38,6,46,14,54,22,62,30,
        37,5,45,13,53,21,61,29,
        36,4,44,12,52,20,60,28,
        35,3,43,11,51,19,59,27,
        34,2,42,10,50,18,58,26,
        33,1,41,9,49,17,57,25,
    ]

    result = permutate(reverse_order, final_permutation_table)
    print(f"Encrypted value: {result}")
