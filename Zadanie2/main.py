import socket
import os
import math
import struct
import binascii
import threading
import time

je_thread = True


def typ_spravy():
    """
    Funkcia od pouzivatela zistuje, aky typ spravy chce odoslat.
    :return:    Jeden znak, (t -> text, s -> subor).
    """
    print("Pre odoslanie textu  zadajte 't'.")
    print("Pre odoslanie suboru zadajte 's'.")
    while True:
        typ = input("Zadajte typ spravy: ")
        if typ == 't' or typ == 's':
            break
        print("Nespravny typ spravy (t/s).")
    return typ


def velkost_fragmentu():
    """
    Funkcia od pouzivatela zistuj, aku velkost fragmentu chce pouzit.
    :return:    Int, velkost fragmentu.
    """
    print("Zadajte velkost jedneho fragmentu (maximalna velkost je 1463 B): ")
    while True:
        fragment = int(input("Zadajte velkost fragmentu: "))
        if 1 <= fragment <= 1463:
            break
        print("Nespravna velkost fragmentu.")
    return fragment


def odosli_data(vysielac_socket, adressa, flag, meno_suboru, velkost_dat, velkost_frag, data, chyba):
    """
    Funkcia sluzi na odoslanie zadanych sprav na server.
    :param vysielac_socket:     Socket vysielaca.
    :param adressa:             Tuple adresa prijimaca (ip, port)
    :param flag:                Typ spravy.
    :param meno_suboru:         Meno suboru, ak odosielame subor.
    :param velkost_dat:         Celkova velkost prenasanych dat.
    :param velkost_frag:        Velkost jedneho fragmentu.
    :param data:                Zakodovane data, ktore odosielam.
    :param chyba:               Urcenie ci generujem chybu alebo nie.
    :return:                    Bool, True  -> ak komunikacia prebehla spravne.
                                      False -> ak komunikacia neprebehla spravne.
    """
    # Ak posielam File, poslem flag 'F' a nazov suboru. Ak posielam Text, poslem iba flag 'T'.
    if flag == "F":
        vysielac_socket.sendto(str.encode(flag) + str.encode(meno_suboru), adressa)
    elif flag == "T":
        vysielac_socket.sendto(str.encode(flag), adressa)

    try:
        vysielac_socket.settimeout(60)
        # Cakanie na odpoved.
        prijate_data, adressa = vysielac_socket.recvfrom(1500)
    except socket.timeout as error:
        print(error)
        return False

    # Zistim pocet paketov.
    pocet_paketov = math.ceil(velkost_dat / velkost_frag)

    celkovy_pocet_prenesenych = 0
    pocet_prenesenych = 0
    pozicia_dat = 0
    odpoved = 0
    # Ak je velkost dat mensia ako velkost fragmentu, nastavim fragment na velkost dat.
    if velkost_dat < velkost_frag:
        velkost_frag = velkost_dat

    while True:
        # Ak odoslem vsetky pakety, odoslem spravu o ukonceni komunikacie.
        if pocet_prenesenych == pocet_paketov:
            pocet_opakovani = 1
            while pocet_opakovani != 3:
                try:
                    data_na_odoslanie = "4"  # Ukoncenie prenosu dat.
                    data_na_odoslanie = data_na_odoslanie.encode()
                    vysielac_socket.sendto(data_na_odoslanie, adressa)
                    vysielac_socket.settimeout(5)
                    prijate_data, adressa = vysielac_socket.recvfrom(1500)
                    prijate_data = prijate_data.decode()
                    if prijate_data == "5":  # Prichadza potvdrenie, break.
                        print("Ukoncenie prenosu dat.")
                        print()
                        return True
                except socket.timeout as error:
                    print("Potvrdenie o prijati ukoncovacej spravy neprislo. (%s)" % str(error))
                    print("Posielanie ukoncovacej spravy (%d. Opakovanie)" % pocet_opakovani)
                    pocet_opakovani += 1
                    if pocet_opakovani == 3:
                        print("Neprisli potvrdzovacie spravy. Vysielac sa vypina...")
                        print()
                        return False
        try:
            # Doimplementacia
            if (pocet_prenesenych + 1) % 2 == 1:
                pozicia_dat += velkost_frag
                pocet_prenesenych += 1
                continue

            # Vytvorim si hlavicku -> Typ, velkost_dat, crc.
            hlavicka = struct.pack("c", '1'.encode()) + struct.pack("H", velkost_frag)

            # Data, ktore odosielam su hlavicka a aktualna cast dat.
            data_na_odoslanie = hlavicka + data[pozicia_dat: pozicia_dat + velkost_frag]

            # Prepocitanie crc z hlavicky a dat.
            crc = binascii.crc_hqx(data_na_odoslanie, 0)

            # Generovanie jednej chyby (Prvy paket).
            if chyba == "A":
                while True:
                    chybne_data = os.urandom(velkost_frag)
                    if chybne_data != data[pozicia_dat: pozicia_dat + velkost_frag]:
                        break

                print("Odosielanie %d. paketu..." % (pocet_prenesenych + 1))

                hlavicka += struct.pack("H", crc)

                data_na_odoslanie = hlavicka + chybne_data

                chyba = "N"
            else:

                hlavicka += struct.pack("H", crc)

                data_na_odoslanie = hlavicka + data[pozicia_dat: pozicia_dat + velkost_frag]

                print("Odosielanie %d. paketu. Velkosť je %d B." % (pocet_prenesenych + 1, velkost_frag))

            # Odoslanie dat.
            vysielac_socket.sendto(data_na_odoslanie, adressa)

            vysielac_socket.settimeout(5)

            # Cakanie na odpoved.
            prijate_data, adressa = vysielac_socket.recvfrom(1500)
            prijate_data = str(prijate_data.decode())
            odpoved = 0

            # Data sa prevzali spravne. Posuniem sa dalej v celkovych datach a inkrementujem pocet prenesenych paketov.
            if prijate_data[0] == "2":
                print("Prijate potvrdenia o prijati spravnych dat.")
                pozicia_dat += velkost_frag
                pocet_prenesenych += 1
                if (velkost_dat - pozicia_dat) - velkost_frag < 0:
                    velkost_frag = velkost_dat - pozicia_dat

            # Data sa neprevzali spravne, znovu sa odosle prislusny paket.
            if prijate_data[0] == "3":
                print("Znovuodosielanie prislusneho paketu.")

            celkovy_pocet_prenesenych += 1
        # Ak server 3krat neodpovie, rusi sa spojenie.
        except socket.timeout as error:
            odpoved += 1
            if odpoved == 3:
                print("Server trikrat neodpovedal, ukoncuje sa spojenie.")
                print(error)
                return False
            print("Neprisla potvrdcovacia sprava, znovuodoslanie prislusneho paketu.")


def keep_alive(vysielaci_socket, adresa):
    """
    Funkcia na druhom threade odosiela keep-alive spravy.
    :param vysielaci_socket:    Socket vysielaca.
    :param adresa:              Adresa prijimaca.
    :return:
    """
    pocet_opakovani = 1
    global je_thread
    while True:
        if not je_thread:
            return
        try:
            # print("Posielanie Keep-Alive spravy.")
            # Odoslanie keep-alive spravy
            vysielaci_socket.sendto(str.encode("K"), adresa)
            vysielaci_socket.settimeout(5)

            # Prijem odpovede.
            data, adresa = vysielaci_socket.recvfrom(1500)
            data.decode()
            if data[0] == "6":
                pocet_opakovani = 1
            # Sprava sa odosiela kazdych 5 sek.
            time.sleep(5)
        # Ak sa server odpoji poslu sa este 2 dalsie keep-alive spravy, ak nepride odpoved ani na jednu,
        # ukoncim spojenie.
        except (socket.timeout, socket.error) as error:
            print("Potvrdenie o prijati Keep-Alive spravy neprislo. (%s)" % str(error))
            print("Posielanie Keep-Alive spravy (%d. Opakovanie)" % pocet_opakovani)
            pocet_opakovani += 1
            if pocet_opakovani == 3:
                return


def inicializacia(port, ip):
    """
    Funkcia zahajuje komunikaciu medzi vysielacom a prijimacom.
    :param port:    Port prijimaca.
    :param ip:      IP prijimaca.
    :return:        Nic.
    """
    print()
    print()
    pocet_pokusov = 0
    while pocet_pokusov != 3:
        try:
            print("Odosielanie inicializacneho paketu serveru...")

            socket_1 = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
            adresa = (ip, port)

            socket_1.sendto(str.encode("I"), adresa)
            socket_1.settimeout(5)

            data, adresa = socket_1.recvfrom(1500)
            data = data.decode()

            if data == "0":
                print("Zahajenie komunikacie.")
                # Ak sa zahaji komunikacia, vytvaram novy thread na keep-alive spravy.
                global je_thread
                je_thread = True
                keep_vetva = threading.Thread(target=keep_alive, args=(socket_1, adresa))
                keep_vetva.start()

                while True:
                    print()
                    print("Chcete odoslat data? -> 1")
                    print("Chcete ukoncit komunikaciu a zmenit role? -> 2")
                    print("Chcete ukoncit program? -> 3")

                    # Zistenie co chcem pouzivatel robit
                    while True:
                        vstup = int(input("Zadajte vstup: "))
                        if type(vstup) == int:
                            break
                        print("Zadajte cislo.")

                    if vstup == 1:
                        typ = typ_spravy()

                        flag = ""
                        meno_suboru = ""
                        velkost_dat = 0
                        data = []

                        if typ == 't':
                            data = input("Zadajte textovu spravu: ")
                            print("Sprava na odoslanie je %s." % data)
                            data = str.encode(data)
                            velkost_dat = len(data)
                            print("Velkost spravy je %d B." % velkost_dat)
                            flag = "T"

                        elif typ == 's':
                            while True:
                                cesta = input("Zadajte cestu k suboru: ")
                                if os.path.isfile(cesta):
                                    meno_suboru = os.path.basename(cesta)
                                    subor = open(cesta, "rb")
                                    data = subor.read()
                                    velkost_dat = os.path.getsize(cesta)
                                    print("Absolutna cesta k suboru %s." % os.path.abspath(cesta))
                                    print("Velkost suboru je %d B." % velkost_dat)
                                    flag = "F"
                                    break

                        velkost_frag = velkost_fragmentu()

                        while True:
                            chyba = input("Chcete generovat chybu? (A/N): ")
                            if chyba == "A" or chyba == "N":
                                print()
                                break
                        # Akonahle zacinam odosielat data, ukoncujem keep-alive thread.
                        je_thread = False
                        keep_vetva.join()

                        # Ak prenos dat skonci uspesne, opat vytvaram keep-alive thread.
                        if odosli_data(socket_1, adresa, flag, meno_suboru, velkost_dat, velkost_frag, data, chyba):
                            je_thread = True
                            keep_vetva = threading.Thread(target=keep_alive, args=(socket_1, adresa))
                            keep_vetva.start()

                    elif vstup == 2:
                        je_thread = False
                        keep_vetva.join()
                        socket_1.sendto(str("E").encode(), adresa)
                        print("Hlavne menu.")
                        return

                    elif vstup == 3:
                        je_thread = False
                        keep_vetva.join()
                        print("Ukoncenie programu. ")
                        exit(0)
                    else:
                        print("Zadali ste nespravne cislo.")
                        continue

        except (socket.timeout, socket.error) as e:
            print(e)
        pocet_pokusov += 1


def vysielac_login():
    """
        Funkcia zisti od pouzivatela port a IP adresu prijimatela a nasledne ide inicializacia.
        :return:    Nic.
        """
    cislo_portu = int(input("Zadajte cislo portu prijimatela: "))

    ip_adresa = input("Zadajte IP adresu prijimatela: ")

    inicializacia(cislo_portu, ip_adresa)


def prijimac_login():
    """
    Funkcia sluzi na vytvorenie uzla na prijimanie sprav.
    :return:    Nic.
    """
    port = int(input("Zadajte port: "))

    socket_2 = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    socket_2.bind(("", port))

    pocet_prijatych_paketov = 0
    typ = ""
    vysledna_sprava = ""
    meno_suboru = ""
    cesta_k_suboru = ""
    vysledny_subor = []
    while True:
        try:
            # Cakanie na prijatie dat
            prijate_data, adresa = socket_2.recvfrom(1500)
            socket_2.settimeout(20)
            flag = struct.unpack("c", prijate_data[:1])
            flag = flag[0].decode()
            # Inicializacna sprava.
            if flag == "I":
                print()
                print("Potvrdenie o zacati komunikacie.")
                socket_2.sendto(str.encode("0"), adresa)

            # Sprava o prenasani textu.
            elif flag == "T":
                print("Potvrdenie a zacatie prenosu textu.")
                typ = "T"
                socket_2.sendto(str.encode("0"), adresa)

            # Sprava o prenasani suboru.
            elif flag == "F":
                print("Potvrdenie a zacatie prenosu suboru.")
                meno_suboru = prijate_data[1:]
                typ = "F"
                while True:
                    print("Pre ulozenie suboru do aktualneho priecinka stlacte 1.")
                    print("Pre ulozenie suboru do ineho priecinka stlacte 2.")
                    pomocna = input("Zadajte vstup: ")
                    if pomocna == "1":
                        cesta_k_suboru = ""
                        break
                    elif pomocna == "2":
                        while True:
                            cesta_k_suboru = input("Zadajte cestu k suboru: ")
                            if os.path.isdir(cesta_k_suboru):
                                break
                        break
                socket_2.sendto(str.encode("0"), adresa)

            # Keep-alive sprava.
            elif flag == "K":
                print("Potvrdenie o prijatie Keep-Alive spravy.")
                socket_2.sendto(str.encode("6"), adresa)

            # Ukoncenie prenosu dat.
            elif flag == "4":
                print("Ukoncenie prenosu dat..")
                socket_2.sendto(str.encode("5"), adresa)

                if typ == "T":
                    print("Vysledna sprava : %s" % vysledna_sprava)
                    print("Velkost : %d B." % len(vysledna_sprava))
                    vysledna_sprava = ""

                elif typ == "F":
                    meno_suboru = meno_suboru.decode()
                    if cesta_k_suboru == "":
                        nove_meno = meno_suboru
                    else:
                        nove_meno = cesta_k_suboru + "\\" + meno_suboru

                    subor = open(nove_meno, "wb")

                    for cast in vysledny_subor:
                        subor.write(cast)
                    subor.close()

                    print("Absolutna cesta k suboru %s." % str(os.path.abspath(nove_meno)))
                    print("Prenieslo sa %d paketov, celkova velkost suboru je %d B."
                          % (pocet_prijatych_paketov, os.path.getsize(nove_meno)))

                    vysledny_subor = []
                pocet_prijatych_paketov = 0

            # Prijatie dat.
            elif flag == "1":
                velkost_dat, crc = struct.unpack("HH", prijate_data[1:5])
                hlavicka = struct.pack("c", str.encode(flag[0])) + struct.pack("H", velkost_dat)
                kontrolne_crc = binascii.crc_hqx(hlavicka + prijate_data[5:], 0)

                # Ak je crc zhodne potvrdim spravne prijatie dat.
                if kontrolne_crc == crc:
                    print("Prijate data su korektne.")
                    print(
                        "Potvdenie prijatia %d. paketu. Velkost je %d B." % (pocet_prijatych_paketov + 1, velkost_dat))
                    if typ == "T":
                        sprava = prijate_data[5:].decode()
                        vysledna_sprava += sprava
                        socket_2.sendto("2".encode(), adresa)
                    elif typ == "F":
                        vysledny_subor.append(prijate_data[5:])
                        socket_2.sendto("2".encode(), adresa)
                    pocet_prijatych_paketov += 1
                # Ak sa nezhoduje, vypytam si prislusne data este raz.
                else:
                    print("Prijate data sa nezhoduju.")
                    print("Ziadost o znovuodoslanie %d. paketu." % (pocet_prijatych_paketov + 1))
                    socket_2.sendto("3".encode(), adresa)

            # Ukoncenie komunikacie
            elif flag == "E":
                print("Prijatie paketu o ukonceni komunikacie.")
                print("Vypinam server")
                print()
                break
        except socket.timeout as e:
            print(e)
            print("Neprisli dalsie spravy. Server sa vypina.")
            break


if __name__ == '__main__':
    while True:
        print("Zapnutie programu ako vysielac -> zadajte 1.")
        print("Zapnutie programu ako prijimac -> zadajte 2.")
        print("Pre ukoncenie stlacte 0.")
        vyber = input("Zadajte vstup: ")
        if vyber == "1":
            print("Pokracujete ako vysielac.")
            vysielac_login()
        elif vyber == "2":
            print("Pokracujete ako prijimac.")
            prijimac_login()
        elif vyber == "0":
            break
        else:
            print("Zadali ste nespravny vstup.")
