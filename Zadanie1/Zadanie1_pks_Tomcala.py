import sys
import scapy.all as sc
from pathlib import Path

addresses = []
count = []
http = []
https = []
ftp_d = []
ftp_c = []
ssh = []
telnet = []
icmp = []
arp = []
tftp = []


# Done
def print_number_of_packet(packet_number, oFile):
    """
    Function prints number of packet in pcap.
    :param packet_number:   ID of packet.
    :param oFile:           Output file.
    :return:                Nothing.
    """
    oFile.write("Ramec: %d\n" % packet_number)


# Done
def lenght_of_packet(length, oFile):
    """
    Function prints length of frame.
    :param length:  Length of frame.
    :param oFile:   Output file.
    :return:        Nothing.
    """
    oFile.write("Dlzka ramca poskytnuta pcap API  – %d B\n" % length)
    if length < 60:
        oFile.write("Dlzka ramca prenasaneho po mediu – 64 B\n")
    else:
        oFile.write("Dlzka ramca prenasaneho po mediu – %d B\n" % (length + 4))


# Done
def print_ip(ip, flag, flag2, oFile):
    """
    Function prints IP address in decimal.
    :param ip:      IP address.
    :param flag:    Help variable for printing.
    :param flag2:   Help variable for printing.
    :param oFile:   Output File.
    :return:        Nothing.
    """
    iterator = 0
    for byte in ip:
        oFile.write(str(byte))
        if iterator == 3 and flag:
            oFile.write("\n")
        elif iterator == 3 and flag2:
            oFile.write(" ")
        elif iterator == 3 and not flag:
            oFile.write(" :  \n ")
        else:
            oFile.write(".")
        iterator += 1


# Done
def find_tcp_ports(pckt, index2, ihl, flag, oFile):
    """
    Function prints TCP port and append packet to list of comunication.
    :param pckt:     Actual pacekt.
    :param index2:   Number of packet in pcap.
    :param ihl:      Length of IP header.
    :param flag:     Flag, if program analyzes packets or comunications.
    :param oFile:    Output file.
    :return:         Nothing.
    """
    file = open("file.txt", "r")
    for line in file:
        if line == "#TCP ports\n":
            break

    for line in file:
        if line[0] == '#':
            oFile.write("Nenasiel sa dany typ protokolu.\n")
            break
                    # Dest TCP port                                         # Src TCP port
        if "0x" + pckt[16 + ihl: 18 + ihl].hex() == line[0:6] or "0x" + pckt[14 + ihl: 16 + ihl].hex() == line[0:6]:
            temp = 0
            for index in range(0, len(line)):
                if line[index] == ' ':
                    temp += 1
                if temp == 2:
                    oFile.write(line[index + 1:])
                    oFile.write("Zdrojovy port: %d\n" % int(pckt[14 + ihl: 16 + ihl].hex(), base=16))
                    oFile.write("Cielovy port: %d\n" % int(pckt[16 + ihl:18 + ihl].hex(), base=16))
                    if line[index + 1:] == "HTTP\n" and flag:
                        http.append(index2)
                    elif line[index + 1:] == "HTTPS\n" and flag:
                        https.append(index2)
                    elif line[index + 1:] == "SSH\n" and flag:
                        ssh.append(index2)
                    elif line[index + 1:] == "TELNET\n" and flag:
                        telnet.append(index2)
                    elif line[index + 1:] == "FTP - data\n" and flag:
                        ftp_d.append(index2)
                    elif line[index + 1:] == "FTP - control\n" and flag:
                        ftp_c.append(index2)
                    break

            break
    file.close()


# Done
def find_flags(pckt):
    """
    Function that finds flags for TCP comunication.
    :param pckt:    Actual packet.
    :return:        Return flags of packet in string.
    """
    help_str = "00000000"
    ihl = int(pckt[14:15].hex()[1:], 16) * 4
    flags_in_string = bin(int(pckt[27 + ihl: 28 + ihl].hex(), 16))[2:]
    flags = help_str[len(flags_in_string):] + flags_in_string
    return flags

# Done
def udp_port(pckt, index2, ihl, flag, pcap, oFile):
    """
    Function prints source and destination port in UDP protocol.
    :param pckt:        Actual packet.
    :param index2:      Number of packet in pcap file.
    :param ihl:         Size of IP header.
    :param flag:        Flag, if program analyzes packets or comunications.
    :param pcap:        Pcap file.
    :param oFile:       Output file.
    :return:            Nothing.
    """
    file = open("file.txt", "r")
    for line in file:
        if line == "#UDP ports\n":
            break
    for line in file:
        if line[0] == '#':
            oFile.write("Nenasiel sa dany typ protokolu.\n")
            break
                #  UDP destination port                                     UDP source port
        if "0x" + pckt[16 + ihl: 18 + ihl].hex() == line[0:6] or "0x" + pckt[14 + ihl: 16 + ihl].hex() == line[0:6]:
            for index in range(0, len(line)):
                if line[index] == ' ':
                    oFile.write(line[index + 1:])
                    oFile.write("Zdrojový port: %d" % int(pckt[14 + ihl: 16 + ihl].hex(), base=16) + "\n")
                    oFile.write("Cieľový port: %d" % int(pckt[16 + ihl:18 + ihl].hex(), base=16) + "\n")
                    if line[index + 1:] == "TFTP\n" and flag:       # "0x0045" TFTP port
                        tftp.append(index2)
                    break
            break
        else:
            for tftp_index in tftp:
                tftp_packet = sc.raw(pcap[tftp_index - 1])
                ihl = int(tftp_packet[14:15].hex()[1:], 16) * 4
                # Compare if actual packet contains 69 port (TFTP) on destination port
                # and source port is equal destination port or source port of previous packet
                if tftp_packet[14 + ihl + 2: 14 + ihl + 4].hex() == "0045" and (          # destination source
                    # dest port                                    # Source port
                    pckt[16 + ihl: 18 + ihl].hex() == tftp_packet[14 + ihl: 14 + ihl + 2].hex() or
                    # src port                                     # dest port
                    pckt[14 + ihl: 16 + ihl].hex() == tftp_packet[14 + ihl: 14 + ihl + 2].hex()
                ):
                    if flag:
                        for index in range(0, len(line)):
                            if line[index] == ' ':
                                oFile.write(line[index + 1:])
                                oFile.write("Zdrojový port: %d" % int(pckt[14 + ihl: 16 + ihl].hex(), base=16) + "\n")
                                oFile.write("Cieľový port: %d" % int(pckt[16 + ihl:18 + ihl].hex(), base=16) + "\n")
                                if line[index + 1:] == "TFTP\n" and flag:  # "0x0045" TFTP port
                                    tftp.append(index2)
                                break
                    break
            break


# Done
def find_next_protocol(pckt, index2, ihl, flag, pcap, oFile):
    """
    Function finds out IPv4 protocol (checking 24 Byte). Protocols are located in file.txt.
    - if protocol is "0x06" (TCP) -> finding TCP ports.
    - if protocol is "0x01" (ICMP) -> appending packet to list icmp.
    - else prints protocol.
    :param pckt:    Actual packet.
    :param index2:  Number of packet in pcap.
    :param ihl:     IHL og actual packet.
    :param flag:    Flag, if program analyzes packets or comunication.
    :param pcap:    Pcap file.
    :return:        Nothing.
    """
    file = open("file.txt", "r")
    for line in file:
        if line == "#IP Protocol numbers\n":
            break

    for line in file:
        if line[0] == '#':                                         # Looking for type of protocol in extern txt file.
            oFile.write("Nenasiel sa dany typ protokolu.\n")
            break

        if "0x" + pckt[23:24].hex() == line[0:4]:                  # 24 Byte is Protocol
            temp = 0
            for index in range(0, len(line)):
                if line[index] == ' ':
                    temp += 1
                if temp == 2:
                    oFile.write(line[index + 1:])
                    break
            if "0x" + pckt[23:24].hex() == "0x06":                  # TCP
                if not flag:                                        # Flags in TCP com.
                    flags = find_flags(pckt)
                    oFile.write("Flag-y: ")
                    if flags[7] == '1':
                        oFile.write("FIN: 1 ")
                    if flags[6] == '1':
                        oFile.write("SIN: 1 ")
                    if flags[5] == '1':
                        oFile.write("RST: 1 ")
                    if flags[4] == '1':
                        oFile.write("PSH: 1 ")
                    if flags[3] == '1':
                        oFile.write("ACK: 1 ")
                    oFile.write("\n")
                find_tcp_ports(pckt, index2, ihl, flag, oFile)
            elif "0x" + pckt[23:24].hex() == "0x01":    # ICMP
                if not flag:                                            # Code for ICMP comunication.
                    icmp_file = open("icmp_ports.txt", "r")             # File for ICMP ports.
                    flag2 = False
                    nieco = icmp.index(index2) + 1                      # Fragment protocol, for next packet
                    if pckt[20:21].hex() == "20":                # 20 Byte is Flags -> if it is not "00" it is fragment
                        oFile.write("Fragmentovany IP protocol. (%d)" % (icmp[nieco]) + "\n")
                        return

                    nieco = icmp.index(index2) - 1
                    pckt2 = sc.raw(pcap[icmp[nieco] - 1])           # If previous frame was fragment -> True
                    if pckt2[20:21].hex() == "20":
                        flag2 = True

                    if flag2:                                       # If previous frame was fragment -> True
                        pckt2 = sc.raw(pcap[icmp[nieco] - 1])       # Looking at previous packet.
                        for line2 in icmp_file:
                            if line2[0:4] == "0x" + pckt2[14 + ihl: 14 + ihl + 1].hex():    # Find ICMP port
                                oFile.write("Icmp port: " + line2[5:])                      # in the same position.
                    else:
                        for line2 in icmp_file:                     # Looking at previous packet.
                            if line2[0:4] == "0x" + pckt[14 + ihl: 14 + ihl + 1].hex():
                                oFile.write("Icmp port: " + line2[5:])
                else:
                    icmp.append(index2)
            elif "0x" + pckt[23:24].hex() == "0x11":                 # UDP
                udp_port(pckt, index2, ihl, flag, pcap, oFile)
            break
    file.close()


# Done
def ipv4(pckt, index, flag, pcap, oFile):
    """
    Function prints source and destination IP addresses. It also collects source IP address.
    List addresses contains individual source IP addresses.
    List count contains, how many packets individual IP address send.
    :param pckt:    Actual packet.
    :param index:   Number of packet in pcap.
    :param flag:    Help variable for printing in next functions.
    :param pcap:    Pcap File, that is used in next function.
    :return:        Nothing.
    """
    if addresses.count(pckt[26:30]) == 0:
        addresses.append(pckt[26:30])
    if len(count) - 1 < addresses.index(pckt[26:30]):
        count.append(1)
    else:
        count[addresses.index(pckt[26:30])] += 1

    oFile.write("Zdrojova IP adresa: ")
    print_ip(pckt[26:30], True, False, oFile)

    oFile.write("Cielova IP adresa: ")
    print_ip(pckt[30:34], True, False, oFile)
    ihl = int(pckt[14:15].hex()[1:], 16) * 4
    find_next_protocol(pckt, index, ihl, flag, pcap, oFile)


# Done
def ipv4_max(oFile):
    """
    Function prints all source IP addresses and prints one IP address with most send packets.
    :param oFile:       Output File.
    :return:            Nothing.
    """
    for add in addresses:
        print_ip(add, True, True, oFile)

    maximum = max(count)
    index = count.index(maximum)

    oFile.write("Adresa uzla s najväčším počtom odoslaných paketov: ")
    print_ip(addresses[index], False, True, oFile)
    oFile.write("%d paketov." % (count[index]))


# Done
def type_of_ether_type(pckt, index, flag, pcap, oFile):
    """
    Function finds out type of Ethernet protocol. EtherTypes are located in
    file.txt.
    - if EtherType == 0x0800 (IPv4) -> finding next protocols.
    - if EtherType == 0x0806 (ARP) -> appending to list with ARP packets.
    - else print EtherType
    :param pckt:    Actual packet.
    :param index:   Number of packet in pcap.
    :param flag:    Help variable for printing in next functions.
    :param pcap:    Pcap File, that is used in next function.
    :param oFile    Output file.
    :return:        Nothing.
    """
    file = open("file.txt", "r")

    for line in file:
        if line == "#Ethertypes\n":
            break

    for line in file:
        if line[0] == '#':
            oFile.write("Nenasiel sa dany typ protokolu.\n")
            break
        if "0x" + pckt[12:14].hex() == line[0:6]:
            oFile.write(line[7:])
            if "0x" + pckt[12:14].hex() == "0x0800":                # IPv4 (0x0800)
                ipv4(pckt, index, flag, pcap, oFile)
            if "0x" + pckt[12:14].hex() == "0x0806" and flag:       # ARP  (0x0806)
                arp.append(index)
            break
    file.close()


# Done
def type_of_802(pckt, flag, oFile):
    """
    Function prints type of 802.
    :param pckt:    Actual packet.
    :param flag:    Help variable for printing.
    :param oFile:   Output file.
    :return:        Nithing.
    """
    file = open("file.txt", "r")

    for line in file:
        if line == "#LSAPs\n":
            break

    for line in file:
        if line[0] == '#':
            oFile.write("Nenasiel sa dany typ protokolu.\n")
            break
        if "0x" + pckt[14:15].hex() == line[0:4]:
            oFile.write(line[5:])
            break

    file.close()


# Done
def print_dst_and_src_mac(pckt, oFile):
    """
    Function that prints source and destination MAC addresses.
    :param pckt:    Actual packet.
    :return:        Nothing.
    """
    dst = pckt[0:6]
    src = pckt[6:12]
    for num in range(0, 2):
        if num == 0:
            oFile.write("Zdrojova MAC adresa: ")
            macadd = src
        else:
            oFile.write("Cielova MAC adresa : ")
            macadd = dst
        for index in range(0, 6):
            temp = "0"
            if len(format(macadd[index], "x")) == 1:
                oFile.write(temp + format(macadd[index], "x") + ' ')
            else:
                oFile.write(format(macadd[index], "x") + ' ')
        oFile.write("\n")


# Done
def type_of_packet(pckt, index, flag, pcap, oFile):
    """
    Function finds out type of packet based on 13 and 14 Byte.
    If 13 and 14 Byte > 1500 (EtherType), it is Ethernet II.
    Else program checks 15 Byte:
     - if 15 Byte == "FF" -> IEEE 802.3 - RAW, IPX
     - if 15 Byte == "AA" -> IEEE 802.3 s LLC a SNAP
     - else ->               IEEE 802.3 s LLC
    :param pckt:    Actual packet.
    :param index:   Number of packet in pcap.
    :param flag:    Help variable for printing in next functions.
    :param pcap:    Pcap File, that is used in next function.
    :return:        Nothing.
    """
    if int(pckt[12:14].hex(), base=16) > 1500:
        oFile.write("Ethernet II\n")
        print_dst_and_src_mac(pckt, oFile)
        type_of_ether_type(pckt, index, flag, pcap, oFile)                 # Zistovanie vnorenych protokolov
    else:
        if int(pckt[14:15].hex(), base=16) == 255:
            oFile.write("IEEE 802.3 – Raw\n")
            oFile.write("IPX\n")
        elif int(pckt[14:15].hex(), base=16) == 170:
            oFile.write("IEEE 802.3 s LLC a SNAP\n")
        else:
            oFile.write("IEEE 802.3 s LLC\n")
            type_of_802(pckt, flag, oFile)                                       # Zistovanie dalsich protokolov LLC
        print_dst_and_src_mac(pckt, oFile)


# Done
def print_packet(pckt, oFile):
    """
    Function prints every byte of packet.
    :param pckt:    Packet for printing.
    :param oFile:   Output file.
    :return:        Nothing.
    """
    for index in range(0, len(pckt)):
        if len(hex(pckt[index])[2:]) == 1:
            oFile.write("0")
        if (index + 1) % 16 == 0 and index != 0:
            oFile.write(hex(pckt[index])[2:] + "\n")
        elif (index + 1) % 8 == 0 and index != 0:
            oFile.write(hex(pckt[index])[2:] + "   ")
        else:
            oFile.write(hex(pckt[index])[2:] + " ")
    oFile.write("\n")


# Done
def verify_opening(packet1, packet2, packet3, file):
    """
    Function verify if opening of TCP comunication is correct.
    :param packet1:    First packet.
    :param packet2:    Second packet.
    :param packet3:    Third packet.
    :param file:       Pcap file.
    :return:           If opening is correct True or False.
    """
    pckt = sc.raw(file[packet1 - 1])
    flags = find_flags(pckt)
    if flags != "00000010":
        return False

    pckt = sc.raw(file[packet2 - 1])
    flags = find_flags(pckt)
    if flags != "00010010":
        return False

    pckt = sc.raw(file[packet3 - 1])
    flags = find_flags(pckt)
    if flags != "00010000":
        return False

    return True


# Done
def verify_ending(packet1, packet2, packet3, packet4, file):
    """
    Function verifies correct ending of TCP comunication.
    :param packet1:    Last - 3 packet of comunication.
    :param packet2:    Last - 2 packet of comunication.
    :param packet3:    Last - 1 packet of comunication.
    :param packet4:    Last packet of comunication.
    :param file:       Pcap file.
    :return:           If ending is correct True, otherwise False.
    """
    l_packet = sc.raw(file[packet4 - 1])
    l_flags = find_flags(l_packet)

    t_packet = sc.raw(file[packet3 - 1])
    t_flags = find_flags(t_packet)

    if l_flags[5] == '1' or t_flags[5] == '1':
        return True

    f_packet = sc.raw(file[packet1 - 1])
    f_flags = find_flags(f_packet)

    s_packet = sc.raw(file[packet2 - 1])
    s_flags = find_flags(s_packet)

    if f_flags[7] == '1' and s_flags[3] == '1' and t_flags[7] == '1' and l_flags[3] == '1':
        return True

    return False


# Done
def print_comunication(name, comunication, comlete, isempty, file, ofile_com):
    """
    Function for printing TCP comunication.
    :param name:             Type of TCP comunication.
    :param comunication:     TCP comunication.
    :param comlete:          "Complete" or "incomplete" comunication.
    :param isempty:          If there is TCP comunication True, otherwise False.
    :param file:             Pcap file.
    :param ofile_com:        Output file.
    :return:                 Nothing.
    """
    if isempty:
        ofile_com.write(60 * '*' + "\n")
        ofile_com.write(comlete + " " + name + " komunikacia:\n")
        if len(comunication) > 20:
            for index in range(0, 10):
                pckt = sc.raw(file[comunication[index] - 1])
                ofile_com.write("Rámec č. %d\n" % (comunication[index]))
                type_of_packet(pckt, comunication[index], False, file, ofile_com)
                print_packet(pckt, ofile_com)
                ofile_com.write("\n")
            for index in range(-10, 0):
                pckt = sc.raw(file[comunication[index] - 1])
                ofile_com.write("Rámec č. %d\n" % (comunication[index]))
                type_of_packet(pckt, comunication[index], False, file, ofile_com)
                print_packet(pckt, ofile_com)
                ofile_com.write("\n")
        else:
            for pckt in comunication:
                pcktt = sc.raw(file[pckt - 1])
                ofile_com.write("Rámec č. %d\n" % pckt)
                type_of_packet(pcktt, pckt, False, file, ofile_com)
                print_packet(pcktt, ofile_com)
                ofile_com.write("\n")
    else:
        ofile_com.write(60 * '*' + "\n")
        ofile_com.write("\nV subore sa nenachadza " + comlete + " " + name + " komunikacia")
    ofile_com.write("\n\n")
    ofile_com.write(60 * '*' + "\n\n")


# Done
def tcp_comunication(file, array, port, name, ofile_com):
    """
    Funkcia najde prvu kompletnu a prvu nekompletnu komunikaciu v danom pcap subore.
    Funkcia pracuje s listom, v ktorom su ulozene indexi TCP protokolov.
    Zoberiem si prvy protokol, ktory zatial nie je v komunikacii a zistim si jeho porty.
    Prechadzam vsetky ostatne protokoly a tie, ktore budu mat zhodne porty priradim do rovnakej komunikacie.
    Nasledne overim otvorenie a uzatvorenie komunikacie.
    Ak je kompletna alebo nekompletna tak ju vypise.
    :param file:        Pcap file.
    :param array:       Array of TCP indexes in pcap.
    :param port:        TCP port.
    :param name:        Name of port.
    :param ofile_com:   Output file.
    :return:            Nothing.
    """
    checked = []
    unfinished = []
    finished = []
    find_finished = False
    find_unfinished = False
    for i in range(0, len(array)):
        comunication = []
        pckt = sc.raw(file[array[i] - 1])
        ihl = int(pckt[14:15].hex()[1:], 16) * 4
        if int(pckt[14 + ihl: 16 + ihl].hex(), 16) != port:         # TCP source port
            client_port = int(pckt[14 + ihl: 16 + ihl].hex(), 16)
        else:
            client_port = int(pckt[16 + ihl: 18 + ihl].hex(), 16)   # TCP destination port
        if client_port in checked:                                  # If it is checked continue.
            continue
        checked.append(client_port)
        for j in range(i, len(array)):
            new_packet = sc.raw(file[array[j] - 1])                 # If client port is equal with dst or src port
            if (client_port == int(new_packet[14 + ihl: 16 + ihl].hex(), 16)) or (  # in next packet it is in comunic.
                    client_port == int(new_packet[16 + ihl: 18 + ihl].hex(), 16)):
                comunication.append(array[j])

        length_of_comunication = len(comunication)
        if length_of_comunication < 4:                              # It is not comunication.
            continue
        else:
            if verify_opening(comunication[0], comunication[1], comunication[2], file): # Verify Opening.
                if verify_ending(comunication[length_of_comunication - 4],              # Verify Ending.
                                 comunication[length_of_comunication - 3],
                                 comunication[length_of_comunication - 2],
                                 comunication[length_of_comunication - 1], file):
                    if not finished:
                        finished = comunication
                        find_finished = True
                else:
                    if not unfinished:
                        unfinished = comunication
                        find_unfinished = True
            else:
                continue

        if find_finished and find_unfinished:
            break

    print_comunication(name, finished, "Kompletna", find_finished, file, ofile_com)
    print_comunication(name, unfinished, "Nekompletna", find_unfinished, file, ofile_com)


# Done?
def icmp_comunication(file, array, com_num, ofile_com):
    """
    Funkcia pracuje s listom, v ktorom su ulozene indexi ICMP protokolov.
    Zoberiem si prvy protokol a zistim si jeho src a dst IP adresu.
    Nasledne tieto IP adresy porovnavam s ostatnymi IP adresami ICMP protokolov.
    Ak su vymenene zmenim src a dst IP adresu a protokol vlozim do komunikacie.
    Ak ICMP sprava je napriklad Time Exceeded, pozeram sa na Ip adresy na Bajtoch : 14 + ihl + 20: 14 + ihl + 24,
    14 + ihl + 24: 14 + ihl + 28
    Potom dane protokoly vymazem a rekurzivne pracujem s tymi co ostali az kym neostane prazdne pole indexov.
    :param file:        Pcap file.
    :param array:       Array of indexes of ICMP protocols.
    :param com_num:     Number of comunication.
    :param ofile_com:   Output file.
    :return:            Nothing.
    """
    if not array and com_num == 1:
        ofile_com.write(60 * "*" + "\n")
        ofile_com.write("\nV subore sa nenachadza ICMP komunikacia" + "\n\n")
        ofile_com.write(60 * "*" + "\n")
        return
    if not array:
        return
    pckt = sc.raw(file[array[0] - 1])
    src_ip = pckt[26:30]
    dst_ip = pckt[30:34]
    com = []
    com.append(array[0])
    for i in range(1, len(array)):
        pckt = sc.raw(file[array[i] - 1])
        ihl = int(pckt[14:15].hex()[1:], 16) * 4
        if (src_ip == pckt[14 + ihl + 20: 14 + ihl + 24] and dst_ip == pckt[14 + ihl + 24: 14 + ihl + 28]) or (
                dst_ip == pckt[14 + ihl + 20: 14 + ihl + 24] and src_ip == pckt[14 + ihl + 24: 14 + ihl + 28]):
            com.append(array[i])
        elif src_ip == pckt[30:34] and dst_ip == pckt[26:30] or src_ip == pckt[26:30] and dst_ip == pckt[30:34]:
            if src_ip == pckt[30:34]:
                src_ip = pckt[26:30]
                dst_ip = pckt[30:34]
            else:
                src_ip = pckt[30:34]
                dst_ip = pckt[26:30]
            com.append(array[i])
        else:
            ofile_com.write(60 * "*" + "\n")
            ofile_com.write("Komunikacia c. %d:" % com_num + "\n")
            for inx in com:
                pckt = sc.raw(file[inx - 1])
                ofile_com.write("Cislo ramca: %d" % inx + "\n")
                type_of_packet(pckt, inx, False, file, ofile_com)
                print_packet(pckt, ofile_com)
                ofile_com.write("\n")
            ofile_com.write(60 * "*" + "\n")
            array = [i for i in array if i not in com]
            icmp_comunication(file, array, com_num + 1, ofile_com)
            return

    ofile_com.write(60 * "*" + "\n")
    ofile_com.write("Komunikacia c. %d:" % com_num + "\n")
    for inx in com:
        pckt = sc.raw(file[inx - 1])
        ofile_com.write("Cislo ramca: %d" % inx + "\n")
        type_of_packet(pckt, inx, False, file, ofile_com)
        print_packet(pckt, ofile_com)
        ofile_com.write("\n")
    ofile_com.write(60 * "*" + "\n")
    ofile_com.write("\n")
    return


def arp_comunication(file, array, ofile_com):
    """
    Funkcia pracuje s listom, v ktorom su ulozene indexi ARP protokolov.
    Zoberiem si prvy protokol, ktory zatial nie je v komunikacii a zistim si jeho src, dst IP a src MAC .
    Do pomocneho pola si ulozim prvy protokol a ak k nemu najdem reply tak to povazujem za komunikaciu.
    Ak najdem viacero requestov alebo reply ramce iba vypisem.
    :param file:        Pcap file.
    :param array:       Array of indexes of ARP packets.
    :param ofile_com:   Output file.
    :return:            Nothing.
    """
    number_of_comunication = 1
    in_comunication = [False] * len(array)
    if not array:
        ofile_com.write(60 * "*" + "\n")
        ofile_com.write("\nV subore sa nenachadza ARP komunikacia" + "\n\n")
        ofile_com.write(60 * "*" + "\n")
        return
    size = len(array)
    for i in range(0, size):
        if in_comunication[i]:
            continue
        comunication = []
        is_comunication = False
        pckt = sc.raw(file[array[i] - 1])
        src_mac = pckt[22:28]
        src_ip = pckt[28:32]
        dst_ip = pckt[38:42]
        comunication.append(array[i])
        in_comunication[i] = True
        for j in range(i, size):
            if in_comunication[j]:
                continue
            pckt = sc.raw(file[array[j] - 1])
            if src_mac == pckt[22:28] and src_ip == pckt[28:32] and dst_ip == pckt[38:42]:
                comunication.append(array[j])
                in_comunication[j] = True
            elif src_mac == pckt[32:38] and src_ip == pckt[38:42] and dst_ip == pckt[28:32]:
                comunication.append(array[j])
                in_comunication[j] = True
                is_comunication = True
                break

        ofile_com.write(60 * "*" + "\n")
        if is_comunication:
            ofile_com.write("Komunikacia c.%d:" % number_of_comunication + "\n")
            number_of_comunication = number_of_comunication + 1
        else:
            ofile_com.write("Vypis ARP ramcov.\n")
        for index in comunication:
            pckt = sc.raw(file[index - 1])
            if "0001" == pckt[20:22].hex():
                ofile_com.write("ARP request, IP adresa: %d.%d.%d.%d " % (pckt[38], pckt[39], pckt[40], pckt[41]) + "MAC: ???" + "\n")
                ofile_com.write("Zdrojova IP adresa: %d.%d.%d.%d " % (pckt[28], pckt[29], pckt[30], pckt[31]))
                ofile_com.write("Cielova IP adresa: %d.%d.%d.%d" % (pckt[38], pckt[39], pckt[40], pckt[41]) + "\n")
                ofile_com.write("Ramec c.%d" % (index) + "\n")
                type_of_packet(pckt, index, False, file, ofile_com)
                print_packet(pckt, ofile_com)
            elif "0002" == pckt[20:22].hex():
                ofile_com.write("ARP reply, IP: IP adresa: %d.%d.%d.%d " % (pckt[28], pckt[29], pckt[30], pckt[31]))
                ofile_com.write("MAC: " + pckt[22:28].hex(" ", 1) + "\n")
                ofile_com.write("Zdrojova IP: %d.%d.%d.%d " % (pckt[28], pckt[29], pckt[30], pckt[31]))
                ofile_com.write("Cielova IP adresa: %d.%d.%d.%d" % (pckt[38], pckt[39], pckt[40], pckt[41]) + "\n")
                ofile_com.write("Ramec c.%d" % (index) + "\n")
                type_of_packet(pckt, index, False, file, ofile_com)
                print_packet(pckt, ofile_com)
            ofile_com.write("\n")
        ofile_com.write(60 * "*" + "\n")
        ofile_com.write("\n")


# Done
def tftp_comunication(file, array, ofile_com):
    """
    Funkcia pracuje s listom, v ktorom su ulozene indexx TFTP protokolv.
    Z tohto listu si vyberiem prvy ramec, ktory este nie je v komunikacii a zistim si jeho src a dst port.
    Ak je jeden z nich port 69 znamena to, ze sa jedno o novu komunikaciu
    Nasledne pracujem s portom s, ktory nie je 69 a porovnam ho s portami dalsieho protokolu
    Ak sa jeden z portov rovna tomuto portu pridam protokol do komunikacie
    Ak najdem 69 je to nova komunikacia
    :param file:        Pcap file.
    :param array:       Array of indexes of tftp comunication.
    :param ofile_com:   Output file.
    :return:            Nothing.
    """
    if not array:
        ofile_com.write(60 * "*" + "\n")
        ofile_com.write("\nV subore sa nenachadza TFTP komunikacia" + "\n\n")
        ofile_com.write(60 * "*" + "\n")
        return
    size = len(array)
    in_comunication = [False] * size
    number_of_comunication = 1
    for i in range(0, size):
        if in_comunication[i]:
            continue
        comunication = []
        tftp_packet = sc.raw(file[array[i] - 1])
        ihl = int(tftp_packet[14:15].hex()[1:], 16) * 4
        dst_port = tftp_packet[14 + ihl + 2: 14 + ihl + 4].hex()
        src_port = tftp_packet[14 + ihl: 14 + ihl + 2].hex()
        if dst_port == "0045":                  # Start of tftp com (dst_port is 69)
            in_comunication[i] = True
            comunication.append(array[i])
        for j in range(i, size):
            if in_comunication[j]:
                continue
            tftp_packet2 = sc.raw(file[array[j] - 1])
            ihl2 = int(tftp_packet2[14:15].hex()[1:], 16) * 4
            # If src port of first packet of com is equal to actual packet src or dst port it is in comunicaiton
            if tftp_packet2[14 + ihl2 + 2: 14 + ihl2 + 4].hex() == src_port or tftp_packet2[14 + ihl2: 14 + ihl2 + 2].hex() == src_port:
                in_comunication[j] = True
                comunication.append(array[j])
                continue
            elif tftp_packet2[14 + ihl2 + 2: 14 + ihl2 + 4].hex() == "0045":
                break

        ofile_com.write(60 * "*" + "\n")
        ofile_com.write("Komunikacia cislo %d:" % number_of_comunication + "\n")
        for number_of_packet in comunication:
            ofile_com.write("\n")
            ofile_com.write("Ramec cislo %d:" % number_of_packet + "\n")
            pckt = sc.raw(file[number_of_packet - 1])
            type_of_packet(pckt, number_of_packet, False, file, ofile_com)
            print_packet(pckt, ofile_com)
        ofile_com.write("\n")
        ofile_com.write(60*"*" + "\n")
        number_of_comunication = number_of_comunication + 1


if __name__ == '__main__':
    fileName = input("Zadajte nazov pcap suboru: ")                       # Otvorenie pcap suboru
    path = Path(fileName + ".pcap")
    if not path.is_file():
        sys.exit("Subor sa nenasiel")
    packets = sc.rdpcap(fileName + ".pcap")

    number_of_packet = 1
    ofile = open('ofile.txt', 'w', encoding='utf-8')

    for p in packets:                                                     # Cyklus prechadzajuci cez cely pcap
        packet = sc.raw(p)                                                # Bytes
        packet_length = len(packet)                                       # Zistenie velkosti ramca
        print_number_of_packet(number_of_packet, ofile)                    # Funkcia pre vypis cisla ramca
        lenght_of_packet(packet_length, ofile)                                   # Funkcia pre vypis velkosti ramca
        type_of_packet(packet, number_of_packet, True, packets, ofile)           # Zistovanie typu ramca (Analyza)
        print_packet(packet, ofile)
        number_of_packet += 1
        ofile.write(40 * "-" + "\n")
    ipv4_max(ofile)
    ofile.close()
    end_of_loop = True
    flag = False
    while end_of_loop:
        print("Pre vypis HTTP komunikacie stlacte 1.")
        print("Pre vypis HTTPS komunikacie stlacte 2.")
        print("Pre vypis TELNET komunikacie stlacte 3.")
        print("Pre vypis FTP - control komunikacie stlacte 4.")
        print("Pre vypis FTP - data komunikacie stlacte 5.")
        print("Pre vypis SSH komunikacie stlacte 6.")
        print("Pre vypis TFTP komunikacie stlacte 7.")
        print("Pre vypis ICMP komunikacie stlacte 8.")
        print("Pre vypis ARP komunikacie stlacte 9.")
        print("Pre ukoncenie stlacte 0.")
        number = input("Zadajte cislo: ")
        if not flag:
            ofile_com = open('ofilecom.txt', 'w', encoding='utf-8')
            flag = True

        if number == "1":
            tcp_comunication(packets, http, 80, "http", ofile_com)
        elif number == "2":
            tcp_comunication(packets, https, 443, "https", ofile_com)
        elif number == "3":
            tcp_comunication(packets, telnet, 23, "TELNET", ofile_com)
        elif number == "4":
            tcp_comunication(packets, ftp_c, 21, "FTP - control", ofile_com)
        elif number == "5":
            tcp_comunication(packets, ftp_d, 20, "FTP - data", ofile_com)
        elif number == "6":
            tcp_comunication(packets, ssh, 22, "SSH", ofile_com)
        elif number == "7":
            copy = tftp
            tftp_comunication(packets, copy, ofile_com)
        elif number == "8":
            copy = icmp
            icmp_comunication(packets, copy, 1, ofile_com)
        elif number == "9":
            copy = arp
            arp_comunication(packets, copy, ofile_com)
        elif number == "0":
            end_of_loop = False
        else:
            print("Zadali ste nespravny vstup.")
    ofile_com.close()