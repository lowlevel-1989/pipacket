#!/usr/bin/python3

import socket
import struct

# AF_PACKET is a low-level interface directly to network devices.
# he packets are represented by the tuple (ifname, proto[, pkttype[, hatype[, addr]]])
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)

sock.bind(('lo', 0))

# (layer 2) Ethernet II header, 14 bytes
l2 = struct.pack('!6s6s2s',

                b'\x00\x00\x00\x00\x00\x00', # mac dst
                b'\x00\x00\x00\x00\x00\x00', # mac src
                b'\x08\x00', )               # IPv4

# (layer 3) IPv4 header
l3 = struct.pack('!ccHH2sBBH4s4s',

                # [4 bits] version 0100 [ipv4]
                # [4 bits] Internet Header Length (IHL) 0101
                # IHL tamaño de la cabecera IPv4, por defecto es 5.
                # 5 × 32 bits = 160 bits = 20 bytes
                # version  IHL
                #    0100 0101 == 0x45
                b'\x45',

                # [6 bits] Differentiated Services Code Point (DSCP)
                # [2 bits] Explicit Congestion Notification (ECN)
                # default 0
                b'\x00',

                # [16 bits] Total Length
                # tamaño del paquete incluyendo el header y el payload.
                # tamaño minimo de 20 bytes sin payload
                # se calcula mas adelante
                0x0000,

                # [16 bits] Identification
                # identificación del datagrama, debe ser un numero unico
                #
                # En nuestro caso por facilidad se asignara a 0.
                0x0000,

                # [3 bits] Flags
                # bit 0: Reserved
                # bit 1: Don't Fragment (DF)
                # bit 2: More Fragments (MF)
                #
                # En nuestro caso 010

                # [16 bits] Fragment offset
                # solo dire que para el primer datagrama es 0
                #
                # el resultado final junto a los flags quedaria de esta
                # manera
                #
                # 01000000 00000000
                #   0x40     0x00
                b'\x40\x00',

                # [8 bits] Time to live (TTL)
                # facil de entender, y facil de investigar =3
                0x0A,

                # [8 bits] Protocol
                # Aqui esta la lista de los protocolos con su identificadores
                # REF: https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
                socket.IPPROTO_ICMP,

                # [16 bits] IPv4 Header checksum
                # se calcula mas adelante xD....
                0x0000,

                # [32 bits] Source IP Address
                # 127.0.0.1
                b'\x7F\x00\x00\01',

                # [32 bits] Destination IP Address
                b'\x7F\x00\x00\01',
)

print('PACKET l2 [{:04X}]:'.format(len(l2)))
for i in range(0, len(l2)):
    print('{:02X}'.format(l2[i]),   end=' ')
print('\n')


print('PACKET l3 [{:04X}]:'.format(len(l3)))

# Patch Total Length
print('Patch Total Length')
print('{:02X} {:02X}'.format(l3[0x2], l3[0x3]))
print('{:02X} {:02X}'.format(len(l3) >> 8 & 0xff,  len(l3) & 0xff))
print()

_l3 = list(l3)

_l3[0x2] = len(l3) >> 8 & 0xff
_l3[0x3] = len(l3) & 0xff

print('IPv4 Header checksum')

_checksum = 0
for i in range(0, len(_l3), 2):

    # aseguramos no provocar un overflow
    if (i+1) < len(_l3):
        # trabajamos con 16 bits aqui
        _checksum = _checksum + ( (_l3[i] << 8)  + _l3[i+1] )
    else:
        _checksum = _checksum + _l3[i]

print('checksum prev:             0x{:05X}'.format(_checksum))

_overflow = _checksum >> 16
print('checksum 16 bits overflow:  0x{:04X}'.format(_overflow))

_checksum = _checksum + _overflow & 0xffff
print('checksum + carry:           0x{:04X}'.format(_checksum))
print()

# One's Complement
print("One's Complement")

_checksum = ~_checksum & 0xffff
print('Logical NOT (~) checksum:   0x{:04X}'.format(_checksum), end='\n\n')

# patch checksum
print('Patch checksum')
print('{:02X} {:02X}'.format(_l3[0xA], _l3[0xB]))
print('{:02X} {:02X}'.format(_checksum >> 8 & 0xff,  _checksum & 0xff))
print()

_l3[0xA] = _checksum >> 8 & 0xff
_l3[0xB] = _checksum & 0xff

l3 = bytes(_l3)

print('IPv4 Header')
for i in range(0, len(l3)):
    print('{:02X}'.format(l3[i]),   end=' ')
print('\n')

packet = l2 + l3

sock.send(packet)
