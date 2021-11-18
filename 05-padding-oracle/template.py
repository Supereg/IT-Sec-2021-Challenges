import binascii
import socket
import telnetlib

# If you have done that, copy over a hexlified message + IV over to this script (replacing the zeros)
iv = binascii.unhexlify("f6c44fe914e6988f8cd2ee2f1f9c3bbe")
msg = binascii.unhexlify("4d89d4225d51ecc7d81974faa9d935858da8179d5a7a42f47ad861f63bd5dab78f738f910c56412dcb182663be7655608bbca94f4c2ce324a66a8a0c38f095ef")

# AES Blöcke sind 16 Byte groß
# Das heißt, die verschlüsselte Nachricht hat 4 Blöcke
# Die könnte man mit diesen print Befehlen einzeln anzeigen lassen,
# wenn einem das hilft. Mir hilft das. Ich schäme mich nicht für
# meine Vorliebe von print Statements

#print(binascii.hexlify(msg[0:16]))
#print(binascii.hexlify(msg[16:32]))
#print(binascii.hexlify(msg[32:48]))
#print(binascii.hexlify(msg[48:64]))

# Wir brauchen im Folgenden eine XOR Operation auf byte arrays.
# Ich dachte python hat doch für jeden scheiß ne bultin function.
# Also hab ich das ge-google-t (streng genommen ge-duckduckgo-t),
# scheinbar gibt's da keine built-in function.
# Also hab ich das da kopiert. Funktioniert.
# copyright notice: stolen from https://nitratine.net/blog/post/xor-python-byte-strings/
def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def read_until(s, token):
    """Reads from socket `s` until a string `token` is found in the response of the server"""
    buf = b""
    while True:
        data = s.recv(2048)
        buf += data
        if not data or token in buf:
            return buf

def get_zeros(count):
    zeros = []
    for i in range(count):
        zeros.append(0x00)
    return zeros

# Wir brauchen für den Padding Oracle Angriff einen EVIL byte array
# der dann mit den ciphertext ge-xor-t wird.
# Nachdem wir die erste Stelle geknackt haben, wollen wir bei den 
# weiteren Stellen weiter bruteforcen.
# Die erste Stelle von rechts wird auf das Padding 0x01 geknackt.
# Dafür brauchen wir die Funktion noch nicht. Ab der zweiten Stelle
# von rechts können wir dadurch, dass wir den cleartext von weiter
# rechts schon wissen, berechnen, welche bytes wir rechts vom aktuellen
# bruteforce-byte brauchen.
# Das wird gemacht indem wir (gewünschtes Padding) XOR (geknackter Wert)
# rechnen.
# Diese Funktion macht das für alle Stellen rechts von target_padding
# anhand der geknackten Werte in buffer
def get_xor_text_from_cleartext_for(target_padding, buffer):
    xor_text = []
    for i in reversed(range(target_padding-1)):
        xor_text.append(
            target_padding ^ buffer[len(buffer) - i - 1]
        )
    return xor_text

# Das ist die Hauptfunktion.
# Sie knackt einen der vier Buffer.
# Als Parameter werden übergeben:
#  - side_effects_from: der Teil auf den der modifizierte byte array ge-xor-t wird
#  - decryption_part: der Teil der entschlüsselt wird
def get_flag_part(side_effects_from, decryption_part):

    # In diesem Puffer wird nach jedem Zeichen der geknackte ciphertext als cleartext gespeichert und
    # für weitere Berechnungen von get_xor_text_from_cleartext_for vorgehalten
    buffer = ([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

    for i in range(16): # Für jedes Zeichen im aktuellen AES Block
        for j in range(256): # Probiere alle Möglichkeiten für jedes Byte

            current_pos = (j+1) % 256 # Wir fangen bei 1 an und machen 0 als letztes, weil sonst bei einer 
                                      # richtig gepaddeten Nachricht gleich schluss ist und wir dann keinen
                                      # Erkenntnisgewinn hätten.
            
            # Bauen vom XOR array.
            # Wir brauchen:
            #  - zuerst lauter 0en
            #  - dann unser bruteforce Byte
            #  - dann alle berechneten XOR-bytes für das gesuchte padding (ab dem 2.)
            xor_bytes = bytes(get_zeros(16-(i+1)) + [current_pos] + get_xor_text_from_cleartext_for((i+1), buffer))
            
            # Die Ausgabe kann man ausschalten.
            # Das aht aber zwei Nachteile: man merkt vielleicht nicht wenn was broken ist 
            # und man kann die abgefilmte Ausgabe nicht mehr für eine Hacking-Szene in einer ARD Vorabenserie gebrauchen.
            print(binascii.hexlify(xor_bytes))

            # This is were the magic happens (part of)
            # Wir xor-en unseren vorbereiteten evil-xor-array mit dem side_effects_from und hängen dann
            # noch den decryption_part hinten an auf den dann die side effects kommen.
            eviled_msg = byte_xor(side_effects_from, xor_bytes) + decryption_part

            # Senden an den itsec Server
            s = socket.socket()
            s.connect(("itsec.sec.in.tum.de", 7023))

            start = read_until(s, b"Do you")

            s.send(binascii.hexlify(iv) + b"\n")
            s.send(binascii.hexlify(eviled_msg) + b"\n")

            response = read_until(s, b"\n")
            
            # Wenn wir ein richtiges Padding erzeugen konnten, dann können wir
            # jetzt den clear_text berechnen indem wir das gebruteforcete byte
            # mit dem padding, das wir erzeugt haben xor-en.
            if response == b'OK!\n':
                print(response)
                clear_text = current_pos ^ (i+1)
                print(clear_text)
                buffer[len(buffer)-(i+1)] = clear_text
                break

    return buffer

# Das machen wir für alle 4 AES Blöcke und fügen das dann zusammen
clear_text_msg = get_flag_part(iv, msg[0:16]) + get_flag_part(msg[0:16], msg[16:32]) + get_flag_part(msg[16:32], msg[32:48]) + get_flag_part(msg[32:48], msg[48:64])

print("Your flag is:")
print(bytes(clear_text_msg).decode())