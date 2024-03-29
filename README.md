# CriptoLab

## Códigos usados:

### Cesar
```
def encrypt(text, s):
    result = ""
    for i in range(len(text)):
        char = text[i]
        if char.isupper():
            result += chr((ord(char) + s - 65) % 26 + 65)
        else:
            result += chr((ord(char) + s - 97) % 26 + 97)
    return result
text = input(" ")
s = int(input(" "))

print("Cifrado: " + encrypt(text, s))
```
**Uso terminal: sudo python3 cesar.py "texto" "numero"**

### PINGV4
```
import argparse
from scapy.all import IP, ICMP, send

def send_text_over_icmp(destination_ip, text):
    for char in text:
        ascii_code = ord(char)
        icmp_packet = IP(dst=destination_ip)/ICMP(type=8, id=ascii_code)
        send(icmp_packet)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send text over ICMP")
    parser.add_argument("destination_ip", help="Destination IP address")
    parser.add_argument("text", help="Text to send")

    args = parser.parse_args()

    send_text_over_icmp(args.destination_ip, args.text)
```
**Uso terminal:  sudo python3 pingv4.py "ip destino" "texto"**

### Decriptor
```
```
**Uso terminal: sudo python3 decriptor.py "nombrepcap".pcap**
