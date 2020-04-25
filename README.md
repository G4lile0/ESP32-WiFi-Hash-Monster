# ESP32 WiFi Hash Monster

<p align="center">
    <a href="https://github.com/G4lile0/ESP32-WiFi-Hash-Monster/blob/master/README.md"><img alt="Software License" src="https://img.shields.io/badge/License-MIT-yellow.svg"></a>
    <a href="https://github.com/G4lile0/ESP32-WiFi-Hash-Monster/graphs/contributors"><img alt="Contributors" src="https://img.shields.io/github/contributors/G4lile0/ESP32-WiFi-Hash-Monster"/></a>
    <a href="https://twitter.com/intent/follow?screen_name=g4lile0"><img src="https://img.shields.io/twitter/follow/g4lile0?style=social&logo=twitter" alt="follow on Twitter"></a>
</p>

WiFi Hash Purple Monster, store EAPOL &amp; PMKID packets in an SD CARD using a M5STACK / ESP32 device.

90% of the code is based on the great [PacketMonitor32](https://github.com/spacehuhn/PacketMonitor32/) from   &nbsp; <a href="https://twitter.com/intent/follow?screen_name=spacehuhn"><img src="https://img.shields.io/twitter/follow/spacehuhn?style=social&logo=twitter" alt="follow on Twitter"></a> and the port to [M5Stack](https://m5stack.com/) from [macsbug](https://macsbug.wordpress.com/2018/01/11/packetmonitor32-with-m5stack/). It was a challenge to see if I could mimic the operation of [pwnagotchi](https://github.com/evilsocket/pwnagotchi)
<a href="https://twitter.com/intent/follow?screen_name=pwnagotchi"><img src="https://img.shields.io/twitter/follow/pwnagotchi?style=social&logo=twitter" alt="follow on Twitter"></a> in an ESP32 SoC.

![ui](./images/m5stack_ESP32_hash_monster.jpg)

When a wifi device connect to an AP with WPA2/PSK instead of sharing the wifi key they exchange 4 EAPOL messages, this method is known as the 4-way handshake, capturing these 4 packets is possible to guess the password using dictonary attacks or brute force attack, recentely there is a more efficent way to calculate the wifi key using just one PMKID packet.

Purple Hash Monster capture all the EAPOL / PMKID packets on the SD Card for further analysis.

Short press on first button will change the WiFi channel, long press will enable the SD Card and all EAPOL / PMKID will be stored on the SD-Card.

Short press on the third button will change the backlight brightness, long press will change the brigness of the LED bar.

When a deauth packet is detected left LED bar will became red and for every EAPOL / PMKID detected right LED bar will became green, also de Purple Hash Monster behaviour will change depending on the WiFi trafic and packets detected. 

![ui](./Purple_Hash_Monster_Sprites/64/happy3_64.png) ![ui](./Purple_Hash_Monster_Sprites/64/happy_64.png) ![ui](./Purple_Hash_Monster_Sprites/64/happy4_64.png) ![ui](./Purple_Hash_Monster_Sprites/64/happy2_64.png) ![ui](./Purple_Hash_Monster_Sprites/64/love_64.png)  ![ui](./Purple_Hash_Monster_Sprites/64/surprise_64.png) ![ui](./Purple_Hash_Monster_Sprites/64/angry_64.png)  ![ui](./Purple_Hash_Monster_Sprites/64/bored1_64.png) ![ui](./Purple_Hash_Monster_Sprites/64/bored2_64.png) ![ui](./Purple_Hash_Monster_Sprites/64/bored3_64.png) ![ui](./Purple_Hash_Monster_Sprites/64/sleep1_64.png) ![ui](./Purple_Hash_Monster_Sprites/64/scare_64.png)


Use Arduino IDE to compile it, tested with (ESP32 version 1.0.4) M5stack-fire.

 **Important: PSRAM must be disabled**.


# How guess the WiFi password using brute force attack

**Note:** Cracking an WiFi password using brute force attack for a long WiFi password without GPUs or Cloud help, will be a nightmare but if the password is short or you know the key pattern it will be "easily" cracked. 

Here you have a small guide for linux (Ubuntu) to crack the WiFi password using the files stored on the SD_Card of the Purple Hash Monster using your computer.

First we need to install **hashcat**

<pre>
 sudo apt-get update
 sudo apt install hashcat
</pre>

EAPOL/PMKID stored on the SD-Card are *pcap* files, we have to convert to *hccapx* format to work with hashcat. In terminal from the directory were we have the *pcap* file from the SD-CARD:

<pre>
 wget https://raw.githubusercontent.com/hashcat/hashcat-utils/master/src/cap2hccapx.c
 gcc -o cap2hccapx cap2hccapx.c
 ./cap2hccapx 1.pcap 1.hccapx
</pre>

For example if we know that the wifi password has a lenght of 8 digits we can run the following command, and in few seconds we will have the WiFi Password :)

<pre>
 hashcat --force -m 2500 -a 3 -1 ?d -o cracked 1.hccapx ?1?1?1?1?1?1?1?1
</pre>
















