# ESP32 WiFi Hash Monster

<p align="center">
    <a href="https://github.com/G4lile0/ESP32-WiFi-Hash-Monster/blob/master/README.md"><img alt="Software License" src="https://img.shields.io/badge/License-MIT-yellow.svg"></a>
    <a href="https://github.com/G4lile0/ESP32-WiFi-Hash-Monster/graphs/contributors"><img alt="Contributors" src="https://img.shields.io/github/contributors/G4lile0/ESP32-WiFi-Hash-Monster"/></a>
    <a href="https://twitter.com/intent/follow?screen_name=g4lile0"><img src="https://img.shields.io/twitter/follow/g4lile0?style=social&logo=twitter" alt="follow on Twitter"></a>
</p>

WiFi Hash Purple Monster, store EAPOL &amp; PMKID packets in an SD CARD using a M5STACK / ESP32 device.

90% of the code is based on the great [PacketMonitor32](https://github.com/spacehuhn/PacketMonitor32/) from the great &nbsp; <a href="https://twitter.com/intent/follow?screen_name=g4lile0"><img src="https://img.shields.io/twitter/follow/spacehuhn?style=social&logo=twitter" alt="follow on Twitter"></a> and the port to [M5Stack](https://m5stack.com/) from [macsbug](https://macsbug.wordpress.com/2018/01/11/packetmonitor32-with-m5stack/).


When a wifi device connect to an AP with WPA2/PSK instead of sharing the wifi key they exchange 4 EAPOL messages, this method is known as the 4-way handshake, capturing these 4 packets is possible to guess the password using dictonary attacks or brute force attack, recentely there is a more efficent way to calculate the wifi key using just one PMKID packet.

![ui](./images/m5stack_ESP32_hash_monster.jpg)

Purple Hash Monster capture all the EAPOL / PMKID packets on the SD Card for further analysis.

Short press on first button will change the WiFi channel, long press will enable the SD Card and all EAPOL / PMKID will be stored on the SD-Card.

Short press on the third button will change the backlight brightness, long press will change the brigness of the LED bar.

When a deauth packet is detected left LED bar will became red and for every EAPOL / PMKID detected right LED bar will became green, also de Purple Hash Monster behaviour will change depending on the WiFi trafic and packets detected. 

![ui](./Purple_Hash_Monster_Sprites/64/happy3_64.png) ![ui](./Purple_Hash_Monster_Sprites/64/happy_64.png) ![ui](./Purple_Hash_Monster_Sprites/64/happy4_64.png) ![ui](./Purple_Hash_Monster_Sprites/64/happy2_64.png) ![ui](./Purple_Hash_Monster_Sprites/64/love_64.png)  ![ui](./Purple_Hash_Monster_Sprites/64/surprise_64.png) ![ui](./Purple_Hash_Monster_Sprites/64/angry_64.png)  ![ui](./Purple_Hash_Monster_Sprites/64/bored1_64.png) ![ui](./Purple_Hash_Monster_Sprites/64/bored2_64.png) ![ui](./Purple_Hash_Monster_Sprites/64/bored3_64.png) ![ui](./Purple_Hash_Monster_Sprites/64/sleep1_64.png)


Use Arduino IDE to compile it, tested with board (ESP32 version 1.0.4) M5stack-fire.

 **Important: PSRAM must be disabled**.







