// ESP32-WiFi-Hash-Monster
// 90% based on PacketMonitor32 from spacehuhn //  https://github.com/spacehuhn/PacketMonitor32/
// ported to M5stack by 2018.01.11 macsbug  //    https://macsbug.wordpress.com/2018/01/11/packetmonitor32-with-m5stack/
// modify to capture eapol/handshake with new GUI with the Purple Monster by G4lile0  6/oct/2019
// improvements by tobozo 18/nov/2019:
//   - more compliance with M5 Core functions and TFT_eSprite
//   - SD-loadable support with M5Stack-SD-Updater (requires https://github.com/tobozo/M5Stack-SD-Updater/)
//   - now stable when PSRAM enabled
//   - smoother display rendering using 1-bit sprites for UI
//   - conditional RGB led support, enabled only for M5Fire
//   - buttons reassignment:
//     * SD Activation => BtnA (A for Activation)
//     * Brightness => BtnB (B for Brightness)
//     * Channel => BtnC (C for Channel)
//   - seamless Odroid-GO support (if using https://github.com/tobozo/ESP32-Chimera-Core instead of M5Stack Core)
//  added channel auto-switching (configurable) and reduce the amount of drawing by scriptguru  10/April/2020
//
//
//  more info https://miloserdov.org/?p=1047
//  more info https://www.evilsocket.net/2019/02/13/Pwning-WiFi-networks-with-bettercap-and-the-PMKID-client-less-attack/
// DISPLAY: Channel,RSSI,Packet per Second,eapol,deauth packets,SD Card enabled
// Red NeoPixels deauth  -- Green Neopixel eapol
// Button : click to change channel hold to dis/enable SD
// SD : GPIO4=CS(CD/D3), 23=MOSI(CMD), 18=CLK, 19=MISO(D0)
//--------------------------------------------------------------------
//#include <M5Core2.h>        // https://github.com/m5stack/M5Core2/
//#include <M5Stack.h>        // https://github.com/m5stack/M5Stack/    (use version => 0.3.0 to properly display the Monster)
#include <ESP32-Chimera-Core.h>        // https://github.com/tobozo/ESP32-Chimera-Core/

#include <M5StackUpdater.h> // https://github.com/tobozo/M5Stack-SD-Updater/
#include "Free_Fonts.h"
#include <SPI.h>
#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include <stdio.h>
#include <string>
#include <cstddef>

#include <Preferences.h>
#define MAX_CH 13     // 1-14ch(1-11 US,1-13 EU and 1-14 Japan)
#define AUTO_CHANNEL_INTERVAL 15000 // how often to switch channels automatically, in milliseconds
//#define SNAP_LEN 2324 // max len of each recieved packet
#define SNAP_LEN 2324 // limit packet capture for eapol
#define USE_SD_BY_DEFAULT true

#define MAX_X 315     // 315  128
#define MAX_Y 130     // 230 51
#if CONFIG_FREERTOS_UNICORE
#define RUNNING_CORE 0
#else
#define RUNNING_CORE 1
#endif
#include "Buffer.h"
#include "Faces.h"
#include "FS.h"
#include "SD.h"

#ifdef ARDUINO_M5STACK_FIRE
  #include <FastLED.h>
  #define M5STACK_FIRE_NEO_NUM_LEDS 10
  #define M5STACK_FIRE_NEO_DATA_PIN 15
  // Define the array of leds
  CRGB leds[M5STACK_FIRE_NEO_NUM_LEDS];
#endif

esp_err_t event_handler(void* ctx,system_event_t* event){return ESP_OK;}
/* ===== run-time variables ===== */
Buffer sdBuffer;
Preferences preferences;
bool useSD = USE_SD_BY_DEFAULT;

uint32_t lastDrawTime = 0;
uint32_t lastButtonTime = 0;
uint32_t lastAutoSwitchChTime = 0;
int autoChannels[] = {1, 6, 11};
int AUTO_CH_COUNT = sizeof(autoChannels) / sizeof(int);
int autoChIndex = 0;
int smartCh_old_stuff = 0;
uint8_t autoChMode = 0 ; // 0 No auto -  1 Switch channels automatically   - Smart Switch
uint32_t tmpPacketCounter;
uint32_t pkts[MAX_X+1]; // here the packets per second will be saved
uint32_t deauths = 0; // deauth frames per second
uint32_t total_deauths = 0; // deauth total frames
uint32_t graph_deauths = 0; // deauth total frames

uint32_t eapol = 0;         // eapol frames per second
uint32_t total_eapol = 0;   // eapol total frames
uint32_t graph_eapol = 0;   // eapol total frames

unsigned int ch = 1;  // current 802.11 channel
unsigned int old_ch = 20;  // old  802.11 channel
unsigned int bright = 100;  // default
unsigned int bright_leds = 100;  // default
unsigned int led_status = 0;
unsigned int ledPacketCounter = 0;

int rssiSum;

TFT_eSprite graph1 = TFT_eSprite(&M5.Lcd); // Sprite object graph1
TFT_eSprite graph2 = TFT_eSprite(&M5.Lcd); // Sprite object graph2
TFT_eSprite units1 = TFT_eSprite(&M5.Lcd); // Sprite object units1
TFT_eSprite units2 = TFT_eSprite(&M5.Lcd); // Sprite object units2
TFT_eSprite face1  = TFT_eSprite(&M5.Lcd); // Sprite object face
TFT_eSprite header = TFT_eSprite(&M5.Lcd); // Sprite object header
TFT_eSprite footer = TFT_eSprite(&M5.Lcd); // Sprite object footer

int graph_RSSI = 1;
int delta = 1;
int grid = 0;
int tcount = 0;

char    last_ssid[33];
int8_t  last_rssi;
char  last_eapol_ssid[33];


/*
 * Convert Ethernet address to standard hex-digits-and-colons printable form.
 * Re-entrant version (GNU extensions).
 * Inspired from https://android.googlesource.com/platform/bionic/+/master/libc/bionic/ether_ntoa.c
 */
char *ether_ntoa_r( const uint8_t *addr, char * buf )
{
  snprintf( buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
    addr[0], addr[1],
    addr[2], addr[3],
    addr[4], addr[5]
  );
  return buf;
}
/*
 * Convert Ethernet address to standard hex-digits-and-colons printable form.
 * Inspired from https://android.googlesource.com/platform/bionic/+/master/libc/bionic/ether_ntoa.c
 */
char *ether_ntoa( const uint8_t *addr )
{
  static char buf[18];
  return ether_ntoa_r( addr, buf );
}



/*
 * Data structure for beacon information
 */

#define MAX_SSIDs 1792

struct ssid_info {
  uint8_t mac[6];
  uint8_t ssid[33];
  uint8_t ssid_len;
  bool    ssid_eapol;     // to mark if we already have the eapol.
};


/*
 * Global variables for storing beacons and clients
 */
ssid_info ssid_known[MAX_SSIDs];
uint32_t ssid_count = 0;  //
uint32_t ssid_eapol_count= 0;       // eapol frames per second


// ===== main program ================================================
void setup() {
  #ifdef ARDUINO_M5STACK_FIRE
    // load these before M5.begin() so they can eventually be turned off
    FastLED.addLeds<WS2812B, M5STACK_FIRE_NEO_DATA_PIN, GRB>(leds, M5STACK_FIRE_NEO_NUM_LEDS);
    FastLED.clear();
    FastLED.show();
  #endif
  M5.begin(); // this will fire Serial.begin()
  // New SD Updater support, requires the latest version of https://github.com/tobozo/M5Stack-SD-Updater/
  checkSDUpdater( /*SD, MENU_BIN, 1500*/ ); // Filesystem, Launcher bin path, Wait delay
  // SD card ---------------------------------------------------------
  bool toggle = false;
  unsigned long lastcheck = millis();
  M5.Lcd.fillScreen(TFT_BLACK);
  while( !SD.begin( TFCARD_CS_PIN ) ) {
    toggle = !toggle;
    M5.Lcd.setTextColor( toggle ? TFT_BLACK : TFT_WHITE );
    M5.Lcd.drawString( "INSERT SD", 160, 84, 2 );
    delay( toggle ? 300 : 500 );
    // go to sleep after a minute, no need to hammer the SD Card reader
    if( lastcheck + 60000 < millis() ) {
      //Serial.println( GOTOSLEEP_MESSAGE );
      #ifdef ARDUINO_M5STACK_Core2
        M5.Axp.SetLcdVoltage(2500);
        M5.Axp.DeepSleep();
      #else
        M5.setWakeupButton( BUTTON_B_PIN );
        M5.powerOFF();
      #endif
    }
  }

  // Settings
  preferences.begin("packetmonitor32", false);
  ch = preferences.getUInt("channel", 1);
  preferences.end();

  // System & WiFi ---------------------------------------------------
  nvs_flash_init();
  tcpip_adapter_init();

  //  wificfg.wifi_task_core_id = 0;

  Serial.println("flash init //tcp init");

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  //ESP_ERROR_CHECK(esp_wifi_set_country(WIFI_COUNTRY_EU));
  Serial.println("2");
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  Serial.println("3");
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
  Serial.println("4 ");
  ESP_ERROR_CHECK(esp_wifi_start());
  Serial.println("5 ");
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous));
  Serial.println("6 ");
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
  Serial.println("7 ");
  // now switch on monitor mode
  // ESP_ERROR_CHECK(esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE));
  Serial.println("8 ");
  Serial.println("wifi done");
  delay(1000);

  // display -------------------------------------------------------
  #ifdef ARDUINO_M5STACK_Core2
    // specific M5Core2 tweaks go here
  #else
    M5.Speaker.write(0); // Speaker OFF
  #endif

  M5.Lcd.clear();
  M5.Lcd.setTextColor(TFT_WHITE, TFT_BLACK);
  M5.Lcd.setTextSize(0);
  /* show start screen */
  M5.Lcd.setFreeFont(FM12);
  M5.Lcd.drawString( "Purple Hash Monster", 6, 24);
  M5.Lcd.drawString( "by @g4lile0", 29, 44);
  M5.Lcd.drawString( "90% PacketMonitor32", 6, 74);
  M5.Lcd.drawString( "by @Spacehuhn", 29, 94);
  M5.Lcd.setSwapBytes(true);
  M5.Lcd.pushImage(200, 158, 64, 64, (uint16_t*)love_64);
  delay( 3000 );

  if (useSD) Serial.println("pues esta encendido");

  sdBuffer = Buffer();

  if (setupSD()){
    sdBuffer.checkFS(&SD);
    if( sdBuffer.open(&SD) ) {
      Serial.println(" SD CHECK OPEN");
    } else {
      Serial.println(" SD ERROR, Can't create file");
      useSD = false;
    }
  } else {
    // SD setup failed, card not inserted ?
  }

  if (useSD) {
    Serial.println("pues esta encendido2");
  }
  useSD = USE_SD_BY_DEFAULT;

  // second core ----------------------------------------------------

  // Create a sprite for the header
  header.setColorDepth(1);
  header.createSprite(320, 20);
  header.setFreeFont(FM9);
  header.setTextColor( TFT_BLACK, TFT_BLUE ); // unintuitive: use black/blue mask
  header.setTextDatum(TL_DATUM);
  header.setBitmapColor( TFT_BLUE, TFT_WHITE ); // mask will be converted to this color
  header.fillSprite(TFT_BLUE);

  // Create a sprite for the footer
  footer.setColorDepth(1);
  footer.createSprite(320, 40);
  footer.setFreeFont(FM9);
  footer.setTextColor( TFT_BLACK, TFT_BLUE ); // unintuitive: use black/blue mask
  footer.setTextDatum(TL_DATUM);
  footer.setBitmapColor( TFT_BLUE, TFT_WHITE ); // mask will be converted to this color
  footer.fillSprite(TFT_BLUE);

  // Create a sprite for the graph1
  graph1.setColorDepth(8);
  graph1.createSprite(128+50, 61); // graph1.pushSprite( 90, 138 );
  graph1.setTextColor(TFT_WHITE,TFT_BLACK);
  graph1.setFreeFont(FM9);
  graph1.fillSprite(TFT_BLACK);

  // Create a sprite for the graph2
  graph2.setColorDepth(1);
  graph2.createSprite(MAX_X-40, 100);
  graph2.setBitmapColor( TFT_GREEN, TFT_BLACK );
  graph2.fillSprite(TFT_BLACK);

  // create a sprite for units1
  units1.setColorDepth(1);
  units1.createSprite(40, 120);
  units1.setFreeFont(FM9);
  units1.setTextColor( TFT_WHITE, TFT_BLACK );
  units1.setBitmapColor( TFT_WHITE, TFT_BLACK);  // Pkts Scale
  units1.setTextDatum(MR_DATUM);
  units1.fillSprite(TFT_BLACK);

  // create a sprite for units2
  units2.setColorDepth(8);
  units2.createSprite(52, 64);
  units2.setTextDatum( TR_DATUM );
  units2.fillSprite(TFT_BLACK);

  // Create a sprite for the monster
  face1.setColorDepth(16);
  face1.createSprite(64, 64);
  face1.fillSprite(TFT_BLACK); // Note: Sprite is filled with black when created
  #ifdef _CHIMERA_CORE_
    face1.setSwapBytes(true);
  #else
    face1.setSwapBytes(false);
  #endif
  M5.Lcd.clear();

  // The scroll area is set to the full sprite size upon creation of the sprite
  // but we can change that by defining a smaller area using "setScrollRect()"if needed
  // parameters are x,y,w,h,color as in drawRect(), the color fills the gap left by scrolling
  //graph1.setScrollRect(64, 0, 64, 61, TFT_DARKGREY);  // Try this line to change the graph scroll area
  xTaskCreatePinnedToCore(
    coreTask,               /* Function to implement the task */
    "coreTask",             /* Name of the task */
    8192,                   /* Stack size in words */
    NULL,                   /* Task input parameter */
    0,                      /* Priority of the task */
    NULL,                   /* Task handle. */
    RUNNING_CORE);          /* Core where the task should run */
  // start Wifi sniffer ---------------------------------------------
  #ifdef ARDUINO_M5STACK_FIRE
  xTaskCreatePinnedToCore(&blinky, "blinky", 2500,NULL,1,NULL,1);
  #endif

}


// ===== main program ================================================
void loop() {
  //vTaskDelay(portMAX_DELAY);
  // no need to waste a cycle for an empty loop
  vTaskSuspend(NULL);
}


// ===== functions ===================================================
double getMultiplicator( uint32_t range ) {
  uint32_t maxVal = 1;
  for (int i = 40; i < MAX_X; i++) {
    if (pkts[i] > maxVal) maxVal = pkts[i];
  }
  if (maxVal > 0) {
    return (double)range / (double)maxVal;
  }
  return 1;
}


// ===== functions ===================================================
void setChannel(int newChannel) {
  ch = newChannel;
  if (ch > MAX_CH || ch < 1) ch = 1;
  // avoid to write too much on the flash in auto-switching mode
  if (autoChMode == 0) {
    preferences.begin("packetmonitor32", false);
    preferences.putUInt("channel", ch);
    preferences.end();
  }
  //esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous);
  //  esp_wifi_set_promiscuous(true);
}


void autoSwitchChannel(uint32_t currentTime) {
  autoChIndex = (autoChIndex + 1) % AUTO_CH_COUNT;
  setChannel(autoChannels[autoChIndex]);
  Serial.print("Auto-switching to channel ");
  Serial.println(ch);
  lastAutoSwitchChTime = currentTime;
}


void smartSwitchChannel(uint32_t currentTime) {
  lastAutoSwitchChTime = currentTime;

  if (smartCh_old_stuff < ssid_count+total_eapol+total_deauths) {
    smartCh_old_stuff = ssid_count+total_eapol+total_deauths;
    Serial.println(" Interesting channel new stuff detected :) ");
  } else {
    smartCh_old_stuff = ssid_count+total_eapol+total_deauths;
    ch = (ch + 1) % (MAX_CH + 1);
    setChannel(ch);
    Serial.print(" Boring, smart-switching to channel ");
    Serial.println(ch);
  }
}



// ===== functions ===================================================

static bool SDSetupDone = false;

bool setupSD() {
  if( SDSetupDone ) return true;
  SD.end();
  int attempts = 20;
  do {
    SDSetupDone = SD.begin( TFCARD_CS_PIN );
  } while( --attempts > 0 && ! SDSetupDone );

  if (!SDSetupDone ) {
    Serial.println("Card Mount Failed"); return false;
  }
  uint8_t cardType = SD.cardType();
  if (cardType == CARD_NONE) {
    SDSetupDone = false;
    Serial.println("No SD_MMC card attached"); return false;
  }
  Serial.print("SD_MMC Card Type: ");
  if (cardType == CARD_MMC) {
    Serial.println("MMC");
  } else if (cardType == CARD_SD) {
    Serial.println("SDSC");
  } else if (cardType == CARD_SDHC) {
    Serial.println("SDHC");
  } else {
    Serial.println("UNKNOWN");
  }
  uint64_t cardSize = SD.cardSize() / (1024 * 1024);
  Serial.printf("SD_MMC Card Size: %lluMB\n", cardSize);
  SDSetupDone = true;
  return true;
}

// ===== functions ===================================================

#define DATA_LENGTH           112
#define TYPE_MANAGEMENT       0x00
#define TYPE_CONTROL          0x01
#define TYPE_DATA             0x02
#define SUBTYPE_PROBE_REQUEST 0x04
#define SUBTYPE_PROBE_RESPONSE 0x05
#define SUBTYPE_BEACONS        0x08


struct RxControl {
  signed rssi:8; // signal intensity of packet
  unsigned rate:4;
  unsigned is_group:1;
  unsigned:1;
  unsigned sig_mode:2; // 0:is 11n packet; 1:is not 11n packet;
  unsigned legacy_length:12; // if not 11n packet, shows length of packet.
  unsigned damatch0:1;
  unsigned damatch1:1;
  unsigned bssidmatch0:1;
  unsigned bssidmatch1:1;
  unsigned MCS:7; // if is 11n packet, shows the modulation and code used (range from 0 to 76)
  unsigned CWB:1; // if is 11n packet, shows if is HT40 packet or not
  unsigned HT_length:16;// if is 11n packet, shows length of packet.
  unsigned Smoothing:1;
  unsigned Not_Sounding:1;
  unsigned:1;
  unsigned Aggregation:1;
  unsigned STBC:2;
  unsigned FEC_CODING:1; // if is 11n packet, shows if is LDPC packet or not.
  unsigned SGI:1;
  unsigned rxend_state:8;
  unsigned ampdu_cnt:8;
  unsigned channel:4; //which channel this packet in.
  unsigned:12;
};


struct SnifferPacket{
  struct RxControl rx_ctrl;
  uint8_t data[DATA_LENGTH];
  uint16_t cnt;
  uint16_t len;
};


char * wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type) {
  switch(type) {
    case WIFI_PKT_MGMT: return (char*)"MGMT";
    case WIFI_PKT_DATA: return (char*)"DATA";
    default:
    case WIFI_PKT_MISC: return (char*)"MISC";
  }
}

/*
// deprecated, see ether_ntoa()
static void getMAC(char *addr, uint8_t* data, uint16_t offset) {
  sprintf(addr, "%02x:%02x:%02x:%02x:%02x:%02x", data[offset+0], data[offset+1], data[offset+2], data[offset+3], data[offset+4], data[offset+5]);
}
*/


static void setLastSSID(uint16_t start, uint16_t size, uint8_t* data) {
  int u=0;
  for(uint16_t i = start; i < DATA_LENGTH && i < start+size; i++) {
    //Serial.write(data[i]);
    last_ssid[u]=data[i];
    u++;
  }
  last_ssid[u]=0;
  //Serial.print("SSID Char:");
  //Serial.println(last_ssid);
}


void wifi_promiscuous(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)pkt->rx_ctrl;

  if (type == WIFI_PKT_MISC) return;   // wrong packet type
  if (ctrl.sig_len > 293) return; // packet too long    if (ctrl.sig_len > SNAP_LEN) return;
  uint32_t packetLength = ctrl.sig_len;
  if (type == WIFI_PKT_MGMT) packetLength -= 4;
  // fix for known bug in the IDF
  // https://github.com/espressif/esp-idf/issues/886
  //Serial.print(".");
  tmpPacketCounter++;
  rssiSum += ctrl.rssi;
  unsigned int u;

  if (type == WIFI_PKT_MGMT &&  (pkt->payload[0] == 0xA0 || pkt->payload[0] == 0xC0 )) {
    deauths++;
    //      if (useSD) sdBuffer.addPacket(pkt->payload, packetLength);
    // deauth
    #ifdef ARDUINO_M5STACK_FIRE
      for (int pixelNumber = 5; pixelNumber < 10; pixelNumber++){
        leds[pixelNumber].setRGB( bright_leds, 0, 0);;
      }
      FastLED.show();
    #endif
  }

  if (( (pkt->payload[30] == 0x88 && pkt->payload[31] == 0x8e)|| ( pkt->payload[32] == 0x88 && pkt->payload[33] == 0x8e) )){
    eapol++;  // new eapol packets :)

    #ifdef ARDUINO_M5STACK_FIRE
      // turn right led in green
      for (int pixelNumber = 0; pixelNumber <= 4; pixelNumber++){
        leds[pixelNumber].setRGB(  0,bright_leds, 0);
      }
      FastLED.show();
    #endif

    log_d("Got EAPOL ...");

    memcpy( &ssid_known[MAX_SSIDs-1].mac, pkt->payload+16, 6 );   // MAC source HW address

    for (u = 0; u < ssid_count; u++) {
      if (!memcmp(ssid_known[u].mac, ssid_known[MAX_SSIDs-1].mac, 6))  {
        // only if is new print it
        if (!ssid_known[u].ssid_eapol) {
          ssid_eapol_count++;
          ssid_known[u].ssid_eapol = true;
          for(int i = 0; i < ssid_known[u].ssid_len ; i++) {
            last_eapol_ssid[i] = ssid_known[u].ssid[i];
          }
          last_eapol_ssid[ssid_known[u].ssid_len+1]=0;
          Serial.printf("[EAPOL] Found new MAC: %s (SSID: %s)\n",
            ether_ntoa(ssid_known[u].mac),
            last_eapol_ssid
          );
        }
        break;
      }
    }
    //  uint8_t SSID_length = pkt->payload[25];
    //  Serial.println(" SSID: ");
    //  setLastSSID(26, SSID_length, pkt->payload);
    if (useSD) {
      sdBuffer.addPacket(pkt->payload, packetLength);
    }
  }

  //  if (type != WIFI_PKT_MGMT )  return;
  // We add the packets only for prove

  unsigned int frameControl = ((unsigned int)pkt->payload[1] << 8) + pkt->payload[0];

  uint8_t version      = (frameControl & 0b0000000000000011) >> 0;
  uint8_t frameType    = (frameControl & 0b0000000000001100) >> 2;
  uint8_t frameSubType = (frameControl & 0b0000000011110000) >> 4;
  uint8_t toDS         = (frameControl & 0b0000000100000000) >> 8;
  uint8_t fromDS       = (frameControl & 0b0000001000000000) >> 9;

  /*
  // Only look for probe request packets
  if (frameType != TYPE_MANAGEMENT ||
  //  frameSubType != SUBTYPE_PROBE_REQUEST ||
    frameSubType != SUBTYPE_PROBE_RESPONSE ||
    frameSubType != SUBTYPE_BEACONS ||
    frameSubType != 0x0028  // QoS Data
    ) return;
  //if  (!((frameSubType == SUBTYPE_PROBE_RESPONSE) || (frameSubType == SUBTYPE_BEACONS ) || (frameSubType == 0x0028))) return;
  //if  ((frameSubType == SUBTYPE_PROBE_RESPONSE) || (frameSubType == SUBTYPE_BEACONS )) {
  */

  if ((frameSubType == SUBTYPE_BEACONS) && (version == 0) ) {
    uint8_t SSID_length = pkt->payload[37];
    if (SSID_length>32) return;

    bool ascii_error = false;
    for (u =0; u<SSID_length;u++) {
      if (!isprint(pkt->payload[38+u])) {
        log_w("NO IMPRI %02d - %02d", u , SSID_length );
        ascii_error = true;
      }
      if (!isAscii(pkt->payload[38+u])) {
        log_w("NO ASCII %02d - %02d", u , SSID_length );
        ascii_error = true;
      }
    }

    if (ascii_error) return;

    memcpy(&ssid_known[MAX_SSIDs-1].mac,pkt->payload+16,6);

    bool known = false;
    for (u = 0; u < ssid_count; u++) {
      if (!memcmp(ssid_known[u].mac, ssid_known[MAX_SSIDs-1].mac, 6))  {
        known = true;
        break;
      }
    }

    if (!known) {
      // only write the beacon packet the first time that we see it, to reduce writing on the SD-CARD.
      if (useSD) sdBuffer.addPacket(pkt->payload, packetLength);

      memcpy( &ssid_known[ssid_count].mac,  &ssid_known[MAX_SSIDs-1].mac ,6);
      memcpy( &ssid_known[ssid_count].ssid, pkt->payload+38, SSID_length);
      ssid_known[u].ssid_len = SSID_length;
      ssid_count++;
      setLastSSID( 38, SSID_length, pkt->payload );
      last_rssi = pkt->rx_ctrl.rssi;

      Serial.printf("SSID count: %4d | Pack length: %4d  | SSID: %32s | RSSI: %4d\n",
        ssid_count,
        packetLength,
        last_ssid,
        last_rssi
      );
    }
  }

  //#define SUBTYPE_PROBE_REQUEST 0x04
  //#define SUBTYPE_PROBE_RESPONSE 0x05
  //#define SUBTYPE_BEACONS        0x08

  if (frameType != TYPE_MANAGEMENT )  return;

  // Only look for probe request packets
  // if (frameType != TYPE_MANAGEMENT ||
  // frameSubType != SUBTYPE_PROBE_REQUEST
  //  )
  //        return;

  //  Serial.print(ctrl.rssi, DEC);
  //Serial.print(".");
  //Serial.println("");
  //Serial.printf("PACKET TYPE=%s CHAN=%02d, RSSI=%02d ",wifi_sniffer_packet_type2str(type),ctrl.channel,ctrl.rssi);
  //Serial.printf("PACKET TYPE=%s CHAN=%02d, RSSI=%02d ",wifi_sniffer_packet_type2str(type),pkt->rx_ctrl.channel,pkt->rx_ctrl.rssi);

  // Deprecated :
  // char addr[] = "00:00:00:00:00:00";
  // getMAC(addr, pkt->payload, 10);

  // log_d("MAC: %s", ether_ntoa( pkt->payload+10 ) );

  //  Serial.print(" Peer MAC: ");
  //  Serial.print(addr);

  //  uint8_t SSID_length = pkt->payload[25];
  //  Serial.print(" SSID: ");
  //  setLastSSID(26, SSID_length, pkt->payload);
}
// ===== functions ===================================================


char headerStr[64] = {0};
// header text template
const char* headerTpl = "%s:%02d|AP:%d|Pkts:%d[%d][%d]%s";

void draw() {

  int len, rssi;
  if (pkts[MAX_X - 1] > 0)
    rssi = rssiSum / (int)pkts[MAX_X - 1];
  else
    rssi = rssiSum;

  graph_RSSI= rssi;
  draw_RSSI();
  total_eapol += eapol;
  graph_eapol += eapol;
  total_deauths += deauths;
  graph_deauths += deauths;

  char modeStr[2] = {0,0};

  switch( autoChMode ) {
    case 0: modeStr[0] = 'C'; break;
    case 1: modeStr[0] = 'A'; break;
    case 2: modeStr[0] = 'S'; break;
  }

  sprintf( headerStr, headerTpl,
    modeStr,
    ch,
    ssid_count,
    tmpPacketCounter,
    eapol,
    deauths,
    useSD ? "|SD" : ""
  );

  header.fillSprite( TFT_BLUE );
  header.drawString(headerStr, 4, 2); // string DRAW
  header.pushSprite( 0, 0 );

  uint16_t toppos = MAX_Y-100;
  double multiplicator = getMultiplicator( 100 );

  double maxval = 100 / multiplicator;

  int noceil = maxval;
  int toceil = 10 - (noceil%10);
  if( toceil !=10 ) {
    maxval = noceil + toceil; // round it up
    multiplicator = 100 / maxval;
  }

  double valstep = maxval / 5;

  int s = 10, a = 0;
  units1.fillSprite( TFT_BLACK );

  for ( int ypos = MAX_Y, idx = 0; ypos > 70; ypos = ypos - s ){
    units1.drawString(String( int( idx * valstep ) ), 30, ypos - 1 - a - 20);
    //units1.drawString(String( (MAX_Y - ypos)*2 ), 30, ypos - 1 - a - 20);
    a = a + 10;
    idx++;
  }
  units1.pushSprite( 0, 20 );

  graph2.drawLine(0, 0, MAX_X, 0, 1);// MAX LINE DRAW

  for (int i = 40; i < MAX_X; i++) {                  // LINE DRAW
    len = pkts[i] * multiplicator;
    //len = len * 2;
    //if ( ((MAX_Y-toppos) - len) < ((MAX_Y-toppos) - 100)){ len = 100;}  // over flow
    graph2.drawLine(i-40, 100, i-40, 1, 0);      // LINE ERASE
    graph2.drawLine(i-40, 100, i-40, 100 - len, 1);// LINE DRAW

    if (i < MAX_X - 1) pkts[i] = pkts[i + 1];
  }

  graph2.pushSprite( 40, MAX_Y-100 );

  byte aleatorio; // = random (1,10);

  if ((deauths>0) && (eapol==0)) {
    face1.pushImage(0, 0, 64, 64, angry_64);
  }

  if (tmpPacketCounter<10) {
    aleatorio = random (1,5);
    switch (aleatorio) {
      case 1:  face1.pushImage(0, 0, 64, 64, bored1_64); break;
      case 2:  face1.pushImage(0, 0, 64, 64, bored2_64); break;
      case 3:  face1.pushImage(0, 0, 64, 64, bored3_64); break;
      case 4:  face1.pushImage(0, 0, 64, 64, sleep1_64); break;
      default: face1.pushImage(0, 0, 64, 64, sleep2_64); break;
    }
  }

  if (tmpPacketCounter>500) {
    aleatorio = random (1,2);
    switch (aleatorio) {
      case 1:  face1.pushImage(0, 0, 64, 64, scare_64);    break;
      default: face1.pushImage(0, 0, 64, 64, surprise_64); break;
    }
  }

  if ((eapol==0) && (deauths==0) && (tmpPacketCounter>10)) {
    aleatorio = random (1,5);
    switch (aleatorio) {
      case 1:  face1.pushImage(0, 0, 64, 64, happy_64);  break;
      case 2:  face1.pushImage(0, 0, 64, 64, happy2_64); break;
      case 3:  face1.pushImage(0, 0, 64, 64, happy3_64); break;
      default: face1.pushImage(0, 0, 64, 64, happy4_64); break;
    }
  }

  if (eapol>0)   {
    face1.pushImage(0, 0, 64, 64, love_64);
  }

  face1.pushSprite(10, 140);

  draw_RSSI();

}


void draw_RSSI() {

  units2.fillSprite( TFT_BLACK );

  units2.setTextColor( TFT_YELLOW, TFT_BLACK );
  units2.drawNumber( graph_RSSI,       44, 0, 2 );

  units2.setTextColor( TFT_GREEN,  TFT_BLACK );
  units2.drawNumber( total_eapol,      44, 16,2 );

  units2.setTextColor( TFT_RED,    TFT_BLACK );
  units2.drawNumber( total_deauths,    44, 32, 2 );

  units2.setTextColor( TFT_WHITE,  TFT_BLACK );
  units2.drawNumber( ssid_eapol_count, 44, 48, 2 );

  units2.pushSprite( 268, 136 );

  footer.fillSprite( TFT_BLUE );
  String p = "New SSID:"+(String)last_ssid +" "+(String)last_rssi ;
  footer.drawString(p, 4 , 3);                 // string DRAW
  p = "New HS: "+(String)last_eapol_ssid;
  footer.drawString(p, 4 , 3+17);                 // string DRAW
  footer.pushSprite( 0, 138+32+32 );

  // Draw point in graph1 sprite at far right edge (this will scroll left later)
  if (graph_RSSI != 0)  graph1.drawFastVLine( 127+50, -(graph_RSSI/2), 2, TFT_YELLOW); // draw 2 pixel point on graph

  if (graph_eapol>59) graph_eapol=0;
  if (graph_eapol != 0)  graph1.drawFastVLine( 127+50, 60-constrain(graph_eapol,1,60), 2, TFT_GREEN); // draw 2 pixel point on graph

  if (graph_deauths>59) graph_deauths=0;
  if (graph_deauths != 0)  graph1.drawFastVLine( 127+50, 60-constrain(graph_deauths,1,60), 2, TFT_RED); // draw 2 pixel point on graph

  // write the channel on the scroll window.
  if (ch != old_ch){
    old_ch=ch;
    graph1.drawString( "  ", 127+50-25, 1 );
    graph1.drawNumber( ch,   127+50-17, 1, 2 );
  }
  // Push the sprites onto the TFT at specified coordinates
  graph1.pushSprite( 90, 138 );
  // Now scroll the sprites scroll(dt, dy) where:
  // dx is pixels to scroll, left = negative value, right = positive value
  // dy is pixels to scroll, up = negative value, down = positive value
  graph1.scroll(-1, 0); // scroll graph 1 pixel left, 0 up/down

  // Draw the grid on far right edge of sprite as graph has now moved 1 pixel left
  grid++;
  if (grid >= 10) {
    // Draw a vertical line if we have scrolled 10 times (10 pixels)
    grid = 0;
    graph1.drawFastVLine( 127+50, 0, 61, TFT_NAVY ); // draw line on graph
  } else { // Otherwise draw points spaced 10 pixels for the horizontal grid lines
    for (int p = 0; p <= 60; p += 10) graph1.drawPixel( 127+50, p, TFT_NAVY );
  }
  tcount--;
}


// ====== functions ===================================================
void coreTask( void * p ) {
  uint32_t currentTime;
  Serial.println("Setting default channel");
  setChannel(ch);
  Serial.println("Channel set !");
  tmpPacketCounter = 0; // reset to avoid overflow on first render

  while (true) {
    bool needDraw = false;
    currentTime = millis();
    /* bit of spaghetti code, have to clean this up later :D_ */

    if (autoChMode==1) {
      if ( currentTime - lastAutoSwitchChTime > AUTO_CHANNEL_INTERVAL ) {
        autoSwitchChannel(currentTime);
        needDraw = true;
      }
    }

    if (autoChMode==2) {
      if ( currentTime - lastAutoSwitchChTime > AUTO_CHANNEL_INTERVAL ) {
        smartSwitchChannel(currentTime);
        needDraw = true;
      }
    }

    if ( currentTime - lastButtonTime > 100 ) {
      M5.update();
      // buttons assignment :
      //  - SD Activation => BtnA (A for Activation)
      //  - Brightness => BtnB (B for Brightness)
      //  - Channel => BtnC (C for Channel)
      if( M5.BtnA.wasReleased() ) {
        if (bright>1) {
          Serial.println("Incognito Mode");
          bright=0;
          bright_leds=0;
          M5.Lcd.setBrightness(bright);
        } else {
          bright=100;
          bright_leds=100;
          M5.Lcd.setBrightness(bright);
        }
      } else if (M5.BtnA.wasReleasefor(700)) {
        if (useSD) {
          useSD = false;
          sdBuffer.close(&SD);
        } else {
          if (setupSD()) {
            if( !sdBuffer.open(&SD) ) {
              Serial.println(" SD ERROR, Can't create file, disabling SD");
              SDSetupDone = false; // resetting SD state but this is not enough
              useSD = false; // disable SD for the meantime
            }
          }
        }
        needDraw = true;
      }

      if( M5.BtnB.wasReleased() ) {
        bright+=50;
        if (bright>251) bright=0;
        M5.Lcd.setBrightness(bright);
      } else if (M5.BtnB.wasReleasefor(700)) {
        bright_leds+=100;
        if (bright_leds>251) bright_leds=0;
        Serial.println(bright_leds);
      }

      if( M5.BtnC.wasReleased() ) {
        setChannel(ch + 1);
        needDraw = true;
      } else if (M5.BtnC.wasReleasefor(700)) {
        autoChMode++;
        if (autoChMode>2) autoChMode=0;
        Serial.println(autoChMode);
      }

      lastButtonTime = currentTime;
      if (needDraw) draw();
    }

    // save buffer to SD
    if (useSD) sdBuffer.save(&SD);
    // draw Display
    if ( currentTime - lastDrawTime > 1000 ) {
      lastDrawTime = currentTime;
      // Serial.printf("\nFree RAM %u %u\n",
      // heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT),
      // heap_caps_get_minimum_free_size(MALLOC_CAP_32BIT));
      // for debug purposes
      pkts[MAX_X - 1] = tmpPacketCounter;
      draw();
      eapol = 0 ;
      deauths = 0;
      //Serial.println((String)pkts[MAX_X - 1]);
      ledPacketCounter = tmpPacketCounter;
      tmpPacketCounter = 0;
      rssiSum = 0;
    }
    // Serial input
    if (Serial.available()) {
      ch = Serial.readString().toInt();
      if (ch < 1 || ch > 14) ch = 1;
      setChannel(ch);
    }
  }
  draw_RSSI();
  //  M5.Lcd.pushImage(200, 200, 64, 64, happy_64);
}


#ifdef ARDUINO_M5STACK_FIRE
void blinky( void * p ) {
  while(1) {
    if ((eapol== 0) && (deauths == 0)) {
      for (int pixelNumber = 0; pixelNumber < M5STACK_FIRE_NEO_NUM_LEDS ; pixelNumber++){
        leds[pixelNumber].setRGB(  0, 0, 0);
        if (led_status==pixelNumber)
         leds[pixelNumber].setRGB(  0, 0, bright_leds);
      }
      led_status++;
      if (led_status>M5STACK_FIRE_NEO_NUM_LEDS)
        led_status=0;
      FastLED.show();
    }
    int led_delay =1000;
    if (ledPacketCounter == 0) led_delay = 2000;
    if (ledPacketCounter > 10) led_delay = 1000;
    if (ledPacketCounter > 100) led_delay = 500;
    if (ledPacketCounter > 400) led_delay = 300;
    if (ledPacketCounter > 1000) led_delay = 150;

    vTaskDelay(led_delay / portTICK_RATE_MS);
  }
}
#endif


// ===================================================================
