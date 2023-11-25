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

#include <ESP32-Chimera-Core.h>        // https://github.com/tobozo/ESP32-Chimera-Core/

#define tft M5.Lcd
/* #if !defined USE_M5STACK_UPDATER
  // comment this out to disable SD-Updater
  #define USE_M5STACK_UPDATER
#endif */

#ifdef USE_M5STACK_UPDATER
  #ifdef ARDUINO_M5STACK_Core2
    #define M5STACK_UPDATER_MENUDELAY 5000 // how long (millis) the SDUpdater lobby is visible at boot
  #else
    #define M5STACK_UPDATER_MENUDELAY 0 // M5Stack Classic/Fire don't need to see the menu
  #endif
  #define SDU_APP_NAME "WiFi Hash Monster" // title for SD-Updater UI
  #include <M5StackUpdater.h> // https://github.com/tobozo/M5Stack-SD-Updater/
#endif

#if defined ESP_IDF_VERSION_MAJOR && ESP_IDF_VERSION_MAJOR >= 4
  // Use LWIP stack
  #include "esp_wifi.h"
#else
  // Use legacy stack
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
  esp_err_t event_handler(void* ctx,system_event_t* event){return ESP_OK;}
#endif

#include <Preferences.h>
#include "Buffer.h"
#include "Faces.h"
#include "FS.h"
#include "SD.h"

#ifdef ARDUINO_M5STACK_FIRE
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wcpp"
  #include <FastLED.h>
  #pragma diagnostic pop
  #define M5STACK_FIRE_NEO_NUM_LEDS 10
  #define M5STACK_FIRE_NEO_DATA_PIN 15
  // Define the array of leds
  CRGB leds[M5STACK_FIRE_NEO_NUM_LEDS];
#endif

#define MAX_CH 13     // 1-14ch(1-11 US,1-13 EU and 1-14 Japan)
#define AUTO_CHANNEL_INTERVAL 15000 // how often to switch channels automatically, in milliseconds
#define USE_SD_BY_DEFAULT true

#define DRAW_DELAY 1000 // redraw graphs every second
#define BUTTON_DEBOUNCE 150 // check button every n millis
#define PKTS_BUF_SIZE 320 // buffer size for "packets/s" graph
#define MAX_SSIDs 1792 // buffer cache size (*32bits) for Beacon information, reduce this in case of memory problems

#if CONFIG_FREERTOS_UNICORE
  #define RUNNING_CORE 0
#else
  #define RUNNING_CORE 1
#endif


/* ===== run-time variables ===== */
Buffer sdBuffer;
Preferences preferences;

bool useSD = USE_SD_BY_DEFAULT;
static bool SDSetupDone = false;
static bool SDReady = false;
static bool UIReady = false;
static bool WelComeTaskReady = false;

uint32_t lastDrawTime = 0;
uint32_t lastButtonTime = millis();
uint32_t lastAutoSwitchChTime = 0;

int autoChannels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}; // customize this
int AUTO_CH_COUNT = sizeof(autoChannels) / sizeof(int);
int autoChIndex = 0;
int smartCh_old_stuff = 0;
uint8_t autoChMode = 0 ; // 0 No auto -  1 Switch channels automatically   - Smart Switch
const char* authChmodeStr[3] = {"[C]hannel Fixed", "[A]utomatic switching", "[S]mart switching" };
uint32_t tmpPacketCounter;
uint32_t pkts[PKTS_BUF_SIZE+1]; // here the packets per second will be saved
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
int graph_RSSI = 1;
int delta = 1;
int grid = 0;
int tcount = 0;

int8_t last_rssi;
char   last_ssid[33] = { '[', 'n', 'o', 'n', 'e', ']', '\0' };
char   last_ssid_mac[18] = {0};
char   last_eapol_ssid[33] = { '[', 'n', 'o', 'n', 'e', ']', '\0' };
char   last_eapol_mac[18] = {0};

TFT_eSprite header = TFT_eSprite(&tft); // 1bit   color sprite for header
TFT_eSprite footer = TFT_eSprite(&tft); // 1bit   color sprite for footer
TFT_eSprite face1  = TFT_eSprite(&tft); // 16bits color sprite for face
TFT_eSprite graph1 = TFT_eSprite(&tft); // 1bit   color sprite for graph1
TFT_eSprite graph2 = TFT_eSprite(&tft); // 8bits  color sprite for graph2
TFT_eSprite units1 = TFT_eSprite(&tft); // 1bit   color sprite for units1
TFT_eSprite units2 = TFT_eSprite(&tft); // 8bits  color sprite for units2

// position for header sprite
int headerPosX = 0;
int headerPosY = 0;
// dimensions for header sprite
int headerWidth  = 320-headerPosX;
int headerHeight = 20;

// position for footer sprite
int footerPosX = 20;
int footerPosY = 202;
// dimensions for footer sprite
int footerWidth  = 320-footerPosX;
int footerHeight = 240-footerPosY;

// dimensions for monster sprite
int face1Width  = 64;
int face1Height = 64;
// position for monster sprite
int face1PosX = 5;
int face1PosY = 140;

// dimensions for units1 sprite
int units1Width  = 40;
int units1Height = 120;
// position for units1 sprite
int units1PosX = 0;
int units1PosY = 20;

// dimensions for graph1 sprite
int graph1Width = 320-units1Width;
int graph1Height = 100;
// position for graph1 sprite
int graph1PosX = units1Width;
int graph1PosY = 28;

// dimensions for units2 sprite
int units2Width  = 36;
int units2Height = face1Height;
// position for units2 sprite
int units2PosX = 320-units2Width;
int units2PosY = graph1PosY+graph1Height+2;

// position for graph2 sprite
int graph2PosX = face1Width+face1PosX+5; // right side of monster sprite
int graph2PosY = graph1PosY+graph1Height+6;
// dimensions for graph2 sprite
int graph2Width = 320-(graph2PosX+units2Width); // must fit between monster sprite and unit2 sprite
int graph2Height = face1Height-4;


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
 * Format numbers to 4 chars when possible
 * using M/K units, may overflow over 999M
 */
static char unitOutput[16] = {'\0'};
static char *formatUnit( int64_t number )
{
  *unitOutput = {'\0'};
  if( number > 999999 ) {
    sprintf(unitOutput, "%lldM", number/1000000);
  } else if( number > 999 ) {
    sprintf(unitOutput, "%lldK", number/1000);
  } else {
    sprintf(unitOutput, "%lld", number);
  }
  return unitOutput;
}



/*
 * Data structure for beacon information
 */
struct ssid_info
{
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


void setupWiFiPromisc()
{
  Serial.println("NVS Flash init");
  nvs_flash_init();
  #if defined ESP_IDF_VERSION_MAJOR && ESP_IDF_VERSION_MAJOR >= 4
    // esp-idf 4.4 uses LWIP
    Serial.println("LWIP init");
    esp_netif_init();
  #else
    Serial.println("TCP adapter init");
    tcpip_adapter_init();
  #endif
  //  wificfg.wifi_task_core_id = 0;
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  #if defined ESP_IDF_VERSION_MAJOR && ESP_IDF_VERSION_MAJOR >= 4
    // esp_event_loop_init is deprecated in esp-idf 4.4
    Serial.println("[1] Skipping event loop init");
  #else
    Serial.println("[1] Attaching NULL event handler");
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
  #endif
  Serial.println("[2] Initing WiFi with config defaults");
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  //ESP_ERROR_CHECK(esp_wifi_set_country(WIFI_COUNTRY_EU));
  Serial.println("[3] Setting wifi storage to ram");
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  Serial.println("[4] Setting wifi mode to NULL");
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
  Serial.println("[5] Starting WiFi");
  ESP_ERROR_CHECK(esp_wifi_start());
  Serial.println("[6] Attaching promiscuous receiver callback");
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous));
  Serial.println("[7] Enabling promiscuous mode");
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
  Serial.printf("[8] Setting WiFi Channel to: %d\n", ch);
  // now switch on monitor mode
  ESP_ERROR_CHECK(esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE));
  Serial.println("[9] WiFi setup done");
}






// ===== main program ================================================
void setup()
{
  #ifdef ARDUINO_M5STACK_FIRE
    // load these before M5.begin() so they can eventually be turned off
    FastLED.addLeds<WS2812B, M5STACK_FIRE_NEO_DATA_PIN, GRB>(leds, M5STACK_FIRE_NEO_NUM_LEDS);
    FastLED.clear();
    FastLED.show();
  #endif
  M5.begin(); // this will fire Serial.begin()

  #ifdef USE_M5STACK_UPDATER
    // New SD Updater support, requires the latest version of https://github.com/tobozo/M5Stack-SD-Updater/
    #if defined M5_SD_UPDATER_VERSION_INT
      SDUCfg.setLabelMenu("<< Menu");
      SDUCfg.setLabelSkip("Launch");
    #endif
    checkSDUpdater( SD, MENU_BIN, M5STACK_UPDATER_MENUDELAY, TFCARD_CS_PIN ); // Filesystem, Launcher bin path, Wait delay
  #endif
  // SD card ---------------------------------------------------------
  bool toggle = false;
  unsigned long lastcheck = millis();
  tft.fillScreen(TFT_BLACK);
  while( !M5.sd_begin() ) {
    toggle = !toggle;
    tft.setTextColor( toggle ? TFT_BLACK : TFT_WHITE );
    tft.setTextDatum( MC_DATUM );
    tft.setTextSize( 2 );
    tft.drawString( "INSERT SD", tft.width()/2, tft.height()/2);
    tft.setTextDatum( TL_DATUM );
    delay( toggle ? 300 : 500 );
    // go to sleep after a minute, no need to hammer the SD Card reader
    if( lastcheck + 60000 < millis() ) {
      //Serial.println( GOTOSLEEP_MESSAGE );
      #ifdef ARDUINO_M5STACK_Core2
        M5.sd_end();
        M5.Axp.SetLcdVoltage(2500);
        M5.Axp.PowerOff();
      #elif defined(ARDUINO_M5STACK_FIRE) || defined(ARDUINO_M5Stack_Core_ESP32)
        M5.setWakeupButton( BUTTON_B_PIN );
        M5.powerOFF();
      #endif
    }
  }

  SDSetupDone = true;
  preferences.begin("packetmonitor32", false);
  ch         = preferences.getUInt("channel",    1);
  autoChMode = preferences.getUInt("autoChMode", 0);
  preferences.end();

  #ifdef ARDUINO_M5STACK_Core2
    // specific M5Core2 tweaks go here
  #else // M5Classic / M5Fire turn buzzer off
    M5.Speaker.write(0);
  #endif

  xTaskCreatePinnedToCore( bootAnimationTask, "bootAnimationTask", 8192, NULL, 16, NULL, RUNNING_CORE);
  xTaskCreatePinnedToCore( initSpritesTask,   "initSpritesTask",   8192, NULL, 16, NULL, RUNNING_CORE);
  xTaskCreatePinnedToCore( coreTask,          "coreTask",          8192, NULL, 16, NULL, RUNNING_CORE);

  #ifdef ARDUINO_M5STACK_FIRE
  xTaskCreatePinnedToCore( &blinky,           "blinky",            2500, NULL, 1,  NULL, 1);
  #endif

}


// ===== main program ================================================
void loop()
{
  // no need to waste a cycle for an empty loop
  vTaskSuspend(NULL);
}


static void initSpritesTask( void* param )
{
  // Create a 1bit sprite for the header
  header.setColorDepth(1);
  if(!header.createSprite( headerWidth, headerHeight ) ) {
    log_e("Can't create header sprite");
  }
  header.setFont( &fonts::AsciiFont8x16 );
  header.setTextSize( 1.0 );
  header.setTextColor( TFT_BLACK, TFT_BLUE ); // unintuitive: use black/blue mask
  header.setTextDatum(TL_DATUM);
  header.setBitmapColor( TFT_BLUE, TFT_WHITE ); // mask will be converted to this color
  header.fillSprite(TFT_BLUE);

  // Create a 1bit sprite for the footer
  footer.setColorDepth(1);
  if(!footer.createSprite( footerWidth, footerHeight ) ) {
    log_e("Can't create footer sprite");
  }
  footer.setFont( &fonts::AsciiFont8x16 );
  footer.setTextSize( 1.0 );
  footer.setTextColor( TFT_BLACK, TFT_BLUE ); // unintuitive: use black/blue mask
  footer.setTextDatum(TL_DATUM);
  footer.setBitmapColor( TFT_BLUE, TFT_WHITE ); // mask will be converted to this color
  footer.fillSprite( TFT_BLUE );

  // Create an 8bits sprite for the graph2
  graph2.setColorDepth(8);
  if(!graph2.createSprite(graph2Width+1, graph2Height+1) ) {
    log_e("Can't create graph2 sprite");
  }
  graph2.setTextColor(TFT_WHITE,TFT_BLACK);
  graph2.setFont( &fonts::Font2 );
  graph2.setTextSize( 0.75 );
  graph2.fillSprite(TFT_BLACK);

  // create a 8bits sprite for units2
  units2.setColorDepth(8);
  if(!units2.createSprite( units2Width, units2Height ) ) {
    log_e("Can't create units2 sprite");
  }
  units2.setTextDatum( TR_DATUM );
  units2.setFont( &fonts::Font2 );
  units2.fillSprite(TFT_BLACK);

  // Create a 1bit sprite for the graph1
  graph1.setColorDepth(1);
  if(!graph1.createSprite( graph1Width, graph1Height ) ) {
    log_e("Can't create graph1 sprite");
  }
  graph1.setFont(&fonts::Font2);
  //graph1.setTextSize( 0.75 );
  graph1.setBitmapColor( TFT_GREEN, TFT_BLACK );
  graph1.setTextColor( TFT_WHITE, TFT_BLACK );
  graph1.setTextDatum( TR_DATUM );
  graph1.fillSprite(TFT_BLACK);

  // create a 1bit sprite for units1
  units1.setColorDepth(1);
  if(!units1.createSprite( units1Width, units1Height ) ) {
    log_e("Can't create units1 sprite");
  }
  units1.setFont(&fonts::FreeMono9pt7b);
  units1.setTextColor( TFT_WHITE, TFT_BLACK );
  units1.setBitmapColor( TFT_WHITE, TFT_BLACK);  // Pkts Scale
  units1.setTextDatum(MR_DATUM);
  units1.setTextSize( 0.75 );
  units1.fillSprite(TFT_BLACK);

  // Create a 16bits sprite for the monster
  face1.setColorDepth(16);
  if(!face1.createSprite( face1Width, face1Height ) ) {
    log_e("Can't create face sprite");
  }
  face1.fillSprite(TFT_BLACK); // Note: Sprite is filled with black when created
  face1.setSwapBytes(true); // apply endianness since images are stored in 16bits words
  UIReady = true;
  log_w("Leaving initSprites task !");
  vTaskDelete(NULL);
}



static void bootAnimationTask( void* param )
{
  int waitmillis = 1000; // max animation duration
  float xpos = 200;      // initial monster x position
  float ypos = 158;      // initial monster y position
  float xdir = 1;        // bounce horizontal direction
  float vcursor = 0.0;   // cursor for sine
  float vstep = 0.009;   // vspeed
  float hstep = 0.35;    // hspeed
  float vamplitude = 56; // bounce height
  float voffset = 176;   // vertical offset
  int imgId = 12;        // image ID

  tft.clear();
  tft.setTextColor(TFT_WHITE, TFT_BLACK);
  tft.setTextSize(0);

  tft.setFont(&fonts::FreeMono12pt7b);
  tft.drawString( "Purple Hash Monster", 6, 24);
  tft.drawString( "by @g4lile0", 26, 44);
  tft.drawString( "90% PacketMonitor32", 6, 74);
  tft.drawString( "by @Spacehuhn", 26, 94);
  tft.setSwapBytes(true);

  ypos = voffset - ( abs( cos(vcursor) )*vamplitude );
  tft.pushImage(xpos, ypos, 64, 64, monsterSet[imgId]);

  // animate the monster while the sprites are being inited
  while( waitmillis-- > 0 || ( waitmillis < 0 && !UIReady) ) {
    ypos = voffset - ( abs( cos(vcursor) )*vamplitude );
    tft.pushImage(xpos, ypos, 64, 64, monsterSet[imgId]);
    if(  (xdir == 1  && xpos+xdir >= tft.width()-64)
      || (xdir == -1 && xpos+xdir < 0 ) ) {
      xdir = -xdir;
      imgId = random(0,13);
    }
    xpos += xdir*hstep;
    vcursor += vstep;
    vTaskDelay(1);
  }

  tft.fillRect( 0, 0, 320, 120, TFT_BLACK );

  tft.drawString( "Checking SD...", 6, 74);

  if( !sdBuffer.init() ) { // allocate buffer memory
    // TODO: print error on display
    Serial.println("Error, not enough memory for buffer");
    while(1) vTaskDelay(1);
  }

  if ( setupSD() ) {
    sdBuffer.checkFS(&SD);
    sdBuffer.pruneZeroFiles(&SD); // SD cleanup: remove zero-length pcap files from previous scans

    if( sdBuffer.open(&SD) ) {
      Serial.println("SD CHECK OPEN");
    } else {
      Serial.println("SD ERROR, Can't create file");
      useSD = false;
    }
  } else {
    // SD setup failed, card not inserted ?
    Serial.println("SD Setup failed");
  }

  tft.drawString( "Setting up WiFi...", 6, 44);

  setupWiFiPromisc();

  WelComeTaskReady = true;
  log_d("Leaving welcome task !");
  vTaskDelete( NULL );
}



// ===== functions ===================================================
double getMultiplicator( uint32_t range )
{
  uint32_t maxVal = 1;
  for (int i = 40; i < PKTS_BUF_SIZE; i++) {
    if (pkts[i] > maxVal) maxVal = pkts[i];
  }
  if (maxVal > 0) {
    return (double)range / (double)maxVal;
  }
  return 1;
}


// ===== functions ===================================================
void setChannel(int newChannel)
{
  log_d("Setting new channel to : %d", newChannel );
  ch = newChannel;
  if (ch > MAX_CH || ch < 1) ch = 1;
  // avoid to write too much on the flash in auto-switching mode
  if (autoChMode == 0) {
    preferences.begin("packetmonitor32", false);
    preferences.putUInt("channel", ch);
    preferences.end();
  }
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous);
}


void autoSwitchChannel(uint32_t currentTime)
{
  autoChIndex = (autoChIndex + 1) % AUTO_CH_COUNT;
  setChannel(autoChannels[autoChIndex]);
  Serial.printf("[A]uto-switching to channel %d\n", ch);
  lastAutoSwitchChTime = currentTime;
}


void smartSwitchChannel(uint32_t currentTime)
{
  lastAutoSwitchChTime = currentTime;

  if (smartCh_old_stuff < ssid_count+total_eapol+total_deauths) {
    smartCh_old_stuff = ssid_count+total_eapol+total_deauths;
    Serial.printf("[S]mart-switching: Channel #%d is interesting, collected %d packets so far :)\n", ch, smartCh_old_stuff);
  } else {
    unsigned int oldchannel = ch;
    smartCh_old_stuff = ssid_count+total_eapol+total_deauths;
    ch = (ch + 1) % (MAX_CH + 1);
    Serial.printf("[S]mart-switching: Channel #%d is boring, smart-switching to #%d\n", oldchannel, ch);
    setChannel(ch);
  }
}



// ===== functions ===================================================



bool setupSD()
{
  if( SDSetupDone ) return true;
  M5.sd_end();
  int attempts = 20;
  do {
    SDSetupDone = M5.sd_begin(); // SD.begin( TFCARD_CS_PIN );
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


struct RxControl
{
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


struct SnifferPacket
{
  struct RxControl rx_ctrl;
  uint8_t data[DATA_LENGTH];
  uint16_t cnt;
  uint16_t len;
};


char * wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
  switch(type) {
    case WIFI_PKT_MGMT: return (char*)"MGMT";
    case WIFI_PKT_DATA: return (char*)"DATA";
    default:
    case WIFI_PKT_MISC: return (char*)"MISC";
  }
}


static void setLastSSID(uint16_t start, uint16_t size, uint8_t* data)
{
  int u=0;
  for(uint16_t i = start; i < DATA_LENGTH && i < start+size; i++) {
    //Serial.write(data[i]);
    last_ssid[u]=data[i];
    u++;
  }
  last_ssid[u]=0;
}


void wifi_promiscuous(void* buf, wifi_promiscuous_pkt_type_t type)
{
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  wifi_pkt_rx_ctrl_t ctrl = (wifi_pkt_rx_ctrl_t)pkt->rx_ctrl;

  if (type == WIFI_PKT_MISC) return;   // wrong packet type
  if (ctrl.sig_len > 293) return; // packet too long
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
          snprintf( last_eapol_mac, 18, "%s", ether_ntoa(ssid_known[u].mac) );

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
        log_d("NO IMPRI %02d - %02d", u , SSID_length );
        ascii_error = true;
      }
      if (!isAscii(pkt->payload[38+u])) {
        log_d("NO ASCII %02d - %02d", u , SSID_length );
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
      snprintf( last_ssid_mac, 18, "%s", ether_ntoa(ssid_known[ssid_count].mac) );
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




// ===== UI functions ===================================================


void drawHeaderVal( TFT_eSprite *sprite, int32_t posx, int32_t posy, String title, String value )
{
  header.setTextColor( TFT_BLUE ); // invert
  uint8_t rectW = (title.length()*8)+4;
  header.fillRect( posx, posy, rectW, 14, TFT_BLACK );
  header.drawString(title, posx+2, posy);
  header.setTextColor( TFT_BLACK, TFT_BLUE ); // restore
  header.drawString(value, posx+rectW, posy);
}


void draw()
{
  int len, rssi;
  if (pkts[PKTS_BUF_SIZE - 1] > 0)
    rssi = rssiSum / (int)pkts[PKTS_BUF_SIZE - 1];
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

  header.fillSprite( TFT_BLUE );

  drawHeaderVal( &header, 2,   4, modeStr,  "" );
  drawHeaderVal( &header, 22,  4, "CH",     ":"+String(ch) );
  drawHeaderVal( &header, 70,  4, "AP",     ":"+String(formatUnit(ssid_count)) );
  drawHeaderVal( &header, 130, 4, "Pk",     ":"+String(formatUnit(tmpPacketCounter)) );
  drawHeaderVal( &header, 192, 4, "E/D",    ":"+String(formatUnit(eapol))+"/"+String(formatUnit(deauths)) );
  drawHeaderVal( &header, 268, 4, "SD",     ":"+String(useSD?"On":"Off") );

  header.pushSprite( headerPosX, headerPosY );

  double multiplicator = getMultiplicator( 100 );

  double maxval = 100 / multiplicator;

  int noceil = maxval;
  int toceil = 10 - (noceil%10);
  if( toceil !=10 ) {
    maxval = noceil + toceil; // round it up
    multiplicator = 100 / maxval;
  }

  double valstep = maxval / 5;

  units1.fillSprite( TFT_BLACK );

  for ( int ypos = units1Height-10, idx = 0; ypos > 0; ypos -= 20 )
  {
    units1.drawString(String( int( idx * valstep ) ), 30, ypos );
    idx++;
  }

  units1.pushSprite( units1PosX, units1PosY );

  for (int i = 40; i < PKTS_BUF_SIZE; i++) {
    int xpos = i-40;
    len = pkts[i] * multiplicator;
    graph1.drawLine(xpos, graph1Height, xpos, 0, 0);                 // LINE ERASE
    graph1.drawLine(xpos, graph1Height, xpos, graph1Height - len, 1);// LINE DRAW
    // scroll pkts data buffer
    if (i < PKTS_BUF_SIZE - 1) pkts[i] = pkts[i + 1];
  }

  #ifdef ARDUINO_M5STACK_Core2
    // show onscreen clock since M5Core2 has a RTC module
    struct timeval tv;
    if (gettimeofday(&tv, NULL)!= 0) {
      // Failed to obtain time
    } else {
      struct tm* ptm;
      ptm = localtime (&tv.tv_sec);
      char timeStr[15] = {0};
      const char* timeTpl = " %02d : %02d : %02d";
      snprintf( timeStr, 14, timeTpl, ptm->tm_hour, ptm->tm_min, ptm->tm_sec );
      graph1.drawString( timeStr, graph1Width, 0 );
    }
  #endif

  graph1.pushSprite( graph1PosX, graph1PosY );

  byte aleatorio; // = random (1,10);

  if ((deauths>0) && (eapol==0)) {
    face1.pushImage(0, 0, face1Width, face1Height, angry_64);
  }

  if (tmpPacketCounter<10) {
    aleatorio = random (1,5);
    switch (aleatorio) {
      case 1:  face1.pushImage(0, 0, face1Width, face1Height, bored1_64); break;
      case 2:  face1.pushImage(0, 0, face1Width, face1Height, bored2_64); break;
      case 3:  face1.pushImage(0, 0, face1Width, face1Height, bored3_64); break;
      case 4:  face1.pushImage(0, 0, face1Width, face1Height, sleep1_64); break;
      default: face1.pushImage(0, 0, face1Width, face1Height, sleep2_64); break;
    }
  }

  if (tmpPacketCounter>500) {
    aleatorio = random (1,2);
    switch (aleatorio) {
      case 1:  face1.pushImage(0, 0, face1Width, face1Height, scare_64);    break;
      default: face1.pushImage(0, 0, face1Width, face1Height, surprise_64); break;
    }
  }

  if ((eapol==0) && (deauths==0) && (tmpPacketCounter>10)) {
    aleatorio = random (1,5);
    switch (aleatorio) {
      case 1:  face1.pushImage(0, 0, face1Width, face1Height, happy_64);  break;
      case 2:  face1.pushImage(0, 0, face1Width, face1Height, happy2_64); break;
      case 3:  face1.pushImage(0, 0, face1Width, face1Height, happy3_64); break;
      default: face1.pushImage(0, 0, face1Width, face1Height, happy4_64); break;
    }
  }

  if (eapol>0)   {
    face1.pushImage(0, 0, face1Width, face1Height, love_64);
  }

  face1.pushSprite( face1PosX, face1PosY, TFT_BLACK);

  draw_RSSI();
}



void draw_RSSI()
{

  footer.fillSprite( TFT_BLUE );

  String p = String(last_ssid[0]!='\0' ? last_ssid : "[hidden]" )+" "+(String)last_rssi+" "+(String)last_ssid_mac;
  footer.drawString(p, 2, 3);
  p = String(last_eapol_ssid[0]!='\0'? last_eapol_ssid : "[none]")+" "+(String)last_eapol_mac;
  footer.drawString(p, 2, 3+18);
 
  #ifdef ARDUINO_M5STACK_Core2 //ARDUINO_M5Stack_Core_ESP32
    // battery percentage
    float batLevel =   M5.Axp.GetBatVoltage(); //M5.Power.getBatteryLevel();
    p = "Batt: " + (String)batLevel;
    //Serial.printf("Battery Level - %.1f\n", batLevel);
    footer.drawString(p, 220, 3+18);  
  #endif
  
  footer.pushSprite( footerPosX, footerPosY );

  // Draw point in graph2 sprite at far right edge (this will scroll left later)
  if (graph_RSSI != 0)  graph2.drawFastVLine( graph2Width, -(graph_RSSI/2), 2, TFT_YELLOW); // draw 2 pixel point on graph

  if (graph_eapol>59) graph_eapol=0;
  if (graph_eapol != 0)  graph2.drawFastVLine( graph2Width, graph2Height-constrain(graph_eapol,1,graph2Height), 2, TFT_GREEN); // draw 2 pixel point on graph

  if (graph_deauths>59) graph_deauths=0;
  if (graph_deauths != 0)  graph2.drawFastVLine( graph2Width, graph2Height-constrain(graph_deauths,1,graph2Height), 2, TFT_RED); // draw 2 pixel point on graph

  // write the channel on the scroll window.
  if (ch != old_ch){
    old_ch=ch;
    graph2.drawString( "  ", graph2Width-25, 1 );
    graph2.drawNumber( ch,   graph2Width-17, 1 );
  }

  // Push the sprites onto the TFT at specified coordinates
  graph2.pushSprite( graph2PosX, graph2PosY );
  // Now scroll the sprites scroll(dt, dy) where:
  // dx is pixels to scroll, left = negative value, right = positive value
  // dy is pixels to scroll, up = negative value, down = positive value
  graph2.scroll(-1, 0); // scroll graph 1 pixel left, 0 up/down

  // Draw the grid on far right edge of sprite as graph has now moved 1 pixel left
  grid++;
  if (grid >= 10) {
    // Draw a vertical line if we have scrolled 10 times (10 pixels)
    grid = 0;
    graph2.drawFastVLine( graph2Width, 0, 61, TFT_NAVY ); // draw line on graph
  } else { // Otherwise draw points spaced 10 pixels for the horizontal grid lines
    for (int p = 0; p <= graph2Height; p += 10) graph2.drawPixel( graph2Width, p, TFT_NAVY );
  }
  tcount--;


  units2.fillSprite( TFT_BLACK );

  units2.setTextColor( TFT_YELLOW, TFT_BLACK );
  units2.drawString( " " + String(formatUnit(graph_RSSI)),       units2Width-1, 2 );

  units2.setTextColor( TFT_GREEN,  TFT_BLACK );
  units2.drawString( " " + String(formatUnit(total_eapol)),      units2Width-1, 18 );

  units2.setTextColor( TFT_RED,    TFT_BLACK );
  units2.drawString( " " + String(formatUnit(total_deauths)),    units2Width-1, 34 );

  units2.setTextColor( TFT_WHITE,  TFT_BLACK );
  units2.drawString( " " + String(formatUnit(ssid_eapol_count)), units2Width-1, 50 );

  units2.pushSprite( units2PosX, units2PosY );
}

#if defined( ARDUINO_M5STACK_Core2 ) // M5Core2 starts APX after display is on
  Button* _btns[3] = { &M5.BtnA, &M5.BtnB, &M5.BtnC };
  int _btns_state[3] = {0, 0, 0 };
  int _btns_time[3] = {0, 0, 0};
#endif

bool setButtons( uint8_t btnEnabled ) {
  for( uint8_t i=0; i<3; i++ ) {
    if( i == btnEnabled && _btns_state[i] == 0) {
      Serial.printf("Button %d pressed\n", btnEnabled);
      _btns_state[i] = 1;
      //_btns[i]->setState( 1 );
      _btns_time[i] = millis();
      
      switch (i)
        {
        case 0:
          if (bright>1) {
            Serial.println("Incognito Mode");
            bright=0;
            bright_leds=0;
            tft.setBrightness(bright);
          } else {
            bright=100;
            bright_leds=100;
            tft.setBrightness(bright);
          }
          return false;
          break;
        case 1:
          bright+=50;
          if (bright>251) bright=0;
          tft.setBrightness(bright);
          return false;
          break;
        case 2:
          setChannel(ch + 1);
          return true;
        break;
        
        default:
          return false;
          break;
        }
    }
  }
  return false;
}

bool clearButtons() {
  for ( uint8_t i=0; i<3; i++) {
    if ( _btns_state[i] == 1 ) {
      _btns_state[i] = 0;
      //_btns[i]->setState( 0 );
      Serial.printf("Button %d released.\n", i);

      if ( millis() - _btns_time[i] > 700) {
        Serial.printf("Button %d long press.\n", i);
        switch (i)
        {
        case 0:
          // toggle SD use
          if ( useSD ) { // in use, disable
            sdBuffer.close(&SD); // flush current buffer
            useSD = false;
            SDSetupDone = false;
            M5.sd_end();
          } else { // not in use, try to enable
            if ( setupSD() ) {
              if( !sdBuffer.open(&SD) ) {
                Serial.println(" SD ERROR, Can't create file, disabling SD");
                useSD = false;
                SDSetupDone = false;
                M5.sd_end();
              }
            }
          }
          return true;
          
          break;
        case 1:
          bright_leds+=100;
          if (bright_leds>251) bright_leds=0;
          Serial.printf("LED Brigthness: %d", bright_leds);
          return false;
          break;
        case 2:
          autoChMode++;
          if (autoChMode>2) autoChMode=0;
          Serial.printf("Channel hop mode is now set to: %s\n", authChmodeStr[autoChMode] );
          preferences.begin("packetmonitor32", false);
          preferences.putUInt("autoChMode", autoChMode);
          preferences.end();
          return false;
          break;
        
        default:
          return false;
          break;
        }
        
      }
    }  
  }
  return false;
}

// ====== Core task ===================================================
void coreTask( void * p )
{
  while( !UIReady ) vTaskDelay(1); // wait for sprites to init
  while( !WelComeTaskReady ) vTaskDelay(1); // wait for animation to terminate

  uint32_t currentTime;
  setChannel(ch);
  Serial.printf("[C]urrent channel: %d\n", ch);
  tmpPacketCounter = 0; // reset to avoid overflow on first render

  tft.clear();
  // draw icons
  tft.fillRect( 0, footerPosY, 32, 40, TFT_BLUE );
  tft.pushImage( 2, footerPosY+2,  16, 16, (uint16_t*)rssi_16x16_rgb565,  TFT_BLACK );
  tft.pushImage( 2, footerPosY+20, 16, 16, (uint16_t*)eapol_16x16_rgb565, TFT_BLACK );

  lastButtonTime = millis();
  M5.update();

  while (true) {
    bool needDraw = false;
    currentTime = millis();
    
    TouchPoint_t tp = M5.Touch.getPressPoint();
    //lgfx::touch_point_t tp = M5.M5Core2TouchButtonEmu->tp;
    //Serial.printf("Press point: %d, %d\n", tp.x, tp.y);
    int lcd_width = M5.Lcd.width(); //320
    int lcd_height = M5.Lcd.height(); //240
    //Serial.printf("Width/Height: %d, %d\n", lcd_width, lcd_height);
    int button_zone_width = ((320+1)/3); // 1/3rd of the screen per button
    int button_marginleft = 15; // dead space in pixels before and after each button to prevent overlap
    int button_marginright = button_zone_width-button_marginleft;
    int button_num = -1;

    if (tp.x == -1 && tp.y == -1) {
      needDraw = clearButtons();
    }

    if (tp.y >= 250) {
      int tpxmod = tp.x%button_zone_width;
      if ( tpxmod > button_marginleft && tpxmod < button_marginright ) {
        button_num = tp.x / button_zone_width;
      }

      needDraw = setButtons( button_num );
    }

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
  
    if (needDraw) draw();
   
    // maintain buffer and save to SD if necessary
    if (useSD) sdBuffer.save(&SD);
    // draw Display
    if ( currentTime - lastDrawTime > DRAW_DELAY ) {
      lastDrawTime = currentTime;
      // Serial.printf("\nFree RAM %u %u\n",
      // heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT),
      // heap_caps_get_minimum_free_size(MALLOC_CAP_32BIT));
      // for debug purposes
      pkts[PKTS_BUF_SIZE - 1] = tmpPacketCounter;
      draw();
      eapol = 0 ;
      deauths = 0;
      //Serial.println((String)pkts[PKTS_BUF_SIZE - 1]);
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
  vTaskDelete(NULL);
}


#ifdef ARDUINO_M5STACK_FIRE
void blinky( void * p )
{
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
