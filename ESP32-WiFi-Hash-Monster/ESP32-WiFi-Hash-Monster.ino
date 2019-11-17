// ESP32-WiFi-Hash-Monster
// 90% based on PacketMonitor32 from spacehuhn //  https://github.com/spacehuhn/PacketMonitor32/
// ported to M5stack by 2018.01.11 macsbug  //    https://macsbug.wordpress.com/2018/01/11/packetmonitor32-with-m5stack/
// modify to capture eapol/handshake by G4lile0  6/oct/2019
//  more info https://miloserdov.org/?p=1047
//  more info https://www.evilsocket.net/2019/02/13/Pwning-WiFi-networks-with-bettercap-and-the-PMKID-client-less-attack/
// DISPLAY: Channel,RSSI,Packet per Second,eapol,deauth packets,SD Card enabled
// Red NeoPixels deauth  -- Green Neopixel eapol
// Button : click to change channel hold to dis/enable SD
// SD : GPIO4=CS(CD/D3), 23=MOSI(CMD), 18=CLK, 19=MISO(D0)
//--------------------------------------------------------------------
#include <M5Stack.h>
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
#define MAX_CH 14     // 1-14ch(1-11 US,1-13 EU and 1-14 Japan)
//#define SNAP_LEN 2324 // max len of each recieved packet

#define SNAP_LEN 2324 // limit packet capture for eapol

#define BUTTON_PIN_A 39 // button to change the channel
#define BUTTON_PIN_C 37 // button to change the bright of the LCD


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


//#include <Adafruit_NeoPixel.h>
#include <FastLED.h>

#define M5STACK_FIRE_NEO_NUM_LEDS 10
#define M5STACK_FIRE_NEO_DATA_PIN 15

//  Adafruit_NeoPixel pixels = Adafruit_NeoPixel(M5STACK_FIRE_NEO_NUM_LEDS, M5STACK_FIRE_NEO_DATA_PIN, NEO_GRB + NEO_KHZ400);

// Define the array of leds
CRGB leds[M5STACK_FIRE_NEO_NUM_LEDS];



enum { sd_sck = 18, sd_miso = 19, sd_mosi = 23, sd_ss = 4 };
esp_err_t event_handler(void* ctx,system_event_t* event){return ESP_OK;}
/* ===== run-time variables ===== */
Buffer sdBuffer;
Preferences preferences;
bool useSD = false;
bool buttonPressed_A = false;
bool buttonEnabled_A = true;
bool buttonPressed_C = false;
bool buttonEnabled_C = true;



uint32_t lastDrawTime;
uint32_t lastButtonTime;
uint32_t tmpPacketCounter;
uint32_t pkts[MAX_X]; // here the packets per second will be saved
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
TFT_eSprite face1   = TFT_eSprite(&M5.Lcd); // Sprite object face

int graph_RSSI = 1;
int delta = 1;
int grid = 0;
int tcount = 0;

char last_ssid[33];
char last_eapol_ssid[33];


/*
 * Data structure for beacon information
 */

#define MAX_SSIDs 256

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
  // Serial ----------------------------------------------------------
  Serial.begin(115200);
  
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

//
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous));

  Serial.println("6 ");
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
  Serial.println("7 ");

 // now switch on monitor mode    
 // ESP_ERROR_CHECK(esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE));

  Serial.println("8 ");

  Serial.println("wifi done");
  
  
  // display -------------------------------------------------------
  M5.begin();
  dacWrite(25, 0); // Speaker OFF
  M5.Lcd.fillScreen(TFT_BLACK);
  M5.Lcd.setTextColor(WHITE, BLACK);
  M5.Lcd.setTextSize(1);
  M5.Lcd.setRotation(1);
  /* show start screen */
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setFreeFont(FM12);
  M5.Lcd.drawString( "Purple Hash Monster", 6, 24);
  M5.Lcd.drawString( "by @g4lile0", 29, 44);
  M5.Lcd.drawString( "90% PacketMonitor32", 6, 64);
  M5.Lcd.drawString( "by @Spacehuhn", 29, 84);
 
  M5.Lcd.setSwapBytes(true);
  M5.Lcd.pushImage(200, 158, 64, 64, love_64);
  delay(2000);
  //M5.Lcd.pushImage(240, 164, 64, 64, happy_64);
  //delay(500);
 
/*
 * 
  // Draw the icons
  M5.Lcd.pushImage(100, 120, 64, 64, angry_64);
  delay(1000);
  M5.Lcd.pushImage(178, 138, 64, 64, bored1_64);
  delay(1000);
  M5.Lcd.pushImage(178, 138, 64, 64, bored2_64);
  delay(1000);
  M5.Lcd.pushImage(178, 138, 64, 64, bored3_64);

  delay(1000);
  M5.Lcd.pushImage(178, 138, 64, 64, love_64);

  delay(1000);
  M5.Lcd.pushImage(178, 138, 64, 64, happy_64);

  delay(1000);
  M5.Lcd.pushImage(178, 138, 64, 64, happy2_64);


  delay(1000);
  M5.Lcd.pushImage(178, 138, 64, 64, happy3_64);


 */

//   angry_64
//   bored1_64  bored2_64 bored2_64
//   happy_64   happy2_64 happy3_64 happy2_64
//   love_64
//   scare_64
//   sleep1, sleep2
//   surprise

  setChannel(ch);
  
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setFreeFont(FM9);
  int s = 10, a = 0;
  M5.Lcd.setTextColor( WHITE, BLACK);  // Pkts Scale
  

 for ( int ypos = MAX_Y; ypos > 60; ypos = ypos - s ){
    M5.Lcd.setTextDatum(MR_DATUM);
    M5.Lcd.drawString(String( (MAX_Y - ypos)*2 ),30, ypos - 1 - a);
    a = a + 10;
  }

  
  M5.Lcd.setFreeFont(FM9);
  M5.Lcd.setTextDatum(TL_DATUM);
  M5.Lcd.fillRect(0, 0, 320, 20, BLUE);
  // SD card ---------------------------------------------------------
  SPI.end();
  SPI.begin(sd_sck, sd_miso, sd_mosi, sd_ss); 
  SD.begin(sd_ss, SPI, 24000000);
 
  
 // if(!SD.begin(sd_ss,SPI)){
 //   Serial.println("Card Mount Failed");return;
 // }
  
  sdBuffer = Buffer();

  if (useSD) Serial.println("pues esta encendido");


  
  if (setupSD()){sdBuffer.open(&SD);Serial.println(" SD CHECK OPEN");
  }

 if (useSD) Serial.println("pues esta encendido2");
  useSD = false;
  
  // I/O -----------------------------------------------------------
  pinMode(BUTTON_PIN_A, INPUT_PULLUP);
  pinMode(BUTTON_PIN_C, INPUT_PULLUP);
  
  // second core ----------------------------------------------------


   FastLED.addLeds<WS2812B, M5STACK_FIRE_NEO_DATA_PIN, GRB>(leds, M5STACK_FIRE_NEO_NUM_LEDS);

  // Create a sprite for the graph
  graph1.setColorDepth(8);
  graph1.createSprite(128+50, 61);
  graph1.fillSprite(TFT_BLUE); // Note: Sprite is filled with black when created


  // Create a sprite for the graph
  face1.setColorDepth(16);
  face1.createSprite(64, 64);
  face1.fillSprite(TFT_BLACK); // Note: Sprite is filled with black when created



  // The scroll area is set to the full sprite size upon creation of the sprite
  // but we can change that by defining a smaller area using "setScrollRect()"if needed
  // parameters are x,y,w,h,color as in drawRect(), the color fills the gap left by scrolling
  //graph1.setScrollRect(64, 0, 64, 61, TFT_DARKGREY);  // Try this line to change the graph scroll area


  xTaskCreatePinnedToCore(
    coreTask,               /* Function to implement the task */
    "coreTask",             /* Name of the task */
    2500,                   /* Stack size in words */
    NULL,                   /* Task input parameter */
    0,                      /* Priority of the task */
    NULL,                   /* Task handle. */
    RUNNING_CORE);          /* Core where the task should run */
  // start Wifi sniffer ---------------------------------------------
    xTaskCreatePinnedToCore(&blinky, "blinky", 2500,NULL,1,NULL,1);

}
// ===== main program ================================================
void loop() {
  vTaskDelay(portMAX_DELAY);
   
}
// ===== functions ===================================================
double getMultiplicator() {
  uint32_t maxVal = 1;
  for (int i = 0; i < MAX_X; i++) {
    if (pkts[i] > maxVal) maxVal = pkts[i];
  }
  if (maxVal > MAX_Y) return (double)MAX_Y / (double)maxVal;
  else return 1;
}
// ===== functions ===================================================
void setChannel(int newChannel) {
  ch = newChannel;
  if (ch > MAX_CH || ch < 1) ch = 1;
  preferences.begin("packetmonitor32", false);
  preferences.putUInt("channel", ch);
  preferences.end();
  //esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous_rx_cb(&wifi_promiscuous);
//  esp_wifi_set_promiscuous(true);
}
// ===== functions ===================================================
bool setupSD() {
  if (!SD.begin(sd_ss, SPI)) {
    Serial.println("Card Mount Failed"); return false;
  }
  uint8_t cardType = SD.cardType();
  if (cardType == CARD_NONE) {
    Serial.println("No SD_MMC card attached"); return false;
  }
  Serial.print("SD_MMC Card Type: ");
  if (cardType == CARD_MMC){         Serial.println("MMC");
  } else if (cardType == CARD_SD){   Serial.println("SDSC");
  } else if (cardType == CARD_SDHC){ Serial.println("SDHC");
  } else {                           Serial.println("UNKNOWN");
  }
  uint64_t cardSize = SD.cardSize() / (1024 * 1024);
  Serial.printf("SD_MMC Card Size: %lluMB\n", cardSize);
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




char * wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
  switch(type) {
  case WIFI_PKT_MGMT: return "MGMT";
  case WIFI_PKT_DATA: return "DATA";
  default:  
  case WIFI_PKT_MISC: return "MISC";
  }
}



static void getMAC(char *addr, uint8_t* data, uint16_t offset) {
  sprintf(addr, "%02x:%02x:%02x:%02x:%02x:%02x", data[offset+0], data[offset+1], data[offset+2], data[offset+3], data[offset+4], data[offset+5]);


}

static void printDataSpan(uint16_t start, uint16_t size, uint8_t* data) {
   int u=0;
  for(uint16_t i = start; i < DATA_LENGTH && i < start+size; i++) {
    Serial.write(data[i]);
    last_ssid[u]=data[i];
    u++;
    }
    last_ssid[u]=0;
    Serial.print("SSID Char:");
    Serial.println(last_ssid);
  
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

  
  if (type == WIFI_PKT_MGMT && 
     (pkt->payload[0] == 0xA0 || pkt->payload[0] == 0xC0 )) {
      deauths++;
    
//      if (useSD) sdBuffer.addPacket(pkt->payload, packetLength);
 
        // deauth
        for (int pixelNumber = 5; pixelNumber < 10; pixelNumber++){    
            leds[pixelNumber].setRGB( bright_leds, 0, 0);;
                 
                }
           FastLED.show();
         
       
     }




  if (( (pkt->payload[30] == 0x88 && pkt->payload[31] == 0x8e)|| ( pkt->payload[32] == 0x88 && pkt->payload[33] == 0x8e) )){
        eapol++;  // new eapol packets :)
        
        // turn right led in green
        for (int pixelNumber = 0; pixelNumber <= 4; pixelNumber++){    
                leds[pixelNumber].setRGB(  0,bright_leds, 0);
                
                }
          FastLED.show();
        Serial.println("eapol");

        memcpy(&ssid_known[MAX_SSIDs-1].mac,pkt->payload+16,6);   // MAC source HW address 

  
        
        for (u = 0; u < ssid_count; u++) {
            if (!memcmp(ssid_known[u].mac, ssid_known[MAX_SSIDs-1].mac, 6))  {
                  // only if is new print it 
                    if (!ssid_known[u].ssid_eapol) {
                                Serial.println("MAC encontrada");
                                ssid_eapol_count++;
                                ssid_known[u].ssid_eapol=true;
                                Serial.println(ssid_known[u].ssid_len);
                                for(int i = 0; i < ssid_known[u].ssid_len ; i++) {
                                     last_eapol_ssid[i]=ssid_known[u].ssid[i];
                                                                                   }
                                last_eapol_ssid[ssid_known[u].ssid_len+1]=0;                                                  
                                Serial.println(last_eapol_ssid);
                     
                                                   }
                    
       
            
                                               break;                        }
                    
                    } 

      




        
//        uint8_t SSID_length = pkt->payload[25];
//        Serial.println(" SSID: ");
//        printDataSpan(26, SSID_length, pkt->payload);

        if (useSD) sdBuffer.addPacket(pkt->payload, packetLength);


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
 * 

  // Only look for probe request packets
  if (frameType != TYPE_MANAGEMENT ||
//  frameSubType != SUBTYPE_PROBE_REQUEST ||
  frameSubType != SUBTYPE_PROBE_RESPONSE ||
  frameSubType != SUBTYPE_BEACONS ||
  frameSubType != 0x0028  // QoS Data 
  )
        return;


 */

//if  (!((frameSubType == SUBTYPE_PROBE_RESPONSE) || (frameSubType == SUBTYPE_BEACONS ) || (frameSubType == 0x0028))) return;
//if  ((frameSubType == SUBTYPE_PROBE_RESPONSE) || (frameSubType == SUBTYPE_BEACONS )) {

if  ((frameSubType == SUBTYPE_BEACONS) && (isAlphaNumeric(pkt->payload[38])) && (isAlphaNumeric(pkt->payload[39]))&& (isAlphaNumeric(pkt->payload[42])) ) {
    if (useSD) sdBuffer.addPacket(pkt->payload, packetLength);
    uint8_t SSID_length = pkt->payload[37];

    if (SSID_length>32) return;

 
    memcpy(&ssid_known[MAX_SSIDs-1].mac,pkt->payload+16,6);
    
    bool known = false;
    for (u = 0; u < ssid_count; u++) {
        if (!memcmp(ssid_known[u].mac, ssid_known[MAX_SSIDs-1].mac, 6))  {
            known = true;
            break;
                    } } 


    if (!known) {
      
        memcpy(&ssid_known[ssid_count].mac,&ssid_known[MAX_SSIDs-1].mac ,6);
        memcpy(&ssid_known[ssid_count].ssid,pkt->payload+38, SSID_length);
        
        ssid_known[u].ssid_len=SSID_length;
        ssid_count++;
        Serial.print(" SSID count: ");
        Serial.println(ssid_count);
        Serial.print(" pack lengt: ");
        Serial.println(packetLength);
        Serial.println(" SSID: ");
        printDataSpan(38, SSID_length, pkt->payload);

        

        
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


char addr[] = "00:00:00:00:00:00";
  getMAC(addr, pkt->payload, 10);
//  Serial.print(" Peer MAC: ");
//  Serial.print(addr);


//  uint8_t SSID_length = pkt->payload[25];
//  Serial.print(" SSID: ");
//  printDataSpan(26, SSID_length, pkt->payload);



}
// ===== functions ===================================================



void draw() {
  

  double multiplicator = getMultiplicator();
  int len, rssi;
  if (pkts[MAX_X - 1] > 0) rssi = rssiSum / (int)pkts[MAX_X - 1];
  else rssi = rssiSum;


  graph_RSSI= rssi;
  draw_RSSI();
  total_eapol += eapol;
  graph_eapol += eapol;
  total_deauths += deauths;
  graph_deauths += deauths;

  
  
  String p = "C:"+(String)ch + "|AP:" + (String)ssid_count + "|Pkts " +
     (String)tmpPacketCounter + "[" + (String)eapol + "]" + "["+ (String)deauths + "]" +
     (useSD ? "|SD" : "");

  M5.Lcd.setTextColor(WHITE,BLUE);                    // packet
  M5.Lcd.drawString(p + "   ", 10, 2);                 // string DRAW
  M5.Lcd.drawLine(40,MAX_Y-100,MAX_X,MAX_Y-100,GREEN);// MAX LINE DRAW

  for (int i = 40; i < MAX_X; i++) {                  // LINE DRAW
    len = pkts[i] * multiplicator;
    len = len * 2;
    if ( (MAX_Y - len) < (MAX_Y - 100)){ len = 100;}  // over flow
    M5.Lcd.drawLine(i, MAX_Y, i, 31, TFT_BLACK);      // LINE EARSE
    M5.Lcd.drawLine(i, MAX_Y, i, MAX_Y - len , GREEN);// LINE DRAW
    if (i < MAX_X - 1) pkts[i] = pkts[i + 1];
  }


  
  byte aleatorio; // = random (1,10);



//  


  if ((deauths>0) && (eapol==0)) {
    face1.pushImage(0, 0, 64, 64, angry_64);
  }


  if (tmpPacketCounter<10) {
      aleatorio = random (1,5);
        switch (aleatorio) {
          case 1:
                 face1.pushImage(0, 0, 64, 64, bored1_64);
          break;
          
          case 2:
                 face1.pushImage(0, 0, 64, 64, bored2_64);
          break;
          
          case 3:
                 face1.pushImage(0, 0, 64, 64, bored3_64);
          break;
          
          case 4:
                 face1.pushImage(0, 0, 64, 64, sleep1_64);
          break;
          
          default:
                 face1.pushImage(0, 0, 64, 64, sleep2_64);
          break;
          
          
                           }
  }



  if (tmpPacketCounter>500) {
      aleatorio = random (1,2);
        switch (aleatorio) {
          case 1:
                 face1.pushImage(0, 0, 64, 64, scare_64);
          break;
          
          default:
                 face1.pushImage(0, 0, 64, 64, surprise_64);
          break;
          
                           }
  }





  
  if ((eapol==0) && (deauths==0) && (tmpPacketCounter>10)) {

      aleatorio = random (1,5);
        switch (aleatorio) {
          case 1:
                 face1.pushImage(0, 0, 64, 64, happy_64);
          break;
          
          case 2:
                 face1.pushImage(0, 0, 64, 64, happy2_64);
          break;
          
          case 3:
                 face1.pushImage(0, 0, 64, 64, happy3_64);
          break;
          
          default:
                 face1.pushImage(0, 0, 64, 64, happy4_64);
          break;
        }
             
  }
  

  if (eapol>0)   {
    face1.pushImage(0, 0, 64, 64, love_64);
  }


  face1.setSwapBytes(true);
  face1.pushSprite(10, 140);


 
draw_RSSI();

}


void draw_RSSI() {


  
  // Draw point in graph1 sprite at far right edge (this will scroll left later)
  if (graph_RSSI != 0)  graph1.drawFastVLine(127+50,-(graph_RSSI/2),2,TFT_YELLOW); // draw 2 pixel point on graph

  if (graph_eapol>59) graph_eapol=0;
  if (graph_eapol != 0)  graph1.drawFastVLine(127+50,60-constrain(graph_eapol,1,60),2,GREEN); // draw 2 pixel point on graph
 
  if (graph_deauths>59) graph_deauths=0;
  if (graph_deauths != 0)  graph1.drawFastVLine(127+50,60-constrain(graph_deauths,1,60),2,RED); // draw 2 pixel point on graph


  // write the channel on the scroll window.
  if (ch != old_ch){
      old_ch=ch;
      graph1.setTextColor(TFT_WHITE,BLACK);
      graph1.setFreeFont(FM9);
      graph1.drawString( "  ", 127+50-25,1);
      graph1.drawNumber(ch,127+50-17,1,2);
      
    }
  


  // Push the sprites onto the TFT at specied coordinates
  graph1.pushSprite(90+0, 138);

  M5.Lcd.setTextColor(TFT_YELLOW,BLACK); 
  M5.Lcd.setTextDatum(TR_DATUM);
  M5.Lcd.drawString( "   ", 90+128+50+2+32, 138);
  M5.Lcd.drawNumber( graph_RSSI, 90+128+50+2+40, 138,2);
  M5.Lcd.setTextColor(GREEN,BLACK); 
  M5.Lcd.drawNumber( total_eapol, 90+128+50+2+40, 138+16,2);
  M5.Lcd.setTextColor(RED,BLACK); 
  M5.Lcd.drawNumber( total_deauths, 90+128+50+2+40, 138+32,2);
  M5.Lcd.setTextColor(WHITE,BLACK); 
  M5.Lcd.drawNumber( ssid_eapol_count, 90+128+50+2+40, 138+48,2);

  M5.Lcd.setTextColor(WHITE,BLUE); 
  M5.Lcd.fillRect(0,138+32+32 , 320, 40, BLUE);
      
  String p = "New SSID:"+(String)last_ssid ;
  M5.Lcd.drawString(p ,2 ,138+32+32+2);                 // string DRAW

  p = "New HS: "+(String)last_eapol_ssid;
  M5.Lcd.drawString(p ,2 ,138+32+32+2+16);                 // string DRAW




  // Now scroll the sprites scroll(dt, dy) where:
  // dx is pixels to scroll, left = negative value, right = positive value
  // dy is pixels to scroll, up = negative value, down = positive value
  graph1.scroll(-1, 0); // scroll graph 1 pixel left, 0 up/down

  // Draw the grid on far right edge of sprite as graph has now moved 1 pixel left
  grid++;
  if (grid >= 10)
  { // Draw a vertical line if we have scrolled 10 times (10 pixels)
    grid = 0;
    graph1.drawFastVLine(127+50, 0, 61, TFT_NAVY); // draw line on graph
  }
  else
  { // Otherwise draw points spaced 10 pixels for the horizontal grid lines
    for (int p = 0; p <= 60; p += 10) graph1.drawPixel(127+50, p, TFT_NAVY);
  }
  tcount--;
}


// ====== functions ===================================================
void coreTask( void * p ) {
  uint32_t currentTime;
  while (true) {
    currentTime = millis();
    /* bit of spaghetti code, have to clean this up later :D_ */
 
    // check button A
    if (digitalRead(BUTTON_PIN_A) == LOW) {
      M5.Lcd.fillRect(0, 0, 320, 20, BLUE);
      if (buttonEnabled_A) {
        if (!buttonPressed_A) {
          buttonPressed_A = true;
          lastButtonTime = currentTime;
        } else if (currentTime - lastButtonTime >= 2000){
          if (useSD) {
            useSD = false;
            sdBuffer.close(&SD);
            draw();
          } else {
            if (setupSD())
              sdBuffer.open(&SD);
            draw();
          }
          buttonPressed_A = false;
          buttonEnabled_A = false;
        }
      }
    } else {
      if (buttonPressed_A) {
        setChannel(ch + 1);
        draw();
      }
      buttonPressed_A = false;
      buttonEnabled_A = true;
    }


    // check button C
    if (digitalRead(BUTTON_PIN_C) == LOW) {
  //    M5.Lcd.fillRect(0, 0, 320, 20, BLUE);
      if (buttonEnabled_C) {
        if (!buttonPressed_C) {
          buttonPressed_C = true;
          lastButtonTime = currentTime;
        } else if (currentTime - lastButtonTime >= 2000){
          bright_leds+=100;
          if (bright_leds>251) bright_leds=0;
          Serial.println(bright_leds);
          
          buttonPressed_C = false;
          buttonEnabled_C = false;
        }
      }
    } else {
      if (buttonPressed_C) {
        bright+=50;
        if (bright>251) bright=0;
        M5.Lcd.setBrightness(bright);
        }
      buttonPressed_C = false;
      buttonEnabled_C = true;
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
 //   M5.Lcd.pushImage(200, 200, 64, 64, happy_64);


}

void blinky( void * p ) {

      while(1){

               

          if ((eapol== 0) && (deauths == 0)) {
                    for (int pixelNumber = 0; pixelNumber < M5STACK_FIRE_NEO_NUM_LEDS ; pixelNumber++){
                    leds[pixelNumber].setRGB(  0, 0, 0);
                    if (led_status==pixelNumber)  leds[pixelNumber].setRGB(  0, 0, bright_leds);
                     }
                    led_status++;
                    if  (led_status>M5STACK_FIRE_NEO_NUM_LEDS) led_status=0;
              
                    FastLED.show();         
                                                                                                     
                
                                               }
          int led_delay =1000;
          
          if (ledPacketCounter == 0)  led_delay = 2000;
          if (ledPacketCounter > 10)  led_delay = 1000;
          if (ledPacketCounter > 100)  led_delay = 500;
          if (ledPacketCounter > 400)  led_delay = 300;
          if (ledPacketCounter > 1000)  led_delay = 150;
                                          
          vTaskDelay(led_delay / portTICK_RATE_MS);
    
    }

}


// ===================================================================
