
#ifdef TFT_SDA_READ
  #warning "Screenshots support enabled !!"

  #include "tiny_jpeg_encoder.h"

  #ifndef tft
  #define tft M5.Lcd
  #define UNDEF_TFT
  #endif
  

  static char screenshotFilenameStr[255] = {'\0'};
  //const char* screenshotFilenameTpl = "/%s-%04d-%02d-%02d_%02dh%02dm%02ds.jpg";
  //static uint16_t imgBuffer[320]; // one scan line used for screen capture
  static bool readPixelSuccess = false;

  static uint8_t  *rgbBuffer = NULL;
  static uint16_t *imgBuffer = NULL; // one scan line used for screen capture

  void screenshotRamInit() {
    if( psramInit() ) {
      imgBuffer = (uint16_t*)ps_calloc( 320*240, sizeof( uint16_t ) );
      rgbBuffer = (uint8_t*)ps_calloc( 320*240*3, sizeof( uint8_t ) );
      tinyJpegEncoderInit();
    } else {
      Serial.println("Screenshot without psram not supported yet, disabling");
      readPixelSuccess = false;
    }
  }

  void screenShotInit() {
    uint16_t value_in = TFT_BLUE;
    Serial.print("Test readPixel(), expected:");
    Serial.print( value_in, HEX );
    tft.fillRect(10,10,50,50, TFT_BLUE);       //  <----- Test color
    uint16_t value_out = tft.readPixel(30,30);
    Serial.print(", got:");
    Serial.println(value_out, HEX);  // <----- Try to read color
    if( value_in == value_out && psramInit() ) {
      readPixelSuccess = true;
      screenshotRamInit(); // allocate some psRam
    }
    tft.clear();
  }
  
  static void screenShot( const char* prefix = "screenshot" ) {
    if( readPixelSuccess == false ) {
      Serial.println("This TFT is unsupported, or it hasn't been tested yet");
    }
    struct tm now;
    getLocalTime(&now,0);
    *screenshotFilenameStr = {'\0'};
    
    tft.readRectRGB(0, 0, tft.width(), tft.height(), rgbBuffer);

    sprintf(screenshotFilenameStr, "/%s-%04d-%02d-%02d_%02dh%02dm%02ds.jpg", prefix, (now.tm_year)+1900,( now.tm_mon)+1, now.tm_mday,now.tm_hour , now.tm_min, now.tm_sec);
    if ( !tje_encode_to_file(screenshotFilenameStr, tft.width(), tft.height(), 3 /*3=RGB,4=RGBA*/, rgbBuffer) ) {
      Serial.println("Could not write JPEG");
    } else {
      Serial.printf("Screenshot saved as %s\n", screenshotFilenameStr);
      tft.fillScreen( TFT_WHITE );
      delay(150);
      tft.drawJpgFile( SD, screenshotFilenameStr, 0, 0, tft.width(), tft.height(), 0, 0, JPEG_DIV_NONE );
      delay( 5000 );
    }

    return;
  }

  #ifdef UNDEF_TFT
  #undef tft
  #endif
#else
  #warning "SCREENSHOT SUPPORT IS DISABLED"
  static bool readPixelSuccess = false;
  static void screenShot( const char* prefix ) { ; }
  void screenShotInit() { ; }
#endif
