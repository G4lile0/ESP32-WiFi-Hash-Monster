#ifndef Buffer_h
#define Buffer_h

#include "Arduino.h"
#include "FS.h"
//#include "SD_MMC.h"

#if defined ARDUINO_M5Stack_Core_ESP32
  #define BUF_BLOCKS 4
  #define EWH_MALLOC malloc
#else
  #define BUF_BLOCKS 24
  #if defined BOARD_HAS_PSRAM
    #define EWH_MALLOC ps_malloc
  #else
    #define EWH_MALLOC malloc
  #endif
#endif

#define BUF_SIZE BUF_BLOCKS * 1024
#define SNAP_LEN 2324 // max len of each recieved packet

extern bool useSD;

class Buffer {
  public:
    Buffer();
    bool init();
    void checkFS(fs::FS* fs);
    bool open(fs::FS* fs);
    void close(fs::FS* fs);
    void addPacket(uint8_t* buf, uint32_t len);
    void save(fs::FS* fs);
    void forceSave(fs::FS* fs);



  private:
    void write(int32_t n);
    void write(uint32_t n);
    void write(uint16_t n);
    void write(uint8_t* buf, uint32_t len);

    uint64_t micros64();

    uint8_t* bufA;
    uint8_t* bufB;

    uint32_t bufSizeA = 0;
    uint32_t bufSizeB = 0;

    bool writing = false; // acceppting writes to buffer
    bool useA = true; // writing to bufA or bufB
    bool saving = false; // currently saving onto the SD card

    char fileNameStr[32] = {0};
    const char *folderName = "/pcap"; // no trailing slash
    const char *fileNameTpl = "%s/%04X.pcap"; // hex is better for natural sorting, assume max 65536 files
    File file;

    uint32_t previous_micros = 0;
    uint32_t micros_high = 0;
};

#endif
