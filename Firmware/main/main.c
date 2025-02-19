#include "ed25519.h"
#include "hal.h"
#include "sha2.h"
#include "memzero.h"

#define MAX_CMD_ARGS 8
const char *cmdArgs[MAX_CMD_ARGS];
char cmdBuf[4096];
uint8_t dataBuf[2048];
uint8_t pubKeyBuf[32];
uint8_t signResultBuf[256];

/* Secrets */
uint8_t deviceSecretInfo[HAL_SECRET_INFO_SIZE];
uint8_t userSecretSeedBuf[32];
uint8_t secretKeyBuf[32];
/* End of secrets */

int isUserSeedSet = 0;


int decodeHexDigit(char ch) {
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  return -1;
}

int tryDecodeHexBuf(const char *hex, uint8_t *dst, size_t dstLen) {
  int dstPos = 0;
  memset(dst, 0, dstLen);
  while (*hex) {
    char c1 = *hex;
    char c2 = *(hex + 1);
    if (c2 == 0) {
      return -1;
    }
    hex += 2;
    int d1 = decodeHexDigit(c1);
    int d2 = decodeHexDigit(c2);
    if ((d1 < 0) || (d2 < 0)) {
      return -1;
    }
    if (dstPos >= dstLen) {
      return -1;
    }
    dst[dstPos] = (d1 << 4) | d2;
    dstPos++;
  }
  return dstPos;
}

void clearSecretKey() { 
  memzero(secretKeyBuf, sizeof(secretKeyBuf));
}

int deriveSecretKeyWithUsage(const char *usage) {
  SHA256_CTX ctx = {0};
  clearSecretKey();
  if (!isUserSeedSet) {
    return -1;
  }
  if (strlen(usage) < 5) {
    return -1;
  }
  sha256_Init(&ctx);
  sha256_Update(&ctx, (uint8_t *)usage, strlen(usage));
  sha256_Update(&ctx, userSecretSeedBuf, sizeof(userSecretSeedBuf));
  sha256_Update(&ctx, (uint8_t *)usage, strlen(usage));
  const char* appendStr = "44KeyGenerateSecretKeyForUsage!";
  sha256_Update(&ctx, (uint8_t *)appendStr, strlen(appendStr));
  sha256_Final(&ctx, secretKeyBuf);
  return 0;
}

// Prepare secret key for usage
int cmdPrepareSecretKey(const char *usage, const char *ensureUsagePrefix) {
  if (!isUserSeedSet) {
    halUartWriteStr("+ERR,user seed not set\r\n");
    return -1;
  }
  if (strlen(usage) < 5) {
    halUartWriteStr("+ERR,usage too short\n");
    return -1;
  }
  if (strncmp(usage, ensureUsagePrefix, strlen(ensureUsagePrefix)) != 0) {
    halUartWriteStr("+ERR,usage prefix mismatch\n");
    return -1;
  }
  int ret = deriveSecretKeyWithUsage(usage);
  if (ret < 0) {
    halUartWriteStr("+ERR,failed\n");
    return -1;
  }
  return 0;
}

void cmdPubKey() {
  if (cmdPrepareSecretKey(cmdArgs[1], "ed25519-ssh-") != 0) {
    return;
  }
  ed25519_publickey(secretKeyBuf, pubKeyBuf);
  clearSecretKey();
  halUartWriteStr("+OK,");
  halUartWriteHexBuf(pubKeyBuf, sizeof(pubKeyBuf));
  halUartWriteStr("\n");
}

void cmdSign() {
  if (cmdPrepareSecretKey(cmdArgs[1], "ed25519-ssh-") != 0) {
    return;
  }
  ed25519_publickey(secretKeyBuf, pubKeyBuf);
  int dataLen = tryDecodeHexBuf(cmdArgs[2], dataBuf, sizeof(dataBuf));
  if (dataLen < 8) {
    halUartWriteStr("+ERR,invalid data\n");
    return;
  }
  ed25519_sign(dataBuf, dataLen, secretKeyBuf, pubKeyBuf, signResultBuf);
  clearSecretKey();
  halUartWriteStr("+OK,");
  halUartWriteHexBuf(signResultBuf, sizeof(ed25519_signature));
  halUartWriteStr("\n");
}

void cmdFormat() {
  if (isUserSeedSet) {
    halUartWriteStr("+ERR,user seed already set\n");
    return;
  }
  int dataLen = tryDecodeHexBuf(cmdArgs[1], dataBuf, sizeof(dataBuf));
  if (dataLen != 32) {
    halUartWriteStr("+ERR,invalid data\n");
    return;
  }
  
  memzero(deviceSecretInfo, HAL_SECRET_INFO_SIZE);

  for (int i = 0; i < 32; i++) {
    deviceSecretInfo[i] = dataBuf[i];
  }
  for (int loop = 0; loop < 10; loop++) {
    for (int i = 0; i < HAL_SECRET_INFO_SIZE; i++) {
      deviceSecretInfo[i] ^= halRandomU32() & 0xFF;
    }
    vTaskDelay(1000 / portTICK_PERIOD_MS);
  }
  deviceSecretInfo[HAL_SECRET_INFO_SIZE - 2] = 0x55;
  deviceSecretInfo[HAL_SECRET_INFO_SIZE - 1] = 0xAA;

  HAL_ASSERT(halProgramSecretInfo(deviceSecretInfo) == 0);
  halUartWriteStr("+OK\n");
  // Reboot
  esp_restart();
}

void cmdUserSeed() {
  if (isUserSeedSet) {
    halUartWriteStr("+ERR,user seed already set\n");
    return;
  }
  int dataLen = tryDecodeHexBuf(cmdArgs[1], dataBuf, sizeof(dataBuf));
  if (dataLen != 32) {
    halUartWriteStr("+ERR,invalid data\n");
    return;
  }
  memzero(deviceSecretInfo, HAL_SECRET_INFO_SIZE);
  HAL_ASSERT(halReadSecretInfo(deviceSecretInfo) == 0);
  if (deviceSecretInfo[HAL_SECRET_INFO_SIZE - 2] != 0x55 || deviceSecretInfo[HAL_SECRET_INFO_SIZE - 1] != 0xAA) {
    halUartWriteStr("+ERR,not formatted\n");
    return;
  }
  SHA256_CTX ctx = {0};
  sha256_Init(&ctx);
  sha256_Update(&ctx, dataBuf, 32);
  sha256_Update(&ctx, deviceSecretInfo, HAL_SECRET_INFO_SIZE);
  memzero(deviceSecretInfo, HAL_SECRET_INFO_SIZE);
  sha256_Update(&ctx, dataBuf, 32);
  const char* appendStr = "44KeyGenerateUserSecretSeedByPassword!";
  sha256_Update(&ctx, (uint8_t *)appendStr, strlen(appendStr));
  sha256_Final(&ctx, userSecretSeedBuf);
  isUserSeedSet = 1;
  halUartWriteStr("+OK\n");
}

int app_main(void) {
  halInit();
  halUartClearInput();

  while (1) {
    memset(cmdBuf, 0, sizeof(cmdBuf));
    for (int i = 0; i < MAX_CMD_ARGS; i++) {
      cmdArgs[i] = "";
    }
    int ret = halUartReadLine(cmdBuf, sizeof(cmdBuf));
    if (ret != 0) {
      continue;
    }
    if (strlen(cmdBuf) < 2) {
      continue;
    }
    // Split cmdBuf by ',', and store the result in cmdArgs
    int argCount = 1;
    int pos = 0;
    cmdArgs[0] = cmdBuf;
    while ((argCount < MAX_CMD_ARGS) && (cmdBuf[pos])) {
      if (cmdBuf[pos] == ',') {
        cmdBuf[pos] = 0;
        cmdArgs[argCount] = cmdBuf + pos + 1;
        argCount++;
      }
      pos++;
    }
    if (strcmp(cmdArgs[0], "+PING") == 0) {
      halUartWriteStr("+PONG\n");
    } else if (strcmp(cmdArgs[0], "+USERSEED") == 0) {
      cmdUserSeed();
    } else if (strcmp(cmdArgs[0], "+PUBKEY") == 0) {
      cmdPubKey();
    } else if (strcmp(cmdArgs[0], "+SIGN") == 0) {
      cmdSign();
    } else if (strcmp(cmdArgs[0], "+FORMAT") == 0) {
      cmdFormat();
    } else {
      halUartWriteStr("+ERR,unknown command\n");
    }
  }
  return 0;
}