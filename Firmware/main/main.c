#include "ed25519.h"
#include "hal.h"
#include "sha2.h"

#define MAX_CMD_ARGS 8
const char *cmdArgs[MAX_CMD_ARGS];
char cmdBuf[4096];
uint8_t dataBuf[1024];
uint8_t pubKeyBuf[32];
uint8_t secretKeyBuf[32];
uint8_t signResultBuf[256];

int isMasterSeedValid = 0;

void genRandomBytes(void *p, size_t len) {
  for (int i = 0; i < len; i++) {
    ((uint8_t *)p)[i] = esp_random() & 0xFF;
  }
}

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

void clearKey() { memset(secretKeyBuf, 0, sizeof(secretKeyBuf)); }

int deriveSecretKeyWithUsage(const char *usage) {
  SHA256_CTX ctx = {0};
  clearKey();
  if (strlen(usage) < 5) {
    return -1;
  }
  sha256_Init(&ctx);
  sha256_Update(&ctx, halSecret, HAL_SECRET_INFO_SIZE);
  sha256_Update(&ctx, (uint8_t *)usage, strlen(usage));
  sha256_Final(&ctx, secretKeyBuf);
  return 0;
}

// Prepare secret key for usage
int cmdPrepareSecretKey(const char *usage, const char *ensureUsagePrefix) {
  if (!isMasterSeedValid) {
    halUartWriteStr("+ERR,key not generated\n");
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
  clearKey();
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
  clearKey();
  halUartWriteStr("+OK,");
  halUartWriteHexBuf(signResultBuf, sizeof(ed25519_signature));
  halUartWriteStr("\n");
}

void cmdGenKey() {
  int dataLen = tryDecodeHexBuf(cmdArgs[1], dataBuf, sizeof(dataBuf));
  if (dataLen != 32) {
    halUartWriteStr("+ERR,invalid data\n");
    return;
  }
  memset(halSecret, 0, HAL_SECRET_INFO_SIZE);
  // TODO: open wifi for random number generation
  for (int i = 0; i < dataLen; i++) {
    halSecret[i] = dataBuf[i];
  }
  for (int loop = 0; loop < 10; loop++) {
    for (int i = 0; i < HAL_SECRET_INFO_SIZE; i++) {
      halSecret[i] ^= esp_random() & 0xFF;
    }
    vTaskDelay(1000 / portTICK_PERIOD_MS);
  }
  halSecret[HAL_SECRET_INFO_SIZE - 2] = 0x55;
  halSecret[HAL_SECRET_INFO_SIZE - 1] = 0xAA;

  halProgramSecret();
  halUartWriteStr("+OK\n");
  // Reboot
  esp_restart();
}

int app_main(void) {
  halInit();
  halUartClearInput();
  if ((halSecret[HAL_SECRET_INFO_SIZE - 2] == 0x55) &&
      (halSecret[HAL_SECRET_INFO_SIZE - 1] == 0xAA)) {
    isMasterSeedValid = 1;
  }
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
    if (strcmp(cmdArgs[0], "+PUBKEY") == 0) {
      cmdPubKey();
    } else if (strcmp(cmdArgs[0], "+SIGN") == 0) {
      cmdSign();
    } else if (strcmp(cmdArgs[0], "+GENKEY") == 0) {
      cmdGenKey();
    } else {
      halUartWriteStr("+ERR,unknown command\n");
    }
  }
  return 0;
}