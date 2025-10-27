#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "sha3.h"

const char *sha_usage = "usage: sha3shake sha <SECURITY_LEVEL_BITS> <FILE>";
const char *shake_usage = "usage: sha3shake shake <SECURITY_LEVEL_BITS> <OUTPUT_BYTES> <SEED>";

char hash_buf[64];

char *readFile();

int main(int argv, char **argc) {
  int mdlen;
  bool is_sha, is_shake;
  sha3_ctx_t sha;

  if (argv < 2) {
    printf("Not enough arguments!\n%s\n%s", sha_usage, shake_usage);
    return 1;
  }

  is_sha = strcmp("sha", argc[1]) == 0;
  is_shake = strcmp("shake", argc[1]) == 0;
  if (!is_sha && !is_shake) {
    printf("Unknown usage mode, expected 'sha' or 'shake'\n%s\n%s", sha_usage, shake_usage);
    return 1;
  }


  if (is_shake) {
    if (argv < 5) {
      printf("Not enough arguments!\n%s", shake_usage);
      return 1;
    } else if (argv > 5) {
      printf("Too many arguments!\n%s", shake_usage);
      return 1;
    }

    mdlen = strtol(argc[2], NULL, 10);
    if (mdlen != 128
     && mdlen != 256) {
      printf("SECURITY_LEVEL_BITS must be ether 128 or 256. found: '%s'", argc[2]);
      return 1;
    }
    mdlen >>= 3;

    int output_len = strtol(argc[3], NULL, 10);
    if (output_len <= 0) {
      printf("OUTPUT_BYTES must be an integer 1 or greater. found: '%s'", argc[3]);
      return 1;
    }

    if (mdlen == 16) {
      shake128_init(&sha);
    } else if (mdlen == 32) {
      shake256_init(&sha);
    }

    shake_update(&sha, argc[4], strlen(argc[4]));
    shake_xof(&sha);

    while (output_len > 0) {
     int len = output_len > mdlen ? mdlen : output_len;
     output_len -= mdlen;

     shake_out(&sha, hash_buf, len);

     for (int i = 0; i < len; i++) {
       printf("%02x", (unsigned char) hash_buf[i]);
     }
    }
  } else {
    assert(is_sha);
    if (argv < 4) {
      printf("Not enough arguments!\n%s", sha_usage);
      return 1;
    } else if (argv > 4) {
      printf("Too many arguments!\n%s", sha_usage);
      return 1;
    }

    mdlen = strtol(argc[2], NULL, 10);
    if (mdlen != 224
     && mdlen != 256
     && mdlen != 384
     && mdlen != 512) {
      printf("SECURITY_LEVEL_BITS, must be 224, 256, 384, or 512. found: '%s'", argc[1]);
      return 1;
    }
    mdlen >>= 3;

    const char *contents = readFile(argc[3]);
    if (!contents) {
      perror("open");
      return 1;
    }
    const size_t len = strlen(contents);

    sha3(contents, len, hash_buf, mdlen);

    for (int i = 0; i < mdlen; i++) {
      printf("%02x", (unsigned char) hash_buf[i]);
    }
    printf(" %s\n", argc[3]);
  }

  return 0;
}

char *readFile(char *filename) {
  char *fcontent = NULL;
  int fsize = 0;

  {
    FILE *fp;
    fp = fopen(filename, "r");
    if (!fp) {
      perror("fopen");
      return NULL;
    }
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    rewind(fp);
    fcontent = (char*) malloc(sizeof(char) * (fsize + 1));
    fsize = fread(fcontent, 1, fsize, fp);

    fclose(fp);
  }
  fcontent[fsize] = 0;

  return fcontent;
}
