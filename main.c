#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sha3.h"

char hash_buf[224 >> 3];

int main(int argv, char **argc) {
  // if (argv != 2) {
  //   printf("usage: sha3shake <FILE>");
  //   return 1;
  // }

  char in[] = "";

  // 6B4E03423667DBB73B6E15454F0EB1ABD4597F9A1B078E3F5B5A6BC7
  // 6B4E03423667DBB73B6E15454F0EB1ABD4597F9A1B078E3F5B5A6BC7

  // 2F1A5F7159E34EA19CDDC70EBF9B81F1A66DB40615D7EAD3CC1F1B954D82A3AF
  // 6C6240725650084B4727C448673349DF04950D0D0513C28361FFE582290B41C8

  sha3(in, strlen(in), hash_buf, sizeof(hash_buf));

  for (int i = 0; i < sizeof(hash_buf); i++)
    printf("%02X", (unsigned char) hash_buf[i]);
  printf("\n");

  return 0;

}
