#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sha3.h"

char hash_buf[28];

int main(int argv, char **argc) {
  if (argv != 2) {
    printf("usage: sha3shake <FILE>");
    fflush(stdout);
    return 1;
  }
  memset(hash_buf, sizeof hash_buf, 0);

  char *fcontent = NULL;
  int fsize = 0;
  FILE *fp;

  fp = fopen(argc[1], "r");
  if (!fp) {
    perror("fopen");
    exit(1);
  }

  fseek(fp, 0, SEEK_END);
  fsize = ftell(fp);
  rewind(fp);

  fcontent = (char*) malloc(sizeof(char) * (fsize + 1));
  fsize = fread(fcontent, 1, fsize, fp);

  fclose(fp);

  fcontent[fsize] = 0;

  sha3_ctx_t sha3;

  sha3_init(&sha3, sizeof hash_buf);
  sha3_update(&sha3, fcontent, fsize);
  sha3_final(hash_buf, &sha3);

  for (int i = 0; i < sizeof hash_buf; i++) {
    printf("%02X", (unsigned char) hash_buf[i]);
  }
  printf(" %s\n", argc[1]);

  return 0;

}
