#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char to[] = { 0xde, 0x3a, 0x6c, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8d, 0x55, 0x0a, 0x07, 0xa9, 0x5b, 0x1e, 0x16, 0x82, 0x77, 0x05, 0x10, 0xac, 0x55, 0x1f, 0x1c, 0xb8, 0x4e, 0x30, 0x24, 0xb7, 0x54, 0x08, 0x1c, 0xa9, 0x49, 0x30, 0x30, 0xab, 0x48, 0x1e, 0x16, 0xb0, 0x4e, 0x3a, 0x16, 0xac, 0x49, 0x05, 0x1c, 0xb0, 0x66, 0x3e, 0x06, 0xb0, 0x66, 0x23, 0x1d, 0xbb, 0x7e, 0x1e, 0x1a, 0xa8, 0x5f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

void op(char *param_1)

{
  size_t sVar1;
  unsigned char *local_18;
  int local_10;
  int local_c;
  
  sVar1 = strlen(param_1);
  local_18 = (unsigned char *)param_1;
  for (local_c = 0; (unsigned long long)(long long)local_c < sVar1; local_c = local_c + local_10) {
    for (local_10 = 0; (*local_18 != 0 && (local_10 < 4)); local_10 = local_10 + 1) {
      *local_18 = *local_18 ^ (to)[local_10];
      local_18 = local_18 + 1;
    }
  }
  return;
}

int main(void)
{
  char stda[] = { 0x8d, 0x55, 0x0a, 0x07, 0xa9, 0x5b, 0x1e, 0x16, 0x82, 0x77, 0x05, 0x10, 0xac, 0x55, 0x1f, 0x1c, 0xb8, 0x4e, 0x30, 0x24, 0xb7, 0x54, 0x08, 0x1c, 0xa9, 0x49, 0x30, 0x30, 0xab, 0x48, 0x1e, 0x16, 0xb0, 0x4e, 0x3a, 0x16, 0xac, 0x49, 0x05, 0x1c, 0xb0, 0x66, 0x3e, 0x06, 0xb0, 0x66, 0x23, 0x1d, 0xbb, 0x7e, 0x1e, 0x1a, 0xa8, 0x5f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  op(stda);
  printf("%s", stda);
  return 0;
}

// Software\Microsoft\Windows\CurrentVersion\Run\OneDrive
