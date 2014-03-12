#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "conversion.h"

/*
Written 2014 by Anti-weakpasswords
https://github.com/Anti-weakpasswords

This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org>
*/


int main (int argc, char *argv[])
{
  // Code below is a primitive example with almost none of the error and bad data handling you SHOULD have!!!
  
  printf("Usage: %s [string to convert TO hex] [hex string to convert TO binary and then convert that binary TO Base64]\n",argv[0]);
  puts("  The strings do NOT have to be the same.");
  puts("WARNING: This is mainly just a demonstration of public domain skeleton conversion code - just enough to work in nearly constant time");
  puts("   for constant length output - i.e. password hashing with a fixed output length and salt size.");
  char* out;
  char* outBase64;
  uint8_t isError;
  
  if(argc < 3)
    {
    puts("You must enter at least 2 arguments.");
    return 1;
    }
  
  // Allocate and zero out RAM for the hex output string - 2 hex digits per input byte, plus a trailing \0 to end the string.
  out = (char *)calloc((size_t) strlen(argv[1])*2+1,(size_t) 1);
  
  bin2HexLower((uint8_t *)argv[1],strlen(argv[1]),(uint8_t *)out);
  printf("binToHex hex output lowercase: \n%s\n",out);

  bin2HexUpper((uint8_t *)argv[1],strlen(argv[1]),(uint8_t *)out);
  printf("binToHex hex output uppercase: \n%s\n",out);

  
  free(out);
  if (strlen(argv[2]) % 2 != 0)
    {
    puts("Hex strings MUST have an even number of characters, i.e. 61 or 5a7A");
    }
  // Allocate and zero out RAM for the "binary" output - 2 hex digits per input byte, plus a trailing \0 to end the string.
  // FOR TRUE BINARY OUTPUT, do NOT include the +1 byte for the trailing \0 - but do NOT treat it as a string then, either!!!
  out = (char *)calloc((size_t) strlen(argv[2])/2+1,(size_t) 1);
  isError = hex2Bin((uint8_t *) argv[2],strlen(argv[2]),(uint8_t *)out);
  if (isError)
    {
      puts("Invalid character found in argument 2, the hex string.  Replaced by a nibble of 0's.");
    }
  printf("hex2Bin binary output: \n%s\n",out);
  
  // Size is the number of 4 byte sets we'll output, plus one for padding if need be, plus one for a \0 string terminator.
  outBase64 = (char *)calloc((size_t) (strlen(out)*4)/3+4+1,(size_t) 1);
  bin2Base64PlusSlashEquals((uint8_t *)out,strlen(out),(uint8_t *)outBase64);
  printf("hex2Base64RFCPaddedNoCrlf Base64 output: \n%s\n",outBase64);
  
  return 0;
}
