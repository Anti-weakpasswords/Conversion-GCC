#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

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

void bin2Base64PlusSlashEqualsOneLine(uint8_t *in, uint64_t inLen, uint8_t *out);
  // Basic lookup table going from binary to Base64
  // This Base64 uses the RFC alphabet of a-zA-Z0-9+/    with = padding
  // This Base64 does NOT put anything CR or LF characters in the output (i.e. it's not the full MIME standard)
  
  // Reasonably close to a constant time implementation if and only if the input size is identical.  This is to reduce vulnerabilities to timing attacks.
  // This code is intended to be easy to read and portable, not fast - the original purpose is encoding and decoding data that was very computationally expensive to
  //   create (password hashes), so any inefficiencies here are rendered insignificant in comparison.
  
  // NO ERROR HANDLING!  ADD THAT!


void bin2HexLower(uint8_t *in, uint64_t inLen, uint8_t *out);
  // Basic lookup table going from binary to the two-character hex code that matches 0-9a-f in ASCII/ANSI/UTF-7/UTF-8.

  // Reasonably close to a constant time implementation if and only if the input size is identical.  This is to reduce vulnerabilities to timing attacks.
  // This code is intended to be easy to read and portable, not fast - the original purpose is encoding and decoding data that was very computationally expensive to
  //   create (password hashes), so any inefficiencies here are rendered insignificant in comparison.

  
  /* To use, assuming argv[1] is what you're sending in to be converted
    char* out;
    
    // Allocate and zero out RAM for the hex output string - 2 hex digits per input byte, plus a trailing \0 to end the string.
    out = (uint8_t *)calloc((size_t) strlen(argv[1])*2+1,(size_t) 1);
    bin2HexLower((uint8_t *)argv[1],strlen(argv[1]),(uint8_t *)out);
    printf("binToHex: %s\n",out);
  
  */
  
  // NO ERROR HANDLING!  ADD THAT!


void bin2HexUpper(uint8_t *in, uint64_t inLen, uint8_t *out);
  // Basic lookup table going from binary to the two-character hex code that matches 0-9a-f in ASCII/ANSI/UTF-7/UTF-8.

  // Reasonably close to a constant time implementation if and only if the input size is identical.  This is to reduce vulnerabilities to timing attacks.
  // This code is intended to be easy to read and portable, not fast - the original purpose is encoding and decoding data that was very computationally expensive to
  //   create (password hashes), so any inefficiencies here are rendered insignificant in comparison.

  
  /* To use, assuming argv[1] is what you're sending in to be converted
    char* out;
    
    // Allocate and zero out RAM for the hex output string - 2 hex digits per input byte, plus a trailing \0 to end the string.
    out = (uint8_t *)calloc((size_t) strlen(argv[1])*2+1,(size_t) 1);
    bin2HexUpper((uint8_t *)argv[1],strlen(argv[1]),(uint8_t *)out);
    printf("binToHex: %s\n",out);
  
  */
  
  // NO ERROR HANDLING!  ADD THAT!

uint8_t hex2Bin(uint8_t *in, uint64_t inLen, uint8_t *out);
  // Basic lookup table going from hex char to nibbles - includes BOTH upper case AND lower case
  //   There are 256 entries since we actually have to deal with an entire byte at a time
  // inLen MUST be an even number.

  // Reasonably close to a constant time implementation if and only if the input size is identical.  This is to reduce vulnerabilities to timing attacks.
  // This code is intended to be easy to read and portable, not fast - the original purpose is encoding and decoding data that was very computationally expensive to
  //   create (password hashes), so any inefficiencies here are rendered insignificant in comparison.

  
  // ALMOST NO ERROR HANDLING!  ADD THAT!
