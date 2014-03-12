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

void bin2Base64PlusSlashEquals(uint8_t *in, uint64_t inLen, uint8_t *out)
{
  // Basic lookup table going from binary to Base64
  // This Base64 uses the RFC alphabet of a-zA-Z0-9+/    with = padding
  // This Base64 does NOT put anything CR or LF characters in the output (i.e. it's not the full MIME standard)
  
  // Reasonably close to a constant time implementation if and only if the input size is identical.  This is to reduce vulnerabilities to timing attacks.
  // This code is intended to be easy to read and portable, not fast - the original purpose is encoding and decoding data that was very computationally expensive to
  //   create (password hashes), so any inefficiencies here are rendered insignificant in comparison.
  
  // NO ERROR HANDLING!  ADD THAT!
  // Here's the lookup table
  static uint8_t sixBitsToHex[64] = 
    {
    0x41 // ASCII A
    ,0x42 // ASCII B
    ,0x43 // ASCII C
    ,0x44 // ASCII D
    ,0x45 // ASCII E
    ,0x46 // ASCII F
    ,0x47 // ASCII G
    ,0x48 // ASCII H
    ,0x49 // ASCII I
    ,0x4a // ASCII J
    ,0x4b // ASCII K
    ,0x4c // ASCII L
    ,0x4d // ASCII M
    ,0x4e // ASCII N
    ,0x4f // ASCII O
    ,0x50 // ASCII P
    ,0x51 // ASCII Q
    ,0x52 // ASCII R
    ,0x53 // ASCII S
    ,0x54 // ASCII T
    ,0x55 // ASCII U
    ,0x56 // ASCII V
    ,0x57 // ASCII W
    ,0x58 // ASCII X
    ,0x59 // ASCII Y
    ,0x5a // ASCII Z
    ,0x61 // ASCII a
    ,0x62 // ASCII b
    ,0x63 // ASCII c
    ,0x64 // ASCII d
    ,0x65 // ASCII e
    ,0x66 // ASCII f
    ,0x67 // ASCII g
    ,0x68 // ASCII h
    ,0x69 // ASCII i
    ,0x6a // ASCII j
    ,0x6b // ASCII k
    ,0x6c // ASCII l
    ,0x6d // ASCII m
    ,0x6e // ASCII n
    ,0x6f // ASCII o
    ,0x70 // ASCII p
    ,0x71 // ASCII q
    ,0x72 // ASCII r
    ,0x73 // ASCII s
    ,0x74 // ASCII t
    ,0x75 // ASCII u
    ,0x76 // ASCII v
    ,0x77 // ASCII w
    ,0x78 // ASCII x
    ,0x79 // ASCII y
    ,0x7a // ASCII z
    ,0x30 // ASCII 0
    ,0x31 // ASCII 1
    ,0x32 // ASCII 2
    ,0x33 // ASCII 3
    ,0x34 // ASCII 4
    ,0x35 // ASCII 5
    ,0x36 // ASCII 6
    ,0x37 // ASCII 7
    ,0x38 // ASCII 8
    ,0x39 // ASCII 9
    ,0x2b // ASCII +
    ,0x2f // ASCII /
    };

  static uint8_t padding = 0x3d;
  
  // Base64 in all its forms converts between 3 8 bit bytes (24 bits) and 4 6 bit units (24 bits)
  //  Since we're going from 3x8 to 4x6, let's see how many sets of 3 we have, and then how many 8 bit bytes are left over.
  uint64_t setsOfThree;
  uint64_t charsLeftOver;
  uint8_t outSet[4]; // the output set - essentially, 4 6 bit units.
  uint8_t inSet[3]; // the input set - essentially, 3 8 bit bytes
  uint8_t inUnit;
  
  setsOfThree = inLen / 3;
  charsLeftOver = inLen % 3;
  
  for (uint64_t i = 0; i<setsOfThree;i++)
    {
    // The leftmost 6 bits of outSet byte 1 is 6 bit unit 1
    // In this case, bit shifting is used exclusively for readability.
    inSet[0] = in[i*3];
    inSet[1] = in[i*3+1];
    inSet[2] = in[i*3+2];

    inUnit = inSet[0] >> 2; // right shift by two since we only want what were originally the leftmost 6 bits of an 8 bit byte in the rightmost 6 bits of our 6 bit unit, and >> fills in with 0's
    outSet[0] = sixBitsToHex[inUnit];

    inUnit = inSet[0] << 6; // left shift by 6 to get exactly the rightmost 2 bits of the 1st byte
    inUnit = inUnit >> 2; // and move then over so we're not using the 1st and 2nd positions of the 8 bit byte
    inUnit |= inSet[1] >> 4; // now OR it with the leftmost 4 bits of the 2nd byte!  
    outSet[1] = sixBitsToHex[inUnit];

    inUnit = inSet[1] << 4; // now the rightmost 4 bits of the 2nd byte
    inUnit = inUnit >> 2; // and move then over so we're not using the 1st and 2nd positions of the 8 bit byte
    inUnit |= (inSet[2] >> 6); // now OR it with the leftmost 2 bits of the 3rd byte!  
    outSet[2] = sixBitsToHex[inUnit];

    inUnit = inSet[2] << 2; // now let's get only the rightmost 6 bits of the last byte
    inUnit = inUnit >> 2; 
    outSet[3] = sixBitsToHex[inUnit];

    out[i*4] = outSet[0];
    out[i*4+1] = outSet[1];
    out[i*4+2] = outSet[2];
    out[i*4+3] = outSet[3];
    };

  
  if(charsLeftOver == 2)
  {
    // The leftmost 6 bits of outSet byte 1 is 6 bit unit 1
    // In this case, bit shifting is used exclusively for readability.
    inSet[0] = in[inLen-2];
    inSet[1] = in[inLen-1];
    //inSet[2] won't be used because it doesn't exist.

    inUnit = inSet[0] >> 2; // right shift by two since we only want the leftmost 6 bits, and >> fills in with 0's
    outSet[0] = sixBitsToHex[inUnit];

    inUnit = inSet[0] << 6; // left shift by 6 to get exactly the rightmost 2 bits of the 1st byte
    inUnit = inUnit >> 2; // then shift back to the right to put these two bits in the right place
    inUnit |= inSet[1] >> 4; // now OR it with the leftmost 4 bits of the 2nd byte!  
    outSet[1] = sixBitsToHex[inUnit];

    inUnit = inSet[1] << 4; // now the rightmost 4 bits of the 2nd byte
    inUnit = inUnit >> 2; // and move then over so we're not using the 1st and 2nd positions of the 8 bit byte
    // there's only 4 bits here, since 2*8=16, and 2*6=12, and 16-12=4.
    outSet[2] = sixBitsToHex[inUnit];

    // no unit 4; this is of course something a timing attack might notice.
    outSet[3] = padding; // there isn't any last 6 bits - use padding.

    out[setsOfThree*4] = outSet[0];
    out[setsOfThree*4+1] = outSet[1];
    out[setsOfThree*4+2] = outSet[2];
    out[setsOfThree*4+3] = outSet[3];
  };

  if(charsLeftOver == 1)
  {
    // The leftmost 6 bits of outSet byte 1 is 6 bit unit 1
    // In this case, bit shifting is used exclusively for readability.
    inSet[0] = in[inLen-1];
    //inSet[1] and inSet[2] won't be used because they don't exist.

    inUnit = inSet[0] >> 2; // right shift by two since we only want the leftmost 6 bits, and >> fills in with 0's
    outSet[0] = sixBitsToHex[inUnit];

    inUnit = inSet[0] << 6; // left shift by 6 to get exactly the rightmost 2 bits of the 1st byte
    inUnit = inUnit >> 2; // then shift back to the right to put these two bits in the right place
    // just those 2 bits are all we have left.
    outSet[1] = sixBitsToHex[inUnit];

    // no unit 3; this is of course something a timing attack might notice.
    outSet[2] = padding;

    // no unit 4; this is of course something a timing attack might notice.
    outSet[3] = padding; // there isn't any last 6 bits - use padding.
    
    out[setsOfThree*4] = outSet[0];
    out[setsOfThree*4+1] = outSet[1];
    out[setsOfThree*4+2] = outSet[2];
    out[setsOfThree*4+3] = outSet[3];
  };
  
}




void bin2HexLower(uint8_t *in, uint64_t inLen, uint8_t *out)
{
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
  static uint8_t nibbleToHex[16] = 
    {
    0x30  // ASCII 0
    ,0x31 // ASCII 1
    ,0x32 // ASCII 2
    ,0x33 // ASCII 3
    ,0x34 // ASCII 4
    ,0x35 // ASCII 5
    ,0x36 // ASCII 6
    ,0x37 // ASCII 7
    ,0x38 // ASCII 8
    ,0x39 // ASCII 9
    ,0x61 // ASCII a
    ,0x62 // ASCII b
    ,0x63 // ASCII c
    ,0x64 // ASCII d
    ,0x65 // ASCII e
    ,0x66 // ASCII f
    };
  for (uint64_t i = 0; i<inLen;i++)
    {
    // First hex digit
    out[i*2] = nibbleToHex[(in[i]) >> 4]; // First we take the leftmost four bits - >> is the rightshift operator, and it fills in 0 into the bits that it's replacing, while discarding the bits on the right.
    // Second hex digit
    out[i*2+1] = nibbleToHex[(0x0f & in[i])]; // second we take the rightmost four - to do that, we use a bitwise AND to 0 out the leftmost four bits
    };
}



void bin2HexUpper(uint8_t *in, uint64_t inLen, uint8_t *out)
{
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
  static uint8_t nibbleToHex[16] = 
    {
    0x30  // ASCII 0
    ,0x31 // ASCII 1
    ,0x32 // ASCII 2
    ,0x33 // ASCII 3
    ,0x34 // ASCII 4
    ,0x35 // ASCII 5
    ,0x36 // ASCII 6
    ,0x37 // ASCII 7
    ,0x38 // ASCII 8
    ,0x39 // ASCII 9
    ,0x41 // ASCII A
    ,0x42 // ASCII B
    ,0x43 // ASCII C
    ,0x44 // ASCII D
    ,0x45 // ASCII E
    ,0x46 // ASCII F
    };
  for (uint64_t i = 0; i<inLen;i++)
    {
      out[i*2] = nibbleToHex[(in[i]) >> 4];
      out[i*2+1] = nibbleToHex[(0x0f & in[i])];
    };
}

uint8_t hex2Bin(uint8_t *in, uint64_t inLen, uint8_t *out)
{
  // Basic lookup table going from hex char to nibbles - includes BOTH upper case AND lower case
  //   There are 256 entries since we actually have to deal with an entire byte at a time
  // inLen MUST be an even number.

  // Reasonably close to a constant time implementation if and only if the input size is identical.  This is to reduce vulnerabilities to timing attacks.
  // This code is intended to be easy to read and portable, not fast - the original purpose is encoding and decoding data that was very computationally expensive to
  //   create (password hashes), so any inefficiencies here are rendered insignificant in comparison.

  
  // ALMOST NO ERROR HANDLING!  ADD THAT!
  static uint8_t hexToNibble[256] = 
  {
  0xf0  // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0x0 // ASCII 0
  ,0x1 // ASCII 1
  ,0x2 // ASCII 2
  ,0x3 // ASCII 3
  ,0x4 // ASCII 4
  ,0x5 // ASCII 5
  ,0x6 // ASCII 6
  ,0x7 // ASCII 7
  ,0x8 // ASCII 8
  ,0x9 // ASCII 9
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xa // ASCII A
  ,0xb // ASCII B
  ,0xc // ASCII C
  ,0xd // ASCII D
  ,0xe // ASCII E
  ,0xf // ASCII F
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xa // ASCII a
  ,0xb // ASCII b
  ,0xc // ASCII c
  ,0xd // ASCII d
  ,0xe // ASCII e
  ,0xf // ASCII f
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  ,0xf0 // ASCII value that is NOT a valid hex character
  };
  uint8_t isError = 0;
  
  for (uint64_t i = 0; i<(inLen);i+=2)
    {
    // Primitive reasonably close to constant time error check; note that the invalid hex digit will simply end up putting a nibble of 0's in the output string
    //   which also keeps the time close to constant, error or no
    if(hexToNibble[in[i]] == 0xf0)
      {
      isError |= 1;
      }
    if(hexToNibble[in[i+1]] == 0xf0)
      {
      isError |= 1;
      }
    // This depends on i/2 truncating/flooring to the correct index, and then we'll get the leftmost nibble and left-shift it 4, 
    //   then the rightmost nibble and OR in the rightmost nibble out of the byte we're working with of it
    out[i/2] = (hexToNibble[in[i]] << 4) | (hexToNibble[in[i+1]] & 0x0f);
    };
  return isError;
}

