/*

This is an implementation of the AES algorithm, specifically ECB, CTR and CBC mode.
Block size can be chosen in aes.h - available choices are AES128, AES192, AES256.

The implementation is verified against the test vectors in:
  National Institute of Standards and Technology Special Publication 800-38A 2001 ED

ECB-AES128
----------

  plain-text:
    6bc1bee22e409f96e93d7e117393172a
    ae2d8a571e03ac9c9eb76fac45af8e51
    30c81c46a35ce411e5fbc1191a0a52ef
    f69f2445df4f9b17ad2b417be66c3710

  key:
    2b7e151628aed2a6abf7158809cf4f3c

  resulting cipher
    3ad77bb40d7a3660a89ecaf32466ef97 
    f5d3d58503b9699de785895a96fdbaaf 
    43b1cd7f598ece23881b00e3ed030688 
    7b0c785e27e8ad3f8223207104725dd4 


NOTE:   String length must be evenly divisible by 16byte (str_len % 16 == 0)
        You should pad the end of the string with zeros if this is not the case.
        For AES192/256 the key size is proportionally larger.

*/


/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include <string.h> // CBC mode, for memset
#include "aes.h"

/*****************************************************************************/
/* Defines:                                                                  */
/*****************************************************************************/
// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4

#if defined(AES256) && (AES256 == 1)
    #define Nk 8
    #define Nr 14
#elif defined(AES192) && (AES192 == 1)
    #define Nk 6
    #define Nr 12
#else
    #define Nk 4        // The number of 32 bit words in a key.
    #define Nr 10       // The number of rounds in AES Cipher.
#endif

// jcallan@github points out that declaring Multiply as a function 
// reduces code size considerably with the Keil ARM compiler.
// See this link for more information: https://github.com/kokke/tiny-AES-C/pull/3
#ifndef MULTIPLY_AS_A_FUNCTION
  #define MULTIPLY_AS_A_FUNCTION 0
#endif




/*****************************************************************************/
/* Private variables:                                                        */
/*****************************************************************************/
// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];

// hamming code state - array holding the hamming codes of the intermediate results
typedef uint8_t hamstate_t[4][4];


// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM - 
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

// The round constant word array, Rcon[i], contains the values given by 
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

// the constant hamming code LUTs
static const uint8_t h_rd[256] = { 
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x02, 0x0e, 0x09, 0x05, 0x03, 0x0b, 0x0e, 0x00, 0x08, 0x03, 0x07, 0x01, 0x0f, 0x03, 0x0d, 0x0a, 
  0x02, 0x01, 0x0c, 0x0d, 0x0a, 0x0e, 0x01, 0x0e, 0x05, 0x0d, 0x07, 0x08, 0x0e, 0x0f, 0x0f, 0x06, 
  0x0f, 0x01, 0x0c, 0x0e, 0x00, 0x0a, 0x05, 0x0a, 0x0d, 0x0c, 0x06, 0x0d, 0x01, 0x01, 0x0b, 0x08, 
  0x05, 0x0d, 0x08, 0x08, 0x07, 0x0a, 0x06, 0x06, 0x0b, 0x03, 0x0c, 0x0d, 0x07, 0x0d, 0x09, 0x04, 
  0x0a, 0x02, 0x0a, 0x0a, 0x09, 0x0d, 0x00, 0x0a, 0x09, 0x0f, 0x00, 0x0a, 0x0c, 0x0e, 0x04, 0x09, 
  0x0a, 0x0b, 0x00, 0x0f, 0x06, 0x02, 0x07, 0x03, 0x08, 0x01, 0x05, 0x02, 0x0e, 0x06, 0x0d, 0x04, 
  0x08, 0x02, 0x0e, 0x09, 0x04, 0x05, 0x06, 0x0a, 0x0c, 0x04, 0x0d, 0x00, 0x04, 0x04, 0x00, 0x03, 
  0x07, 0x04, 0x0a, 0x0e, 0x0f, 0x0d, 0x01, 0x08, 0x08, 0x0c, 0x0c, 0x05, 0x0e, 0x0c, 0x00, 0x05, 
  0x09, 0x0c, 0x00, 0x0c, 0x06, 0x09, 0x0f, 0x05, 0x03, 0x01, 0x03, 0x07, 0x09, 0x0b, 0x04, 0x0c, 
  0x0c, 0x0f, 0x08, 0x04, 0x0b, 0x02, 0x02, 0x05, 0x02, 0x01, 0x0d, 0x0b, 0x09, 0x05, 0x07, 0x0f, 
  0x00, 0x05, 0x0c, 0x04, 0x00, 0x08, 0x03, 0x08, 0x0b, 0x06, 0x06, 0x01, 0x01, 0x04, 0x05, 0x08, 
  0x0b, 0x0f, 0x03, 0x03, 0x03, 0x0e, 0x0b, 0x00, 0x00, 0x0c, 0x0b, 0x04, 0x0a, 0x06, 0x0b, 0x09, 
  0x00, 0x0b, 0x00, 0x07, 0x02, 0x02, 0x01, 0x0e, 0x09, 0x07, 0x07, 0x0c, 0x0d, 0x0b, 0x0b, 0x08, 
  0x02, 0x09, 0x02, 0x04, 0x03, 0x0e, 0x06, 0x01, 0x0f, 0x0e, 0x0f, 0x0e, 0x04, 0x05, 0x01, 0x03, 
  0x03, 0x07, 0x0b, 0x0d, 0x06, 0x02, 0x0d, 0x07, 0x05, 0x0f, 0x07, 0x0a, 0x07, 0x02, 0x0f, 0x0a, 
  0x00, 0x09, 0x06, 0x0f, 0x06, 0x08, 0x07, 0x05, 0x09, 0x08, 0x09, 0x02, 0x04, 0x01, 0x03, 0x06 };

/*
static const uint8_t h_2rd[256] = { 
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x05, 0x06, 0x08, 0x08, 0x09, 0x06, 0x08, 0x0b, 0x0d, 0x03, 0x06, 0x05, 0x04, 0x0a, 0x09, 0x06,
  0x0b, 0x06, 0x0b, 0x08, 0x0a, 0x05, 0x05, 0x0b, 0x09, 0x0b, 0x08, 0x0a, 0x0b, 0x08, 0x05, 0x06,
  0x0a, 0x04, 0x0b, 0x0e, 0x05, 0x08, 0x04, 0x0b, 0x0e, 0x0b, 0x09, 0x09, 0x05, 0x0b, 0x0e, 0x0e,
  0x03, 0x09, 0x0e, 0x0b, 0x0d, 0x0b, 0x0d, 0x0b, 0x0e, 0x0d, 0x05, 0x0b, 0x0a, 0x05, 0x0b, 0x06,
  0x0d, 0x08, 0x0e, 0x0e, 0x05, 0x06, 0x05, 0x06, 0x0e, 0x06, 0x09, 0x09, 0x0e, 0x09, 0x06, 0x06,
  0x05, 0x0b, 0x00, 0x0a, 0x03, 0x0a, 0x0b, 0x06, 0x05, 0x09, 0x0a, 0x05, 0x0e, 0x0e, 0x0e, 0x0a,
  0x08, 0x04, 0x0b, 0x04, 0x0e, 0x05, 0x05, 0x08, 0x0e, 0x0a, 0x03, 0x0b, 0x0d, 0x05, 0x0a, 0x08,
  0x0e, 0x0b, 0x03, 0x09, 0x08, 0x09, 0x0e, 0x0a, 0x09, 0x09, 0x09, 0x0d, 0x03, 0x07, 0x0a, 0x0b,
  0x09, 0x0d, 0x0e, 0x09, 0x08, 0x09, 0x0d, 0x05, 0x08, 0x09, 0x08, 0x06, 0x0e, 0x06, 0x0e, 0x06,
  0x0d, 0x06, 0x06, 0x09, 0x0d, 0x0e, 0x06, 0x06, 0x0e, 0x0a, 0x0b, 0x0d, 0x0a, 0x06, 0x0e, 0x0a,
  0x08, 0x0e, 0x05, 0x0d, 0x0e, 0x0d, 0x0d, 0x05, 0x08, 0x09, 0x0b, 0x0e, 0x08, 0x0b, 0x0b, 0x06,
  0x0a, 0x08, 0x06, 0x06, 0x0b, 0x09, 0x05, 0x0b, 0x05, 0x05, 0x09, 0x09, 0x05, 0x06, 0x09, 0x03,
  0x09, 0x05, 0x0e, 0x05, 0x0e, 0x0b, 0x0b, 0x0b, 0x0b, 0x0a, 0x05, 0x06, 0x05, 0x0a, 0x0b, 0x08,
  0x0e, 0x06, 0x09, 0x05, 0x0d, 0x0d, 0x0a, 0x0e, 0x0e, 0x05, 0x06, 0x09, 0x08, 0x08, 0x05, 0x09,
  0x0b, 0x09, 0x08, 0x0d, 0x05, 0x09, 0x0b, 0x08, 0x09, 0x05, 0x0b, 0x09, 0x09, 0x05, 0x0d, 0x04,
  0x08, 0x08, 0x08, 0x0e, 0x04, 0x09, 0x0d, 0x0e, 0x0d, 0x0b, 0x05, 0x05, 0x08, 0x0e, 0x0a, 0x0e };


static const uint8_t h_3rd[256] = { 
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x0c, 0x09, 0x08, 0x03, 0x0f, 0x0b, 0x07, 0x01, 0x04, 0x0e, 0x00, 0x0d, 0x04, 0x01, 0x08, 0x06,
  0x0c, 0x0d, 0x0a, 0x07, 0x08, 0x07, 0x0c, 0x07, 0x0c, 0x07, 0x01, 0x04, 0x06, 0x05, 0x0a, 0x03,
  0x0b, 0x02, 0x0b, 0x08, 0x00, 0x09, 0x0d, 0x08, 0x08, 0x0b, 0x0d, 0x09, 0x0c, 0x0c, 0x0a, 0x0a,
  0x0c, 0x09, 0x0a, 0x05, 0x0f, 0x09, 0x02, 0x02, 0x0a, 0x00, 0x05, 0x07, 0x0e, 0x06, 0x09, 0x00,
  0x09, 0x03, 0x07, 0x07, 0x09, 0x09, 0x01, 0x09, 0x06, 0x05, 0x0f, 0x07, 0x05, 0x09, 0x01, 0x09,
  0x08, 0x05, 0x00, 0x0a, 0x0c, 0x0c, 0x0f, 0x0f, 0x05, 0x02, 0x02, 0x0d, 0x09, 0x0d, 0x09, 0x0e,
  0x0b, 0x02, 0x06, 0x06, 0x00, 0x03, 0x02, 0x07, 0x04, 0x0e, 0x08, 0x0f, 0x0e, 0x0f, 0x00, 0x0e,
  0x00, 0x0f, 0x06, 0x08, 0x05, 0x08, 0x03, 0x05, 0x0a, 0x05, 0x04, 0x02, 0x08, 0x0a, 0x01, 0x03,
  0x06, 0x0b, 0x0e, 0x04, 0x03, 0x07, 0x0a, 0x02, 0x0f, 0x03, 0x01, 0x01, 0x06, 0x0b, 0x01, 0x04,
  0x0a, 0x0b, 0x0b, 0x00, 0x04, 0x03, 0x0d, 0x02, 0x02, 0x0c, 0x06, 0x04, 0x08, 0x0d, 0x01, 0x0a,
  0x0f, 0x0c, 0x0b, 0x0f, 0x0f, 0x04, 0x00, 0x05, 0x0b, 0x0d, 0x02, 0x02, 0x03, 0x0f, 0x03, 0x0b,
  0x05, 0x04, 0x0e, 0x0f, 0x00, 0x09, 0x05, 0x00, 0x01, 0x0a, 0x0b, 0x00, 0x08, 0x0d, 0x0a, 0x07,
  0x0e, 0x05, 0x0e, 0x0f, 0x03, 0x0d, 0x0d, 0x07, 0x08, 0x0e, 0x0e, 0x05, 0x07, 0x04, 0x04, 0x0a,
  0x02, 0x07, 0x03, 0x0e, 0x01, 0x06, 0x03, 0x03, 0x04, 0x06, 0x04, 0x08, 0x01, 0x0d, 0x0d, 0x0e,
  0x01, 0x00, 0x0a, 0x06, 0x03, 0x02, 0x06, 0x01, 0x0c, 0x0b, 0x0f, 0x06, 0x00, 0x0c, 0x0b, 0x06,
  0x0e, 0x07, 0x0c, 0x05, 0x0c, 0x0b, 0x0e, 0x0d, 0x08, 0x04, 0x09, 0x0d, 0x01, 0x02, 0x00, 0x0c };
*/

/*
 * Jordan Goulder points out in PR #12 (https://github.com/kokke/tiny-AES-C/pull/12),
 * that you can remove most of the elements in the Rcon array, because they are unused.
 *
 * From Wikipedia's article on the Rijndael key schedule @ https://en.wikipedia.org/wiki/Rijndael_key_schedule#Rcon
 * 
 * "Only the first some of these constants are actually used – up to rcon[10] for AES-128 (as 11 round keys are needed), 
 *  up to rcon[8] for AES-192, up to rcon[7] for AES-256. rcon[0] is not used in AES algorithm."
 */


/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/
/*
static uint8_t getSBoxValue(uint8_t num)
{
  return sbox[num];
}
*/
#define getSBoxValue(num) (sbox[(num)])
/*
static uint8_t getSBoxInvert(uint8_t num)
{
  return rsbox[num];
}
*/
#define getSBoxInvert(num) (rsbox[(num)])

// The respective tables help predict the hamming codes for the aes transforms
#define getHBoxValue(num) (h_rd[(num)])
#define getH2BoxValue(num) (h_2rd[(num)])
#define getH3BoxValue(num) (h_3rd[(num)])

// Functions used during multiplication

static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

// Multiply is used to multiply numbers in the field GF(2^8)
// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
//       The compiler seems to be able to vectorize the operation better this way.
//       See https://github.com/kokke/tiny-AES-c/pull/34
#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
  }
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

// bits in the byte are numbered 0-7
static uint8_t get_bit(uint8_t byte, uint8_t bitnum)
{
  return ((byte >> bitnum) & 0x01);
}

static uint8_t flip_bit(uint8_t byte, uint8_t target)
{
  return (byte ^ (0x01 << target));
}

// creating hamming code from a byte of data
static uint8_t hamming_encode(uint8_t given)
{ 
  uint8_t hambyte = 0x00;
  uint8_t zero = get_bit(given, 0);
  uint8_t one = get_bit(given, 1);
  uint8_t two = get_bit(given, 2);
  uint8_t three = get_bit(given, 3);
  uint8_t four = get_bit(given, 4);
  uint8_t five = get_bit(given, 5);
  uint8_t six = get_bit(given, 6);
  uint8_t seven = get_bit(given, 7);

  uint8_t setzero = three ^ two ^ one ^ zero;
  uint8_t setone = six ^ five ^ four ^ zero;
  uint8_t settwo = seven ^ five ^ four ^ two ^ one;
  uint8_t setthree = seven ^ six ^ four ^ three ^ one;

  hambyte = (setzero | (setone << 0x01) | (settwo << 0x02) | (setthree << 0x03) );
  return hambyte;
}

static void correct_state(state_t* state, hamstate_t* hamstate, hamstate_t* pcode)
{
  //int8_t anspos[2];
  uint8_t c, r; 
  int8_t x;
  for (r = 0; r < 4; ++r)
  {
    for (c = 0; c < 4; ++c)
    {
      int8_t pone = -1, ptwo = -1;
      //printf("(*hamstate)[c][r]: 0x0%hhx, (*pcode)[c][r]: 0x0%hhx\n", (*hamstate)[c][r], (*pcode)[c][r]);
      uint8_t diff = ( (*hamstate)[c][r] ^ (*pcode)[c][r] );
      printf("diff:%x\n", diff);
      if(diff != 0)
      {
        for(x = 3; x >= 0; --x)
        {
          //printf("haha diff\n");
          //go through hamming bits of [c][r] of hamstate and pcode to spot any differences.
          //differences can be spotted through
          printf("\tdiff(%u): %x\n", x, ( (diff >> x) % 2 ));
          if( ( (diff >> x) % 2 ) == 0)
          {
            printf("Error at %d at pos [%u][%u]. (*hamstate)[c][r]: 0x0%hhx, (*pcode)[c][r]: 0x0%hhx\n", x, c, r, (*hamstate)[c][r], (*pcode)[c][r]);
            if(pone == -1)
              pone = x;
            else if(ptwo == -1)
              ptwo = x;
          }
        }
        //do the actual flip here of (*state)[c][r]. Follows table 3 from the main 2009 hamming code paper. 
        printf("pos0: %d, pos1: %d\n", pone, ptwo);
        printf("State before: 0x%hhx\n", (*state)[c][r]);
        if(pone == 3 && ptwo == 2)
        {
          (*state)[c][r] = flip_bit((*state)[c][r], 0x00);
        }
        else if(pone == 3 && ptwo == 1)
        {
          (*state)[c][r] = flip_bit((*state)[c][r], 0x02);
        }
        else if(pone == 3 && ptwo == 0)
        {
          (*state)[c][r] = flip_bit((*state)[c][r], 0x05);
        }
        else if(pone == 2 && ptwo == 1)
        {
          (*state)[c][r] = flip_bit((*state)[c][r], 0x03);
        }
        else if(pone == 2 && ptwo == 0)
        {
          (*state)[c][r] = flip_bit((*state)[c][r], 0x06);
        }
        else if(pone == 1 && ptwo == 0)
        {
          (*state)[c][r] = flip_bit((*state)[c][r], 0x07);
        }
        else if(pone == 1 && ptwo == -1)
        {
          (*state)[c][r] = flip_bit((*state)[c][r], 0x01);
        }
        else if(pone == 0 && ptwo == -1)
        {
          (*state)[c][r] = flip_bit((*state)[c][r], 0x04);
        }
        /*
        if(anspos[0] != -1)
          flip_bit((*state)[c][r], anspos[0]);
        if(anspos[1] != -1)
          flip_bit((*state)[c][r], anspos[1]);
        */
        printf("State after: 0x%hhx\n", (*state)[c][r]);
      }
      //for through rows
    }
    //for through columns
  }
}

static void encode_state(state_t* state, hamstate_t* hamstate)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*hamstate)[j][i] = hamming_encode((*state)[j][i]);
    }
  }
}

static void predictAddKey(uint8_t round, state_t* state, const uint8_t* RoundKey, hamstate_t* pcode)
{
  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*pcode)[i][j] ^= hamming_encode(RoundKey[(round * Nb * 4) + (i * Nb) + j]);
    }
  }
}

static void predictSub(state_t* state, hamstate_t* pcode)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*pcode)[j][i] = getHBoxValue((*state)[j][i]);
    }
  }
}

static void predictShift(hamstate_t* pcode)
{
  uint8_t temp;

  // Rotate first row 1 columns to left  
  temp           = (*pcode)[0][1];
  (*pcode)[0][1] = (*pcode)[1][1];
  (*pcode)[1][1] = (*pcode)[2][1];
  (*pcode)[2][1] = (*pcode)[3][1];
  (*pcode)[3][1] = temp;

  // Rotate second row 2 columns to left  
  temp           = (*pcode)[0][2];
  (*pcode)[0][2] = (*pcode)[2][2];
  (*pcode)[2][2] = temp;

  temp           = (*pcode)[1][2];
  (*pcode)[1][2] = (*pcode)[3][2];
  (*pcode)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp           = (*pcode)[0][3];
  (*pcode)[0][3] = (*pcode)[3][3];
  (*pcode)[3][3] = (*pcode)[2][3];
  (*pcode)[2][3] = (*pcode)[1][3];
  (*pcode)[1][3] = temp;
}

static void predictMixCols(state_t* state, hamstate_t* pcode)
{

  for(uint8_t c = 0; c < 4; ++c)
  {
    (*pcode)[c][0] = hamming_encode(xtime((*state)[c][0])) ^ hamming_encode(Multiply((*state)[c][1], 0x03)) ^ hamming_encode((*state)[c][2]) ^ hamming_encode((*state)[c][3]);
    (*pcode)[c][1] = hamming_encode((*state)[c][0]) ^ hamming_encode(xtime((*state)[c][1])) ^ hamming_encode(Multiply((*state)[c][2], 0x03)) ^ hamming_encode((*state)[c][3]);
    (*pcode)[c][2] = hamming_encode((*state)[c][0]) ^ hamming_encode((*state)[c][1]) ^ hamming_encode(xtime((*state)[c][2])) ^ hamming_encode(Multiply((*state)[c][3], 0x03));
    (*pcode)[c][3] = hamming_encode(Multiply((*state)[c][0], 0x03)) ^ hamming_encode((*state)[c][1]) ^ hamming_encode((*state)[c][2]) ^ hamming_encode(xtime((*state)[c][3]));
    //printf("Line: (%p) 0x%hhx, (%p) 0x%hhx, (%p) 0x%hhx, (%p) 0x%hhx\n", pcode[0][c], (*pcode)[0][c], pcode[1][c], (*pcode)[1][c], pcode[2][c], (*pcode)[2][c], pcode[3][c], (*pcode)[3][c]);

    //-----------------------------------------------
    // Code for hamming prediction using the tables
    //-----------------------------------------------

    /*
    //printf("First Entry: (0x%hhx) 0x%hhx ^ (0x%hhx) 0x%hhx ^ (0x%hhx) 0x%hhx ^ (0x%hhx) 0x%hhx\n", (*state)[c][0], getH2BoxValue((*state)[c][0]), (*state)[c][1], getH3BoxValue((*state)[c][1]), (*state)[c][2], getHBoxValue((*state)[c][2]), (*state)[c][3], getHBoxValue((*state)[c][3]));
    (*pcode)[c][0] = getH2BoxValue((*state)[c][0]) ^ getH3BoxValue((*state)[c][1]) ^ getHBoxValue((*state)[c][2]) ^ getHBoxValue((*state)[c][3]);
    (*pcode)[c][1] = getHBoxValue((*state)[c][0]) ^ getH2BoxValue((*state)[c][1]) ^ getH3BoxValue((*state)[c][2]) ^ getHBoxValue((*state)[c][3]);
    (*pcode)[c][2] = getHBoxValue((*state)[c][0]) ^ getHBoxValue((*state)[c][1]) ^ getH2BoxValue((*state)[c][2]) ^ getH3BoxValue((*state)[c][3]);
    (*pcode)[c][3] = getH3BoxValue((*state)[c][0]) ^ getHBoxValue((*state)[c][1]) ^ getHBoxValue((*state)[c][2]) ^ getH2BoxValue((*state)[c][3]);
    //printf("Line: (%p) 0x%hhx, (%p) 0x%hhx, (%p) 0x%hhx, (%p) 0x%hhx\n", pcode[0][c], (*pcode)[0][c], pcode[1][c], (*pcode)[1][c], pcode[2][c], (*pcode)[2][c], pcode[3][c], (*pcode)[3][c]);

    printf("First Entry: (0x%hhx) 0x%hhx ^ (0x%hhx) 0x%hhx ^ (0x%hhx) 0x%hhx ^ (0x%hhx) 0x%hhx\n", (*state)[0][c], getH2BoxValue((*state)[0][c]), (*state)[1][c], getH3BoxValue((*state)[1][c]), (*state)[2][c], getHBoxValue((*state)[2][c]), (*state)[3][c], getHBoxValue((*state)[3][c]));
    (*pcode[0][c]) = getH2BoxValue((*state)[0][c]) ^ getH3BoxValue((*state)[1][c]) ^ getHBoxValue((*state)[2][c]) ^ getHBoxValue((*state)[3][c]);
    (*pcode[1][c]) = getHBoxValue((*state)[0][c]) ^ getH2BoxValue((*state)[1][c]) ^ getH3BoxValue((*state)[2][c]) ^ getHBoxValue((*state)[3][c]);
    (*pcode[2][c]) = getHBoxValue((*state)[0][c]) ^ getHBoxValue((*state)[1][c]) ^ getH2BoxValue((*state)[2][c]) ^ getH3BoxValue((*state)[3][c]);
    (*pcode[3][c]) = getH3BoxValue((*state)[0][c]) ^ getHBoxValue((*state)[1][c]) ^ getHBoxValue((*state)[2][c]) ^ getH2BoxValue((*state)[3][c]);
    */

  }

  /*
  uint8_t r, c;
  printf("\nPredict code:\n");
  for (r = 0; r < 4; ++r)
  {
    for (c = 0; c < 4; ++c)
    {
      printf("(%p) 0x%hhx, ", (pcode)[c][r], (*pcode)[c][r] );
    }
    printf("\n");
  }
  printf("\n");
  */
}

static void compareCodes(state_t* state, hamstate_t* hamstate, hamstate_t* pcode, char* transform)
{
  /*
  uint8_t r, c;
  printf("\nState After %s:\n", transform);
  for (r = 0; r < 4; ++r)
  {
    for (c = 0; c < 4; ++c)
    {
      printf("0x%hhx, ", (*state)[c][r] );
    }
    printf("\n");
  }

  printf("\nHamState:\n");
  for (r = 0; r < 4; ++r)
  {
    for (c = 0; c < 4; ++c)
    {
      printf("0x0%hhx, ", (*hamstate)[c][r] );
    }
    printf("\n");
  }

  printf("\nPredicted Codes:\n");
  for (r = 0; r < 4; ++r)
  {
    for (c = 0; c < 4; ++c)
    {
      printf("0x0%hhx, ", (*pcode)[c][r] );
    }
    printf("\n");
  }
  printf("\n");
  //*/
  
  if(memcmp((char*) hamstate, (char*) pcode, sizeof(hamstate_t)) != 0)
  {
    printf("Codes do not agree in %s, before correction\n", transform);
    correct_state(state, hamstate, pcode);

    /*
    encode_state(state, hamstate);

    //uint8_t r, c;
    printf("\nHamState:\n");
    for (r = 0; r < 4; ++r)
    {
      for (c = 0; c < 4; ++c)
      {
        printf("0x0%hhx, ", (*hamstate)[c][r] );
      }
      printf("\n");
    }

    printf("\nPredicted Codes:\n");
    for (r = 0; r < 4; ++r)
    {
      for (c = 0; c < 4; ++c)
      {
        printf("0x0%hhx, ", (*pcode)[c][r] );
      }
      printf("\n");
    }
    printf("\n");
    //*/
    if(memcmp((char*) hamstate, (char*) pcode, sizeof(hamstate_t)) != 0)
    {
      printf("Codes do not agree in %s, after correction\n", transform);
      exit(2);
    }
  }
  /*
  else
  {
    printf("Codes equal! ");
  }
  */
}

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
  unsigned i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations
  
  // The first round key is the key itself.
  for (i = 0; i < Nk; ++i)
  {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for (i = Nk; i < Nb * (Nr + 1); ++i)
  {
    {
      k = (i - 1) * 4;
      tempa[0]=RoundKey[k + 0];
      tempa[1]=RoundKey[k + 1];
      tempa[2]=RoundKey[k + 2];
      tempa[3]=RoundKey[k + 3];

    }

    if (i % Nk == 0)
    {
      // This function shifts the 4 bytes in a word to the left once.
      // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

      // Function RotWord()
      {
        const uint8_t u8tmp = tempa[0];
        tempa[0] = tempa[1];
        tempa[1] = tempa[2];
        tempa[2] = tempa[3];
        tempa[3] = u8tmp;
      }

      // SubWord() is a function that takes a four-byte input word and 
      // applies the S-box to each of the four bytes to produce an output word.

      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }

      tempa[0] = tempa[0] ^ Rcon[i/Nk];
    }
#if defined(AES256) && (AES256 == 1)
    if (i % Nk == 4)
    {
      // Function Subword()
      {
        tempa[0] = getSBoxValue(tempa[0]);
        tempa[1] = getSBoxValue(tempa[1]);
        tempa[2] = getSBoxValue(tempa[2]);
        tempa[3] = getSBoxValue(tempa[3]);
      }
    }
#endif
    j = i * 4; k=(i - Nk) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)
{
  KeyExpansion(ctx->RoundKey, key);
}
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
  KeyExpansion(ctx->RoundKey, key);
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)
{
  memcpy (ctx->Iv, iv, AES_BLOCKLEN);
}
#endif

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey, hamstate_t* hamstate, hamstate_t* pcode)
{
  predictAddKey(round, state, RoundKey, pcode);

  uint8_t i,j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }

  encode_state(state, hamstate);
  compareCodes(state, hamstate, pcode, "AddRoundKey");
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t* state, hamstate_t* hamstate, hamstate_t* pcode)
{
  predictSub(state, pcode);
  /*
  // doesn't work in this position. Works injecting the fault anywhere else in the method
  // and everywhere in all other methods
  printf("Original state[0][0]: 0x%hhx\n", (*state)[0][0]);
  (*state)[2][3] = flip_bit((*state)[2][3], 0x00);
  printf("New state[0][0]: 0x%hhx\n", (*state)[0][0]);
  //*/
  
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxValue((*state)[j][i]);
    }
  }
  
  encode_state(state, hamstate);
  compareCodes(state, hamstate, pcode, "SubBytes");
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t* state, hamstate_t* hamstate, hamstate_t* pcode)
{
  predictShift(pcode);

  uint8_t temp;

  // Rotate first row 1 columns to left  
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left  
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp           = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;

  encode_state(state, hamstate);
  compareCodes(state, hamstate, pcode, "ShiftRows");
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_t* state, hamstate_t* hamstate, hamstate_t* pcode)
{
  predictMixCols(state, pcode);

  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {  
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }

  encode_state(state, hamstate);
  compareCodes(state, hamstate, pcode, "MixColumns");
}

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(state_t* state)
{
  int i;
  uint8_t a, b, c, d;
  for (i = 0; i < 4; ++i)
  { 
    a = (*state)[i][0];
    b = (*state)[i][1];
    c = (*state)[i][2];
    d = (*state)[i][3];

    (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}


// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(state_t* state)
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[j][i] = getSBoxInvert((*state)[j][i]);
    }
  }
}

static void InvShiftRows(state_t* state)
{
  uint8_t temp;

  // Rotate first row 1 columns to right  
  temp = (*state)[3][1];
  (*state)[3][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[0][1];
  (*state)[0][1] = temp;

  // Rotate second row 2 columns to right 
  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to right
  temp = (*state)[0][3];
  (*state)[0][3] = (*state)[1][3];
  (*state)[1][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[3][3];
  (*state)[3][3] = temp;
}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  hamstate_t hamstate, pcode;
  encode_state(state, &pcode);

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0, state, RoundKey, &hamstate, &pcode);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without MixColumns()

  for (round = 1; ; ++round)
  {
    SubBytes(state, &hamstate, &pcode); 
    ShiftRows(state, &hamstate, &pcode);
    if (round == Nr) {
      break;
    }
    MixColumns(state, &hamstate, &pcode);
    AddRoundKey(round, state, RoundKey, &hamstate, &pcode);
  }
  // Add round key to last round
  AddRoundKey(Nr, state, RoundKey, &hamstate, &pcode);
}

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
static void InvCipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  hamstate_t hamstate, pcode;
  // Add the First round key to the state before starting the rounds.
  AddRoundKey(Nr, state, RoundKey, &hamstate, &pcode);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without InvMixColumn()
  for (round = (Nr - 1); ; --round)
  {
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(round, state, RoundKey, &hamstate, &pcode);
    if (round == 0) {
      break;
    }
    InvMixColumns(state);
  }

}
#endif // #if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)

/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
#if defined(ECB) && (ECB == 1)


void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
  // The next function call encrypts the PlainText with the Key using AES algorithm.
  Cipher((state_t*)buf, ctx->RoundKey);
}

void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
  // The next function call decrypts the PlainText with the Key using AES algorithm.
  InvCipher((state_t*)buf, ctx->RoundKey);
}


#endif // #if defined(ECB) && (ECB == 1)





#if defined(CBC) && (CBC == 1)


static void XorWithIv(uint8_t* buf, const uint8_t* Iv)
{
  uint8_t i;
  for (i = 0; i < AES_BLOCKLEN; ++i) // The block in AES is always 128bit no matter the key size
  {
    buf[i] ^= Iv[i];
  }
}

void AES_CBC_encrypt_buffer(struct AES_ctx *ctx, uint8_t* buf, uint32_t length)
{
  uintptr_t i;
  uint8_t *Iv = ctx->Iv;
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    XorWithIv(buf, Iv);
    Cipher((state_t*)buf, ctx->RoundKey);
    Iv = buf;
    buf += AES_BLOCKLEN;
  }
  /* store Iv in ctx for next call */
  memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}

void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf,  uint32_t length)
{
  uintptr_t i;
  uint8_t storeNextIv[AES_BLOCKLEN];
  for (i = 0; i < length; i += AES_BLOCKLEN)
  {
    memcpy(storeNextIv, buf, AES_BLOCKLEN);
    InvCipher((state_t*)buf, ctx->RoundKey);
    XorWithIv(buf, ctx->Iv);
    memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN);
    buf += AES_BLOCKLEN;
  }

}

#endif // #if defined(CBC) && (CBC == 1)



#if defined(CTR) && (CTR == 1)

/* Symmetrical operation: same function for encrypting as for decrypting. Note any IV/nonce should never be reused with the same key */
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length)
{
  uint8_t buffer[AES_BLOCKLEN];

  unsigned i;
  int bi;
  for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
  {
    if (bi == AES_BLOCKLEN) /* we need to regen xor compliment in buffer */
    {
      
      memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
      Cipher((state_t*)buffer,ctx->RoundKey);

      /* Increment Iv and handle overflow */
      for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
      {
      	/* inc will overflow */
        if (ctx->Iv[bi] == 255)
      	{
          ctx->Iv[bi] = 0;
          continue;
        } 
        ctx->Iv[bi] += 1;
        break;   
      }

      bi = 0;
    }//end of first if

    buf[i] = (buf[i] ^ buffer[bi]);
  }//end of for loop
}

#endif // #if defined(CTR) && (CTR == 1)

