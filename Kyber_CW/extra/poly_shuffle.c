#include <stdint.h>

#include "../kyber/ref/params.h"
#include "../kyber/ref/poly.h"
#include "../kyber/ref/ntt.h"
#include "../kyber/ref/reduce.h"
#include "../kyber/ref/cbd.h"
#include "../kyber/ref/symmetric.h"
#include "../kyber/ref/verify.h"
#include "randombytes.h"

#define poly_tomsg KYBER_NAMESPACE(poly_tomsg)
#define CONCAT(a, b) a##b
#define WRAP(f) CONCAT(__wrap_, f)

static uint8_t ordered_array_256[256] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255};

/*************************************************
* Name:        poly_tomsg
*
* Description: Convert polynomial to 32-byte message
*              SHUFFLED proof of concept
*
* Arguments:   - uint8_t *msg: pointer to output message
*              - const poly *a: pointer to input polynomial
**************************************************/
void WRAP(poly_tomsg)(uint8_t msg[KYBER_INDCPA_MSGBYTES], const poly *a)
{
  unsigned int i,j;
  uint32_t t;
  unsigned int temp, random_index;
  unsigned int s_i, s_j;

  for(i = KYBER_N - 1; i>=1; --i) { 
    randombytes(&random_index, 1);
    random_index = random_index%(i + 1);
    temp = ordered_array_256[i];
    ordered_array_256[i] = ordered_array_256[random_index];
    ordered_array_256[random_index] = temp;
  }

  for(i = 0; i < KYBER_INDCPA_MSGBYTES; i++){
    msg[i] = 0;
  }

  trigger_high();
  for(i=0;i<KYBER_N/8;i++) {
    for(j=0;j<8;j++) {
      temp = ordered_array_256[8*i+j];
      s_i = temp>>3;
      s_j = temp&0x7;
      t  = a->coeffs[temp];
      // t += ((int16_t)t >> 15) & KYBER_Q;
      // t  = (((t << 1) + KYBER_Q/2)/KYBER_Q) & 1;
      t <<= 1;
      t += 1665;
      t *= 80635;
      t >>= 28;
      t &= 1;
      msg[s_i] |= t << s_j;
    }
  }
  trigger_low();
}
