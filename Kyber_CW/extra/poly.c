#include <stdint.h>

#include "../kyber/ref/params.h"
#include "../kyber/ref/poly.h"
#include "../kyber/ref/ntt.h"
#include "../kyber/ref/reduce.h"
#include "../kyber/ref/cbd.h"
#include "../kyber/ref/symmetric.h"
#include "../kyber/ref/verify.h"

#define poly_tomsg KYBER_NAMESPACE(poly_tomsg)
#define CONCAT(a, b) a##b
#define WRAP(f) CONCAT(__wrap_, f)

/*************************************************
* Name:        poly_tomsg
*
* Description: Convert polynomial to 32-byte message
*
* Arguments:   - uint8_t *msg: pointer to output message
*              - const poly *a: pointer to input polynomial
**************************************************/
void WRAP(poly_tomsg)(uint8_t msg[KYBER_INDCPA_MSGBYTES], const poly *a)
{
  unsigned int i,j;
  uint32_t t;

  trigger_high();
  for(i=0;i<KYBER_N/8;i++) {
    msg[i] = 0;
    for(j=0;j<8;j++) {
      t  = a->coeffs[8*i+j];
      // t += ((int16_t)t >> 15) & KYBER_Q;
      // t  = (((t << 1) + KYBER_Q/2)/KYBER_Q) & 1;
      t <<= 1;
      t += 1665;
      t *= 80635;
      t >>= 28;
      t &= 1;
      msg[i] |= t << j;
    }
  }
  trigger_low();
}