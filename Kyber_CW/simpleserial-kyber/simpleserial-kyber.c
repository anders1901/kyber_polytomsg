/*
    This file is part of the ChipWhisperer Example Targets
    Copyright (C) 2021 NewAE Technology Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "hal.h"
#include "simpleserial.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if HAL_TYPE == HAL_k82f
#include "MK82F25615.h"
#include "core_cm4.h"
#endif

#if HAL_TYPE == HAL_stm32f3
#include "stm32f303x8.h"
#include "core_cm4.h"
#endif

#include "arm_etm.h"

#include "../crypto/fkyber/kyber/ref/params.h"
#include "../crypto/fkyber/kyber/ref/indcpa.h"

#if KYBER_K == 2
#define C_SERIAL_BYTES 128
#elif KYBER_K == 3
#define C_SERIAL_BYTES 64
#elif KYBER_K == 4
#define C_SERIAL_BYTES 32
#endif 

#define SERIAL_BYTES 128

static uint8_t m[KYBER_INDCPA_MSGBYTES];
static uint8_t c[KYBER_INDCPA_BYTES];
static uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES];

static uint16_t offset_c;
static uint16_t offset_sk;


/************************************************************************
 * Name:        reset_offset_c
 *
 * Description: Resets the offset of the ciphertext
 *
 * Arguments:
 *            - uint8_t* x : chipwhisperer i/o data     (NOT USED)
 *            - uint8_t len: chipwhisperer i/o data len (NOT USED)
 *************************************************************************/
uint8_t reset_offset_c(uint8_t *x, uint8_t len)
{
  offset_c = 0;
  return 0x00;
}


/************************************************************************
 * Name:        reset_offset_sk
 *
 * Description: Resets the offset of the sk
 *
 * Arguments:
 *            - uint8_t* x : chipwhisperer i/o data     (NOT USED)
 *            - uint8_t len: chipwhisperer i/o data len (NOT USED)
 *************************************************************************/
uint8_t reset_offset_sk(uint8_t *x, uint8_t len)
{
  offset_sk = 0;
  return 0x00;
}


/************************************************************************
 * Name:        init_c
 *
 * Description: Initialize len bytes of a Kyber PKE ciphertexy 
 *              starting from offset_c
 *
 * Arguments:
 *            - uint8_t* x : chipwhisperer i/o data containing len bytes of the ciphertext
 *            - uint8_t len: chipwhisperer i/o data len
 *************************************************************************/
uint8_t init_c(uint8_t *x, uint8_t len)
{
  if (offset_c >= KYBER_INDCPA_BYTES)
  {
    return 0x01;
  }

  memcpy(&c[offset_c], x, len);

  offset_c += len;
  return 0x00;
}

/************************************************************************
 * Name:        init_sk
 *
 * Description: Initialize len bytes of a Kyber PKE sk 
 *              starting from offset_sk
 *
 * Arguments:
 *            - uint8_t* x : chipwhisperer i/o data containing len bytes of the sk
 *            - uint8_t len: chipwhisperer i/o data len
 *************************************************************************/
uint8_t init_sk(uint8_t *x, uint8_t len)
{
  if (offset_sk >= KYBER_INDCPA_SECRETKEYBYTES)
  {
    return 0x01;
  }

  memcpy(&sk[offset_sk], x, len);

  offset_sk += len;
  return 0x00;
}

/************************************************************************
 * Name:        return_c
 *
 * Description: Puts 64 bytes of a Kyber PKE ciphertext starting from 
 *              an offset based on x
 * 
 * Arguments:
 *            - uint8_t* x : chipwhisperer i/o data, 2 bytes interpreted as offset
 *            - uint8_t len: chipwhisperer i/o data len (NOT USED)
 *************************************************************************/
uint8_t return_c(uint8_t *x, uint8_t len)
{
  uint16_t local_offset;

  local_offset = *((uint16_t *)x);
  simpleserial_put('r', 64, &c[local_offset]);
  return 0x00;
}

/************************************************************************
 * Name:        return_sk
 *
 * Description: Puts 64 bytes of a Kyber PKE sk starting from 
 *              an offset based on x
 * 
 * Arguments:
 *            - uint8_t* x : chipwhisperer i/o data, 2 bytes interpreted as offset
 *            - uint8_t len: chipwhisperer i/o data len (NOT USED)
 *************************************************************************/
uint8_t return_sk(uint8_t *x, uint8_t len)
{
  uint16_t local_offset;

  local_offset = *((uint16_t *)x);
  simpleserial_put('r', 64, &sk[local_offset]);
  return 0x00;
}

/************************************************************************
 * Name:        kyber_decrypt
 *
 * Description: Decryption function of the PKE scheme underlying Kyber.
 *
 * Arguments:
 *            - uint8_t *x: chipwhisperer i/o data (NOT USED)
 *            - uint8_t len  : chipwhisperer length of operation (NOT USED)
 *************************************************************************/
uint8_t kyber_decrypt(uint8_t *x, uint8_t len)
{
  indcpa_dec(m, c, sk);
  simpleserial_put('r', KYBER_INDCPA_MSGBYTES, m);
  return 0x00;
}

int main(void)
{
  platform_init();
  init_uart();
  trigger_setup();
  simpleserial_init();

  offset_c = 0;
  offset_sk = 0;

  simpleserial_addcmd('a', 0, reset_offset_c);
  simpleserial_addcmd('b', 0, reset_offset_sk);

  simpleserial_addcmd('c', C_SERIAL_BYTES, init_c);
  simpleserial_addcmd('s', SERIAL_BYTES, init_sk);

  simpleserial_addcmd('e', 4, return_c);
  simpleserial_addcmd('f', 4, return_sk);

  simpleserial_addcmd('d', 0, kyber_decrypt);

  while (1)
    simpleserial_get();
}
