#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

// void randombytes(uint8_t *out, size_t outlen);
int randombytes(uint8_t* buf, size_t xlen);
#endif
