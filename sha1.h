#pragma once
#ifndef SHA1_H
#define SHA1_H

#if _WIN32
typedef unsigned long long u_int64_t;
#endif

#include <stdlib.h>
#include <string.h>

unsigned char *
SHA_1(const unsigned char *d, size_t n, unsigned char *md);

#endif /* SHA1_H */
