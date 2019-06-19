/*
 * Copyright (C) 2016 Gustavo Sverzut Barbieri
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library;
 * if not, see <http://www.gnu.org/licenses/>.
 */
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <mbedtls/sha1.h>
#include <mbedtls/base64.h>

#include "curl-websocket.h"

static inline void _cws_debug(const char *prefix, const void *buffer, size_t len)
{
    const uint8_t *bytes = (const uint8_t *) buffer;
    size_t i;
    if (prefix)
        fprintf(stderr, "%s:", prefix);
    for (i = 0; i < len; i++) {
        uint8_t b = bytes[i];
        if (isprint(b))
            fprintf(stderr, " %#04x(%c)", b, b);
        else
            fprintf(stderr, " %#04x", b);
    }
    if (prefix)
        fprintf(stderr, "\n");
}

static void _cws_sha1(const void *input, size_t input_len, uint8_t output[20]) {
    mbedtls_sha1_context sha1_ctx = { 0 };
#ifndef SHA_DIGEST_LENGTH
#define SHA_DIGEST_LENGTH 20
#endif
    unsigned char sha1_hash[SHA_DIGEST_LENGTH] = { 0 };

    mbedtls_sha1_init(&sha1_ctx);
    mbedtls_sha1_starts(&sha1_ctx);
    mbedtls_sha1_update(&sha1_ctx, (unsigned char *)input, input_len);
    mbedtls_sha1_finish(&sha1_ctx, sha1_hash);
    mbedtls_sha1_free(&sha1_ctx);

    memcpy(output, sha1_hash, SHA_DIGEST_LENGTH);
}

static void _cws_encode_base64(const uint8_t *input, size_t input_len, char *output, size_t out_len)
{
    size_t b64_str_len = 0;
    char *b64_str;

    mbedtls_base64_encode(NULL, 0, &b64_str_len, input, input_len);

    b64_str = (char *) calloc(b64_str_len + 1, sizeof(*b64_str));

    mbedtls_base64_encode((unsigned char *)b64_str, b64_str_len, &b64_str_len, input, input_len);

    if (out_len >= b64_str_len) {
        memcpy(output, b64_str, b64_str_len);
    } else {
        assert(0);
    }
    free(b64_str);
}

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

static void random_bytes_generator(const char *seed, uint8_t *output, size_t len) {
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    if (seed==NULL || strlen(seed)==0 || output==NULL || len==0) {
        return;
    }

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *)seed, strlen(seed));
    mbedtls_ctr_drbg_set_prediction_resistance(&ctr_drbg, MBEDTLS_CTR_DRBG_PR_OFF);
    mbedtls_ctr_drbg_random(&ctr_drbg, output, len);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
}

static void _cws_get_random(uint8_t *buffer, size_t len)
{
    static int count = 0;
    char seed[0x100] = { 0 };
    sprintf(seed, "seed %d seed %d", count, count+1);
    count++;
    random_bytes_generator(seed, (uint8_t *)buffer, len);
}

static inline void _cws_trim(const char **p_buffer, size_t *p_len)
{
    const char *buffer = *p_buffer;
    size_t len = *p_len;

    while (len > 0 && isspace(buffer[0])) {
        buffer++;
        len--;
    }

    while (len > 0 && isspace(buffer[len - 1]))
        len--;

    *p_buffer = buffer;
    *p_len = len;
}

static inline bool _cws_header_has_prefix(const char *buffer, size_t buflen, const char *prefix) {
    size_t prefixlen = strlen(prefix);
    if (buflen < prefixlen)
        return false;
    return strncasecmp(buffer, prefix, prefixlen) == 0;
}

#include <stdint.h>
#undef IS_LITTLE_ENDIAN
#define IS_LITTLE_ENDIAN() (*(uint16_t*)"\0\1">>8)

#undef IS_BIG_ENDIAN
#define IS_BIG_ENDIAN() (*(uint16_t*)"\1\0">>8)

static inline void _cws_hton(void *mem, size_t len) {
    if ( IS_LITTLE_ENDIAN() ) {
        uint8_t *bytes;
        size_t i, mid;

        if (len % 2) { return; }

        mid = len / 2;
        bytes = (uint8_t *)mem;
        for (i = 0; i < mid; i++) {
            uint8_t tmp = bytes[i];
            bytes[i] = bytes[len - i - 1];
            bytes[len - i - 1] = tmp;
        }
    }
}

static inline void _cws_ntoh(void *mem, size_t len) {
    _cws_hton(mem, len);
}
