#if !defined(__CURL_WEBSOCKET_UTILS_H__)
#define __CURL_WEBSOCKET_UTILS_H__

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

void _cws_debug(const char *prefix, const void *buffer, size_t len);

void _cws_sha1(const void *input, size_t input_len, uint8_t output[20]);
void _cws_encode_base64(const uint8_t *input, size_t input_len, char *output, size_t out_len);
void _cws_get_random(uint8_t *buffer, size_t len);
void _cws_trim(const char **p_buffer, size_t *p_len);
bool _cws_header_has_prefix(const char *buffer, size_t buflen, const char *prefix);
void _cws_hton(void *mem, size_t len);
void _cws_ntoh(void *mem, size_t len);

#endif // __CURL_WEBSOCKET_UTILS_H__
