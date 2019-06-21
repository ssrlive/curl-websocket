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
/* c-mode: linux-4 */
#include "curl-websocket.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

struct myapp_ctx {
    CURL *easy;
    CURLM *multi;
    int text_lines;
    int binary_lines;
    int exitval;
    bool running;
};

/*
 * This is a traditional curl_multi app, see:
 *
 * https://curl.haxx.se/libcurl/c/multi-app.html
 *
 * replace this with your own main loop integration
 */
static void a_main_loop(struct myapp_ctx *ctx) {
    CURLM *multi = ctx->multi;
    int still_running = 0;

    curl_multi_perform(multi, &still_running);

    do {
        CURLMsg *msg;
        struct timeval timeout;
        fd_set fdread, fdwrite, fdexcep;
        CURLMcode mc;
        int msgs_left, rc;
        int maxfd = -1;
        long curl_timeo = -1;

        FD_ZERO(&fdread);
        FD_ZERO(&fdwrite);
        FD_ZERO(&fdexcep);

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        curl_multi_timeout(multi, &curl_timeo);
        if (curl_timeo >= 0) {
            timeout.tv_sec = curl_timeo / 1000;
            if (timeout.tv_sec > 1)
                timeout.tv_sec = 1;
            else
                timeout.tv_usec = (curl_timeo % 1000) * 1000;
        }

        mc = curl_multi_fdset(multi, &fdread, &fdwrite, &fdexcep, &maxfd);
        if (mc != CURLM_OK) {
            fprintf(stderr, "ERROR: curl_multi_fdset() failed, code %d '%s'.\n", mc, curl_multi_strerror(mc));
            break;
        }

        /* On success the value of maxfd is guaranteed to be >= -1. We call
        select(maxfd + 1, ...); specially in case of (maxfd == -1) there are
        no fds ready yet so we call select(0, ...) --or Sleep() on Windows--
        to sleep 100ms, which is the minimum suggested value in the
        curl_multi_fdset() doc. */

        if (maxfd == -1) {
#if defined(_WIN32) || defined(WIN32)
            Sleep(100);
            rc = 0;
#else
            /* Portable sleep for platforms other than Windows. */
            struct timeval wait = { 0, 100 * 1000 }; /* 100ms */
            rc = select(0, NULL, NULL, NULL, &wait);
#endif
        } else {
            /* Note that on some platforms 'timeout' may be modified by select().
            If you need access to the original value save a copy beforehand. */
            rc = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);
        }

        switch(rc) {
        case -1:
            /* select error */
            break;
        case 0: /* timeout */
        default: /* action */
            curl_multi_perform(multi, &still_running);
            break;
        }

        /* See how the transfers went */
        while ((msg = curl_multi_info_read(multi, &msgs_left))) {
            if (msg->msg == CURLMSG_DONE) {
                CURLcode result = msg->data.result;
                printf("HTTP completed with status %d '%s'\n", result, curl_easy_strerror(result));
            }
        }
    } while (still_running && ctx->running);
}

static bool send_dummy(CURL *easy, bool text, size_t lines)
{
    size_t len = lines * 80;
    char *buf = (char *) calloc(len + 1, sizeof(*buf));
    const size_t az_range = 'Z' - 'A';
    size_t i;
    bool ret;

    for (i = 0; i < lines; i++) {
        char *ln = buf + i * 80;
        uint8_t chr;

        snprintf(ln, 11, "%9d ", (int)i + 1);
        if (text)
            chr = (i % az_range) + 'A';
        else
            chr = i & 0xff;
        memset(ln + 10, chr, 69);
        ln[79] = '\n';
    }

    ret = cws_send(easy, text, buf, len);
    free(buf);
    return ret;
}

static void on_connect(void *data, CURL *easy, const char *websocket_protocols) {
    struct myapp_ctx *ctx = (struct myapp_ctx *) data;
    fprintf(stderr, "INFO: connected, websocket_protocols='%s'\n", websocket_protocols);
    send_dummy(easy, true, ++ctx->text_lines);
}

static void on_text(void *data, CURL *easy, const char *text, size_t len) {
    struct myapp_ctx *ctx = (struct myapp_ctx *) data;
    fprintf(stderr, "INFO: TEXT={\n%s\n}\n", text);

    if (ctx->text_lines < 5)
        send_dummy(easy, true, ++ctx->text_lines);
    else
        send_dummy(easy, false, ++ctx->binary_lines);

    (void)len;
}

static void on_binary(void *data, CURL *easy, const void *mem, size_t len) {
    struct myapp_ctx *ctx = (struct myapp_ctx *) data;
    const uint8_t *bytes = (const uint8_t *) mem;
    size_t i;

    fprintf(stderr, "INFO: BINARY=%d bytes {\n", (int)len);

    for (i = 0; i < len; i++) {
        uint8_t b = bytes[i];
        if (isprint(b))
            fprintf(stderr, " %#04x(%c)", b, b);
        else
            fprintf(stderr, " %#04x", b);
    }

    fprintf(stderr, "\n}\n");

    if (ctx->binary_lines < 5)
        send_dummy(easy, false, ++ctx->binary_lines);
    else
        cws_ping(easy, "will close on pong", SIZE_MAX);
}

static void on_ping(void *data, CURL *easy, const char *reason, size_t len) {
    fprintf(stderr, "INFO: PING %d bytes='%s'\n", (int)len, reason);
    cws_pong(easy, "just pong", SIZE_MAX);
    (void)data;
}

static void on_pong(void *data, CURL *easy, const char *reason, size_t len) {
    struct myapp_ctx *ctx = (struct myapp_ctx *) data;
    fprintf(stderr, "INFO: PONG %d bytes='%s'\n", (int)len, reason);

    cws_close(easy, CWS_CLOSE_REASON_NORMAL, "close it!", SIZE_MAX);
    (void)data;
    (void)easy;
}

static void on_close(void *data, CURL *easy, cws_close_reason reason, const char *info, size_t len) {
    struct myapp_ctx *ctx = (struct myapp_ctx *) data;
    fprintf(stderr, "INFO: CLOSE=%4d %d bytes '%s'\n", reason, (int)len, info);

    ctx->exitval = (reason == CWS_CLOSE_REASON_NORMAL ? EXIT_SUCCESS : EXIT_FAILURE);
    ctx->running = false;
    (void)easy;
}

int main(int argc, char *argv[]) {
    const char *url;
    const char *protocols;
    struct myapp_ctx _myapp_ctx = {
        /* .easy = */ NULL,
        /* .multi = */ NULL,
        /* .text_lines = */ 0,
        /* .binary_lines = */ 0,
        /* .exitval = */ EXIT_SUCCESS,
    };
    struct cws_callbacks cbs = {
        /* .on_connect = */ on_connect,
        /* .on_text = */ on_text,
        /* .on_binary = */ on_binary,
        /* .on_ping = */ on_ping,
        /* .on_pong = */ on_pong,
        /* .on_close = */ on_close,
        /* .data = */ &_myapp_ctx,
    };

    if (argc <= 1) {
        fprintf(stderr, "ERROR: missing url\n");
        return EXIT_FAILURE;
    } else if (strcmp(argv[1], "-h") == 0 ||
               strcmp(argv[1], "--help") == 0) {
        fprintf(stderr,
                "Usage:\n"
                "\t%s <url> [websocket_protocols]\n"
                "\n"
                "Example:\n"
                "\t%s ws://echo.websocket.org\n"
                "\t%s wss://echo.websocket.org\n"
                "\n",
                argv[0], argv[0], argv[0]);
        return EXIT_SUCCESS;
    }
    url = argv[1];
    protocols = argc > 2 ? argv[2] : NULL;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    _myapp_ctx.easy = cws_new(url, protocols, &cbs);
    if (!_myapp_ctx.easy)
        goto error_easy;

    /* here you should do any extra sets, like cookies, auth... */
    curl_easy_setopt(_myapp_ctx.easy, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(_myapp_ctx.easy, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(_myapp_ctx.easy, CURLOPT_SSL_VERIFYPEER, 0L);

    /*
     * This is a traditional curl_multi app, see:
     *
     * https://curl.haxx.se/libcurl/c/multi-app.html
     */
    _myapp_ctx.multi = curl_multi_init();
    if (!_myapp_ctx.multi)
        goto error_multi;

    curl_multi_add_handle(_myapp_ctx.multi, _myapp_ctx.easy);

    _myapp_ctx.running = true;
    a_main_loop(&_myapp_ctx);

    curl_multi_remove_handle(_myapp_ctx.multi, _myapp_ctx.easy);
    curl_multi_cleanup(_myapp_ctx.multi);

  error_multi:
    cws_free(_myapp_ctx.easy);
  error_easy:
    curl_global_cleanup();

    return _myapp_ctx.exitval;
}
