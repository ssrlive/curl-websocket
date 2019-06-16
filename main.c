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
#if defined(WIN32) || defined(_WIN32)
#include <WinSock2.h>
#endif

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

        if (maxfd == -1) {
#if defined(_WIN32) || defined(WIN32)
            Sleep(100);
            rc = 0;
#else
            struct timeval wait = { 1, 0 }; /* 1s */
            rc = select(0, NULL, NULL, NULL, &wait);
#endif
        } else {
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
                printf("HTTP completed with status %d '%s'\n", msg->data.result, curl_easy_strerror(msg->data.result));
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

        snprintf(ln, 11, "%9zd ", i + 1);
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
    struct myapp_ctx *ctx = data;
    fprintf(stderr, "INFO: connected, websocket_protocols='%s'\n", websocket_protocols);
    send_dummy(easy, true, ++ctx->text_lines);
}

static void on_text(void *data, CURL *easy, const char *text, size_t len) {
    struct myapp_ctx *ctx = data;
    fprintf(stderr, "INFO: TEXT={\n%s\n}\n", text);

    if (ctx->text_lines < 5)
        send_dummy(easy, true, ++ctx->text_lines);
    else
        send_dummy(easy, false, ++ctx->binary_lines);

    (void)len;
}

static void on_binary(void *data, CURL *easy, const void *mem, size_t len) {
    struct myapp_ctx *ctx = data;
    const uint8_t *bytes = mem;
    size_t i;

    fprintf(stderr, "INFO: BINARY=%zd bytes {\n", len);

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
    fprintf(stderr, "INFO: PING %zd bytes='%s'\n", len, reason);
    cws_pong(easy, "just pong", SIZE_MAX);
    (void)data;
}

static void on_pong(void *data, CURL *easy, const char *reason, size_t len) {
    fprintf(stderr, "INFO: PONG %zd bytes='%s'\n", len, reason);

    cws_close(easy, CWS_CLOSE_REASON_NORMAL, "close it!", SIZE_MAX);
    (void)data;
    (void)easy;
}

static void on_close(void *data, CURL *easy, enum cws_close_reason reason, const char *reason_text, size_t reason_text_len) {
    struct myapp_ctx *ctx = data;
    fprintf(stderr, "INFO: CLOSE=%4d %zd bytes '%s'\n", reason, reason_text_len, reason_text);

    ctx->exitval = (reason == CWS_CLOSE_REASON_NORMAL ?
                    EXIT_SUCCESS : EXIT_FAILURE);
    ctx->running = false;
    (void)easy;
}

int main(int argc, char *argv[]) {
    const char *url;
    const char *protocols;
    struct myapp_ctx myapp_ctx = {
        NULL,
        NULL,
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
        /* .data = */ &myapp_ctx,
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

    {
#if defined(WIN32) || defined(_WIN32)
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);

    myapp_ctx.easy = cws_new(url, protocols, &cbs);
    if (!myapp_ctx.easy)
        goto error_easy;

    /* here you should do any extra sets, like cookies, auth... */
    curl_easy_setopt(myapp_ctx.easy, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(myapp_ctx.easy, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(myapp_ctx.easy, CURLOPT_SSL_VERIFYPEER, 0L);

    /*
     * This is a traditional curl_multi app, see:
     *
     * https://curl.haxx.se/libcurl/c/multi-app.html
     */
    myapp_ctx.multi = curl_multi_init();
    if (!myapp_ctx.multi)
        goto error_multi;

    curl_multi_add_handle(myapp_ctx.multi, myapp_ctx.easy);

    myapp_ctx.running = true;
    a_main_loop(&myapp_ctx);

    curl_multi_remove_handle(myapp_ctx.multi, myapp_ctx.easy);
    curl_multi_cleanup(myapp_ctx.multi);

  error_multi:
    cws_free(myapp_ctx.easy);
  error_easy:
    curl_global_cleanup();

    return myapp_ctx.exitval;
}
