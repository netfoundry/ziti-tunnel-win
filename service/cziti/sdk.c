/*
 * Copyright NetFoundry, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "sdk.h"
#include <ziti/ziti_tunnel.h>
#include <ziti/ziti_log.h>
#include <ziti/ziti_events.h>
#include <uv.h>

void libuv_stopper(uv_async_t *a) {
     uv_stop(a->loop);
}
void set_log_level(int level, libuv_ctx *lctx) {
    ziti_log_set_level(level);
}

void log_writer_shim_go(int level, const char *loc, const char *msg, size_t msglen) {
  log_writer_cb(level, (char*)loc, (char*)msg, (int)msglen);
}

void libuv_init(libuv_ctx *lctx) {
    lctx->l = uv_default_loop();
    ziti_log_init(lctx->l, 6 /*default to 6*/, log_writer_shim_go);
    uv_async_init(lctx->l, &lctx->stopper, libuv_stopper);
}

void libuv_runner(void *arg) {
    uv_loop_t *l = arg;
    uv_run(l, UV_RUN_DEFAULT);
}

void libuv_run(libuv_ctx *lctx) {
    uv_thread_create(&lctx->t, libuv_runner, lctx->l);
}

void libuv_stop(libuv_ctx *lctx) {
    uv_async_send(&lctx->stopper);
    int err = uv_thread_join(&lctx->t);
    if (err) {
        ZITI_LOG(ERROR, "failed to join uv_loop thread: %d[%s]", err, uv_strerror(err));
    }
}

static const char* _all[] = {
   "all", NULL
};

const char** all_configs = _all;

extern void call_on_packet(const char *packet, ssize_t len, packet_cb cb, void *ctx) {
     cb(packet, len, ctx);
}

extern void c_mapiter(model_map *map) {
    int rc = 0;
	model_map_iter it = model_map_iterator(map);
	while (it != NULL && rc == 0) {
		char *v = model_map_it_value(it);
		const char *k = model_map_it_key(it);
		printf("k: %s, v: %s", k, v);
		it = model_map_it_next(it);
	}
}

struct ziti_context_event* ziti_event_context_event(ziti_event_t *ev) {
    return &ev->event.ctx;
}

struct ziti_router_event* ziti_event_router_event(ziti_event_t *ev) {
    return &ev->event.router;
}

struct ziti_service_event* ziti_event_service_event(ziti_event_t *ev) {
    return &ev->event.service;
}

ziti_service* ziti_service_array_get(ziti_service_array arr, int idx) {
    return arr ? arr[idx] : NULL;
}

ziti_posture_query_set* posture_query_set_get(ziti_posture_query_set_array arr, int idx) {
    return arr ? arr[idx] : NULL;
}

ziti_posture_query* posture_queries_get(ziti_posture_query_array arr, int idx) {
    return arr ? arr[idx] : NULL;
}

int ziti_dump_c_to_file_cb(void* outputPath, const char *fmt,  ...) {
    static char line[4096];

    va_list vargs;
    va_start(vargs, fmt);
    vsnprintf(line, sizeof(line), fmt, vargs);
    va_end(vargs);

    //call back into go with the line
    ziti_dump_go_to_file_cb(outputPath, line);
    return 0;
}

int ziti_dump_c_to_log_cb(void* stringsBuilder, const char *fmt,  ...) {
    static char line[4096];

    va_list vargs;
    va_start(vargs, fmt);
    vsnprintf(line, sizeof(line), fmt, vargs);
    va_end(vargs);

    //call back into go with the line
    ziti_dump_go_to_log_cb(stringsBuilder, line);
    return 0;
}

//a simple C function to work around cgo not understanding variadic args
void ziti_dump_to_file(void *ctx, char* outputPath) {
    //actually invoke ziti_dump here
    ziti_dump(ctx, ziti_dump_c_to_file_cb, outputPath);
}
//a simple C function to work around cgo not understanding variadic args
 void ziti_dump_to_log(void *ctx, void* stringsBuilder) {
     //actually invoke ziti_dump here
     ziti_dump(ctx, ziti_dump_c_to_log_cb, stringsBuilder);
 }

extern int apply_dns_go(dns_manager *dns_manager, const char *hostname, const char *ip);

dns_manager dns_mgr_c = {
        .apply = apply_dns_go,
        .data = NULL
};

dns_manager* get_dns_mgr_from_c() {
    return &dns_mgr_c;
}

/* functions allowing go to iterate tunneleed_service_t* */
protocol_t* stailq_first_protocol(tunneled_service_t* ts) {
    if(ts == NULL || ts->intercept == NULL ) {
        return NULL;
    }
    return STAILQ_FIRST(&ts->intercept->protocols);
}
address_t* stailq_first_address(tunneled_service_t* ts) {
    if(ts == NULL || ts->intercept == NULL ) {
        return NULL;
    }
    return STAILQ_FIRST(&ts->intercept->addresses);
}
port_range_t* stailq_first_port_range(tunneled_service_t* ts) {
    if(ts == NULL || ts->intercept == NULL ) {
        return NULL;
    }
    return STAILQ_FIRST(&ts->intercept->port_ranges);
}
protocol_t* stailq_next_protocol(protocol_t* cur) {
    return STAILQ_NEXT(cur, entries);
}
address_t* stailq_next_address(address_t* cur) {
    return STAILQ_NEXT(cur, entries);
}
port_range_t* stailq_next_port_range(port_range_t* cur) {
    return STAILQ_NEXT(cur, entries);
}

char* ziti_char_array_get(char** arr, int idx) {
    return arr ? arr[idx] : NULL;
}


