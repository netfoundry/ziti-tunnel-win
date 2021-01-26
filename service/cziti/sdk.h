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
#ifndef GOLANG_SDK_H
#define GOLANG_SDK_H

#include <stdio.h>
#include <stdlib.h>
#define USING_ZITI_SHARED
#include <ziti/ziti.h>
#include <ziti/ziti_log.h>
#include <ziti/ziti_events.h>
#include <uv.h>


typedef struct cziti_ctx_s {
    ziti_options opts;
    ziti_context nf;
    uv_async_t async;
} cziti_ctx;

typedef struct libuv_ctx_s {
    uv_loop_t *l;
    uv_thread_t t;
    uv_async_t stopper;
} libuv_ctx;

void libuv_stopper(uv_async_t *a);
void libuv_init(libuv_ctx *lctx);
void libuv_runner(void *arg);
void libuv_run(libuv_ctx *lctx);
void libuv_stop(libuv_ctx *lctx);

void set_log_out(intptr_t h, libuv_ctx *lctx);
void set_log_level(int level, libuv_ctx *lctx);

extern const char** all_configs;

//posture check functions
extern void ziti_pq_domain_go(ziti_context ztx, char *id, ziti_pr_domain_cb response_cb);
extern void ziti_pq_process_go(ziti_context ztx, char *id, char *path, ziti_pr_process_cb response_cb);
extern void ziti_pq_os_go(ziti_context ztx, char *id, ziti_pr_os_cb response_cb);
extern void ziti_pq_mac_go(ziti_context ztx, char *id, ziti_pr_mac_cb response_cb);

//logging callback
extern void log_writer_shim_go(int level, const char *loc, const char *msg, size_t msglen);

void log_writer_cb(int level, char *loc, char *msg, int msglen);
bool is_null(void* anything);

struct ziti_context_event* ziti_event_context_event(ziti_event_t *ev);
struct ziti_router_event* ziti_event_router_event(ziti_event_t *ev);
struct ziti_service_event* ziti_event_service_event(ziti_event_t *ev);

ziti_service* ziti_service_array_get(ziti_service_array arr, int idx);

extern void ziti_dump_go(char* msg);
#endif /* GOLANG_SDK_H */