/*
// Copyright (c) 2016 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "oc_api.h"
#include "port/oc_clock.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>

#define TRACE() PRINT( "%s:%d: %s\n", __FILE__ , __LINE__ , __PRETTY_FUNCTION__ )

static pthread_mutex_t mutex;
static pthread_cond_t cv;
static struct timespec ts;
static int quit = 0;
static bool switch_state = false;

static void
set_device_custom_property(void *data)
{
    TRACE();
  oc_set_custom_device_property(purpose, "Smart switch");
}

static void
app_init(void)
{
    TRACE();
  oc_init_platform("Intel", NULL, NULL);

  oc_add_device("/oic/d", "oic.d.switch.binary", "RzR's switch", "1.0", "1.0",
                set_device_custom_property, NULL);

#ifdef OC_SECURITY
  oc_storage_config("./creds");
#endif /* OC_SECURITY */
}

static void
get_switch(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
    TRACE();
  PRINT("GET_switch:\n");
  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  case OC_IF_RW:
    oc_rep_set_boolean(root, state, switch_state);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
  PRINT("Switch state %d\n", switch_state);
}

static void
post_switch(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
    TRACE();
  PRINT("PUT_switch:\n");
  bool state = false;
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    PRINT("key: %s ", oc_string(rep->name));
    switch (rep->type) {
    case BOOL:
      state = rep->value_boolean;
      PRINT("value: %d\n", state);
      break;
    default:
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
      return;
      break;
    }
    rep = rep->next;
  }
  oc_send_response(request, OC_STATUS_CHANGED);
  switch_state = state;
}

static void
put_switch(oc_request_t *request, oc_interface_mask_t interface,
           void *user_data)
{
  post_switch(request, interface, user_data);
}

static void
register_resources(void)
{
    TRACE();
  oc_resource_t *res = oc_new_resource("/BinarySwitchResURI", 1, 0);
  oc_resource_bind_resource_type(res, "oic.r.switch.binary");
  oc_resource_bind_resource_interface(res, OC_IF_RW);
  oc_resource_set_default_interface(res, OC_IF_RW);

#ifdef OC_SECURITY
  oc_resource_make_secure(res);
#endif

  oc_resource_set_discoverable(res, true);
  oc_resource_set_periodic_observable(res, 1);
  oc_resource_set_request_handler(res, OC_GET, get_switch, NULL);
  oc_resource_set_request_handler(res, OC_POST, post_switch, NULL);
  oc_resource_set_request_handler(res, OC_PUT, put_switch, NULL);

  oc_add_resource(res);
}

static void
signal_event_loop(void)
{
    TRACE();
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}

static void
handle_signal(int signal)
{
    TRACE();
  signal_event_loop();
  quit = 1;
}

int
main(void)
{
    TRACE();
  int init;
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources = register_resources };

  oc_clock_time_t next_event;

  init = oc_main_init(&handler);
  if (init < 0)
    return init;

  while (quit != 1) {
    next_event = oc_main_poll();
    pthread_mutex_lock(&mutex);
    if (next_event == 0) {
      pthread_cond_wait(&cv, &mutex);
    } else {
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&cv, &mutex, &ts);
    }
    pthread_mutex_unlock(&mutex);
  }

  oc_main_shutdown();
  return 0;
}
