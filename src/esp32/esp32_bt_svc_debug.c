/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the ""License"");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an ""AS IS"" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Interface to sys_config over BLE GATT service.
 * See README.md for high-level description.
 */

#include <ctype.h>
#include <stdlib.h>

#include "common/cs_dbg.h"
#include "common/mg_str.h"
#include "common/queue.h"

#include "mgos_config_util.h"
#include "mgos_debug.h"
#include "mgos_event.h"
#include "mgos_hal.h"
#include "mgos_sys_config.h"
#include "mgos_utils.h"

#include "esp32_bt.h"
#include "esp32_bt_gatts.h"

/* Note: UUIDs below are in reverse, because that's how ESP wants them. */
static const esp_bt_uuid_t mos_dbg_svc_uuid = {
    .len = ESP_UUID_LEN_128,
    .uuid.uuid128 =
        {
         /* _mOS_DBG_SVC_ID_, 5f6d4f53-5f44-4247-5f53-56435f49445f */
         0x5f, 0x44, 0x49, 0x5f, 0x43, 0x56, 0x53, 0x5f, 0x47, 0x42, 0x44, 0x5f,
         0x53, 0x4f, 0x6d, 0x5f,
        },
};

static const esp_bt_uuid_t mos_dbg_log_uuid = {
    .len = ESP_UUID_LEN_128,
    .uuid.uuid128 =
        {
         /* 0mOS_DBG_log___0, 306d4f53-5f44-4247-5f6c-6f675f5f5f30 */
         0x30, 0x5f, 0x5f, 0x5f, 0x67, 0x6f, 0x6c, 0x5f, 0x47, 0x42, 0x44, 0x5f,
         0x53, 0x4f, 0x6d, 0x30,
        },
};
static uint16_t mos_dbg_log_ah, mos_dbg_log_cc_ah;

const esp_gatts_attr_db_t mos_dbg_gatt_db[4] = {
    {
     .attr_control = {.auto_rsp = ESP_GATT_AUTO_RSP},
     .att_desc =
         {
          .uuid_length = ESP_UUID_LEN_16,
          .uuid_p = (uint8_t *) &primary_service_uuid,
          .perm = ESP_GATT_PERM_READ,
          .max_length = ESP_UUID_LEN_128,
          .length = ESP_UUID_LEN_128,
          .value = (uint8_t *) mos_dbg_svc_uuid.uuid.uuid128,
         },
    },
    /* log */
    {{ESP_GATT_AUTO_RSP},
     {ESP_UUID_LEN_16, (uint8_t *) &char_decl_uuid, ESP_GATT_PERM_READ, 1, 1,
      (uint8_t *) &char_prop_read_notify}},
    {{ESP_GATT_RSP_BY_APP},
     {ESP_UUID_LEN_128, (uint8_t *) mos_dbg_log_uuid.uuid.uuid128,
      ESP_GATT_PERM_READ, 0, 0, NULL}},
    {{ESP_GATT_RSP_BY_APP},
     {ESP_UUID_LEN_16, (uint8_t *) &char_client_config_uuid,
      ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE, 0, 0, NULL}},
};

static struct mg_str s_last_debug_entry = MG_NULL_STR;

struct bt_dbg_svc_conn_data {
  uint16_t gatt_if;
  uint16_t conn_id;
  uint16_t mtu;
  bool notify;
  SLIST_ENTRY(bt_dbg_svc_conn_data) next;
};

static SLIST_HEAD(s_conns, bt_dbg_svc_conn_data) s_conns =
    SLIST_HEAD_INITIALIZER(s_conns);

static void s_debug_write_cb(int ev, void *ev_data, void *userdata) {
  const struct mgos_debug_hook_arg *arg =
      (const struct mgos_debug_hook_arg *) ev_data;

  s_last_debug_entry.len = 0;
  free((void *) s_last_debug_entry.p);
  s_last_debug_entry = mg_strdup(mg_mk_str_n(arg->data, arg->len));
  while (s_last_debug_entry.len > 0 &&
         isspace((int) s_last_debug_entry.p[s_last_debug_entry.len - 1])) {
    s_last_debug_entry.len--;
  }
  struct bt_dbg_svc_conn_data *cd = NULL;
  SLIST_FOREACH(cd, &s_conns, next) {
    if (!cd->notify) continue;
    size_t len = MIN(s_last_debug_entry.len, cd->mtu - 3);
    mgos_bt_gatts_send_indicate(cd->gatt_if, cd->conn_id, mos_dbg_log_ah,
                                mg_mk_str_n((char *) s_last_debug_entry.p, len),
                                false /* need_confirm */);
  }
}

static bool mgos_bt_dbg_svc_ev(struct esp32_bt_session *bs,
                               esp_gatts_cb_event_t ev,
                               esp_ble_gatts_cb_param_t *ep) {
  bool ret = false;
  char buf[BT_UUID_STR_LEN];
  struct bt_dbg_svc_conn_data *cd = NULL;
  struct esp32_bt_connection *bc = NULL;
  if (bs != NULL) { /* CREAT_ATTR_TAB is not associated with any session. */
    bc = bs->bc;
    cd = (struct bt_dbg_svc_conn_data *) bs->user_data;
  }
  switch (ev) {
    case ESP_GATTS_CREAT_ATTR_TAB_EVT: {
      const struct gatts_add_attr_tab_evt_param *p = &ep->add_attr_tab;
      uint16_t svch = p->handles[0];
      mos_dbg_log_ah = p->handles[2];
      mos_dbg_log_cc_ah = p->handles[3];
      LOG(LL_DEBUG, ("svch = %d log_ah = %d", svch, mos_dbg_log_ah));
      break;
    }
    case ESP_GATTS_CONNECT_EVT: {
      cd = (struct bt_dbg_svc_conn_data *) calloc(1, sizeof(*cd));
      if (cd == NULL) break;
      cd->gatt_if = bs->bc->gatt_if;
      cd->conn_id = bs->bc->conn_id;
      cd->mtu = bs->bc->mtu;
      LOG(LL_DEBUG, ("MTU %u", cd->mtu));
      cd->notify = false;
      bs->user_data = cd;
      SLIST_INSERT_HEAD(&s_conns, cd, next);
      break;
    }
    case ESP_GATTS_READ_EVT: {
      const struct gatts_read_evt_param *p = &ep->read;
      if (p->handle != mos_dbg_log_ah || cd == NULL) break;
      size_t len = s_last_debug_entry.len;
      if (len < p->offset) {
        len = 0;
      } else {
        len -= p->offset;
      }
      if (len > bs->bc->mtu - 1) len = bs->bc->mtu - 1;
      esp_gatt_rsp_t rsp = {.attr_value = {.handle = mos_dbg_log_ah,
                                           .offset = p->offset,
                                           .len = len}};
      memcpy(rsp.attr_value.value, s_last_debug_entry.p + p->offset, len);
      esp_ble_gatts_send_response(bc->gatt_if, bc->conn_id, p->trans_id,
                                  ESP_GATT_OK, &rsp);
      ret = true;
      break;
    }
    case ESP_GATTS_WRITE_EVT: {
      const struct gatts_write_evt_param *p = &ep->write;
      if (p->handle != mos_dbg_log_cc_ah || cd == NULL) break;
      /* Client config control write - toggle notification. */
      if (p->len != 2) break;
      /* We interpret notify and indicate bits the same. */
      cd->notify = (p->value[0] != 0);
      cd->mtu = bs->bc->mtu;
      LOG(LL_DEBUG, ("%s: log notify %s", esp32_bt_addr_to_str(p->bda, buf),
                     (cd->notify ? "on" : "off")));
      ret = true;
      break;
    }
    case ESP_GATTS_DISCONNECT_EVT: {
      if (cd != NULL) {
        SLIST_REMOVE(&s_conns, cd, bt_dbg_svc_conn_data, next);
        free(cd);
      }
      break;
    }
    default:
      break;
  }
  return ret;
}

bool mgos_bt_service_debug_init(void) {
  if (mgos_sys_config_get_bt_debug_svc_enable()) {
    mgos_event_add_handler(MGOS_EVENT_LOG, s_debug_write_cb, NULL);
    mgos_bt_gatts_register_service(mos_dbg_gatt_db, ARRAY_SIZE(mos_dbg_gatt_db),
                                   mgos_bt_dbg_svc_ev);
  }
  return true;
}
