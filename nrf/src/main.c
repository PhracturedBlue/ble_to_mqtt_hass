/* main.c - Application main entrbt_gatt_attr_value_handley point */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/console/console.h>
#include <zephyr/types.h>
#include <stddef.h>
#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/reboot.h>

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/sys/byteorder.h>

#include <zephyr/drivers/uart.h>

#include <zephyr/version.h>
#include "_appversion.h"

#define BT_GAP_SCAN_FAST_INTERVAL_MIN   0x0030 /* 30 ms */
#define BT_GAP_SCAN_FAST_WINDOW   0x0030 /* 30 ms */

#define BT_SCAN_PARAMS	BT_LE_SCAN_PARAM(BT_LE_SCAN_TYPE_PASSIVE, \
			    BT_LE_SCAN_OPT_FILTER_DUPLICATE, \
			    BT_GAP_SCAN_FAST_INTERVAL_MIN, \
			    BT_GAP_SCAN_FAST_WINDOW)

enum {
    SCAN_STOPPED_EVENT = 0x01,
    CONNECTED_EVENT = 0x02,
    DISCONNECTED_EVENT = 0x04,
    DISCOVERED_EVENT = 0x08,
    READ_EVENT = 0x10,
    THREAD_EVENT = 0x20,
    READY_EVENT = 0x40,
    SCAN_RESTART_EVENT = 0x80,
};

const struct device *const tty_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_console));

static K_EVENT_DEFINE(conn_event);
static atomic_t connected_a = ATOMIC_INIT(0);
//static atomic_t disconnect_a = ATOMIC_INIT(0);
static atomic_t read_ready_a = ATOMIC_INIT(0);
static atomic_t discovered_a = ATOMIC_INIT(0);
static atomic_t timeout_a = ATOMIC_INIT(0);

enum conn_type_e {
	CONN_NONE = 0,
	CONN_GOVEE,
};

enum govee_states_e {
	GOVEE_NONE = 0,
	GOVEE_AUTH_WAIT,
};

struct {
	int8_t used_by;
	int8_t retries;
	struct bt_gatt_discover_params discover_params;
} conn_thread;

struct connection {
	bt_addr_t addr;
	struct bt_conn *conn;
	enum conn_type_e type;
	struct bt_gatt_subscribe_params notify_params;
	struct k_timer timer;
	union {
		struct {
			char name[12];
			uint8_t auth[10];
			uint8_t read_data[20];
			uint8_t write_data[20];
			int8_t power_state;
			enum govee_states_e state;
			int8_t monitor_energy;
			int8_t requested_state;
		} govee;
	};
	uint16_t handles[2];
	uint16_t hci_handle;
	union {
		const struct bt_uuid_128 *uuids;
		struct {
			uint8_t *read_data;
			uint8_t read_data_len;
			uint8_t len;
		};
	} data;
} connections[CONFIG_BT_MAX_CONN] = {0};

uint8_t conn_map[CONFIG_BT_MAX_CONN];
uint8_t send_unknown = 0;

struct conn_fs_item {
	bt_addr_t addr;
	enum conn_type_e type;
	union {
		struct {
			uint8_t auth[8];
			uint8_t monitor_energy;
			char name[12];
		} govee;
	};
};
#define STACK_SIZE 1024
K_THREAD_STACK_DEFINE(stack, STACK_SIZE);

static const struct bt_uuid_128 govee_uuids[] = {
	BT_UUID_INIT_128(BT_UUID_128_ENCODE(0x00010203, 0x0405, 0x0607, 0x0809, 0x0a0b0c0d2b11)), // send
	BT_UUID_INIT_128(BT_UUID_128_ENCODE(0x00010203, 0x0405, 0x0607, 0x0809, 0x0a0b0c0d2b10)), // recv
};

static const uint8_t govee_state_query[] = {0xaa, 0x01};
static const uint8_t govee_power_query[] = {0xaa, 0x00};
static const uint8_t govee_turn_on[] = {0x33, 0x01, 0x01};
static const uint8_t govee_turn_off[] = {0x33, 0x01, 0x00};
static const uint8_t govee_adv[] = {0x09, 0xff, 0x03, 0x88, 0xec, 0x00};

enum log_type_e {
	LOG_DEBUG = 0, 
	LOG_INFO,
	LOG_WARN,
	LOG_ERROR,
	LOG_RESPONSE,
	LOG_SYSTEM,
	LOG_ADV,
	LOG_GOVEE,
};
static uint8_t log_level = LOG_INFO;
struct log_data {
	enum log_type_e type;
	bt_addr_t addr;
	union {
		struct {
			uint8_t ad[255];
			uint8_t len;
                        uint8_t rssi;
		} adv;
		struct {
			char name[12];		// 12
			uint8_t power_state;	// 1
			uint8_t power[20];	// 20
			uint8_t rssi;
		} govee;
		struct {
			uint8_t len;
			uint8_t data[49];
		} raw;
	};
};
K_MSGQ_DEFINE(log_msgq, sizeof(struct log_data), 20, 1);

void govee_timer(struct k_timer *timer);


void safe_strncpy(char *dest, const char*src, int len)
{
	strncpy(dest, src, len);
	dest[len-1] = 0;
}

void log_raw(enum log_type_e lvl, const bt_addr_t *addr, uint8_t *raw, uint8_t len, const char *fmt, ...)
{
	struct log_data data, rsp;
	va_list ap;
	if (lvl < log_level) {
		return;
	}
	data.type = lvl;
	if (addr) {
		data.addr = *addr;
	} else {
		memset(&data.addr, 0, sizeof(data.addr));
	}

	va_start(ap, fmt);
	int name_len = vsnprintf(data.raw.data, sizeof(data.raw.data), fmt, ap);
	va_end(ap);
	data.raw.data[sizeof(data.raw.data)-1] = 0;
	int max_len = sizeof(data.raw.data) - name_len - 1;
	if (max_len > 0 && len > 0) {
		len = len <= max_len ? len : max_len;
		memcpy(&data.raw.data[name_len+1], raw, len);
		data.raw.len = len;
	} else {
		data.raw.len = 0;
	}
		
	while (k_msgq_put(&log_msgq, &data, K_NO_WAIT) != 0) {
		/* message queue is full: pop a message from the front & try again */
		if (lvl >= LOG_ERROR)  {
			break;
		}
		k_msgq_get(&log_msgq, &rsp, K_NO_WAIT);
        }
}

#define log_msg(lvl, addr, ...) log_raw(lvl, addr, NULL, 0, __VA_ARGS__)
#define debug(...) log_msg(LOG_DEBUG, __VA_ARGS__)
#define info(...) log_msg(LOG_INFO, __VA_ARGS__)
#define warn(...) log_msg(LOG_WARN, __VA_ARGS__)
#define error(...) log_msg(LOG_ERROR, __VA_ARGS__)

void log_adv(const bt_addr_t *addr, uint8_t rssi, const uint8_t *msg, int len)
{
	struct log_data data;
	data.type = LOG_ADV;
	len = len < sizeof(data.adv.ad) ? len : sizeof(data.adv.ad);
	data.addr = *addr;
	data.adv.rssi = rssi;
	memcpy(data.adv.ad, msg, len);
	data.adv.len = len;
	k_msgq_put(&log_msgq, &data, K_NO_WAIT);
}

void log_govee(const bt_addr_t *addr, uint8_t rssi, const char *name, int power_state, const uint8_t *power)
{
	struct log_data data;
	data.type = LOG_GOVEE;
	data.addr = *addr;
	data.govee.rssi = rssi;
	safe_strncpy(data.govee.name, name, sizeof(data.govee.name));
	data.govee.power_state = power_state;
	memcpy(data.govee.power, power, 20);
	k_msgq_put(&log_msgq, &data, K_NO_WAIT);
}

int create_connection(struct conn_fs_item *conn_data, int i)
{
	if (conn_data->type != CONN_GOVEE) {
		return false;
	}
	struct connection *conn = &connections[i];
	memset(conn, 0, sizeof(struct connection));
	conn->type = conn_data->type;
	conn->addr = conn_data->addr;
	if (conn_data->type == CONN_GOVEE) {
		conn->govee.auth[0] = 0x33;
		conn->govee.auth[1] = 0xb2;
		conn->govee.monitor_energy = conn_data->govee.monitor_energy;
		conn->govee.requested_state = -1;  // No requested state
		memcpy(conn->govee.auth+2, conn_data->govee.auth, 8);
		safe_strncpy(conn->govee.name, conn_data->govee.name, sizeof(conn->govee.name));
		k_timer_init(&conn->timer, govee_timer, NULL);
		return true;
	}
	return false;
}

int needs_connection(struct connection *conn, struct net_buf_simple *ad)
{
	// Determine if a connection is warranted
	if (conn->type == CONN_GOVEE)
	{
		if (ad->len != 26 || memcmp(&ad->data[16], govee_adv, sizeof(govee_adv)) != 0) {
			warn(&conn->addr, "Couldn't parse Govee adv packet");
			return false;
		}
		int state = ad->data[24];
		log_raw(LOG_DEBUG, &conn->addr, ad->data, ad->len, "CONN");
		debug(&conn->addr, "Mon: %d state: %d req: %d", conn->govee.monitor_energy, state, conn->govee.requested_state);
		if (conn->govee.monitor_energy && state == 1) {
			// Device is powered on, enable monitor
			return true;
		}
		if (conn->govee.requested_state >= 0 && conn->govee.requested_state != state) {
			// Device is not in requested state
			return true;
		}
		if (conn->handles[0] == 0 || conn->handles[1] == 0) {
			// Device has never successfuly connected
			return true;
		}
	}
	return false;
}

void disconnect(struct bt_conn *conn)
{
	if (conn == 0) {
		return;
	}
	int i = conn_map[bt_conn_index(conn)];
	debug(&connections[i].addr, "Disconnecting");
	bt_conn_disconnect(conn, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
}

static void device_found(const bt_addr_le_t *addr, int8_t rssi, uint8_t type,
			 struct net_buf_simple *ad)
{
	char addr_str[BT_ADDR_LE_STR_LEN];
	int err;
	bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
	// if (strncmp(addr_str, "60:74:F4:AB:66:C3", 17) != 0)
	if (type == BT_GAP_ADV_TYPE_ADV_IND ||
	    type == BT_GAP_ADV_TYPE_ADV_DIRECT_IND) {
		for (int i = 0; i < CONFIG_BT_MAX_CONN; i++) {
			if (! connections[i].type || ! bt_addr_eq(&connections[i].addr, &addr->a)) {
				//const bt_addr_t *a = &connections[i].addr;
				//debug(&addr->a, "Checking %d: %p %d vs %02x:%02x:%02x:%02x:%02x:%02x",
				//	i, connections[i].conn, connections[i].type,
				//	a->val[0], a->val[1], a->val[2],
				//	a->val[3], a->val[4], a->val[5]);
				continue;
			}
			if (connections[i].conn) {
				goto exit;
			}
			if (! needs_connection(&connections[i], ad)) {
				// Connection not needed, treat it as a regular ADV device
				break;
			}
			debug(&addr->a, "Device found: (RSSI %d)", rssi);

			if (bt_le_scan_stop()) {
				goto exit;
			}
			k_event_post(&conn_event, SCAN_STOPPED_EVENT);
			atomic_clear_bit(&connected_a, i);
			atomic_clear_bit(&read_ready_a, i);
			atomic_clear_bit(&timeout_a, i);
			err = bt_conn_le_create(addr, BT_CONN_LE_CREATE_CONN,
					BT_LE_CONN_PARAM_DEFAULT, &connections[i].conn);
			if (err) {
				error(&addr->a, "Create conn failed (%d)", err);
				goto exit;
			}
			conn_map[bt_conn_index(connections[i].conn)] = i;
			goto exit;
		}
	}
	if (ad->len) {
		log_adv(&addr->a, rssi, ad->data, ad->len);
	} else {
		debug(&addr->a, "Unknown device");
	}
exit:
	return;
}

void connected_cb(struct bt_conn *conn, uint8_t err)
{
	int i = conn_map[bt_conn_index(conn)];
	info(&connections[i].addr, "Connected (err: %d)", err);

	if (err) {
		connections[i].conn = NULL;
		bt_conn_unref(conn);
		goto exit;
	}
	connections[i].hci_handle = -1;
	err = bt_hci_get_conn_handle(connections[i].conn, &connections[i].hci_handle);
	if (err) {                                      
		error(&connections[i].addr, "No connection handle: %d", err);
		connections[i].hci_handle = -1;
		goto exit;
	}

	if (connections[i].type == CONN_GOVEE) {
		atomic_set_bit(&connected_a, i);
	} else {
		error(&connections[i].addr, "Invalid conn type %d for %d", connections[i].type, i);
		disconnect(conn);
	}
	k_event_post(&conn_event, CONNECTED_EVENT | THREAD_EVENT);
exit:
}

void disconnected_cb(struct bt_conn *conn, uint8_t reason)
{
	int i = conn_map[bt_conn_index(conn)];
	info(&connections[i].addr, "Disconnected %d (reason %d)", i, reason);
	k_timer_stop(&connections[i].timer);

	connections[i].conn = NULL;
	bt_conn_unref(conn);
	if (conn_thread.used_by == i) {
		conn_thread.used_by = -1;
	}

	// atomic_set_bit(&disconnected_a, i);
	// k_event_post(&conn_event, THREAD_EVENT);
}

BT_CONN_CB_DEFINE(conn_cb) = {
	.connected = connected_cb,
	.disconnected = disconnected_cb,
};

static uint8_t notify_func(struct bt_conn *conn, struct bt_gatt_subscribe_params *params, const void *data, uint16_t length)
{
	int idx = conn_map[bt_conn_index(conn)];
	//debug(&connections[i].addr, "Received notification: %d", length);
	if (length > connections[idx].data.read_data_len) {
		error(&connections[idx].addr, "Read too much data: %d", length);
		return BT_GATT_ITER_CONTINUE;
	}
	memcpy(connections[idx].data.read_data, data, length);
	connections[idx].data.len = length;
	atomic_set_bit(&read_ready_a, idx);
	k_event_post(&conn_event, THREAD_EVENT);
	return BT_GATT_ITER_CONTINUE;
}

static uint8_t discover_func(struct bt_conn *conn, const struct bt_gatt_attr *attr,
			     struct bt_gatt_discover_params *params)
{
	const int num_chars = 2;
	int idx = conn_map[bt_conn_index(conn)];
	struct bt_gatt_chrc *chrc;

	// debug(&connections[idx].addr, "Discovery: attr %p", attr);

	if (!attr) {
		info(&connections[idx].addr, "Found all attributes");
		atomic_set_bit(&discovered_a, idx);
		k_event_post(&conn_event, THREAD_EVENT);
		return BT_GATT_ITER_STOP;
	}

	chrc = (struct bt_gatt_chrc *)attr->user_data;

	char uuid[40];
	bt_uuid_to_str(chrc->uuid, uuid, sizeof(uuid));
	info(&connections[idx].addr,"Found char %s", uuid);

	for (int i = 0; i < num_chars; i++) {
		if (!bt_uuid_cmp(chrc->uuid, &connections[idx].data.uuids[i].uuid)) {
			if (! connections[idx].handles[i]) {
				connections[idx].handles[i] = chrc->value_handle;
				info(&connections[idx].addr, "Matched Characteristic %d hdl: %d", i, chrc->value_handle);
			}
			break;
		}
	}
	return BT_GATT_ITER_CONTINUE;
}

void discover(struct connection *conn, int num_chars, const struct bt_uuid_128 *uuids, int init)
{
	int err;
	if (init) {
		conn_thread.retries = 9;
		memset(conn->handles, 0, sizeof(conn->handles));
		conn->data.uuids = uuids;
	} else {
		conn_thread.retries -= 1;
	}
	memset(&conn_thread.discover_params, 0, sizeof(struct bt_gatt_discover_params));
	conn_thread.discover_params.func = discover_func;
	conn_thread.discover_params.start_handle = BT_ATT_FIRST_ATTRIBUTE_HANDLE;
	conn_thread.discover_params.end_handle = BT_ATT_LAST_ATTRIBUTE_HANDLE;
	conn_thread.discover_params.type = BT_GATT_DISCOVER_CHARACTERISTIC;
	err = bt_gatt_discover(conn->conn, &conn_thread.discover_params);
	if (err) {
		error(&conn->addr, "Discovery failed (err %d)", err);
		disconnect(conn->conn);
	}
	debug(&conn->addr, "Discovery started");
}

int check_discovery(struct connection *conn, int init)
{
	const int num_chars = 2;
	for (int i = 0; i < num_chars; i++) {
		if (conn->handles[i] == 0) {
			if (init) {
				debug(&conn->addr, "Missing char handles.  Discovering");
				discover(conn, 2, govee_uuids, true);
				return false;
			}
			error(&conn->addr, "Missing characteristic %d%s", i);
			if (conn_thread.retries) {
				error(&conn->addr, "Retrying find characterstic %d more times", conn_thread.retries);
				discover(conn, 2, govee_uuids, false);
			} else {
				disconnect(conn->conn);
			}
			return false;
		}
	}
	return true;
}

static void read_conn_rssi(const bt_addr_t *addr, uint16_t handle, int8_t *rssi)
{
        struct net_buf *buf, *rsp = NULL;                       
        struct bt_hci_cp_read_rssi *cp;                            
        struct bt_hci_rp_read_rssi *rp;                             
                                                 
        int err;                                                             
                       
        buf = bt_hci_cmd_create(BT_HCI_OP_READ_RSSI, sizeof(*cp));   
        if (!buf) {                                           
                error(addr, "Unable to allocate command buffer\n");
		goto exit;
        }                                                            
                                                 
        cp = net_buf_add(buf, sizeof(*cp));                                 
        cp->handle = sys_cpu_to_le16(handle);
                                                        
        err = bt_hci_cmd_send_sync(BT_HCI_OP_READ_RSSI, buf, &rsp);
        if (err) {                    
                uint8_t reason = rsp ?                         
                        ((struct bt_hci_rp_read_rssi *)rsp->data)->status : 0;
                error(addr, "Read RSSI err: %d reason 0x%02x\n", err, reason);
		goto exit;
        }                                                       
                                                                                  
        rp = (void *)rsp->data;                  
        *rssi = rp->rssi;

        net_buf_unref(rsp);
exit:
}

void govee_timer(struct k_timer *timer)
{
	for (int i = 0; i < CONFIG_BT_MAX_CONN; i++) {
		if (connections[i].conn && connections[i].type == CONN_GOVEE && timer == &connections[i].timer) {
			atomic_set_bit(&timeout_a, i);
			k_event_post(&conn_event, THREAD_EVENT);
			break;
		}
	}
}

void govee_write(struct connection *conn, const uint8_t *data, unsigned int len)
{
	int err;
	uint8_t xor = 0;
	memset(conn->govee.write_data, 0, 20);
	for (int i = 0; i < len; i++) {
		conn->govee.write_data[i] = data[i];
		xor ^= data[i];
	}
	conn->govee.write_data[19] = xor;
	log_raw(LOG_DEBUG, &conn->addr, conn->govee.write_data, 20, "SEND");
	err = bt_gatt_write_without_response(conn->conn, conn->handles[0], conn->govee.write_data, 20, false);
	if (err) {
		error(&conn->addr, "Write failed: (err %d)", err);
		disconnect(conn->conn);
		return;
	}
	k_timer_start(&conn->timer, K_MSEC(2000), K_NO_WAIT);
}

void handle_govee(int idx)
{
	int err;
	struct connection *conn = &connections[idx];
	debug(&conn->addr, "%d Handling Govee: ub: %d", idx, conn_thread.used_by);
	if (conn_thread.used_by == -1) {
		if (atomic_test_and_clear_bit(&connected_a, idx)) {
			conn_thread.used_by = idx;
			if (! check_discovery(conn, true)) {
				return;
			}
			atomic_set_bit(&discovered_a, idx);
		}
	}
	if (conn_thread.used_by == idx) {
		if (atomic_test_and_clear_bit(&discovered_a, idx)) {
			if (check_discovery(conn, false)) {
				memset(&conn->notify_params, 0, sizeof(struct bt_gatt_subscribe_params));
				conn->notify_params.notify = notify_func;
				conn->notify_params.value = BT_GATT_CCC_NOTIFY;
				conn->notify_params.value_handle = conn->handles[1];
				conn->notify_params.ccc_handle = conn->handles[1] + 1;
				conn->data.read_data = conn->govee.read_data;
				conn->data.read_data_len = sizeof(conn->govee.read_data);
				err = bt_gatt_subscribe(conn->conn, &conn->notify_params);
				if (err) {
					error(&conn->addr, "subscribe failed: %d", err);
					disconnect(conn->conn);
					return;
				}
				conn_thread.used_by = -1;
				k_event_post(&conn_event, THREAD_EVENT);
				govee_write(conn, conn->govee.auth, 10);
				info(&conn->addr, "Awaiting authentication");
				conn->govee.state = GOVEE_AUTH_WAIT;
			}
			return;
		}
	}
	if (atomic_test_and_clear_bit(&read_ready_a, idx)) {
		log_raw(LOG_DEBUG, &conn->addr, conn->govee.read_data, 20, "Read Ready");
		if (conn->govee.state == GOVEE_AUTH_WAIT) {
			if (conn->govee.read_data[0] != 0x33 || conn->govee.read_data[1] != 0xb2) {
				error(&conn->addr, "Unexpected auth resp: %02x%02x", conn->govee.read_data[0], conn->govee.read_data[1]);
				return;
			}
			conn->govee.state = GOVEE_NONE;
			info(&conn->addr, "Authorized");
			conn->govee.power_state = -1;
			govee_write(conn, govee_state_query, 2);
			return;
		}
		if (conn->govee.read_data[0] == 0x33 && conn->govee.read_data[1] == 0x01) {
			govee_write(conn, govee_state_query, 2);
			return;
		}
		if (conn->govee.read_data[0] == 0xaa && conn->govee.read_data[1] == 0x01) {
			conn->govee.power_state = !!conn->govee.read_data[2];
			if (conn->govee.requested_state >= 0) {
				if (conn->govee.power_state != conn->govee.requested_state) {
					govee_write(conn, conn->govee.requested_state ? govee_turn_on : govee_turn_off, 3);
				}
				conn->govee.requested_state = -1;
				return;
			} else {
				if (! conn->govee.power_state || ! conn->govee.monitor_energy) {
					disconnect(conn->conn);
					k_event_post(&conn_event, SCAN_RESTART_EVENT);
					return;
				}
			}
			if (conn->govee.monitor_energy) {
				govee_write(conn, govee_power_query, 2);
			}
		} else if (conn->govee.read_data[0] == 0xee && conn->govee.read_data[1] == 0x19) {
			if (conn->govee.power_state >= 0) {
				uint8_t rssi = 0;
				if (conn->hci_handle != -1) {
					read_conn_rssi(&conn->addr, conn->hci_handle, &rssi);
				}
				log_govee(&conn->addr, rssi, conn->govee.name, conn->govee.power_state, conn->govee.read_data);
			}
		}
	}
	if (atomic_test_and_clear_bit(&timeout_a, idx)) {
		debug(&conn->addr, "Timeout");
		govee_write(conn, govee_state_query, 2);
	}
}

void conn_mgr(void *p1, void *p2, void *p3)
{
	conn_thread.used_by = -1;
	while(true) {
		k_event_wait(&conn_event, THREAD_EVENT, false, K_SECONDS(2));
		k_event_clear(&conn_event, THREAD_EVENT);
		for (int i = 0; i < CONFIG_BT_MAX_CONN; i++) {
			if (! connections[i].conn) {
				continue;
			}
			if (connections[i].type == CONN_GOVEE) {
				handle_govee(i);
				debug(NULL, "Done handling Govee");
			}
		}
	}
}

void read_console_thread(void *p1, void *p2, void *p3)
{
	char data[128];
	char *ptr = data;
	char cmd;
	int len;
	int err;
	struct conn_fs_item conn_data;
	k_event_wait(&conn_event, READY_EVENT, false, K_FOREVER);
	while (true) {
		uint8_t c = console_getchar();
		if (c == '\r' || c == '\n') {
			*ptr = 0;
			len = strlen(data);
			if (strcmp(data, "REBOOT") == 0) {
				sys_reboot(SYS_REBOOT_COLD);
				while(1) {}
			}
			if (strcmp(data, "RESCAN") == 0) {
				k_event_post(&conn_event, SCAN_RESTART_EVENT);
				ptr = data;
				continue;
			}
			if (strncmp(data, "ECHO ", 5) == 0) {
				log_msg(LOG_RESPONSE, NULL, &data[5]);
				ptr = data;
				continue;
			}
			if (strncmp(data, "LEVEL ", 6) == 0) {
				int8_t level = data[6] - '0';
				if (level >= LOG_DEBUG  && level <= LOG_ERROR) {
					log_level = level;
					log_msg(LOG_RESPONSE, NULL, "New Level: %d", log_level);
				} else {
					error(NULL, "Bad log level");
				}
				ptr = data;
				continue;
			}
			if (strcmp(data, "CLOSEALL") == 0) {
				// close all connections
				for (int i = 0; i < CONFIG_BT_MAX_CONN; i++) {
					if (connections[i].type) {
						log_msg(LOG_RESPONSE, &connections[i].addr, "Closing %d", i);
						if (connections[i].conn) {
							disconnect(connections[i].conn);
						}
						connections[i].type = CONN_NONE;

					}
				}
				log_msg(LOG_RESPONSE, NULL, "DONE");
				k_event_post(&conn_event, SCAN_RESTART_EVENT);
				ptr = data;
				continue;
			}
			if (strcmp(data, "LIST") == 0) {
				for (int i = 0; i < CONFIG_BT_MAX_CONN; i++) {
					if (! connections[i].type) {
						continue;
					}
					log_msg(LOG_RESPONSE, &connections[i].addr, "Conn %d %s is_conn: %c", i,
 						connections[i].type == CONN_GOVEE ? "GOVEE" : "NONE", connections[i].conn ? 'Y' : 'N');
				}
				log_msg(LOG_RESPONSE, NULL, "DONE");
				ptr = data;
				continue;
			}
			if (memcmp(data, "LOG ", 4) == 0) {
				int lvl = data[4] - '0';
				if (lvl >= LOG_DEBUG && lvl <= LOG_ERROR) {
					log_level = lvl;
				}
				ptr = data;
				continue;
			}
			if (memcmp(data, "SHOWALL ", 8) == 0) {
				send_unknown = !!(data[8] - '0');
				ptr = data;
				continue;
			}
			if (len >= 19) {
				memset(&conn_data, 0, sizeof(conn_data));
				cmd = data[0];
				data[19] = 0;
				err = bt_addr_from_str(&data[2], &conn_data.addr);
				if (err) {
					error(NULL, "Invalid addr %s : %d", data+2, err);
					ptr = data;
					continue;
				}
				if (cmd == 'G') {  // Govee
					conn_data.type = CONN_GOVEE;
					if (len < 2 + 18 + 2 + 16) {
						error(&conn_data.addr, "Failed to parse govee auth");
						ptr = data;
						continue;
					}
					conn_data.govee.monitor_energy = (data[20] == '1');
					if (! hex2bin(&data[22], 16, conn_data.govee.auth, 8)) {
						error(&conn_data.addr, "Failed to parse govee auth");
						ptr = data;
						continue;
					}
					if (len > 2 + 18 + 2 + 17) {
						safe_strncpy(conn_data.govee.name, &data[39], 12);
					}
				} else if (cmd == 'S') { // Set conn parameter
					for (int i = 0; i < CONFIG_BT_MAX_CONN; i++) {
						if (! connections[i].type) {
							continue;
						}
						if (bt_addr_eq(&conn_data.addr, &connections[i].addr)) {
							if (connections[i].type == CONN_GOVEE) {
								int state = data[20] == '1' ? 1 : 0;
								connections[i].govee.requested_state = state;
								log_msg(LOG_RESPONSE, &conn_data.addr, "Power set to: %s", state? "On" : "Off");
								k_event_post(&conn_event, SCAN_RESTART_EVENT);
							}
							break;
						}
					}
					ptr = data;
					continue;
				} else if (cmd == 'D') { // Delete
					for (int i = 0; i < CONFIG_BT_MAX_CONN; i++) {
						if (! connections[i].type) {
							continue;
						}
						if (bt_addr_eq(&conn_data.addr, &connections[i].addr)) {
							if (connections[i].conn) {
								disconnect(connections[i].conn);
							}
							connections[i].type = CONN_NONE;
							info(&conn_data.addr, "Deleted connection %d", i);
							break;
						}
					}
					ptr = data;
					continue;
				} else {
					error(&conn_data.addr, "Unknown command %c", cmd);
					ptr = data;
					continue;
				}
				for (int i = 0; i < CONFIG_BT_MAX_CONN; i++) {
					if (connections[i].type || connections[i].conn) {
						continue;
					}
					if (create_connection(&conn_data, i)) {
						info(&conn_data.addr, "Assigned to conn %d", i);
						k_event_post(&conn_event, SCAN_RESTART_EVENT);
					} else {
						error(&conn_data.addr, "Failed to create conn %d", i);
					}
					break;
				}
			} else {
				error(NULL, "Invalid command: %s", data);
			}
			ptr = data;
			continue;
		} else if (c >= 32 && c < 127) {
			*ptr++ = c;
		} else {
			error(NULL, "Invalid character: %02x", c);
		}
	}
}

void log_thread(void *p1, void *p2, void *p3)
{
	struct log_data data;
	char msg[128];
	char *lvl_str;
	while(true) {
		k_msgq_get(&log_msgq, &data, K_FOREVER);
		char *pos = msg;
		if (data.type == LOG_ADV) {
			// 3 + 1 + 17 + 1 + 2*31 + 1 + 1
			pos += sprintf(pos, "ADV %02x:%02x:%02x:%02x:%02x:%02x %02x ",
					data.addr.val[5], data.addr.val[4], data.addr.val[3],
					data.addr.val[2], data.addr.val[1], data.addr.val[0],
					data.adv.rssi);
			for (int i = 0; i < data.adv.len; i++) {
				pos += sprintf(pos, "%02x", data.adv.ad[i]);
			}
			uint8_t *ptr = data.adv.ad;
			while(ptr < data.adv.ad + data.adv.len) {
				int len = ptr[0];
				int type = ptr[1];
				if (type == 0x09) {
					*pos++ = ' ';
					memcpy(pos, &ptr[2], len-1);
					pos += len-1;
					*pos++ = 0;
					break;
				}
				ptr += len + 1;
			}
		} else if (data.type == LOG_GOVEE) {
			pos += sprintf(pos, "GOV %02x:%02x:%02x:%02x:%02x:%02x %02x %s %d ",
					data.addr.val[5], data.addr.val[4], data.addr.val[3],
					data.addr.val[2], data.addr.val[1], data.addr.val[0],
					data.govee.rssi, data.govee.name, data.govee.power_state);
			for (int i = 0; i < 20; i++) {
				pos += sprintf(pos, "%02x", data.govee.power[i]);
			}
		} else {
			switch(data.type) {
				case LOG_DEBUG: lvl_str = "DBG"; break;
				case LOG_INFO: lvl_str = "INF"; break;
				case LOG_WARN: lvl_str = "WRN"; break;
				case LOG_ERROR: lvl_str = "ERR"; break;
				case LOG_RESPONSE: lvl_str = "RSP"; break;
				case LOG_SYSTEM: lvl_str = "***"; break;
				default: return;
			}
			pos += sprintf(msg, "%s ", lvl_str);
			if (data.addr.val[0] != 0 || data.addr.val[1] != 0 || data.addr.val[2] != 0 ||
			    data.addr.val[3] != 0 || data.addr.val[4] != 0 || data.addr.val[5] != 0) {
				pos += sprintf(pos, "%02x:%02x:%02x:%02x:%02x:%02x ",
					data.addr.val[5], data.addr.val[4], data.addr.val[3],
					data.addr.val[2], data.addr.val[1], data.addr.val[0]);
			}
			int name_len = strlen(data.raw.data);
			pos += sprintf(pos, "%s ", data.raw.data);
			for (int i = 0; i < data.raw.len; i++) {
				pos += sprintf(pos, "%02x%s", data.raw.data[i + name_len + 1], i % 2 ? " " : "");
			}
		}
		// uart_poll_out blocks until byte is sent
		for(char *ptr = msg; ptr < pos; ptr++) {
			uart_poll_out(tty_dev, *ptr);
		}
		uart_poll_out(tty_dev, '\r');
		uart_poll_out(tty_dev, '\n');
	}
}

K_THREAD_DEFINE(t_log, STACK_SIZE,
		log_thread, NULL, NULL, NULL,
		-1, 0, 0);
K_THREAD_DEFINE(t_conmgr, STACK_SIZE,
		conn_mgr, NULL, NULL, NULL,
		-1, 0, 0);
K_THREAD_DEFINE(t_console, STACK_SIZE,
		read_console_thread, NULL, NULL, NULL,
		-1, 0, 0);
int main(void)
{
	int err;
	uint32_t evt = 0;


	// Wait for USB connection
	int count = 0;
	if (DT_NODE_HAS_COMPAT(DT_CHOSEN(zephyr_console), zephyr_cdc_acm_uart)) {
		while (!evt) {
			err = uart_line_ctrl_get(tty_dev, UART_LINE_CTRL_DTR, &evt);
			if (err) {
				break;
			}
			/* Give CPU resources to low priority threads. */
			k_sleep(K_MSEC(100));
			count += 1;
		}
	}
	log_msg(LOG_SYSTEM, NULL, "Zephyr: %s", KERNEL_VERSION_STRING);
	log_msg(LOG_SYSTEM, NULL, "BLE Gateway: %s", APP_VERSION);
	log_msg(LOG_SYSTEM, NULL, "READY");

	console_init();
	err = bt_enable(NULL);
	if (err) {
		error(NULL, "Bluetooth init failed (err %d)", err);
		return 0;
	}

	debug(NULL, "Bluetooth initialized");

	k_event_post(&conn_event, READY_EVENT);
	debug(NULL, "Starting scan");
	while (1) {
		k_event_clear(&conn_event, ~THREAD_EVENT);
		err = bt_le_scan_start(BT_LE_SCAN_ACTIVE, device_found);
		if (err) {
			error(NULL, "Failed to start scan: %d", err);
			k_sleep(K_SECONDS(5));
			continue;
		}

		evt = k_event_wait(&conn_event, SCAN_STOPPED_EVENT | SCAN_RESTART_EVENT, false, K_SECONDS(45));
		// Need to check the event again in case new ones came before semaphore was aquired
		// evt = k_event_test(&conn_event, SCAN_STOPPED_EVENT | SCAN_RESTART_EVENT);
		if (! (evt & SCAN_STOPPED_EVENT) ) {
			bt_le_scan_stop();
			continue;
		}
		evt = k_event_wait(&conn_event, CONNECTED_EVENT, false, K_SECONDS(10));
		if (! evt) {
			error(NULL, "Timeout waiting for connection");
		}
		continue;
	}
	return 0;
}
