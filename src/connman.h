/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2008  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <glib.h>

#include <connman/dbus.h>

#define NM_SERVICE    "org.freedesktop.NetworkManager"
#define NM_PATH       "/org/freedesktop/NetworkManager"
#define NM_INTERFACE  NM_SERVICE

int __connman_manager_init(DBusConnection *conn, gboolean compat);
void __connman_manager_cleanup(void);

int __connman_agent_init(DBusConnection *conn);
void __connman_agent_cleanup(void);

int __connman_agent_register(const char *sender, const char *path);
int __connman_agent_unregister(const char *sender, const char *path);

#include <connman/log.h>

int __connman_log_init(gboolean detach, gboolean debug);
void __connman_log_cleanup(void);

#include <connman/plugin.h>

int __connman_plugin_init(void);
void __connman_plugin_cleanup(void);

#include <connman/driver.h>
#include <connman/element.h>

int __connman_element_init(DBusConnection *conn);
void __connman_element_cleanup(void);

void __connman_element_list(enum connman_element_type type,
						DBusMessageIter *iter);

const char *__connman_element_type2string(enum connman_element_type type);
const char *__connman_element_subtype2string(enum connman_element_subtype type);

#include <connman/iface.h>

int __connman_iface_init(DBusConnection *conn, const char *interface);
void __connman_iface_cleanup(void);

struct connman_iface *__connman_iface_find(int index);
void __connman_iface_list(DBusMessageIter *iter);
gboolean __connman_iface_is_connected(void);

int __connman_iface_create_identifier(struct connman_iface *iface);
int __connman_iface_init_via_inet(struct connman_iface *iface);
int __connman_iface_start(struct connman_iface *iface);
int __connman_iface_stop(struct connman_iface *iface);
int __connman_iface_connect(struct connman_iface *iface,
					struct connman_network *network);
int __connman_iface_disconnect(struct connman_iface *iface);

char *__connman_iface_find_passphrase(struct connman_iface *iface,
							const char *network);
int __connman_iface_load(struct connman_iface *iface);
int __connman_iface_store(struct connman_iface *iface);
int __connman_iface_store_current_network(struct connman_iface *iface);
int __connman_iface_load_networks(struct connman_iface *iface);

void __connman_iface_network_list(struct connman_iface *iface,
						DBusMessageIter *iter);
struct connman_network *__connman_iface_find_network(struct connman_iface *iface,
								const char *path);
int __connman_iface_remove_network(struct connman_iface *iface, const char *path);
const char *__connman_iface_add_network(struct connman_iface *iface,
				const char *identifier, const char *passphrase);

int __connman_network_init(DBusConnection *conn);
void __connman_network_cleanup(void);

const char *__connman_iface_type2string(enum connman_iface_type type);
const char *__connman_iface_state2string(enum connman_iface_state state);
const char *__connman_iface_policy2string(enum connman_iface_policy policy);
enum connman_iface_policy __connman_iface_string2policy(const char *policy);

const char *__connman_ipv4_method2string(enum connman_ipv4_method method);
enum connman_ipv4_method __connman_ipv4_string2method(const char *method);

#include <connman/rtnl.h>

int __connman_rtnl_init(void);
void __connman_rtnl_cleanup(void);

int __connman_rtnl_send(const void *buf, size_t len);

#include <connman/dhcp.h>

int __connman_dhcp_request(struct connman_iface *iface);
int __connman_dhcp_release(struct connman_iface *iface);

#include <connman/resolver.h>

int __connman_resolver_append(struct connman_iface *iface,
						const char *nameserver);
int __connman_resolver_remove(struct connman_iface *iface);
