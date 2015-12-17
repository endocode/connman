/*
 *  Connection Manager
 *
 *  Copyright (C) 2015  Endocode AG.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <linux/fib_rules.h>
#include <net/if.h>
#include <unistd.h>
#include <stdlib.h>
#include <glib.h>

#include "../src/connman.h"

/* #define DEBUG */

struct route_data {
	int cmd;

	unsigned int table_id;
	int family;
	int ifindex;

	const char *src;
	int src_preflen;

	const char *dst;
	int dst_preflen;

	const char *gw;

	unsigned fwmark;
};

struct test_ctx {
	struct route_data *in;
	bool found;
};

static bool ipcmp(int family, const char *ip_str, void *ip_bin)
{

	if (family == AF_INET) {
		struct in_addr *ip = (struct in_addr *) ip_bin;
		struct in_addr tmp;

		inet_pton(AF_INET, ip_str, &tmp);

		return ip->s_addr == tmp.s_addr;

	} else if (family == AF_INET6) {
		struct in6_addr *ip = (struct in6_addr *) ip_bin;
		struct in6_addr tmp;

		inet_pton(AF_INET6, ip_str, &tmp);

		return memcmp(ip, &tmp, sizeof(tmp)) == 0;
	}

	return false;
}

static bool check_rule_attrs(const struct nlmsghdr *hdr,
				const struct route_data *d)
{
	struct rtmsg *msg;
	struct rtattr *attr;
	int bytes;
	int family;

	msg = (struct rtmsg *) NLMSG_DATA(hdr);
	bytes = RTM_PAYLOAD(hdr);
	family = msg->rtm_family;

	for (attr = RTM_RTA(msg); RTA_OK(attr, bytes);
					attr = RTA_NEXT(attr, bytes)) {
		switch (attr->rta_type) {
		case FRA_SRC:
			if (d->src && !ipcmp(family, d->src, RTA_DATA(attr))) {
				DBG("failed checking FRA_SRC");
				return false;
			}
			break;
		case FRA_FWMARK:
			if (d->fwmark &&
				d->fwmark != *((unsigned *) RTA_DATA(attr))) {
				DBG("failed checking FRA_FWMARK");
				return false;
			}
			break;
		}

	}

	return true;
}
static bool check_route_attrs(const struct nlmsghdr *hdr,
				const struct route_data *d)
{
	struct rtmsg *msg;
	struct rtattr *attr;
	int bytes;
	int family;

	msg = (struct rtmsg *) NLMSG_DATA(hdr);
	bytes = RTM_PAYLOAD(hdr);
	family = msg->rtm_family;

	for (attr = RTM_RTA(msg); RTA_OK(attr, bytes);
					attr = RTA_NEXT(attr, bytes)) {

		switch (attr->rta_type) {
		case RTA_DST:
			if (d->dst && !ipcmp(family, d->dst, RTA_DATA(attr))) {
				DBG("failed checking RTA_DST");
				return false;
			}
			break;
		case RTA_GATEWAY:
			if (d->gw && !ipcmp(family, d->gw, RTA_DATA(attr))) {
				DBG("failed checking RTA_GATEWAY");
				return false;
			}
			break;
		case RTA_OIF:
			if (d->ifindex > 0)
				break;

			if (*((int *) RTA_DATA(attr)) != d->ifindex) {
					DBG("failed checking RTA_GATEWAY");
					return false;
			}

			break;
		}
	}

	return true;
}

static gboolean route_find_cb(struct nlmsghdr *nlmsg, void *user_data)
{
	struct rtmsg *msg = NLMSG_DATA(nlmsg);
	struct test_ctx *ctx = (struct test_ctx *) user_data;
	struct route_data *in;

	if (!nlmsg)
		return false;

	msg = (struct rtmsg *) NLMSG_DATA(nlmsg);

	DBG("rtm_family %d rtm_table %d rtm_protocol %d",
			msg->rtm_family, msg->rtm_table, msg->rtm_protocol);

	/* found is false when something is set but doesn't match */
	ctx->found = true;

	in = ctx->in;

	if (in->table_id != msg->rtm_table) {
		DBG("exp_table_id != table_id: %d != %d",
			in->table_id, msg->rtm_table);
		ctx->found = false;
		return false;
	}

	if (in->src_preflen > 0 && in->src_preflen != msg->rtm_src_len) {
		DBG("exp_src_preflen != src_preflen: %d != %d",
			in->src_preflen, msg->rtm_src_len);
		ctx->found = false;
		return false;
	}

	if (in->cmd == RTM_GETROUTE && !check_route_attrs(nlmsg, in)) {
		DBG("failed checking route attrs");
		ctx->found = false;
		return false;
	}

	if (in->cmd == RTM_GETRULE && !check_rule_attrs(nlmsg, in)) {
		DBG("failed checking rule attrs");
		ctx->found = false;
		return false;
	}

	return true;
}

static bool rtm_get(struct route_data *data)

{
	/* Needed to be heap based */
	struct __connman_inet_rtnl_handle *rth;
	int ret;
	struct test_ctx test_data = {
		.in = data,
		.found = false,
	};

	rth = g_try_malloc0(sizeof(struct __connman_inet_rtnl_handle));
	g_assert(rth);

	memset(rth, 0, sizeof(*rth));

	rth->req.n.nlmsg_type = data->cmd;
	rth->req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	rth->req.n.nlmsg_flags = NLM_F_DUMP|NLM_F_REQUEST;
	rth->req.n.nlmsg_pid = 0;

	rth->req.u.r.rt.rtm_family = data->family;
	rth->req.u.r.rt.rtm_protocol = RTPROT_BOOT;
	rth->req.u.r.rt.rtm_scope = RT_SCOPE_UNIVERSE;
	rth->req.u.r.rt.rtm_type = RTN_UNICAST;

	if (data->table_id < 256) {
		rth->req.u.r.rt.rtm_table = data->table_id;
	} else {
		rth->req.u.r.rt.rtm_table = RT_TABLE_UNSPEC;
		__connman_inet_rtnl_addattr32(&rth->req.n, sizeof(rth->req),
						FRA_TABLE, data->table_id);
	}

	if (data->src) {
		unsigned char buf[sizeof(struct in6_addr)];
		unsigned addr_len = data->family == AF_INET ? 4 : 16;

		if (inet_pton(data->family, data->src, buf) <= 0)
			return -EINVAL;

		__connman_inet_rtnl_addattr_l(&rth->req.n, sizeof(rth->req),
						FRA_SRC, buf, addr_len);
		rth->req.u.r.rt.rtm_src_len = addr_len * 8;
	}

	if (data->dst) {
		unsigned char buf[sizeof(struct in6_addr)];
		unsigned addr_len = data->family == AF_INET ? 4 : 16;

		if (inet_pton(data->family, data->dst, buf) <= 0)
			return -EINVAL;

		__connman_inet_rtnl_addattr_l(&rth->req.n, sizeof(rth->req),
						RTA_DST, buf, addr_len);
		rth->req.u.r.rt.rtm_dst_len = data->dst_preflen;
	}

	if (data->gw) {
		unsigned char buf[sizeof(struct in6_addr)];
		unsigned addr_len = data->family == AF_INET ? 4 : 16;

		if (inet_pton(data->family, data->gw, buf) <= 0)
			return -EINVAL;

		__connman_inet_rtnl_addattr_l(&rth->req.n, sizeof(rth->req),
						RTA_GATEWAY, buf, addr_len);
	}

	if (data->ifindex >= 0) {
		__connman_inet_rtnl_addattr32(&rth->req.n, sizeof(rth->req),
					      RTA_OIF, data->ifindex);

	}

	if (data->fwmark) {
		__connman_inet_rtnl_addattr32(&rth->req.n, sizeof(rth->req),
						FRA_FWMARK, data->fwmark);
	}

	ret = __connman_inet_rtnl_open(rth);
	if (ret < 0) {
		connman_error("can't open rtnetlink channel");
		goto err;
	}

	ret = __connman_inet_rtnl_talk(rth, &rth->req.n, 5,
					route_find_cb, &test_data);
	if (ret < 0) {
		connman_error("can't set multipath flags, err=%d", ret);
		goto err;
	}

	/* To avoid starting a main loop, just check for events here. */
	g_main_context_iteration(NULL, true);

err:
	return test_data.found;

}

static __u32 get_interface_flags(char *if_name)
{
	struct ifaddrs *ifas = NULL;
	struct ifaddrs *ifa;
	__u32 flags = 0;
	bool found = false;

	g_assert(getifaddrs(&ifas) == 0);
	g_assert(ifas);

	for (ifa = ifas; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_name && strcmp(ifa->ifa_name, if_name) == 0) {
			flags = ifa->ifa_flags;
			found = true;
			break;
		}
	}

	freeifaddrs(ifas);

	g_assert(found);
	return flags;
}


static void test_state_transition(void)
{
	/*
	 * - Note 1: This test needs root or ??? capability to run.
	 * - Note 2: Using loopback because it's always there and
	 * it's always idx 1.
	 */

	__u32 flags;
	__u32 mask = IFF_NOMULTIPATH | IFF_MPBACKUP;
	int err;

	/* Do tests: */

	err = __connman_multipath_set(1, CONNMAN_MULTIPATH_STATE_OFF);
	g_assert(!err);
	flags = mask & get_interface_flags("lo");
	g_assert((flags & IFF_NOMULTIPATH));
	g_assert(!(flags & IFF_MPBACKUP));

	err = __connman_multipath_set(1, CONNMAN_MULTIPATH_STATE_ON);
	g_assert(!err);
	flags = mask & get_interface_flags("lo");
	g_assert(!(flags & IFF_NOMULTIPATH));
	g_assert(!(flags & IFF_MPBACKUP));

	err = __connman_multipath_set(1, CONNMAN_MULTIPATH_STATE_BACKUP);
	g_assert(!err);
	flags = mask & get_interface_flags("lo");
	g_assert(!(flags & IFF_NOMULTIPATH));
	g_assert((flags & IFF_MPBACKUP));

	err = __connman_multipath_set(1, CONNMAN_MULTIPATH_STATE_OFF);
	g_assert(!err);
	flags = mask & get_interface_flags("lo");
	g_assert((flags & IFF_NOMULTIPATH));
	g_assert(!(flags & IFF_MPBACKUP));

	err = __connman_multipath_set(1, CONNMAN_MULTIPATH_STATE_ON);
	g_assert(!err);
	flags = mask & get_interface_flags("lo");
	g_assert(!(flags & IFF_NOMULTIPATH));
	g_assert(!(flags & IFF_MPBACKUP));

	/*
	 * TODO: save and restore the original state of the  multipath
	 * related flags.
	 */
}

static int get_dev_ipv6_ll_addr(const char *dev, char *addr_str)
{
	struct ifaddrs *ifaddr, *ifa;
	int ret = -1;

	g_assert(getifaddrs(&ifaddr) != -1);

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		struct sockaddr_in6 *addr;

		if (strcmp(ifa->ifa_name, dev) != 0)
			continue;

		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;

		addr = (struct sockaddr_in6 *) ifa->ifa_addr;
		if (!inet_ntop(AF_INET6, &addr->sin6_addr,
				addr_str, INET6_ADDRSTRLEN))
			continue;

		/* found it */
		ret = 0;
		break;
	}

	freeifaddrs(ifaddr);

	return ret;

}

static bool find_rule(unsigned int table_id, const char *src_ip)
{
	struct route_data r = {0};
	r.table_id = table_id;
	r.src = src_ip;
	r.cmd = RTM_GETRULE;
	r.family = connman_inet_check_ipaddress(src_ip);

	return rtm_get(&r);
}

static bool find_rule_fwmark_src(unsigned int table_id, unsigned fwmark,
					const char *src_ip)
{
	struct route_data r = {0};
	r.table_id = table_id;
	r.fwmark = fwmark;
	r.src = src_ip;
	r.cmd = RTM_GETRULE;
	r.family = connman_inet_check_ipaddress(src_ip);

	return rtm_get(&r);
}

static bool find_route(unsigned int table_id, const char *dst_ip,
			int prefix_len, int ifindex)
{
	struct route_data r = {0};
	r.table_id = table_id;
	r.dst = dst_ip;
	r.dst_preflen = prefix_len;
	r.family = connman_inet_check_ipaddress(dst_ip);
	r.ifindex = ifindex;
	r.cmd = RTM_GETROUTE;

	return rtm_get(&r);
}

static bool find_default_route(unsigned int table_id, const char *gw_ip,
				int ifindex)
{
	struct route_data r = {0};
	r.table_id = table_id;
	r.gw = gw_ip;
	r.family = connman_inet_check_ipaddress(gw_ip);
	r.ifindex = ifindex;
	r.cmd = RTM_GETROUTE;

	return rtm_get(&r);
}

static void test_multipath_config_ipv4(void)
{
	int cfg, clear;
	bool rule_ok, route_ok, route_default_ok;

	int ifidx = if_nametoindex("dummy0");
	g_assert(ifidx > 0);

	cfg = __connman_multipath_configure(ifidx, 44,
				"1.1.1.2", "1.1.1.2", 24);

	rule_ok = find_rule(44, "1.1.1.2");
	route_ok = find_route(44, "1.1.1.2", 24, ifidx);
	route_default_ok = find_default_route(44, "1.1.1.2", ifidx);

	clear = __connman_multipath_clean(ifidx, 44,
				"1.1.1.2", "1.1.1.2", 24);

	/* check at end to do config and clear together */
	g_assert(cfg == 0);
	g_assert_true(rule_ok);
	g_assert_true(route_ok);
	g_assert_true(route_default_ok);
	g_assert(clear == 0);
}

static void test_multipath_config_ipv6(void)
{
	int cfg, clear;
	bool rule_ok, route_ok, route_default_ok;

	int ifidx = if_nametoindex("dummy0");
	char ll_addr[INET6_ADDRSTRLEN + 1];

	g_assert(ifidx > 0);
	g_assert(get_dev_ipv6_ll_addr("dummy0", ll_addr) == 0);

	cfg = __connman_multipath_configure(ifidx, 66, ll_addr, ll_addr, 64);

	rule_ok = find_rule(66, ll_addr);
	route_ok = find_route(66, "fe80::", 64, ifidx);
	route_default_ok = find_default_route(66, ll_addr, ifidx);

	clear = __connman_multipath_clean(ifidx, 66, ll_addr, ll_addr, 64);

	/* check at end to do config and clear together */
	g_assert(cfg == 0);
	g_assert_true(rule_ok);
	g_assert_true(route_ok);
	g_assert_true(route_default_ok);
	g_assert(clear == 0);
}

static void test_inet_fwmark_ipv4(void)
{
	int ifidx = if_nametoindex("dummy0");
	g_assert(ifidx > 0);

	__connman_inet_add_src_fwmark_rule(100, AF_INET, 567, "1.1.1.2");
	g_assert_true(find_rule_fwmark_src(100, 567, "1.1.1.2"));

	__connman_inet_del_src_fwmark_rule(100, AF_INET, 567, "1.1.1.2");
	g_assert_false(find_rule_fwmark_src(100, 567, "1.1.1.2"));
}

static void test_inet_fwmark_ipv6(void)
{
	int ifidx = if_nametoindex("dummy0");
	char ll_addr[INET6_ADDRSTRLEN + 1];

	g_assert(ifidx > 0);
	g_assert(get_dev_ipv6_ll_addr("dummy0", ll_addr) == 0);

	__connman_inet_add_src_fwmark_rule(200, AF_INET6, 222, "2001::1");
	g_assert_true(find_rule_fwmark_src(200, 222, "2001::1"));

	__connman_inet_del_src_fwmark_rule(200, AF_INET6, 222, "2001::1");
	g_assert_false(find_rule_fwmark_src(200, 222, "2001::1"));
}

static void test_setup()
{
	if (system("modprobe dummy"))
		connman_warn("test_setup: can't load dummy module");
	if (system("ip link set dummy0 up"))
		connman_warn("test_setup: bring dummy0 up");
	if (system("ip addr add 1.1.1.2 dev dummy0"))
		connman_warn("test_setup: can't set ip in dummy0");
}

static int test_teardown()
{
	return system("modprobe -r dummy");
}

int main(int argc, char *argv[])
{
	int ret;

	g_test_init(&argc, &argv, NULL);

#ifdef DEBUG
	__connman_log_init(argv[0], "*", false, false,
			"Unit Tests Multipath", VERSION);
#endif

	g_test_add_func("/multipath/test_state", test_state_transition);

	test_setup();
	g_test_add_func("/multipath/test_multipath_config_ipv4",
		test_multipath_config_ipv4);
	g_test_add_func("/multipath/test_multipath_config_ipv6",
		test_multipath_config_ipv6);
	g_test_add_func("/multipath/test_inet_fwmark_ipv4",
		test_inet_fwmark_ipv4);
	g_test_add_func("/multipath/test_inet_fwmark_ipv6",
		test_inet_fwmark_ipv6);

	ret = g_test_run();

	test_teardown();

	return ret;
}
