/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2015  Endocode AG. All rights reserved.
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

#include <errno.h>
#include <stdbool.h>
#include <linux/rtnetlink.h>
#include <linux/fib_rules.h>
#include <net/if.h>

#include <connman/ipaddress.h>

#include "connman.h"


static int rtnl_send(struct __connman_inet_rtnl_handle *rth)
{
	int ret;

	if (!rth)
		return -ENOENT;

	ret = __connman_inet_rtnl_open(rth);
	if (ret < 0) {
		connman_warn("can't open rtnetlink channel");
		goto done;
	}

	ret = __connman_inet_rtnl_send(rth, &rth->req.n);
	if (ret < 0) {
		connman_warn("can't set multipath flags, err=%d", ret);
		goto done;
	}
done:
	__connman_inet_rtnl_close(rth);
	return ret;
}

/*
 * Set state for interface *index* to on/off and alternatively backup.
 */
int __connman_multipath_set(int index, enum connman_multipath_state state)
{
	struct __connman_inet_rtnl_handle rth;
	struct ifinfomsg *ifl;
	int ret = 0;

	memset(&rth, 0, sizeof(rth));

	rth.req.n.nlmsg_type = RTM_SETLINK;
	rth.req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	rth.req.n.nlmsg_flags = NLM_F_REQUEST;

	ifl = &rth.req.u.l.ifl;
	ifl->ifi_family = AF_UNSPEC;
	ifl->ifi_type = 0;
	ifl->ifi_index = index;

	ifl->ifi_change |= (IFF_NOMULTIPATH | IFF_MPBACKUP);
	switch (state) {
	case CONNMAN_MULTIPATH_STATE_ON:
		/* On */
		ifl->ifi_flags &= ~(IFF_NOMULTIPATH | IFF_MPBACKUP);
		break;
	case CONNMAN_MULTIPATH_STATE_BACKUP:
		/* On in backup mode. */
		ifl->ifi_flags &= ~IFF_NOMULTIPATH;
		ifl->ifi_flags |= IFF_MPBACKUP;
		break;
	case CONNMAN_MULTIPATH_STATE_OFF:
		/*
		 * Off. Disable backup too, so that off->on transition
		 * doesn't keep the backup flag.
		 */
		ifl->ifi_flags |= IFF_NOMULTIPATH;
		ifl->ifi_flags &= ~IFF_MPBACKUP;
		break;
	default:
		ifl->ifi_change = 0;
	}

	if (!ifl->ifi_change)
		return ret;

	return rtnl_send(&rth);
}

/*
 * Modify routes or rules for a given interface and table.
 */
static int multipath_table_modify(int cmd, int family, int ifindex,
				unsigned int table_id,
				const char *addr,
				unsigned addr_len,
				unsigned prefix_len)
{
	struct __connman_inet_rtnl_handle rth;

	memset(&rth, 0, sizeof(rth));

	rth.req.n.nlmsg_type = cmd;
	rth.req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	rth.req.n.nlmsg_flags = NLM_F_REQUEST;

	rth.req.u.r.rt.rtm_family = family;
	rth.req.u.r.rt.rtm_protocol = RTPROT_BOOT;
	rth.req.u.r.rt.rtm_scope = RT_SCOPE_UNIVERSE;

	switch (cmd) {
	case RTM_DELROUTE:
	case RTM_NEWROUTE:
		rth.req.n.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
		rth.req.u.r.rt.rtm_type = RTN_UNICAST;
		rth.req.u.r.rt.rtm_scope = RT_SCOPE_LINK;

		__connman_inet_rtnl_addattr32(&rth.req.n, sizeof(rth.req),
					      RTA_OIF, ifindex);

		__connman_inet_rtnl_addattr_l(&rth.req.n, sizeof(rth.req),
						RTA_DST, addr, addr_len);
		rth.req.u.r.rt.rtm_dst_len = prefix_len;

		break;
	case RTM_NEWRULE:
	case RTM_DELRULE:
		__connman_inet_rtnl_addattr_l(&rth.req.n, sizeof(rth.req),
						FRA_SRC, addr, addr_len);

		rth.req.u.r.rt.rtm_src_len = addr_len * 8;
		rth.req.n.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
		rth.req.u.r.rt.rtm_type = RTN_UNICAST;
		break;
	default:
		return -EINVAL;
	}

	if (table_id < 256) {
		rth.req.u.r.rt.rtm_table = table_id;
	} else {
		rth.req.u.r.rt.rtm_table = RT_TABLE_UNSPEC;
		__connman_inet_rtnl_addattr32(&rth.req.n, sizeof(rth.req),
						FRA_TABLE, table_id);
	}


	return rtnl_send(&rth);
}


/* str addr -> generic network order bytes */
static int host2addr(int family, const char *host_str, char *addr_dst)
{
	unsigned addr_len;

	switch (family) {
	case AF_UNSPEC:
		family = AF_INET;
	case AF_INET:
		addr_len = 4;
		break;
	case AF_INET6:
		addr_len = 16;
		break;
	default:
		return -EINVAL;
	}

	/* Set source IP. */
	if (inet_pton(family, host_str, addr_dst) <= 0)
		return -EINVAL;

	return addr_len;
}

/*
 * Turn a given addr into a network based on prefix len: A.B.C.D/24 -> A.B.C.0.
 */
static int prefix2net(int family, const char *addr, int prefix_len, char *net)
{
	switch (family) {
	case AF_UNSPEC:
	case AF_INET: {
		struct in_addr *addr_tmp = (struct in_addr *) addr;
		struct in_addr *net_tmp = (struct in_addr *) net;

		/* turn non-prefix bits off */
		net_tmp->s_addr = htonl(~((1 << (32 - prefix_len)) - 1));
		net_tmp->s_addr &= addr_tmp->s_addr;

		return 0;
	}
	case AF_INET6: {
		/* ipv6 works well with */
		memcpy(net, addr, sizeof(struct in6_addr));
		return 0;
	}
	default:
		return -EINVAL;
	}
}

enum multipath_cmd {
	MPATH_CONFIG = 0,
	MPATH_CLEAR
};

static int multipath_modify(enum multipath_cmd cmd,
				int ifindex,
				unsigned int table_id,
				const char *host,
				const char *gateway,
				int prefix_len)

{
	int family = connman_inet_check_ipaddress(host);
	int addr_len;
	char addr[sizeof(struct in6_addr)];
	char addr_net[sizeof(struct in6_addr)];

	char *verb = cmd == MPATH_CONFIG ? "add" : "del";
	int rule_cmd = cmd == MPATH_CONFIG ? RTM_NEWRULE : RTM_DELRULE;
	int route_cmd = cmd == MPATH_CONFIG ? RTM_NEWROUTE : RTM_DELROUTE;

	int ret;

	addr_len = host2addr(family, host, addr);
	if (addr_len < 0) {
		connman_error("bad specified ip %s", host);
		return -EINVAL;
	}

	if (prefix2net(family, addr, prefix_len, addr_net) < 0) {
		connman_error("can't compute net from %s/%d", host, prefix_len);
		return -EINVAL;
	}

	/* ip rule ADD|DEL from ADDR table TBL_ID */
	ret = multipath_table_modify(rule_cmd,
					family, ifindex, table_id,
					addr, addr_len, 0);
	if (ret < 0) {
		connman_warn("multipath: can't %s rule for if %d table %d",
				verb, ifindex, table_id);
		return -EINVAL;
	}

	/* ip route ADD|DEL NET/PREFIX dev IFIDX scope link table TBL_ID */
	ret = multipath_table_modify(route_cmd,
					family, ifindex, table_id,
					addr_net, addr_len, prefix_len);
	if (ret < 0) {
		connman_warn("multipath: can't %s route for if %d table %d",
				verb, ifindex, table_id);
		return -EINVAL;
	}

	if (!gateway)
		return 0;

	/* ip route ADD|DEL default via GW dev IFIDX table TBL_ID */
	if (cmd == MPATH_CONFIG)
		ret = __connman_inet_add_default_to_table(
			table_id, ifindex, gateway);
	else
		ret = __connman_inet_del_default_from_table(
			table_id, ifindex, gateway);

	if (ret < 0) {
		connman_warn("multipath: can't %s default route for if %d table %d",
				verb, ifindex, table_id);
		return -EINVAL;
	}

	return 0;
}

int __connman_multipath_configure(int ifindex,
					unsigned int table_id,
					const char *host,
					const char *gateway,
					int prefix_len)
{
	return multipath_modify(MPATH_CONFIG,
				ifindex, table_id,
				host, gateway, prefix_len);
}

int __connman_multipath_clean(int ifindex,
				unsigned int table_id,
				const char *host,
				const char *gateway,
				int prefix_len)

{
	return multipath_modify(MPATH_CLEAR,
				ifindex, table_id,
				host, gateway, prefix_len);
}
