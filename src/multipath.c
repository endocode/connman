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

#include <stdbool.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include "connman.h"

/*
 * Set state for interface *index* to on/off and alternatively backup.
 */
void __connman_multipath_set(int index, enum connman_multipath_state state)
{
	struct __connman_inet_rtnl_handle rth;
	struct ifinfomsg *ifl;
	int ret;

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
		return;

	ret = __connman_inet_rtnl_open(&rth);
	if (ret < 0) {
		connman_warn("can't set multipath flags, err=%d", ret);
		goto done;
	}

	ret = __connman_inet_rtnl_send(&rth, &rth.req.n);

done:
	__connman_inet_rtnl_close(&rth);
}
