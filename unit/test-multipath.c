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

#include <sys/types.h>
#include <ifaddrs.h>

#include <glib.h>

#include "../src/connman.h"

/* #define DEBUG */
#ifdef DEBUG
#include <stdio.h>

#define LOG(fmt, arg...) do { \
	fprintf(stdout, "%s:%s() " fmt "\n", \
			__FILE__, __func__ , ## arg); \
} while (0)
#else
#define LOG(fmt, arg...)
#endif

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

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/multipath/test_state", test_state_transition);

	return g_test_run();
}
