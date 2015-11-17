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

#ifndef __CONNMAN_MULTIPATH_H
#define __CONNMAN_MULTIPATH_H

enum connman_multipath_state {
	CONNMAN_MULTIPATH_STATE_OFF	= 0,
	CONNMAN_MULTIPATH_STATE_ON	= 1,
	CONNMAN_MULTIPATH_STATE_BACKUP	= 2,
	CONNMAN_MULTIPATH_STATE_UNKNOWN	= 3,
};

/*
 * TODO:
 * These flags are not included in the libc or kernel headers.
 * We should find another resolution for them.
 */
#define IFF_NOMULTIPATH 0x80000         /* Disable for MPTCP            */
#define IFF_MPBACKUP    0x100000        /* Use as backup path for MPTCP */


#endif
