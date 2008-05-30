/*
 *
 *  obexd - OBEX Daemon
 *
 *  Copyright (C) 2008  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2008  Nokia Corporation
 *  Copyright (C) 2008  INdT - Instituto Nokia de Tecnologia
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#include <glib.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

static void obex_event(obex_t *obex, obex_object_t *obj, int mode,
		int event, int obex_cmd, int obex_rsp)
{
	debug("obex: mode=%d, event=%d, obex_cmd=%d, obex_rsp=%d",
			mode, event, obex_cmd, obex_rsp);
}

int obex_server_start(int fd, int mtu)
{
	obex_t *obex;
	int ret;

	obex = OBEX_Init(OBEX_TRANS_FD, obex_event, 0);
	if (!obex)
		return -EIO;

	ret = FdOBEX_TransportSetup(obex, fd, fd, mtu);
	if (ret < 0) {
		OBEX_Cleanup(obex);
		return ret;
	}

	return 0;
}

int obex_server_stop()
{
	return 0;
}
