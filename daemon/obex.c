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

#include "obex.h"

#define TARGET_SIZE	16
#define FTP_TARGET	"\xF9\xEC\x7B\xC4\x95\x3C\x11\xD2\x98\x4E\x52\x54\x00\xDC\x9E\x09"

/* Connection ID */
static guint32 cid = 0x0000;

typedef struct {
    guint8	version;
    guint8	flags;
    guint16	mtu;
} __attribute__ ((packed)) obex_connect_hdr_t;

struct obex_handlers {
	guint8 *target;
	void (*get) (obex_t *obex, obex_object_t *obj);
	void (*put) (obex_t *obex, obex_object_t *obj);
	void (*setpath) (obex_t *obex, obex_object_t *obj);
};

struct obex_handlers opp = {
	.target		= NULL,
	.get		= NULL,
	.put		= opp_put,
	.setpath	= NULL,
};

struct obex_handlers ftp = {
	.target		= FTP_TARGET,
	.get		= ftp_get,
	.put		= ftp_put,
	.setpath	= ftp_setpath,
};

static void cmd_connect(obex_t *obex, obex_object_t *obj, guint8 *target)
{
	obex_connect_hdr_t *nonhdr;
	obex_headerdata_t hd;
	const guint8 *t;
	guint ts, hlen, newsize;
	guint16 mtu;
	guint8 hi;

	/* FIXME: Reject if NonHdrData is invalid? */
	if (OBEX_ObjectGetNonHdrData(obj, (guint8 **) &nonhdr) != sizeof(*nonhdr)) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		debug("Invalid OBEX CONNECT packet");
		return;
	}

	mtu = g_ntohs(nonhdr->mtu);
	debug("Version: 0x%02x. Flags: 0x%02x  OBEX packet length: %d",
			nonhdr->version, nonhdr->flags, mtu);
	/* Leave space for headers */
	newsize = mtu - 200;
	debug("Resizing stream chunks to %d", newsize);
	/* FIXME: Use the new size */

	if (!target) {
		/* OPP doesn't contains target */
		OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);
		return;
	}

	while (OBEX_ObjectGetNextHeader(obex, obj, &hi, &hd, &hlen)) {
		if (hi == OBEX_HDR_TARGET) {
			t = hd.bs;
			ts = hlen;
		}
	}

	if ((ts != TARGET_SIZE) || memcmp(target, t, TARGET_SIZE) != 0) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		return;
	}

	/* FIXME: Add non header values */

	hd.bs = target;
	OBEX_ObjectAddHeader(obex, obj,
			OBEX_HDR_WHO, hd, TARGET_SIZE,
			OBEX_FL_FIT_ONE_PACKET);
	hd.bs = NULL;
	hd.bq4 = ++cid;
	OBEX_ObjectAddHeader(obex, obj,
			OBEX_HDR_CONNECTION, hd, 4,
			OBEX_FL_FIT_ONE_PACKET);

	OBEX_ObjectSetRsp (obj, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);
}

static void obex_event(obex_t *obex, obex_object_t *obj, gint mode,
					gint evt, gint cmd, gint rsp)
{
	struct obex_handlers *hl;

	obex_debug(evt, cmd, rsp);

	switch (evt) {
	case OBEX_EV_PROGRESS:
		break;
	case OBEX_EV_ABORT:
		OBEX_ObjectSetRsp(obj, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
		break;
	case OBEX_EV_REQDONE:
		switch (cmd) {
		case OBEX_CMD_DISCONNECT:
			OBEX_TransportDisconnect(obex);
			break;
		case OBEX_CMD_PUT:
		case OBEX_CMD_GET:
			break;
		default:
			break;
		}
		break;
	case OBEX_EV_REQHINT:
		switch (cmd) {
		case OBEX_CMD_PUT:
		case OBEX_CMD_GET:
		case OBEX_CMD_CONNECT:
		case OBEX_CMD_DISCONNECT:
			OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE,
					OBEX_RSP_SUCCESS);
			break;
		default:
			OBEX_ObjectSetRsp(obj, OBEX_RSP_NOT_IMPLEMENTED,
					OBEX_RSP_NOT_IMPLEMENTED);
			break;
		}
		break;
	case OBEX_EV_REQCHECK:
		switch (cmd) {
		case OBEX_CMD_PUT:
			break;
		default:
			break;
		}
		break;
	case OBEX_EV_REQ:
		hl = OBEX_GetUserData(obex);
		switch (cmd) {
		case OBEX_CMD_SETPATH:
		case OBEX_CMD_GET:
		case OBEX_CMD_PUT:
			/* FIXME: Check target */
			break;
		}

		/* FIXME: call handles */
		switch (cmd) {
		case OBEX_CMD_DISCONNECT:
			break;
		case OBEX_CMD_CONNECT:
			cmd_connect(obex, obj, hl->target);
			break;
		case OBEX_CMD_SETPATH:
			if (hl->setpath)
				hl->setpath(obex, obj);
			else
				OBEX_ObjectSetRsp(obj,
					OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
			break;
		case OBEX_CMD_GET:
			if (hl->get)
				hl->get(obex, obj);
			else
				OBEX_ObjectSetRsp(obj,
					OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
			break;
		case OBEX_CMD_PUT:
			if (hl->put)
				hl->put(obex, obj);
			else
				OBEX_ObjectSetRsp(obj,
					OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
			break;
		default:
			debug("Unknown request: 0x%X", cmd);
			OBEX_ObjectSetRsp(obj,
				OBEX_RSP_NOT_IMPLEMENTED, OBEX_RSP_NOT_IMPLEMENTED);
			break;
		}
		break;
	case OBEX_EV_STREAMAVAIL:
		break;
	case OBEX_EV_LINKERR:
		break;
	case OBEX_EV_PARSEERR:
		break;
	case OBEX_EV_UNEXPECTED:
		break;

	default:
		debug("Unknown evt %d", evt);
		break;
	}
}

static void obex_handle_destroy(gpointer user_data)
{
	obex_t *obex = user_data;

	OBEX_Cleanup(obex);
}

static gboolean obex_handle_input(GIOChannel *io, GIOCondition cond, gpointer user_data)
{
	obex_t *obex = user_data;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR))
		return FALSE;


	if (OBEX_HandleInput(obex, 1) < 0) {
		error("Handle input error");
		return FALSE;
	}

	return TRUE;
}

gint obex_server_start(gint fd, gint mtu, guint16 svc)
{
	struct obex_handlers *hl;
	GIOChannel *io;
	obex_t *obex;
	gint ret;

	switch (svc) {
	case OBEX_FTP:
		hl = &ftp;
		break;
	case OBEX_OPUSH:
		hl = &opp;
		break;
	default:
		debug("Invalid OBEX server");
		return -EINVAL;
	}

	obex = OBEX_Init(OBEX_TRANS_FD, obex_event, 0);
	if (!obex)
		return -EIO;

	OBEX_SetUserData(obex, hl);

	ret = FdOBEX_TransportSetup(obex, fd, fd, mtu);
	if (ret < 0) {
		OBEX_Cleanup(obex);
		return ret;
	}

	io = g_io_channel_unix_new(fd);
	g_io_add_watch_full(io, G_PRIORITY_DEFAULT,
			G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			obex_handle_input, obex, obex_handle_destroy);
	g_io_channel_unref(io);

	return 0;
}

gint obex_server_stop()
{
	return 0;
}
