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

struct obex_handlers {
	guint8 target[16];
	void (*connect) (obex_t *obex, obex_object_t *obj);
	void (*disconnect) (obex_t *obex, obex_object_t *obj);
	void (*get) (obex_t *obex, obex_object_t *obj);
	void (*put) (obex_t *obex, obex_object_t *obj);
	void (*setpath) (obex_t *obex, obex_object_t *obj);
};

static void ftp_connect(obex_t *obex, obex_object_t *obj)
{

}

static void ftp_get(obex_t *obex, obex_object_t *obj)
{

}

static void ftp_put(obex_t *obex, obex_object_t *obj)
{

}

static void ftp_setpath(obex_t *obex, obex_object_t *obj)
{

}

static struct obex_handlers opp_handlers = {
	.target		= NULL,
	.connect	= NULL,
	.disconnect	= NULL,
	.get		= NULL,
	.put		= NULL,
	.setpath	= NULL,
};

static struct obex_handlers ftp_handlers = {
	.target		= { 0xF9, 0xEC, 0x7B, 0xC4, 0x95, 0x3C, 0x11, 0xD2, 0x98, 0x4E, 0x52, 0x54, 0x00, 0xDC, 0x9E, 0x09 },
	.connect	= ftp_connect,
	.disconnect	= NULL,
	.get		= ftp_get,
	.put		= ftp_put,
	.setpath	= ftp_setpath,
};

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
			OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);
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
			if (hl->disconnect)
				hl->disconnect(obex, obj);
			break;
		case OBEX_CMD_CONNECT:
			if (hl->connect)
				hl->connect(obex, obj);
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

	obex = OBEX_Init(OBEX_TRANS_FD, obex_event, 0);
	if (!obex)
		return -EIO;

	ret = FdOBEX_TransportSetup(obex, fd, fd, mtu);
	if (ret < 0) {
		OBEX_Cleanup(obex);
		return ret;
	}

	io = g_io_channel_unix_new(fd);
	g_io_add_watch_full(io, G_PRIORITY_DEFAULT,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				obex_handle_input, obex, obex_handle_destroy);
	switch (svc) {
	case OBEX_FTP:
		hl = &ftp_handlers;
		break;
	case OBEX_OPUSH:
		hl = &opp_handlers;
		break;
	}

	OBEX_SetUserData(obex, hl);
	g_io_channel_unref(io);

	return 0;
}

gint obex_server_stop()
{
	return 0;
}
