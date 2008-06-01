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
static const guint8 FTP_TARGET[TARGET_SIZE] = { 0xF9, 0xEC, 0x7B, 0xC4,
					0x95, 0x3C, 0x11, 0xD2,
					0x98, 0x4E, 0x52, 0x54,
					0x00, 0xDC, 0x9E, 0x09 };

/* Connection ID */
static guint32 cid = 0x0000;

typedef struct {
    guint8	version;
    guint8	flags;
    guint16	mtu;
} __attribute__ ((packed)) obex_connect_hdr_t;

static void cmd_not_implemented(obex_t *obex, obex_object_t *obj)
{
	OBEX_ObjectSetRsp(obj, OBEX_RSP_NOT_IMPLEMENTED,
			OBEX_RSP_NOT_IMPLEMENTED);
}

struct obex_commands {
	void (*get) (obex_t *obex, obex_object_t *obj);
	void (*put) (obex_t *obex, obex_object_t *obj);
	void (*setpath) (obex_t *obex, obex_object_t *obj);
};

struct obex_commands opp = {
	.get		= cmd_not_implemented,
	.put		= opp_put,
	.setpath	= cmd_not_implemented,
};

struct obex_commands ftp = {
	.get		= ftp_get,
	.put		= ftp_put,
	.setpath	= ftp_setpath,
};

struct obex_session {
	guint32		cid;
	guint16		mtu;
	const guint8	*target;
	struct obex_commands *cmds;
};

static void cmd_connect(struct obex_session *os,
			obex_t *obex, obex_object_t *obj)
{
	obex_connect_hdr_t *nonhdr;
	obex_headerdata_t hd;
	const guint8 *target;
	guint targetsize, hlen, newsize;
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

	if (os->target == NULL) {
		/* OPP doesn't contains target */
		OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);
		return;
	}

	hi = targetsize = 0;
	while (OBEX_ObjectGetNextHeader(obex, obj, &hi, &hd, &hlen)) {
		target = hd.bs;
		targetsize = hlen;
	}

	if (hi != OBEX_HDR_TARGET || targetsize != TARGET_SIZE
			|| memcmp(os->target, target, TARGET_SIZE) != 0) {
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

	os->cid = cid;
}

static gboolean chk_cid(obex_t *obex, obex_object_t *obj, guint32 cid)
{
	obex_headerdata_t hd;
	guint hlen;
	guint8 hi;
	gboolean ret = FALSE;

	while (OBEX_ObjectGetNextHeader(obex, obj, &hi, &hd, &hlen)) {
		if (hi == OBEX_HDR_CONNECTION && hlen == 4) {
			ret = (hd.bq4 == cid ? TRUE : FALSE);
			break;
		}
	}

	if (ret == FALSE)
		OBEX_ObjectSetRsp(obj, OBEX_RSP_SERVICE_UNAVAILABLE,
				OBEX_RSP_SERVICE_UNAVAILABLE);
	else
		OBEX_ObjectReParseHeaders(obex, obj);

	return ret;
}

static void cmd_get(struct obex_session *os, obex_t *obex, obex_object_t *obj)
{
	g_return_if_fail(chk_cid(obex, obj, os->cid));

	os->cmds->get(obex, obj);
}

static void cmd_put(struct obex_session *os, obex_t *obex, obex_object_t *obj)
{
	g_return_if_fail(chk_cid(obex, obj, os->cid));

	os->cmds->put(obex, obj);
}

static void cmd_setpath(struct obex_session *os,
			obex_t *obex, obex_object_t *obj)
{
	g_return_if_fail(chk_cid(obex, obj, os->cid));

	os->cmds->setpath(obex, obj);
}

static void obex_event(obex_t *obex, obex_object_t *obj, gint mode,
					gint evt, gint cmd, gint rsp)
{
	struct obex_session *os;
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
		os = OBEX_GetUserData(obex);
		switch (cmd) {
		case OBEX_CMD_DISCONNECT:
			break;
		case OBEX_CMD_CONNECT:
			cmd_connect(os, obex, obj);
			break;
		case OBEX_CMD_SETPATH:
			cmd_setpath(os, obex, obj);
			break;
		case OBEX_CMD_GET:
			cmd_get(os, obex, obj);
			break;
		case OBEX_CMD_PUT:
			cmd_put(os, obex, obj);
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
	struct obex_session *os;
	obex_t *obex = user_data;

	os = OBEX_GetUserData(obex);
	g_free(os);

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
	struct obex_session *os;
	GIOChannel *io;
	obex_t *obex;
	gint ret;

	os = g_new0(struct obex_session, 1);
	switch (svc) {
	case OBEX_OPUSH:
		os->target = NULL;
		os->cmds = &opp;
		break;
	case OBEX_FTP:
		os->target = FTP_TARGET;
		os->cmds = &ftp;
		break;
	default:
		g_free(os);
		debug("Invalid OBEX server");
		return -EINVAL;
	}

	obex = OBEX_Init(OBEX_TRANS_FD, obex_event, 0);
	if (!obex)
		return -EIO;

	OBEX_SetUserData(obex, os);

	ret = FdOBEX_TransportSetup(obex, fd, fd, mtu);
	if (ret < 0) {
		g_free(os);
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
