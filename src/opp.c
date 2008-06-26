/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2008  Nokia Corporation
 *  Copyright (C) 2007-2008  Instituto Nokia de Tecnologia (INdT)
 *  Copyright (C) 2007-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include <glib.h>

#include "logging.h"
#include "dbus.h"
#include "obex.h"

#define VCARD_TYPE "text/x-vcard"
#define VCARD_FILE CONFIGDIR "/vcard.vcf"

gint opp_chkput(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os;
	gchar *new_folder, *new_name, *path;
	gint32 time;
	gint ret;

	os = OBEX_GetUserData(obex);
	if (os == NULL)
		return -EINVAL;

	if (!os->size)
		return -EINVAL;

	if (os->server->auto_accept)
		goto skip_auth;

	time = 0;
	ret = request_authorization(os->cid, OBEX_GetFD(obex), os->name,
				os->type, os->size, time, &new_folder, &new_name);

	if (ret < 0)
		return -EPERM;

	if (new_folder) {
		g_free(os->current_folder);
		os->current_folder = new_folder;
	}

	if (new_name) {
		g_free(os->name);
		os->name = new_name;
	}

skip_auth:
	path = g_build_filename(os->current_folder, os->name, NULL);

	os->fd = open(path, O_WRONLY | O_CREAT, 0600);
	if (os->fd < 0) {
		error("open(%s): %s (%d)", path, strerror(errno), errno);
		g_free(path);
		return -EPERM;
	}

	g_free(path);

	emit_transfer_started(os->cid);

	return 0;
}

void opp_put(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os;

	os = OBEX_GetUserData(obex);
	if (os == NULL)
		return;

	if (os->current_folder == NULL) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		return;
	}

	if (os->name == NULL) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_BAD_REQUEST);
		return;
	}

	OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);
}

void opp_get(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os;
	obex_headerdata_t hv;
	gint size;

	os = OBEX_GetUserData(obex);
	if (os == NULL)
		return;

	if (os->name)
		goto fail;

	if (os->type == NULL)
		goto fail;

	if (!strcmp(os->type, VCARD_TYPE)) {
		size = os_setup_by_name(os, VCARD_FILE);
		if (!size)
			goto fail;
	} else
		goto fail;


	hv.bq4 = size;
	OBEX_ObjectAddHeader(obex, obj, OBEX_HDR_LENGTH, hv, 4, 0);

	/* Add body header */
	hv.bs = NULL;
	OBEX_ObjectAddHeader (obex, obj, OBEX_HDR_BODY,
				hv, 0, OBEX_FL_STREAM_START);
	OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);

	return;

fail:
	OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);

	return;
}
