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

#include <fcntl.h>

#include <glib.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "logging.h"
#include "obex.h"

void ftp_get(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os;
	gchar *path = NULL;
	int fd;

	os = OBEX_GetUserData(obex);
	if (os == NULL)
		return;

	debug("%s - name: %s type: %s path: %s", __func__, os->name, os->type,
						os->current_path);

	if (os->current_path == NULL)
		return;

	if (os->name)
		path = g_build_filename(os->current_path, os->name, NULL);

	if (path == NULL)
		return;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return;

	os->stream_fd = fd;

	OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE,
			OBEX_RSP_SUCCESS);
}

void ftp_put(obex_t *obex, obex_object_t *obj)
{
	OBEX_ObjectSetRsp(obj, OBEX_RSP_NOT_IMPLEMENTED,
			OBEX_RSP_NOT_IMPLEMENTED);
}

void ftp_setpath(obex_t *obex, obex_object_t *obj)
{
	obex_headerdata_t hdr;
	guint32 hlen;
	guint8 hi;
	guint8 *nohdr_data;
	char *name = NULL;

	OBEX_ObjectGetNonHdrData(obj, &nohdr_data);
	if (!nohdr_data) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE,
				OBEX_RSP_PRECONDITION_FAILED);
		error("Set path failed: flag not found!");
		return;
	}

	while (OBEX_ObjectGetNextHeader(obex, obj, &hi, &hdr, &hlen)) {
		if (hi == OBEX_HDR_NAME) {
			name = (char *) g_malloc0(hlen/2 + 1);
			OBEX_UnicodeToChar((uint8_t *)name, hdr.bs, hlen/2);
			debug("Set path name: %s", name);
			break;
		}
	}

	if ((nohdr_data[0] & 0x01) == 0x01) {
		debug("Set to parent path");
		//TODO: Set to patent path

		OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);
		goto done;
	}

	if (!name) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_BAD_REQUEST);
		error("Set path failed: name missing!");
		goto done;
	}

	if (strlen(name) == 0) {
		debug("Set to root");
		//TODO: Set to root

		OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);
		goto done;
	}

	//TODO: Check and set to name path

		OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_SUCCESS);

done:
	free(name);
}
