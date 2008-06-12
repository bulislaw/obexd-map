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
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <glib.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "logging.h"
#include "obex.h"
#include "logging.h"

#define LST_TYPE "x-obex/folder-listing"
#define CAP_TYPE "x-obex/capability"

#define CAP_FILE CONFIGDIR "/capability.xml"

static gint get_by_type(struct obex_session *os, gchar *type)
{
	gint size = 0;

	if (!strcmp(type, CAP_TYPE)) {
		size = os_setup_by_name(os, CAP_FILE);
		if (!size)
			goto fail;
	} else
		goto fail;

	return size;

fail:
	return 0;
}

void ftp_get(obex_t *obex, obex_object_t *obj)
{
	obex_headerdata_t hv;
	struct obex_session *os;
	guint32 size;

	os = OBEX_GetUserData(obex);
	if (os == NULL)
		return;

	if (os->current_path == NULL)
		goto fail;

	if (os->name) {
		gchar *path = g_build_filename(os->current_path,
						os->name, NULL);
		size = os_setup_by_name(os, path);
		g_free(path);

		if (!size)
			goto fail;
	} else if (os->type) {
		size = get_by_type(os, os->type);
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
	OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE,
			OBEX_RSP_SUCCESS);

	return;

fail:
	OBEX_ObjectSetRsp (obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);

	return;
}

void ftp_put(obex_t *obex, obex_object_t *obj)
{
	OBEX_ObjectSetRsp(obj, OBEX_RSP_NOT_IMPLEMENTED,
			OBEX_RSP_NOT_IMPLEMENTED);
}

void ftp_setpath(obex_t *obex, obex_object_t *obj)
{
	struct obex_session *os;
	guint8 *nohdr;
	gchar *fullname;

	os = OBEX_GetUserData(obex);

	OBEX_ObjectGetNonHdrData(obj, &nohdr);
	if (!nohdr) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE,
				OBEX_RSP_PRECONDITION_FAILED);
		error("Set path failed: flag not found!");
		return;
	}
	/* Check flag "Backup" */
	if ((nohdr[0] & 0x01) == 0x01) {
		debug("Set to parent path");

		if (strcmp(ROOT_PATH, os->current_path) == 0) {
			OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
			goto done;
		}

		fullname = g_path_get_dirname(os->current_path);
		g_free(os->current_path);
		os->current_path = g_strdup(fullname);

		debug("Set to parent path: %s", os->current_path);
		OBEX_ObjectSetRsp (obj, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
		goto done;
	}

	if (!os->name) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_BAD_REQUEST);
		debug("Set path failed: name missing!");
		goto done;
	}

	if (strlen(os->name) == 0) {
		debug("Set to root");
		g_free(os->current_path);
		os->current_path = g_strdup(ROOT_PATH);

		OBEX_ObjectSetRsp(obj, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
		goto done;
	}

	/* Check and set to name path */
	if (strstr(os->name, "/../")) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		error("Set path failed: name incorrect!");
		goto done;
	}

	fullname = g_build_filename(os->current_path, os->name, NULL);
	debug("Fullname: %s", fullname);

	if (g_file_test(fullname, G_FILE_TEST_IS_DIR)) {
		g_free(os->current_path);
		os->current_path = g_strdup(fullname);

		OBEX_ObjectSetRsp(obj, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
		goto done;
	}

	if (!g_file_test(fullname, G_FILE_TEST_EXISTS) && nohdr[0] == 0 &&
				mkdir(fullname, 0775) >=  0) {
		g_free(os->current_path);
		os->current_path = g_strdup(fullname);
		OBEX_ObjectSetRsp(obj, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
		goto done;

	}

	OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
done:
	g_free(fullname);
}
