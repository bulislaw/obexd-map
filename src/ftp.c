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

#include <glib.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "logging.h"
#include "obex.h"
#include "logging.h"

void ftp_get(obex_t *obex, obex_object_t *obj)
{
	obex_headerdata_t hv;
	struct obex_session *os;
	gchar *path = NULL;
	gint fd = -1;
	struct stat stats;
	guint32 size;

	os = OBEX_GetUserData(obex);
	if (os == NULL)
		return;

	debug("%s - name: %s type: %s path: %s", __func__, os->name, os->type,
						os->current_path);

	if (os->current_path == NULL)
		goto fail;

	if (os->name) {
		path = g_build_filename(os->current_path, os->name, NULL);
	}

	if (path == NULL) {
		goto fail;
	}


	fd = open(path, O_RDONLY);
	if (fd < 0) {
		goto fail;
	}

	if (fstat(fd, &stats)) {
		goto fail;
	}

	size = stats.st_size;
	hv.bq4 = size;
	OBEX_ObjectAddHeader(obex, obj, OBEX_HDR_LENGTH, hv, 4, 0);
	os->stream_fd = fd;

	/* Add body header */
	hv.bs = NULL;
	OBEX_ObjectAddHeader (obex, obj, OBEX_HDR_BODY,
			hv, 0, OBEX_FL_STREAM_START);
	OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE,
			OBEX_RSP_SUCCESS);
	return;

fail:
	g_free(path);
	close(fd);
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
	obex_headerdata_t hd;
	guint32 hlen;
	guint8 hi;
	guint8 *nohdr;
	char *name = NULL;
	char *fullname = NULL;

	os = OBEX_GetUserData(obex);

	OBEX_ObjectGetNonHdrData(obj, &nohdr);
	if (!nohdr) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE,
				OBEX_RSP_PRECONDITION_FAILED);
		error("Set path failed: flag not found!");
		return;
	}

	while (OBEX_ObjectGetNextHeader(obex, obj, &hi, &hd, &hlen)) {
		if (hi == OBEX_HDR_NAME) {
			name = (char *) g_malloc0(hlen/2 + 1);
			OBEX_UnicodeToChar((uint8_t *)name, hd.bs, hlen/2);
			debug("Set path name: %s", name);
			break;
		}
	}

	//Check flag "Backup"
	if ((nohdr[0] & 0x01) == 0x01) {
		debug("Set to parent path");

		if (strcmp(ROOT_PATH, os->current_path) == 0) {
			OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
			goto done;
		}

		os->current_path = g_path_get_dirname(os->current_path);
		debug("Set to parent path: %s", os->current_path);
		OBEX_ObjectSetRsp (obj, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
		goto done;
	}

	if (!name) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_CONTINUE, OBEX_RSP_BAD_REQUEST);
		error("Set path failed: name missing!");
		goto done;
	}

	if (strlen(name) == 0) {
		debug("Set to root");
		os->current_path = g_strdup(ROOT_PATH);

		OBEX_ObjectSetRsp(obj, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
		goto done;
	}

	//Check and set to name path
	if (strstr(name, "/../")) {
		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
		error("Set path failed: name incorrect!");
		goto done;
	}

	fullname = g_build_filename(os->current_path, name, NULL);
	debug("Fullname: %s", fullname);

	if (g_file_test(fullname, G_FILE_TEST_IS_DIR)) {
		os->current_path = g_strdup(fullname);

		OBEX_ObjectSetRsp(obj, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
		goto done;
	}

	if (!g_file_test(fullname, G_FILE_TEST_EXISTS) && nohdr[0] == 0 &&
					mkdir(fullname, 0775) >=  0) {
		os->current_path = g_strdup(fullname);
		OBEX_ObjectSetRsp(obj, OBEX_RSP_SUCCESS, OBEX_RSP_SUCCESS);
		goto done;

	}

		OBEX_ObjectSetRsp(obj, OBEX_RSP_FORBIDDEN, OBEX_RSP_FORBIDDEN);
done:
	g_free(name);
	g_free(fullname);
}
