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

#include <glib.h>

#define OBEX_OPUSH	0x00
#define OBEX_FTP	0x01

struct obex_commands {
	void (*get) (obex_t *obex, obex_object_t *obj);
	void (*put) (obex_t *obex, obex_object_t *obj);
	void (*setpath) (obex_t *obex, obex_object_t *obj);
};

struct server {
	guint16		service;
	gboolean	auto_accept;
	gchar		*folder;
};

struct obex_session {
	guint32		cid;
	guint16		mtu;
	gchar		*name;
	gchar		*type;
	gchar		*current_folder;
	guint8		*buf;
	gchar		*temp;
	gint32		offset;
	gint32		size;
	gint		fd;
	const guint8	*target;
	struct obex_commands *cmds;
	struct server *server;
};

gint obex_server_start(gint fd, gint mtu, struct server *server);
gint obex_server_stop();

void opp_connect(obex_t *obex, obex_object_t *obj);
void opp_put(obex_t *obex, obex_object_t *obj);
void opp_get(obex_t *obex, obex_object_t *obj);

void ftp_connect(obex_t *obex, obex_object_t *obj);
void ftp_get(obex_t *obex, obex_object_t *obj);
void ftp_put(obex_t *obex, obex_object_t *obj);
void ftp_setpath(obex_t *obex, obex_object_t *obj);

gint os_setup_by_name(struct obex_session *os, gchar *file);
