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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/rfcomm.h>

#include <glib.h>
#include <dbus/dbus.h>

#include <gdbus.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "logging.h"
#include "obex.h"

/* FIXME: */
#define CONFIG_FILE	"./obex.conf"

/* FIXME: */
#define ftp_record "<?xml version=\"1.0\" encoding=\"UTF-8\" ?> \
<record> \
	<attribute id=\"0x0000\"> \
		<uint32 value=\"0x0001000c\"/> \
	</attribute> \
	<attribute id=\"0x0001\"> \
		<sequence> \
			<uuid value=\"0x1106\"/> \
		</sequence> \
	</attribute> \
	<attribute id=\"0x0002\"> \
		<uint32 value="0x00000006"/> \
	</attribute> \
	<attribute id=\"0x0004\"> \
		<sequence> \
			<sequence> \
				<uuid value=\"0x0100\"/> \
			</sequence> \
			<sequence> \
				<uuid value=\"0x0003\"/> \
				<uint8 value=\"0x0b\"/> \
			</sequence> \
			<sequence> \
				<uuid value=\"0x0008\"/> \
			</sequence> \
		</sequence> \
	</attribute> \
	<attribute id=\"0x0005\"> \
		<sequence> \
			<uuid value=\"0x1002\"/> \
		</sequence> \
	</attribute> \
	<attribute id=\"0x0006\"> \
		<sequence> \
			<uint16 value=\"0x454e\"/> \
			<uint16 value="0x006a" /> \
			<uint16 value="0x0100" /> \
		</sequence> \
	</attribute> \
	<attribute id=\"0x0009\"> \
		<sequence> \
			<sequence> \
				<uuid value=\"0x1106\"/> \
				<uint16 value=\"0x0100\"/> \
			</sequence> \
		</sequence> \
	</attribute> \
	<attribute id=\"0x0100\"> \
		<text value=\"OBEX File Transfer\"/> \
	</attribute> \
</record>\
"

struct server {
	guint8		channel;
	guint16		service;
	guint32		record;
	gboolean	auto_accept;
	gchar		*folder;
	gchar		*uuid;
};

static GSList *servers = NULL;
static DBusConnection *conn = NULL;

static uint32_t register_service_record(const char *xml)
{
	return 0;
}

static gboolean connect_event(GIOChannel *io, GIOCondition cond, gpointer user_data)
{
	struct sockaddr_rc raddr;
	socklen_t alen;
	guint16 *svc = user_data;
	gchar address[18];
	gint err, sk, nsk;

	sk = g_io_channel_unix_get_fd(io);
	alen = sizeof(raddr);
	nsk = accept(sk, (struct sockaddr *) &raddr, &alen);
	if (nsk < 0)
		return TRUE;

	alen = sizeof(raddr);
	if (getpeername(nsk, (struct sockaddr *)&raddr, &alen) < 0) {
		err = errno;
		error("getpeername(): %s(%d)", strerror(err), err);
		close(nsk);
		return TRUE;
	}

	ba2str(&raddr.rc_bdaddr, address);
	info("New connection from: %s channel: %d", address, raddr.rc_channel);

	if (obex_server_start(nsk, 0, *svc) < 0)
		close(nsk);

	return TRUE;
}

static void server_destroyed(gpointer user_data)
{
	guint16 *svc = user_data;

	error("Server destroyed");

	g_free(svc);
}

static gint server_register(const gchar *name, guint16 service,
		guint8 channel, const gchar *folder, gboolean auto_accept)
{
	struct sockaddr_rc laddr;
	GIOChannel *io;
	gint err, sk, arg;
	guint16 *svc;
	const gchar *bda_str = "00:12:5A:0F:D8:BB";

	/* FIXME: Add the service record */

	sk = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0) {
		err = errno;
		error("socket(): %s(%d)", strerror(err), err);
		return -err;
	}

	arg = fcntl(sk, F_GETFL);
	if (arg < 0) {
		err = errno;
		goto failed;
	}

	arg |= O_NONBLOCK;
	if (fcntl(sk, F_SETFL, arg) < 0) {
		err = errno;
		goto failed;
	}

	memset(&laddr, 0, sizeof(laddr));
	laddr.rc_family = AF_BLUETOOTH;
	str2ba(bda_str, &laddr.rc_bdaddr);
	laddr.rc_channel = channel;

	if (bind(sk, (struct sockaddr *) &laddr, sizeof(laddr)) < 0) {
		err = errno;
		goto failed;
	}

	if (listen(sk, 10) < 0) {
		err = errno;
		goto failed;
	}

	io = g_io_channel_unix_new(sk);
	svc = g_malloc0(sizeof(guint16));
	*svc = service;
	g_io_channel_set_close_on_unref(io, TRUE);
	g_io_add_watch_full(io, G_PRIORITY_DEFAULT,
			G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			connect_event, svc, server_destroyed);
	g_io_channel_unref(io);

	return 0;

failed:
	error("Bluetooth server register failed: %s(%d)", strerror(err), err);
	close(sk);

	return -err;
}

static gint server_unregister(guint16 service)
{
	/* FIXME: Remove service record and disable it */

	return 0;
}

gint obex_bt_init(const GKeyFile *keyfile)
{
	DBusError derr;
	gint err;

	/* FIXME: Parse the content */
	err = server_register("OBEX FTP Server", OBEX_FTP, 10, "/tmp/ftp", TRUE);
	if (err < 0)
		goto failed;

	dbus_error_init(&derr);
	conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, &derr);
	if (!conn) {
		error("Can't connect to system bus: %s", derr.message);
		dbus_error_free(&derr);
		return -EIO;
	}

	return 0;

failed:
	return -1;
}

void obex_bt_exit(void)
{
	if (conn)
		dbus_connection_unref(conn);
}
