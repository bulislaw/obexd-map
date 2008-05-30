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
#include <unistd.h>
#include <fcntl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/rfcomm.h>

#include <glib.h>
#include <dbus/dbus.h>

#include "obex.h"

/* FIXME: */
#define CONFIG_FILE	"~/.obexd/bluetooth.conf"

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
	uint8_t	 channel;
	uint16_t service;
	uint32_t record;	/* Service Record Handle */
	gboolean auto_accept;
	char	*folder;
	char	*uuid;
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
	char address[18];
	int err, sk, nsk;

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

	if (obex_server_start(nsk, 0) < 0)
		close(nsk);

	return TRUE;
}

static void server_destroyed(gpointer user_data)
{
	error("Server destroyed");
}

static int server_register(const char *name, uint16_t service,
		uint8_t channel, const char *folder, gboolean auto_accept)
{
	struct sockaddr_rc laddr;
	GIOChannel *io;
	int err, sk, arg, lm = 0;

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

	laddr.rc_family = AF_BLUETOOTH;
	bacpy(&laddr.rc_bdaddr, BDADDR_ANY);
	laddr.rc_channel = channel;

	if (bind(sk, (struct sockaddr *)&laddr, sizeof(laddr)) < 0) {
		err = errno;
		goto failed;
	}

	if (listen(sk, 10) < 0) {
		err = errno;
		goto failed;
	}

	io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(io, TRUE);
	g_io_add_watch_full(io, G_PRIORITY_DEFAULT,
			G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			connect_event, NULL, server_destroyed);
	g_io_channel_unref(io);

	return 0;

failed:
	error("Bluetooth server register failed: %s(%d)", strerror(err), err);
	close(sk);

	return -err;
}

static int server_unregister(uint16_t service)
{
	/* FIXME: Remove service record and disable it */

	return 0;
}

int obex_bt_init(void)
{
	GKeyFile *keyfile;
	GError *gerr = NULL;
	DBusError derr;
	int err;

	keyfile = g_key_file_new();

	if (!g_key_file_load_from_file(keyfile, CONFIG_FILE, 0, &gerr)) {
		error("Parsing %s failed: %s", CONFIG_FILE, gerr->message);
		g_error_free(gerr);
		goto failed;
	}

	/* FIXME: Parse the content */
	err = server_register("OBEX FTP Server", 0x1106, 10, "/tmp/ftp", TRUE);
	if (err < 0)
		goto failed;

	dbus_error_init(&derr);
	conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, &derr);
	if (!conn) {
		error("Can't connect to system bus: %s", derr.message);
		dbus_error_free(&derr);
		return -EIO;
	}

	g_key_file_free(keyfile);

	return 0;

failed:
	g_key_file_free(keyfile);

	return -1;
}

void obex_bt_exit(void)
{
	if (conn)
		dbus_connection_unref(conn);
}
