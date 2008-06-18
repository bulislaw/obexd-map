/*
 *
 *  OBEX Server
 *
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

#include <gdbus.h>

#include "obexd.h"
#include "logging.h"

#define TRANSFER_INTERFACE OPENOBEX_SERVICE ".Transfer"

static GDBusMethodTable manager_methods[] = {
	{ }
};

static GDBusSignalTable manager_signals[] = {
	{ "TransferStarted", 	"o" 	},
	{ "TransferCompleted",	"ob"	},
	{ }
};

static GDBusMethodTable transfer_methods[] = {
	{ "Cancel",	""	},
	{ }
};

static GDBusSignalTable transfer_signals[] = {
	{ "Progress",	"uu"	},
	{ }
};

static DBusConnection *connection = NULL;

gboolean manager_init(DBusConnection *conn)
{
	DBG("conn %p", conn);

	connection = dbus_connection_ref(conn);
	if (connection == NULL)
		return FALSE;

	return g_dbus_register_interface(connection, OPENOBEX_MANAGER_PATH,
					OPENOBEX_MANAGER_INTERFACE,
					manager_methods, manager_signals, NULL,
					NULL, NULL);
}

void manager_cleanup(void)
{
	DBG("conn %p", connection);

	g_dbus_unregister_interface(connection, OPENOBEX_MANAGER_PATH,
						OPENOBEX_MANAGER_INTERFACE);

	dbus_connection_unref(connection);
}

/* FIXME: Change the name  */
void emit_transfer_started(guint32 id)
{
	gchar *path = g_strdup_printf("/transfer%u", id);
	gboolean ret;

	ret = g_dbus_register_interface(connection, path,
				TRANSFER_INTERFACE,
				transfer_methods, transfer_signals, NULL,
				NULL, NULL);
	if (ret == FALSE) {
		error("Cannot register Transfer interface.");
		return;
	}

	ret = g_dbus_emit_signal(connection, OPENOBEX_MANAGER_PATH,
			OPENOBEX_MANAGER_INTERFACE, "TransferStarted",
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_INVALID);
	if (ret == FALSE) {
		error("Cannot send Transfer started signal");
		return;
	}

	g_free(path);
}

void emit_transfer_completed(guint32 id, gboolean success)
{
	gchar *path = g_strdup_printf("/transfer%u", id);

	g_dbus_emit_signal(connection, OPENOBEX_MANAGER_PATH,
			OPENOBEX_MANAGER_INTERFACE, "TransferCompleted",
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_BOOLEAN, &success,
			DBUS_TYPE_INVALID);

	g_dbus_unregister_interface(connection, path,
				TRANSFER_INTERFACE);

	g_free(path);
}

void emit_transfer_progress(guint32 id, guint32 total, guint32 transfered)
{
	gchar *path = g_strdup_printf("/transfer%u", id);

	g_dbus_emit_signal(connection, path,
			TRANSFER_INTERFACE, "Progress",
			DBUS_TYPE_UINT32, &total,
			DBUS_TYPE_UINT32, &transfered,
			DBUS_TYPE_INVALID);

	g_free(path);
}
