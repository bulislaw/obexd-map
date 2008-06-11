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

static GDBusMethodTable manager_methods[] = {
	{ }
};

static GDBusSignalTable manager_signals[] = {
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
