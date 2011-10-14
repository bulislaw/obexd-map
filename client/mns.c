/*
 *
 *  OBEX Client
 *
 *  Copyright (C) 2007-2010  Intel Corporation
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <glib.h>
#include <gdbus.h>

#include "log.h"
#include "transfer.h"
#include "session.h"
#include "driver.h"
#include "mns.h"

#define ERROR_INF MNS_INTERFACE ".Error"
#define MASINSTANCEID_TAG	0x0F

#define MET_NEW_MESSAGE		1
#define MET_DELIVERY_SUCCESS	2
#define MET_SENDING_SUCCESS	3
#define MET_DELIVERY_FAILURE	4
#define MET_SENDING_FAILURE	5
#define MET_MEMORY_FULL		6
#define MET_MEMORY_AVAILABLE	7
#define MET_MESSAGE_DELETED	8
#define MET_MESSAGE_SHIFT	9

#define MT_EMAIL	1
#define MT_SMS_GSM	2
#define MT_SMS_CDMA	3
#define MT_MMS		4

#define MNS_UUID "00001133-0000-1000-8000-00805f9b34fb"

struct event_apparam {
	uint8_t	tag;
	uint8_t	len;
	uint8_t masinstanceid;
} __attribute__ ((packed));

static DBusConnection *conn = NULL;

struct mns {
	DBusMessage *msg;
	struct obc_session *session;
};

static void mns_send_event_callback(struct obc_session *session,
					GError *err, void *user_data)
{
	struct mns *mns = user_data;
	struct obc_transfer *transfer = obc_session_get_transfer(session);
	DBusMessage *reply;

	DBG("session = %p, mns = %p, transfer = %p", session, mns, transfer);

	if (mns->msg == NULL)
		goto done;

	if (err != NULL) {
		DBG("err: %s", err->message);
		reply = g_dbus_create_error(mns->msg,
						ERROR_INF ".Failed",
						"%s", err->message);
	} else {
		reply = dbus_message_new_method_return(mns->msg);
	}

	g_dbus_send_message(conn, reply);
	dbus_message_unref(mns->msg);
	mns->msg = NULL;

done:
	obc_transfer_unregister(transfer);
}


static DBusMessage *mns_send_event(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct mns *mns = user_data;
	GString *buf;
	uint8_t evtype;
	uint8_t msgtype;
	uint8_t masinstanceid;
	const char *handle, *folder, *old_folder;
	struct event_apparam eapp;
	char *cbuf;

	DBG("mns = %p", mns);

	if (mns->msg) {
		DBG("Another transfer in progress!");
		return g_dbus_create_error(message,
				"org.openobex.Error.InProgress",
				"Transfer in progress");
	}

	buf = g_string_new("");

	if (dbus_message_get_args(message, NULL,
			DBUS_TYPE_BYTE, &masinstanceid,
			DBUS_TYPE_BYTE, &evtype,
			DBUS_TYPE_STRING, &handle,
			DBUS_TYPE_STRING, &folder,
			DBUS_TYPE_STRING, &old_folder,
			DBUS_TYPE_BYTE, &msgtype,
			DBUS_TYPE_INVALID) == FALSE) {
		DBG("Invalid arguments!");
		return g_dbus_create_error(message,
				ERROR_INF ".InvalidArguments", NULL);
	}

	eapp.tag = MASINSTANCEID_TAG;
	eapp.len = 1;
	eapp.masinstanceid = masinstanceid;

	g_string_append(buf, "<MAP-event-report version=\"1.0\">\n");

	switch (evtype) {
	case MET_NEW_MESSAGE:
		g_string_append(buf, "<event type=\"NewMessage\"");
		break;
	case MET_DELIVERY_SUCCESS:
		g_string_append(buf, "<event type=\"DeliverySuccess\"");
		break;
	case MET_SENDING_SUCCESS:
		g_string_append(buf, "<event type=\"SendingSuccess\"");
		break;
	case MET_DELIVERY_FAILURE:
		g_string_append(buf, "<event type=\"DeliveryFailure\"");
		break;
	case MET_SENDING_FAILURE:
		g_string_append(buf, "<event type=\"SendingFailure\"");
		break;
	case MET_MEMORY_FULL:
		g_string_append(buf, "<event type=\"MemoryFull\"");
		break;
	case MET_MEMORY_AVAILABLE:
		g_string_append(buf, "<event type=\"MemoryAvailable\"");
		break;
	case MET_MESSAGE_DELETED:
		g_string_append(buf, "<event type=\"MessageDeleted\"");
		break;
	case MET_MESSAGE_SHIFT:
		g_string_append(buf, "<event type=\"MessageShift\"");
		break;
	default:
		DBG("Incorrect type of event!");
		g_string_free(buf, TRUE);
		return g_dbus_create_error(message,
				ERROR_INF ".InvalidArguments",
				"Incorrect event type");
	}

	/* FIXME: escape disallowed characters */
	if ((evtype != MET_MEMORY_FULL) && (evtype != MET_MEMORY_AVAILABLE)) {
		g_string_append_printf(buf, " handle=\"%s\"", handle);
		g_string_append_printf(buf, " folder=\"%s\"", folder);
		switch (msgtype) {
		case MT_EMAIL:
			g_string_append(buf, " msg_type=\"EMAIL\"");
			break;
		case MT_SMS_GSM:
			g_string_append(buf, " msg_type=\"SMS_GSM\"");
			break;
		case MT_SMS_CDMA:
			g_string_append(buf, " msg_type=\"SMS_CDMA\"");
			break;
		case MT_MMS:
			g_string_append(buf, " msg_type=\"MMS\"");
			break;
		default:
			/* FIXME */
			break;
		}
	}

	if (evtype == MET_MESSAGE_SHIFT)
		g_string_append_printf(buf, " old_folder=\"%s\"", old_folder);

	g_string_append(buf, "/>\n</MAP-event-report>");

	DBG("Object to be sent:");
	DBG("%s", buf->str);

	cbuf = buf->str;

	g_string_free(buf, FALSE);

	/* XXX: currently it also sends obex length header. can we ignore this?
	 * This makes test device respond with code 500.
	 * (also see MAP specification, page 64)
	 * note: temporary "fixed" in obex-priv.c (may definitely break another
	 * things)
	 */
	/* XXX: implementation sends separate Body and EndOfBody headers in
	 * separate packets - ugly (would require fix in openobex) */
	/* XXX: session_put makes a copy of eapp, cbuf will be freed after use
	 */

	if (obc_session_put(mns->session, "x-bt/MAP-event-report", NULL, NULL,
				(const guint8 *)&eapp, sizeof(eapp),
				mns_send_event_callback, cbuf, mns) < 0) {
		DBG("obc_session_put() failed!");
		return g_dbus_create_error(message,
				ERROR_INF ".Failed",
				"Fail me more.");
	}

	mns->msg = dbus_message_ref(message);

	return NULL;
}


static GDBusMethodTable mns_methods[] = {
	{ "SendEvent",	"yysssy",	"",	mns_send_event,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ }
};

static void mns_free(void *data)
{
	struct mns *mns = data;

	obc_session_unref(mns->session);
	g_free(mns);
}

static int mns_probe(struct obc_session *session)
{
	const char *path = obc_session_get_path(session);
	struct mns *mns;

	DBG("%s", path);

	mns = g_try_malloc0(sizeof(*mns));
	if (!mns)
		return -ENOMEM;

	mns->session = obc_session_ref(session);

	if (!g_dbus_register_interface(conn, path, MNS_INTERFACE,
				mns_methods, NULL, NULL, mns, mns_free)) {
		mns_free(mns);
		return -ENOMEM;
	}

	return 0;
}

static void mns_remove(struct obc_session *session)
{
	const char *path = obc_session_get_path(session);

	DBG("%s", path);

	g_dbus_unregister_interface(conn, path, MNS_INTERFACE);
}


static struct obc_driver mns = {
	.service = "MNS",
	.uuid = MNS_UUID,
	.target = OBEX_MNS_UUID,
	.target_len = OBEX_MNS_UUID_LEN,
	.probe = mns_probe,
	.remove = mns_remove
};

int mns_init(void)
{
	int err;

	DBG("");

	conn = dbus_bus_get(DBUS_BUS_SESSION, NULL);
	if (!conn)
		return -EIO;

	err = obc_driver_register(&mns);
	if (err < 0) {
		dbus_connection_unref(conn);
		conn = NULL;
		return err;
	}

	return 0;
}

void mns_exit(void)
{
	DBG("");

	dbus_connection_unref(conn);
	conn = NULL;

	obc_driver_unregister(&mns);
}
