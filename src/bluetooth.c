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
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "logging.h"
#include "obex.h"

#define OPUSH_CHANNEL	9
#define FTP_CHANNEL	10

#define ROOT_PATH "/tmp"

static GSList *handles = NULL;
static sdp_session_t *session = NULL;

static void add_lang_attr(sdp_record_t *r)
{
	sdp_lang_attr_t base_lang;
	sdp_list_t *langs = 0;

	/* UTF-8 MIBenum (http://www.iana.org/assignments/character-sets) */
	base_lang.code_ISO639 = (0x65 << 8) | 0x6e;
	base_lang.encoding = 106;
	base_lang.base_offset = SDP_PRIMARY_LANG_BASE;
	langs = sdp_list_append(0, &base_lang);
	sdp_set_lang_attr(r, langs);
	sdp_list_free(langs, 0);
}

static uint32_t register_record(const gchar *name,
				guint16 service, guint8 channel)
{
	uuid_t root_uuid, uuid, l2cap_uuid, rfcomm_uuid, obex_uuid;
	sdp_list_t *root, *svclass_id, *apseq, *profiles, *aproto, *proto[3];
	sdp_data_t *sdp_data;
	sdp_profile_desc_t profile;
	sdp_record_t record;
	uint8_t formats = 0xFF;
	int ret;

	switch (service) {
	case OBEX_OPUSH:
		sdp_uuid16_create(&uuid, OBEX_OBJPUSH_SVCLASS_ID);
		sdp_uuid16_create(&profile.uuid, OBEX_OBJPUSH_PROFILE_ID);
		break;
	case OBEX_FTP:
		sdp_uuid16_create(&uuid, OBEX_FILETRANS_SVCLASS_ID);
		sdp_uuid16_create(&profile.uuid, OBEX_FILETRANS_PROFILE_ID);
		break;
	default:
		return 0;
	}

	/* Browse Groups */
	memset(&record, 0, sizeof(sdp_record_t));
	record.handle = 0xffffffff;
	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(&record, root);
	sdp_list_free(root, NULL);

	/* Service Class */
	svclass_id = sdp_list_append(NULL, &uuid);
	sdp_set_service_classes(&record, svclass_id);
	sdp_list_free(svclass_id, NULL);

	/* Profile Descriptor */
	profile.version = 0x0100;
	profiles = sdp_list_append(NULL, &profile);
	sdp_set_profile_descs(&record, profiles);
	sdp_list_free(profiles, NULL);

	/* Protocol Descriptor */
	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(NULL, &l2cap_uuid);
	apseq = sdp_list_append(NULL, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(NULL, &rfcomm_uuid);
	sdp_data = sdp_data_alloc(SDP_UINT8, &channel);
	proto[1] = sdp_list_append(proto[1], sdp_data);
	apseq = sdp_list_append(apseq, proto[1]);

	sdp_uuid16_create(&obex_uuid, OBEX_UUID);
	proto[2] = sdp_list_append(NULL, &obex_uuid);
	apseq = sdp_list_append(apseq, proto[2]);

	aproto = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(&record, aproto);

	sdp_data_free(sdp_data);
	sdp_list_free(proto[0], NULL);
	sdp_list_free(proto[1], NULL);
	sdp_list_free(proto[2], NULL);
	sdp_list_free(apseq, NULL);
	sdp_list_free(aproto, NULL);

	/* Suported Repositories */
	if (service == OBEX_OPUSH)
		sdp_attr_add_new(&record, SDP_ATTR_SUPPORTED_FORMATS_LIST,
				SDP_UINT8, &formats);

	/* Service Name */
	sdp_set_info_attr(&record, name, NULL, NULL);

	add_lang_attr(&record);

	ret = sdp_record_register(session, &record, SDP_RECORD_PERSIST);

	sdp_list_free(record.attrlist, (sdp_free_func_t) sdp_data_free);
	sdp_list_free(record.pattern, free);

	return (ret < 0 ? 0 : record.handle);
}

static gboolean connect_event(GIOChannel *io, GIOCondition cond, gpointer user_data)
{
	struct sockaddr_rc raddr;
	socklen_t alen;
	struct server *server = user_data;
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

	if (obex_server_start(nsk, 0, server) < 0)
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
	struct server *server;
	uint32_t *handle;

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
	bacpy(&laddr.rc_bdaddr, BDADDR_ANY);
	laddr.rc_channel = channel;

	if (bind(sk, (struct sockaddr *) &laddr, sizeof(laddr)) < 0) {
		err = errno;
		goto failed;
	}

	if (listen(sk, 10) < 0) {
		err = errno;
		goto failed;
	}

	handle = malloc(sizeof(uint32_t));
	*handle = register_record(name, service, channel);
	if (*handle == 0) {
		g_free(handle);
		err = EIO;
		goto failed;
	}

	handles = g_slist_prepend(handles, handle);

	server = g_malloc0(sizeof(struct server));
	server->service = service;
	server->folder = g_strdup(folder);
	server->auto_accept = auto_accept;

	io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(io, TRUE);
	g_io_add_watch_full(io, G_PRIORITY_DEFAULT,
			G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			connect_event, server, server_destroyed);
	g_io_channel_unref(io);

	debug("Registered: %s, record handle: 0x%x, folder: %s", name, *handle, folder);

	return 0;

failed:
	error("Bluetooth server register failed: %s(%d)", strerror(err), err);
	close(sk);

	return -err;
}

static gint setup_server(GKeyFile *keyfile,
			const gchar *group, gint16 service)
{
	const gchar *name, *folder;
	gchar *key_name, *key_folder;
	gboolean auto_accept;
	gint8 channel;
	gint ret;

	key_name = g_key_file_get_string(keyfile, group, "name", NULL);
	channel = g_key_file_get_integer(keyfile, group, "channel", NULL);
	key_folder = g_key_file_get_string(keyfile, group, "folder", NULL);
	auto_accept = g_key_file_get_boolean(keyfile, group,
						"auto_accept", NULL);

	switch (service) {
	case OBEX_OPUSH:
		name = (key_name ? : "OBEX OPUSH server");
		folder = (key_folder ? : ROOT_PATH);
		channel = (channel ? : OPUSH_CHANNEL);
		break;
	case OBEX_FTP:
		name = (key_name ? : "OBEX FTP server");
		folder = (key_folder ? : ROOT_PATH);
		channel = (channel ? : FTP_CHANNEL);
		break;
	}

	ret = server_register(name, service, channel, folder, auto_accept);

	g_free(key_name);
	g_free(key_folder);

	return ret;
}

gint bluetooth_init(GKeyFile *keyfile)
{
	gint err;
	gchar **list;
	gint i;

	session = sdp_connect(BDADDR_ANY, BDADDR_LOCAL, SDP_RETRY_IF_BUSY);
	if (!session) {
		gint err = errno;
		error("sdp_connect(): %s(%d)", strerror(err), err);
		return -err;
	}

	err = 0;
	list = g_key_file_get_string_list(keyfile, "Bluetooth", "Enable", NULL, NULL);
	if (list == NULL)
		goto failed;

	for (i = 0; list[i]; i++) {
		if (g_str_equal(list[i], "OPUSH"))
			err = setup_server(keyfile, "OPUSH", OBEX_OPUSH);
		if (g_str_equal(list[i], "FTP"))
			err = setup_server(keyfile, "FTP", OBEX_FTP);
	}

	g_strfreev(list);

	if (err < 0)
		goto failed;

	return 0;

failed:
	sdp_close(session);

	return -1;
}

static void unregister_record(gpointer rec_handle, gpointer user_data)
{
	uint32_t *handle = rec_handle;

	sdp_device_record_unregister_binary(session, BDADDR_ANY, *handle);
	g_free(handle);
}

void bluetooth_exit(void)
{
	g_slist_foreach(handles, unregister_record, NULL);
	g_slist_free(handles);

	sdp_close(session);
}
