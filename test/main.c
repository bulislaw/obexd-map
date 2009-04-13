/*
 *
 *  OBEX Test
 *
 *  Copyright (C) 2007-2009  Marcel Holtmann <marcel@holtmann.org>
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
#include <unistd.h>
#include <stdlib.h>

#include <glib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <gw-obex.h>

enum {
	CONNECT,
	PULLPHONEBOOK,
	PULLVCARDLISTING,
	INVALID
};

static int sdp_search(const bdaddr_t *src, const bdaddr_t *dst,
					uint16_t uuid, uint8_t *channel)
{
	sdp_session_t *session;
	sdp_list_t *search, *attributes, *rsp;
	uuid_t svclass;
	uint16_t attr;
	int err;

	session = sdp_connect(src, dst, SDP_WAIT_ON_CLOSE);
	if (session == NULL)
		return -1;

	sdp_uuid16_create(&svclass, uuid);
	search = sdp_list_append(NULL, &svclass);

	attr = SDP_ATTR_PROTO_DESC_LIST;
	attributes = sdp_list_append(NULL, &attr);

	err = sdp_service_search_attr_req(session, search,
				SDP_ATTR_REQ_INDIVIDUAL, attributes, &rsp);
	if (err < 0) {
		sdp_close(session);
		return -1;
	}

	for (; rsp; rsp = rsp->next) {
		sdp_record_t *rec = (sdp_record_t *) rsp->data;
		sdp_list_t *protos;

		if (!sdp_get_access_protos(rec, &protos)) {
			uint8_t ch = sdp_get_proto_port(protos, RFCOMM_UUID);
			if (ch > 0) {
				*channel = ch;
				sdp_close(session);
				return 0;
			}
		}
	}

	sdp_close(session);

	return -1;
}

static int rfcomm_connect(const bdaddr_t *src, const bdaddr_t *dst,
							uint8_t channel)
{
	struct sockaddr_rc addr;
	int sk;

	sk = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0)
		return -EIO;

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, src);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return -EIO;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, dst);
	addr.rc_channel = channel;

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return -EIO;
	}

	return sk;
}

static gchar *option_device = NULL;
static gint option_channel = 0;
static gchar *option_path = NULL;
static gboolean option_ftp = FALSE;
static gboolean option_pbap = FALSE;

static gchar *option_connect = NULL;
static gchar *option_pullphonebook = NULL;
static gchar *option_setphonebook = NULL;
static gchar *option_pullvcardlisting = NULL;

static GOptionEntry options[] = {
	{ "device", 'i', 0, G_OPTION_ARG_STRING, &option_device,
				"Specify local device interface", "DEV" },
	{ "channel", 'C', 0, G_OPTION_ARG_INT, &option_channel,
				"Specify remote RFCOMM channel", "CHANNEL" },
	{ "path", 'P', 0, G_OPTION_ARG_STRING, &option_path,
				"Specify initial path to set", "PATH" },
	{ "ftp", 'f', 0, G_OPTION_ARG_NONE, &option_ftp,
				"Use File Transfer target" },
	{ "pbap", 'p', 0, G_OPTION_ARG_NONE, &option_pbap,
				"Use Phonebook Access target" },

	{ "connect", 0, 0, G_OPTION_ARG_STRING, &option_connect,
				"Connect remote OBEX session", "DEV" },
	{ "pullphonebook", 0, 0, G_OPTION_ARG_STRING, &option_pullphonebook,
				"Pull phonebook from remote device", "DEV" },
	{ "setphonebook", 0, 0, G_OPTION_ARG_STRING, &option_setphonebook,
				"Select phonebook on remote device", "DEV" },
	{ "pullvcardlisting", 0, 0, G_OPTION_ARG_STRING, &option_pullvcardlisting,
				"Pull vCard listing from remote device", "DEV" },

	{ NULL },
};

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *err = NULL;
	bdaddr_t src, dst;
	int sk;

	GwObex *obex;
	uint16_t uuid = OBEX_OBJPUSH_SVCLASS_ID;
	uint8_t channel;
	gchar *buf;
	const gchar *target = NULL;
	gint error, buf_len, target_len = 0;
	int mode = INVALID;

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, options, NULL);

	if (g_option_context_parse(context, &argc, &argv, &err) == FALSE) {
		if (err != NULL) {
			g_printerr("%s\n", err->message);
			g_error_free(err);
		} else
			g_printerr("An unknown error occurred\n");
		exit(EXIT_FAILURE);
	}

	g_option_context_free(context);

	if (option_device != NULL) {
		str2ba(option_device, &dst);
		g_free(option_device);
	} else
		bacpy(&src, BDADDR_ANY);

	bacpy(&dst, BDADDR_ANY);

	if (option_connect != NULL) {
		str2ba(option_connect, &dst);
		g_free(option_connect);
		mode = CONNECT;
	}

	if (option_pullphonebook != NULL) {
		str2ba(option_pullphonebook, &dst);
		g_free(option_pullphonebook);
		mode = PULLPHONEBOOK;
		option_pbap = TRUE;
	}

	if (option_setphonebook != NULL) {
		str2ba(option_setphonebook, &dst);
		g_free(option_setphonebook);
		mode = CONNECT;
		option_pbap = TRUE;
		if (option_path == NULL)
			option_path = g_strdup("telecom");
	}

	if (option_pullvcardlisting != NULL) {
		str2ba(option_pullvcardlisting, &dst);
		g_free(option_pullvcardlisting);
		mode = PULLVCARDLISTING;
		option_pbap = TRUE;
		//if (option_path == NULL)
		//	option_path = g_strdup("telecom");
	}

	if (option_ftp == TRUE) {
		uuid = OBEX_FILETRANS_SVCLASS_ID;
		target = OBEX_FTP_UUID;
		target_len = OBEX_FTP_UUID_LEN;
	}

	if (option_pbap == TRUE) {
		uuid = PBAP_PSE_SVCLASS_ID;
		target = OBEX_PBAP_UUID;
		target_len = OBEX_PBAP_UUID_LEN;
	}

	if (bacmp(&dst, BDADDR_ANY) == 0) {
		fprintf(stderr, "Failed to provide action with address\n");
		exit(1);
	}

	if (option_channel < 1) {
		if (sdp_search(&src, &dst, uuid, &channel) < 0) {
			fprintf(stderr, "Failed to get RFCOMM channel\n");
			exit(1);
		}
	} else
		channel = option_channel;

	sk = rfcomm_connect(&src, &dst, channel);
	if (sk < 0) {
		fprintf(stderr, "Failed to connect RFCOMM channel\n");
		exit(1);
	}

	obex = gw_obex_setup_fd(sk, target, target_len, NULL, &error);
	if (obex == NULL) {
		fprintf(stderr, "Failed to create OBEX session\n");
		close(sk);
		exit(1);
	}

	if (option_path != NULL) {
		if (gw_obex_chdir(obex, option_path, &error) == FALSE) {
			fprintf(stderr, "Failed to change directory\n");
			gw_obex_close(obex);
			close(sk);
			exit(1);
		}
	}

	switch (mode) {
	case CONNECT:
		break;

	case PULLPHONEBOOK:
		{
		unsigned char apparam[] = { 0x04, 0x02, 0xff, 0xff };
		//unsigned char apparam[] = { 0x04, 0x02, 0x00, 0x00 };

		if (gw_obex_get_buf_with_apparam(obex,
					"telecom/pb.vcf", "x-bt/phonebook",
					apparam, sizeof(apparam),
					&buf, &buf_len, &error) == TRUE) {
			//printf("%s\n", buf);
			//g_free(buf);
		}
		}
		break;

	case PULLVCARDLISTING:
		{
		unsigned char apparam[] = { 0x04, 0x02, 0xff, 0xff };

		if (gw_obex_get_buf_with_apparam(obex,
					"", "x-bt/vcard-listing",
					apparam, sizeof(apparam),
					&buf, &buf_len, &error) == TRUE) {
			//printf("%s\n", buf);
			//g_free(buf);
		}
		}
		break;
	}

	gw_obex_close(obex);

	close(sk);

	g_free(option_path);

	return 0;
}
