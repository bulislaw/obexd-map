/*
 *
 *  OBEX Test
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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

#include <glib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <gw-obex.h>

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
static gboolean option_ftp = FALSE;
static gboolean option_pbap = FALSE;
static gchar **option_addresses = NULL;

static GOptionEntry options[] = {
	{ "device", 'i', 0, G_OPTION_ARG_STRING, &option_device,
				"Specify local device interface", "DEV" },
	{ "channel", 'P', 0, G_OPTION_ARG_INT, &option_channel,
				"Specify remote RFCOMM channel", "PORT" },
	{ "ftp", 'f', 0, G_OPTION_ARG_NONE, &option_ftp,
				"Use File Transfer target" },
	{ "pbap", 'p', 0, G_OPTION_ARG_NONE, &option_pbap,
				"Use Phonebook Access target" },
	{ G_OPTION_REMAINING, 0, 0, G_OPTION_ARG_STRING_ARRAY,
					&option_addresses, NULL, "address" },
	{ NULL },
};

int main(int argc, char *argv[])
{
	GOptionContext *context;
	GError *err = NULL;
	bdaddr_t src, dst;
	int sk;

	GwObex *obex;
	gchar *buf;
	const gchar *uuid = NULL;
	gint error, buf_len, uuid_len = 0;

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

	if (option_channel < 1)
		option_channel = 11;

	if (option_addresses == NULL) {
		fprintf(stderr, "Failed to specify destination address\n");
		exit(1);
	}

	str2ba(option_addresses[0], &dst);
	g_strfreev(option_addresses);

	sk = rfcomm_connect(&src, &dst, option_channel);
	if (sk < 0) {
		fprintf(stderr, "Failed to connect RFCOMM channel\n");
		exit(1);
	}

	if (option_ftp == TRUE) {
		uuid = OBEX_FTP_UUID;
		uuid_len = OBEX_FTP_UUID_LEN;
	}

	if (option_pbap == TRUE) {
		uuid = OBEX_PBAP_UUID;
		uuid_len = OBEX_PBAP_UUID_LEN;
	}

	obex = gw_obex_setup_fd(sk, uuid, uuid_len, NULL, &error);
	if (obex == NULL) {
		fprintf(stderr, "Failed to create OBEX session\n");
		close(sk);
		exit(1);
	}

	if (option_ftp == FALSE && option_pbap == FALSE) {
		if (gw_obex_get_buf(obex, NULL, "x-obex/capability",
					&buf, &buf_len, &error) == TRUE) {
			printf("%s\n", buf);
			g_free(buf);
		}
	}

	if (option_ftp == TRUE) {
		if (gw_obex_get_buf(obex, NULL, "x-obex/folder-listing",
					&buf, &buf_len, &error) == TRUE) {
			printf("%s\n", buf);
			g_free(buf);
		}
	}

	if (option_pbap == TRUE) {
		if (gw_obex_get_buf(obex, "telecom/pb.vcf", "x-bt/phonebook",
					&buf, &buf_len, &error) == TRUE) {
			printf("%s\n", buf);
			g_free(buf);
		}
	}

	gw_obex_close(obex);

	close(sk);

	return 0;
}
