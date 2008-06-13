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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <syslog.h>

#include <gdbus.h>

#include "logging.h"
#include "bluetooth.h"
#include "obexd.h"

#define CONFIG_FILE	"obex.conf"

static GMainLoop *main_loop = NULL;

static int server_start(const gchar *config_file)
{
	GKeyFile *keyfile;
	GError *gerr = NULL;
	const gchar *filename = (config_file ? : CONFIGDIR "/" CONFIG_FILE);
	gchar **key;
	gsize len;
	int i;

	debug("Configuration file: %s", filename);

	keyfile = g_key_file_new();
	if (!g_key_file_load_from_file(keyfile, filename, 0, &gerr)) {
		error("Parsing %s failed: %s", filename, gerr->message);
		g_error_free(gerr);
		goto fail;
	}

	key = g_key_file_get_string_list(keyfile,
				"General", "EnabledTransports",
				&len, &gerr);
	if (gerr) {
		error("Parsing %s failed: %s", CONFIG_FILE, gerr->message);
		g_error_free(gerr);
		goto fail;
	}

	if (key == NULL || len == 0) {
		error("EnabledTransports not defined");
		goto fail;
	}

	for (i = 0; i < len; i++){

		if (!g_strcasecmp(key[i], "Bluetooth")) {
			bluetooth_init(keyfile);
		} else if (!g_strcasecmp(key[i], "USB")) {
			debug("Not implemented (USB)");
		} else if (!g_strcasecmp(key[i], "IrDA")) {
			debug("Not implemented (IrDA)");
		}
	}

	g_key_file_free(keyfile);
	g_strfreev(key);

	return 0;

fail:
	g_key_file_free(keyfile);

	return -EINVAL;
}

static void server_stop()
{
	/* FIXME: If Bluetooth enabled */
	bluetooth_exit();
}

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

static void usage(void)
{
	printf("OBEX Server version %s\n\n", VERSION);

	printf("Usage:\n"
		"\tobexd [options]\n"
		"\n");

	printf("Options:\n"
		"\t-n, --nodaemon       Don't fork daemon to background\n"
		"\t-d, --debug          Enable output of debug information\n"
		"\t-f, --config         Set configuration file\n"
		"\t-h, --help           Display help\n"
		"\n");
}

static struct option options[] = {
	{ "nodaemon", 0, 0, 'n' },
	{ "debug",    0, 0, 'd' },
	{ "config",    0, 0, 'f' },
	{ "help",     0, 0, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	DBusConnection *conn;
	DBusError err;
	struct sigaction sa;
	int log_option = LOG_NDELAY | LOG_PID;
	int opt, detach = 1, debug = 0;
	gchar *config_file = NULL;

	while ((opt = getopt_long(argc, argv, "+ndhf:", options, NULL)) != EOF) {
		switch(opt) {
		case 'n':
			detach = 0;
			break;
		case 'd':
			debug = 1;
			break;
		case 'h':
		case 'f':
			config_file = g_strdup(optarg);
			break;
		default:
			usage();
			exit(0);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (detach) {
		if (daemon(0, 0)) {
			perror("Can't start daemon");
			exit(1);
		}
	} else
		log_option |= LOG_PERROR;

	openlog("obexd", log_option, LOG_DAEMON);

	if (debug) {
		info("Enabling debug information");
		enable_debug();
	}

	main_loop = g_main_loop_new(NULL, FALSE);

	dbus_error_init(&err);

	conn = g_dbus_setup_bus(DBUS_BUS_SESSION, OPENOBEX_SERVICE, &err);
	if (conn == NULL) {
		if (dbus_error_is_set(&err) == TRUE) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		} else
			fprintf(stderr, "Can't register with session bus\n");
		exit(1);
	}

	if (server_start(config_file) < 0)
		goto fail;

	if (!manager_init(conn))
		goto fail;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	g_main_loop_run(main_loop);

	manager_cleanup();

	server_stop();

fail:
	if (config_file)
		g_free(config_file);

	g_dbus_cleanup_connection(conn);

	g_main_loop_unref(main_loop);

	closelog();

	return 0;
}
