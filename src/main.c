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
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <glib.h>

#include "logging.h"
#include "bluetooth.h"

#define CONFIG_FILE	"obex.conf"

static GMainLoop *main_loop;
static gchar *config_file;

static int start_server(void)
{
	GKeyFile *keyfile;
	GError *gerr = NULL;
	const char *filename = (config_file ? : CONFIGDIR "/" CONFIG_FILE);

	debug("Configuration file: %s", filename);

	keyfile = g_key_file_new();

	if (!g_key_file_load_from_file(keyfile, filename, 0, &gerr)) {
		error("Parsing %s failed: %s", CONFIG_FILE, gerr->message);
		g_error_free(gerr);
		return -EINVAL;
	}

	/* FIXME: Read [General] section */

	obex_bt_init(keyfile);

	g_key_file_free(keyfile);

	return 0;
}

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

static void sig_hup(int sig)
{
}

static void sig_debug(int sig)
{
	        toggle_debug();
}

static void usage(void)
{
	printf("obexd - OBEX daemon ver %s\n", VERSION);
	printf("Usage: \n");
	printf("\thcid [-n] [-d] [-f config file]\n");
}

int main(int argc, char *argv[])
{
	struct sigaction sa;
	int opt, daemonize = 1, debug = 0;

	while ((opt = getopt(argc, argv, "ndf:")) != EOF) {
		switch (opt) {
		case 'n':
			daemonize = 0;
			break;

		case 'd':
			debug = 1;
			break;
		case 'f':
			config_file = g_strdup(optarg);
			break;
		default:
			usage();
			exit(1);
		}
	}

	if (daemonize && daemon(0, 0)) {
		error("Can't daemonize: %s (%d)", strerror(errno), errno);
		exit(1);
	}

	umask(0077);

	start_logging("obexd", "OBEX daemon");
	if (debug) {
		info("Enabling debug information");
		enable_debug();
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);
	sa.sa_handler = sig_hup;
	sigaction(SIGHUP, &sa, NULL);

	sa.sa_handler = sig_debug;
	sigaction(SIGUSR2, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);

	
	/* Create event loop */
	main_loop = g_main_loop_new(NULL, FALSE);

	start_server();

	/* Start event processor */
	g_main_loop_run(main_loop);

	g_main_loop_unref(main_loop);

	g_free(config_file);

	stop_logging();

	return 0;
}
