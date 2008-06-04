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

#include "obexd.h"

static GMainLoop *main_loop = NULL;

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
		"\t-h, --help           Display help\n"
		"\n");
}

static struct option options[] = {
	{ "nodaemon", 0, 0, 'n' },
	{ "debug",    0, 0, 'd' },
	{ "help",     0, 0, 'h' },
	{ }
};

int main(int argc, char *argv[])
{
	DBusConnection *conn;
	struct sigaction sa;
	int log_option = LOG_NDELAY | LOG_PID;
	int opt, detach = 1, debug = 0;

	while ((opt = getopt_long(argc, argv, "+ndh", options, NULL)) != EOF) {
		switch(opt) {
		case 'n':
			detach = 0;
			break;
		case 'd':
			debug = 1;
			break;
		case 'h':
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

	main_loop = g_main_loop_new(NULL, FALSE);

	conn = g_dbus_setup_bus(DBUS_BUS_SESSION, OPENOBEX_SERVICE, NULL);
	if (conn == NULL) {
		fprintf(stderr, "Can't register with session bus\n");
		exit(1);
	}

	manager_init(conn);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	g_main_loop_run(main_loop);

	manager_cleanup();

	g_dbus_cleanup_connection(conn);

	g_main_loop_unref(main_loop);

	closelog();

	return 0;
}
