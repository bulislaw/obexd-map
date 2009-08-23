
AM_MAKEFLAGS = --no-print-directory

servicedir = $(datarootdir)/dbus-1/services

service_in_files =

doc_files = doc/obexd-api.txt doc/agent-api.txt doc/client-api.txt

test_files = test/simple-agent test/send-files \
		test/pull-business-card test/exchange-business-cards \
		test/list-folders test/pbap-client test/ftp-client

gdbus_sources = gdbus/gdbus.h gdbus/mainloop.c gdbus/object.c gdbus/watch.c

gwobex_sources = gwobex/gw-obex.h gwobex/gw-obex.c \
			gwobex/obex-priv.h gwobex/obex-priv.c \
			gwobex/obex-xfer.h gwobex/obex-xfer.c \
			gwobex/utils.h gwobex/utils.c gwobex/log.h

libexec_PROGRAMS =

if SERVER
confdir = $(sysconfdir)/obex

service_in_files += src/obexd.service.in

libexec_PROGRAMS += src/obexd

src_obexd_SOURCES = $(gdbus_sources) \
			src/main.c src/obexd.h src/plugin.h src/plugin.c \
			src/logging.h src/logging.c src/btio.h src/btio.c \
			src/dbus.h src/manager.c src/obex.h src/obex.c \
			src/opp.c src/ftp.c src/pbap.c \
			src/bluetooth.h src/bluetooth.c \
			src/phonebook.h src/phonebook.c

src_obexd_LDADD = @DBUS_LIBS@ @GLIB_LIBS@ @GTHREAD_LIBS@ \
					@OPENOBEX_LIBS@ @BLUEZ_LIBS@ -ldl

src_obexd_LDFLAGS = -Wl,--export-dynamic

plugindir = $(libdir)/obex/plugins

plugin_LTLIBRARIES =

if EBOOK
plugin_LTLIBRARIES += plugins/ebook.la

plugins_ebook_la_SOURCES = plugins/ebook.c

plugins_ebook_la_LIBADD = @EBOOK_LIBS@

plugins_ebook_la_CFLAGS = -fvisibility=hidden @EBOOK_CFLAGS@
plugins_ebook_la_LDFLAGS = -no-undefined -module -avoid-version
endif

noinst_PROGRAMS = test/obex-test

test_obex_test_SOURCES = $(gwobex_sources) test/main.c

test_obex_test_LDADD = @OPENOBEX_LIBS@ @BLUEZ_LIBS@ @GLIB_LIBS@
endif

if CLIENT
service_in_files += client/obex-client.service.in

libexec_PROGRAMS += client/obex-client

client_obex_client_SOURCES = $(gdbus_sources) $(gwobex_sources) client/main.c \
				client/session.h client/session.c \
				client/pbap.h client/pbap.c \
				client/sync.h client/sync.c

client_obex_client_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ @OPENOBEX_LIBS@ @BLUEZ_LIBS@
endif

service_DATA = $(service_in_files:.service.in=.service)

AM_CFLAGS = @OPENOBEX_CFLAGS@ @BLUEZ_CFLAGS@ \
				@GTHREAD_CFLAGS@ @GLIB_CFLAGS@ @DBUS_CFLAGS@ \
						-DPLUGINDIR=\""$(plugindir)"\"

INCLUDES = -I$(top_srcdir)/gdbus -I$(top_srcdir)/gwobex -I$(top_srcdir)/src

CLEANFILES = $(service_DATA)

EXTRA_DIST = $(doc_files) $(test_files) src/obex.conf \
			src/obexd.service.in client/obex-client.service.in

DISTCHECK_CONFIGURE_FLAGS = --enable-client --enable-server --enable-ebook

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp missing install-sh mkinstalldirs

%.service: %.service.in config.log
	$(AM_V_GEN)sed -e "s|\@libexecdir\@|$(libexecdir)|" $< > $@
