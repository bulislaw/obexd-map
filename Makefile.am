
AM_MAKEFLAGS = --no-print-directory

servicedir = $(datarootdir)/dbus-1/services

service_in_files =

doc_files = doc/obexd-api.txt doc/agent-api.txt doc/client-api.txt

test_files = test/simple-agent test/send-files \
		test/pull-business-card test/exchange-business-cards \
		test/list-folders test/pbap-client test/ftp-client \
		test/mns-client

gdbus_sources = gdbus/gdbus.h gdbus/mainloop.c gdbus/watch.c \
					gdbus/object.c gdbus/polkit.c

gwobex_sources = gwobex/gw-obex.h gwobex/gw-obex.c \
			gwobex/obex-priv.h gwobex/obex-priv.c \
			gwobex/obex-xfer.h gwobex/obex-xfer.c \
			gwobex/utils.h gwobex/utils.c gwobex/log.h

btio_sources = btio/btio.h btio/btio.c

libexec_PROGRAMS =

if SERVER
confdir = $(sysconfdir)/obex

service_in_files += src/obexd.service.in

builtin_modules =
builtin_sources =
builtin_nodist =

builtin_modules += bluetooth
builtin_sources += plugins/bluetooth.c

if USB
builtin_modules += usb
builtin_sources += plugins/usb.c
endif

builtin_modules += filesystem
builtin_sources += plugins/filesystem.c plugins/filesystem.h

if NOKIA_PCSUITE
builtin_modules += pcsuite
builtin_sources += plugins/pcsuite.c
endif

builtin_modules += opp
builtin_sources += plugins/opp.c

builtin_modules += ftp
builtin_sources += plugins/ftp.c plugins/ftp.h

builtin_modules += pbap
builtin_sources += plugins/pbap.c plugins/phonebook.h \
			plugins/vcard.h plugins/vcard.c

builtin_modules += mas
builtin_sources += plugins/mas.c plugins/messages.h \
			   plugins/bmsg.h plugins/bmsg.c \
			   plugins/bmsg_parser.h plugins/bmsg_parser.c

builtin_modules += irmc
builtin_sources += plugins/irmc.c

builtin_modules += syncevolution
builtin_sources += plugins/syncevolution.c

builtin_nodist += plugins/phonebook.c
builtin_nodist += plugins/messages.c

libexec_PROGRAMS += src/obexd

src_obexd_SOURCES = $(gdbus_sources) $(builtin_sources) $(btio_sources) \
			src/main.c src/obexd.h src/plugin.h src/plugin.c \
			src/log.h src/log.c src/dbus.h src/manager.c \
			src/obex.h src/obex.c src/obex-priv.h \
			src/mimetype.h src/mimetype.c \
			src/service.h src/service.c \
			src/transport.h src/transport.c \
			src/server.h src/server.c

if MESSAGES_QT

src_obexd_LDADD = @DBUS_LIBS@ @GLIB_LIBS@ @GTHREAD_LIBS@ \
					@EBOOK_LIBS@ @OPENOBEX_LIBS@ \
					@BLUEZ_LIBS@ @LIBICAL_LIBS@ \
					@TRACKER_LIBS@ -ldl \
					messages-qt/libmessages-qt.a \
					@QTCORE_LIBS@ @COMMHISTORY_LIBS@

else

src_obexd_LDADD = @DBUS_LIBS@ @GLIB_LIBS@ @GTHREAD_LIBS@ \
					@EBOOK_LIBS@ @OPENOBEX_LIBS@ \
					@BLUEZ_LIBS@ @LIBICAL_LIBS@ \
					@TRACKER_LIBS@ -ldl

endif

src_obexd_LDFLAGS = -Wl,--export-dynamic

builtin_files = src/builtin.h $(builtin_nodist)

nodist_src_obexd_SOURCES = $(builtin_files)

plugindir = $(libdir)/obex/plugins

plugin_LTLIBRARIES =

noinst_PROGRAMS = test/obex-test

test_obex_test_SOURCES = $(gwobex_sources) test/main.c

test_obex_test_LDADD = @OPENOBEX_LIBS@ @BLUEZ_LIBS@ @GLIB_LIBS@

src/plugin.$(OBJEXT): src/builtin.h

src/builtin.h: src/genbuiltin $(builtin_sources)
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_modules) > $@

endif

if CLIENT
service_in_files += client/obex-client.service.in

libexec_PROGRAMS += client/obex-client

client_obex_client_SOURCES = $(gdbus_sources) \
				$(gwobex_sources) $(btio_sources) \
				client/main.c src/log.h src/log.c \
				client/manager.h client/manager.c \
				client/session.h client/session.c \
				client/sync.h client/sync.c \
				client/pbap.h client/pbap.c \
				client/ftp.h client/ftp.c \
				client/opp.h client/opp.c \
				client/transfer.h client/transfer.c \
				client/agent.h client/agent.c \
				client/driver.h client/driver.c \
				client/mns.h client/mns.c

client_obex_client_LDADD = @GLIB_LIBS@ @DBUS_LIBS@ @OPENOBEX_LIBS@ @BLUEZ_LIBS@
endif

service_DATA = $(service_in_files:.service.in=.service)

AM_CFLAGS = @OPENOBEX_CFLAGS@ @BLUEZ_CFLAGS@ @EBOOK_CFLAGS@ \
			@GTHREAD_CFLAGS@ @GLIB_CFLAGS@ @DBUS_CFLAGS@ \
			@LIBICAL_CFLAGS@ -D_FILE_OFFSET_BITS=64 \
			@TRACKER_CFLAGS@ -DUSE_NICE_ABORT \
			-DOBEX_PLUGIN_BUILTIN -DPLUGINDIR=\""$(plugindir)"\"

INCLUDES = -I$(builddir)/src -I$(srcdir)/src -I$(srcdir)/plugins \
				-I$(srcdir)/gdbus -I$(srcdir)/gwobex \
				-I$(srcdir)/btio

CLEANFILES = $(service_DATA) $(builtin_files)

EXTRA_DIST = src/genbuiltin $(doc_files) $(test_files) \
			src/obexd.service.in client/obex-client.service.in \
			plugins/phonebook-dummy.c plugins/phonebook-ebook.c \
			plugins/phonebook-tracker.c \
			plugins/messages-dummy.c plugins/messages-tracker.c \
			messages-qt/messages-qt.pro messages-qt/messages-qt.cpp \
			messages-qt/Makefile

if MESSAGES_QT
SUBDIRS = messages-qt
endif

DISTCHECK_CONFIGURE_FLAGS = --enable-client --enable-server

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs

%.service: %.service.in config.log
	$(AM_V_GEN)$(SED) -e "s|\@libexecdir\@|$(libexecdir)|" $< > $@

plugins/phonebook.c: plugins/@PHONEBOOK_DRIVER@
	$(AM_V_GEN)$(LN_S) @abs_top_srcdir@/$< $@

plugins/messages.c: plugins/@MESSAGES_DRIVER@
	$(AM_V_GEN)$(LN_S) @abs_top_srcdir@/$< $@
