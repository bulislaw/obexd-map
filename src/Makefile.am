
if SERVER
confdir = $(sysconfdir)/obex

servicedir = $(datarootdir)/dbus-1/services

service_in_files = obexd.service.in

service_DATA = $(service_in_files:.service.in=.service)

libexec_PROGRAMS = obexd

obexd_SOURCES = main.c obexd.h plugin.h plugin.c manager.c btio.h btio.c \
		logging.h logging.c obex.h obex.c opp.c ftp.c pbap.c \
		bluetooth.h bluetooth.c phonebook.h phonebook.c dbus.h

obexd_LDADD = @GDBUS_LIBS@ @DBUS_LIBS@ @GLIB_LIBS@ @GTHREAD_LIBS@ \
					@OPENOBEX_LIBS@ @BLUEZ_LIBS@ -ldl

obexd_LDFLAGS = -Wl,--export-dynamic
endif

if MAINTAINER_MODE
plugindir = $(abs_top_srcdir)/plugins/.libs
else
plugindir = $(libdir)/obex/plugins
endif

AM_CFLAGS = @OPENOBEX_CFLAGS@ @BLUEZ_CFLAGS@ \
		@GTHREAD_CFLAGS@ @GLIB_CFLAGS@ @DBUS_CFLAGS@ @GDBUS_CFLAGS@ \
						-DPLUGINDIR=\""$(plugindir)"\"

CLEANFILES = $(service_DATA)

EXTRA_DIST = $(service_in_files)

MAINTAINERCLEANFILES = Makefile.in

AUTOMAKE_OPTIONS = -Wno-portability

%.service: %.service.in ../config.log
	$(AM_V_GEN)sed -e "s|\@libexecdir\@|$(libexecdir)|" $< > $@
