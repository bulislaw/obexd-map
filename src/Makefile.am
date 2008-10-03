
if SERVER
confdir = $(sysconfdir)/obex

servicedir = $(datarootdir)/dbus-1/services

service_DATA = org.openobex.service

bin_PROGRAMS = obexd

obexd_SOURCES = main.c obexd.h plugin.h plugin.c manager.c \
		logging.h logging.c obex.h obex.c opp.c ftp.c \
		bluetooth.h bluetooth.c dbus.h

obexd_LDADD = @GDBUS_LIBS@ @GMODULE_LIBS@ @GLIB_LIBS@ @DBUS_LIBS@ \
					@OPENOBEX_LIBS@ @BLUEZ_LIBS@
endif

if MAINTAINER_MODE
plugindir = $(abs_top_srcdir)/plugins
else
plugindir = $(libdir)/obex/plugins
endif

AM_CFLAGS = @OPENOBEX_CFLAGS@ @GLIB_CFLAGS@ @GMODULE_CFLAGS@ \
			@BLUEZ_CFLAGS@ @DBUS_CFLAGS@ @GDBUS_CFLAGS@ \
					-DPLUGINDIR=\""$(plugindir)"\"

EXTRA_DIST = simple-agent

MAINTAINERCLEANFILES = Makefile.in
