
if SERVER
confdir = $(sysconfdir)/obex

servicedir = $(datarootdir)/dbus-1/services

service_in_files = obexd.service.in

service_DATA = $(service_in_files:.service.in=.service)

libexec_PROGRAMS = obexd

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

CLEANFILES = $(service_DATA)

EXTRA_DIST = $(service_in_files)

MAINTAINERCLEANFILES = Makefile.in

%.service: %.service.in ../config.log
	sed -e "s|\@libexecdir\@|$(libexecdir)|" $< > $@
