
if CLIENT
servicedir = $(datarootdir)/dbus-1/services

service_in_files = obex-client.service.in

service_DATA = $(service_in_files:.service.in=.service)

libexec_PROGRAMS = obex-client

obex_client_SOURCES = main.c session.h session.c pbap.h pbap.c sync.h sync.c

obex_client_LDADD = @GWOBEX_LIBS@ @GDBUS_LIBS@ @GLIB_LIBS@ @DBUS_LIBS@ \
						@OPENOBEX_LIBS@ @BLUEZ_LIBS@
endif

AM_CFLAGS = @OPENOBEX_CFLAGS@ @GLIB_CFLAGS@ @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ \
						@GDBUS_CFLAGS@ @GWOBEX_CFLAGS@

CLEANFILES = $(service_DATA)

EXTRA_DIST = $(service_in_files)

MAINTAINERCLEANFILES = Makefile.in

AUTOMAKE_OPTIONS = -Wno-portability

%.service: %.service.in ../config.log
	$(AM_V_GEN)sed -e "s|\@libexecdir\@|$(libexecdir)|" $< > $@
