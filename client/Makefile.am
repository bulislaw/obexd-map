
servicedir = $(datarootdir)/dbus-1/services

service_DATA = org.openobex.client.service

bin_PROGRAMS = obex-client

obex_client_SOURCES = main.c

obex_client_LDADD = @GWOBEX_LIBS@ @GDBUS_LIBS@ @GLIB_LIBS@ @DBUS_LIBS@ \
						@OPENOBEX_LIBS@ @BLUEZ_LIBS@

AM_CFLAGS = @OPENOBEX_CFLAGS@ @GLIB_CFLAGS@ @BLUEZ_CFLAGS@ @DBUS_CFLAGS@ \
						@GDBUS_CFLAGS@ @GWOBEX_CFLAGS@

MAINTAINERCLEANFILES = Makefile.in
