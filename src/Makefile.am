
sbin_PROGRAMS = obexd

obexd_SOURCES = main.c logging.h logging.c opp.c ftp.c obex.h obex.c \
						bluetooth.h bluetooth.c

obexd_LDADD = @BLUEZ_LIBS@ @DBUS_LIBS@ @GDBUS_LIBS@ @GLIB_LIBS@ @OPENOBEX_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@ @GLIB_CFLAGS@ @DBUS_CFLAGS@ @GDBUS_CFLAGS@ @OPENOBEX_CFLAGS@

MAINTAINERCLEANFILES = Makefile.in
