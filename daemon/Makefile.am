sbin_PROGRAMS = obexd

obexd_SOURCES = opp.c ftp.c obex.h obex.c bluetooth.h bluetooth.c main.c

obexd_LDADD = $(top_builddir)/common/liblogging.a \
		@BLUEZ_LIBS@ @DBUS_LIBS@ @GDBUS_LIBS@ @GLIB_LIBS@ @OPENOBEX_LIBS@

AM_CFLAGS = @BLUEZ_CFLAGS@ @GLIB_CFLAGS@ @DBUS_CFLAGS@ @GDBUS_CFLAGS@ @OPENOBEX_CFLAGS@

INCLUDES = -I$(top_srcdir)/common

EXTRA_DIST =

MAINTAINERCLEANFILES = Makefile.in
