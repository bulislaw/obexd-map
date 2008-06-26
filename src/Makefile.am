
servicedir = $(datarootdir)/dbus-1/services

confdir = $(sysconfdir)/obex

service_DATA = org.openobex.service

bin_PROGRAMS = obexd

obexd_SOURCES = main.c obexd.h manager.c \
				logging.h logging.c obex.h obex.c \
				opp.c ftp.c bluetooth.h bluetooth.c \
				dbus.h

obexd_LDADD = @GDBUS_LIBS@ @GLIB_LIBS@ @DBUS_LIBS@ \
				@OPENOBEX_LIBS@ @BLUEZ_LIBS@

AM_CFLAGS = @GDBUS_CFLAGS@ @GLIB_CFLAGS@ @DBUS_CFLAGS@ \
				@BLUEZ_CFLAGS@ @OPENOBEX_CFLAGS@

MAINTAINERCLEANFILES = Makefile.in
