
noinst_PROGRAMS = obex-test

obex_test_SOURCES = main.c

obex_test_LDADD = @GWOBEX_LIBS@ @OPENOBEX_LIBS@ @BLUEZ_LIBS@ @GLIB_LIBS@

AM_CFLAGS = @GLIB_CFLAGS@ @BLUEZ_CFLAGS@ @OPENOBEX_CFLAGS@ @GWOBEX_CFLAGS@

EXTRA_DIST = send-files pull-business-card exchange-business-cards \
				list-folders pbap-client simple-agent

MAINTAINERCLEANFILES = Makefile.in
