
plugindir = $(libdir)/obex/plugins

plugin_LTLIBRARIES =

if EBOOK
plugin_LTLIBRARIES += ebook.la

ebook_la_SOURCES = ebook.c
ebook_la_LIBADD = @EBOOK_LIBS@
ebook_la_CFLAGS = @EBOOK_CFLAGS@
endif

AM_LDFLAGS = -no-undefined -module -avoid-version

AM_CFLAGS = -fvisibility=hidden

INCLUDES = -I$(top_srcdir)/src

MAINTAINERCLEANFILES = Makefile.in
