AC_PREREQ(2.60)
AC_INIT(obexd, 0.19)

AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_CONFIG_HEADER(config.h)

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_PREFIX_DEFAULT(/usr/local)

if (test "${libdir}" = '${exec_prefix}/lib'); then
	libdir="${prefix}/lib"
fi

plugindir="${libdir}/obex/plugins"

if (test "$sysconfdir" = '${prefix}/etc'); then
	configdir="${prefix}/etc/obex"
else
	configdir="${sysconfdir}/obex"
fi

AC_DEFINE_UNQUOTED(CONFIGDIR, "${configdir}",
				[Directory for the configuration files])

COMPILER_FLAGS

AC_LANG_C

AC_PROG_CC
AC_PROG_CC_PIE
AC_PROG_INSTALL
AC_PROG_SED

m4_define([_LT_AC_TAGCONFIG], [])
m4_ifdef([AC_LIBTOOL_TAGS], [AC_LIBTOOL_TAGS([])])

AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_CACHE_CHECK(for tm_gmtoff in struct tm, ac_cv_struct_tm_gmtoff,
	AC_TRY_COMPILE([
		#include <time.h>
	], [
		struct tm tm;
		tm.tm_gmtoff = 1;
	], ac_cv_struct_tm_gmtoff=yes, ac_cv_struct_tm_gmtoff=no))

if (test "$ac_cv_struct_tm_gmtoff" = "yes"); then
	AC_DEFINE(HAVE_TM_GMTOFF, 1, [Define if struct tm has a tm_gmtoff member])
fi

AC_CACHE_CHECK(for timezone variable, ac_cv_var_timezone,
	AC_TRY_COMPILE([
		#include <time.h>
	], [
		timezone = 1;
	], ac_cv_var_timezone=yes, ac_cv_var_timezone=no))

if (test "$ac_cv_var_timezone" = "yes"); then
	AC_DEFINE(HAVE_TIMEZONE, 1, [Define if libc defines a timezone variable])
fi

AC_CHECK_LIB(dl, dlopen, dummy=yes,
			AC_MSG_ERROR(dynamic linking loader is required))

PKG_CHECK_MODULES(GLIB, glib-2.0 >= 2.16, dummy=yes,
				AC_MSG_ERROR(libglib 2.16 or later is required))
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

PKG_CHECK_MODULES(DBUS, dbus-1, dummy=yes,
				AC_MSG_ERROR(libdbus-1 is required))
AC_CHECK_LIB(dbus-1, dbus_watch_get_unix_fd, dummy=yes,
	AC_DEFINE(NEED_DBUS_WATCH_GET_UNIX_FD, 1,
		[Define to 1 if you need the dbus_watch_get_unix_fd() function.]))
AC_SUBST(DBUS_CFLAGS)
AC_SUBST(DBUS_LIBS)

PKG_CHECK_MODULES(OPENOBEX, openobex, dummy=yes,
				AC_MSG_ERROR(libopenobex is required))
AC_SUBST(OPENOBEX_CFLAGS)
AC_SUBST(OPENOBEX_LIBS)

PKG_CHECK_MODULES(BLUEZ, bluez, dummy=yes,
				AC_MSG_ERROR(libbluetooth is required))
AC_SUBST(BLUEZ_CFLAGS)
AC_SUBST(BLUEZ_LIBS)

AC_ARG_ENABLE(optimization, AC_HELP_STRING([--disable-optimization],
			[disable code optimization through compiler]), [
	if (test "${enableval}" = "no"); then
		CFLAGS="$CFLAGS -O0"
	fi
])

AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug],
			[enable compiling with debugging information]), [
	if (test "${enableval}" = "yes" && test "${ac_cv_prog_cc_g}" = "yes"); then
		CFLAGS="$CFLAGS -g"
	fi
])

phonebook_driver=dummy
AC_ARG_WITH(phonebook, AC_HELP_STRING([--with-phonebook=DRIVER], [select phonebook driver]), [
	phonebook_driver=${withval}
])

if (test "${phonebook_driver}" = "ebook"); then
	AC_DEFINE(NEED_THREADS, 1, [Define if threading support is required])

	PKG_CHECK_MODULES(EBOOK, libebook-1.2, dummy=yes,
					AC_MSG_ERROR(libebook is required))
	AC_SUBST(EBOOK_CFLAGS)
	AC_SUBST(EBOOK_LIBS)

	PKG_CHECK_MODULES(GTHREAD, gthread-2.0, dummy=yes,
					AC_MSG_ERROR(libgthread is required))
	AC_SUBST(GTHREAD_CFLAGS)
	AC_SUBST(GTHREAD_LIBS)
fi

AC_SUBST([PHONEBOOK_DRIVER], [phonebook-${phonebook_driver}.c])

telephony_driver=dummy
AC_ARG_WITH(telephony, AC_HELP_STRING([--with-telephony=DRIVER], [select telephony driver]), [
	telephony_driver=${withval}
])

AC_SUBST([TELEPHONY_DRIVER], [telephony-${telephony_driver}.c])

AC_ARG_ENABLE(server, AC_HELP_STRING([--disable-server],
				[disable compilation of OBEX server]), [
	enable_server=${enableval}
])
AM_CONDITIONAL(SERVER, test "${enable_server}" != "no")

AC_ARG_ENABLE(client, AC_HELP_STRING([--disable-client],
				[disable compilation of OBEX client]), [
	enable_client=${enableval}
])
AM_CONDITIONAL(CLIENT, test "${enable_client}" != "no")

AC_OUTPUT(Makefile)
