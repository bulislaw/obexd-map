AC_DEFUN([AC_INIT_OBEXD], [
	if (test "${CFLAGS}" = ""); then
		CFLAGS="-Wall -O2"
	fi

	if (test "${prefix}" = "NONE"); then
		dnl no prefix and no sysconfdir, so default to /etc
		if (test "$sysconfdir" = '${prefix}/etc'); then
			AC_SUBST([sysconfdir], ['/etc'])
		fi
	fi

	if (test "$sysconfdir" = '${prefix}/etc'); then
		configdir="${prefix}/etc/obex"
	else
		configdir="${sysconfdir}/obex"
	fi

	AC_DEFINE_UNQUOTED(CONFIGDIR, "${configdir}", [Directory for the configuration files])
])

AC_DEFUN([AC_PATH_GLIB], [
	PKG_CHECK_MODULES(GLIB, glib-2.0, glib_found=yes, glib_found=no)
	AC_SUBST(GLIB_CFLAGS)
	AC_SUBST(GLIB_LIBS)
])

AC_DEFUN([AC_PATH_BLUEZ], [
	PKG_CHECK_MODULES(BLUEZ, bluez > 3, dummy=yes, AC_MSG_ERROR(bluez > 3 is required))
	AC_SUBST(BLUEZ_CFLAGS)
	AC_SUBST(BLUEZ_LIBS)
])

AC_DEFUN([AC_PATH_DBUS], [
	PKG_CHECK_MODULES(DBUS, dbus-1 > 1, dummy=yes, AC_MSG_ERROR(dbus > 1 is required))
	AC_SUBST(DBUS_CFLAGS)
	AC_SUBST(DBUS_LIBS)
])

AC_DEFUN([AC_PATH_OPENOBEX], [
	PKG_CHECK_MODULES(OPENOBEX, openobex >= 1.3, dummy=yes, AC_MSG_ERROR(openobex >= 1.3 is required))
	AC_SUBST(OPENOBEX_CFLAGS)
	AC_SUBST(OPENOBEX_LIBS)
])

AC_DEFUN([AC_ARG_OBEXD], [
	debug_enable=no

	AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug], [enable compiling with debugging information]), [
		debug_enable=${enableval}
	])

	if (test "${debug_enable}" = "yes" && test "${ac_cv_prog_cc_g}" = "yes"); then
		CFLAGS="$CFLAGS -O0"
	fi

	AC_SUBST([GDBUS_CFLAGS], ['-I$(top_srcdir)/gdbus'])
	AC_SUBST([GDBUS_LIBS], ['$(top_builddir)/gdbus/libgdbus.la'])
])
