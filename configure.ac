dnl Process this file with autoconf to produce a configure script.

# Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008 Simon Josefsson.
#
# This file is part of the Generic Security Service (GSS).
#
# GSS is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 3 of the License, or (at your
# option) any later version.
#
# GSS is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GSS; if not, see http://www.gnu.org/licenses or write to
# the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
# Boston, MA 02110-1301, USA.

AC_PREREQ(2.61)
AC_INIT([gss], [0.0.24], [bug-gss@gnu.org])
AC_CONFIG_AUX_DIR([build-aux])

# Library code modified:                              REVISION++
# Interfaces changed/added/removed:   CURRENT++       REVISION=0
# Interfaces added:                             AGE++
# Interfaces removed:                           AGE=0
AC_SUBST(LT_CURRENT, 0)
AC_SUBST(LT_REVISION, 24)
AC_SUBST(LT_AGE, 0)

AM_INIT_AUTOMAKE([1.10])
AC_CONFIG_HEADERS(config.h)

# Checks for programs.
AC_PROG_CC
gl_EARLY
AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL
AM_MISSING_PROG(PERL, perl, $missing_dir)
AM_MISSING_PROG(HELP2MAN, help2man, $missing_dir)

# Internationalization.
AM_GNU_GETTEXT(external)
AM_GNU_GETTEXT_VERSION(0.17)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(locale.h)

# For gnulib stuff in gl/.
gl_INIT
AC_DEFINE([xalloc_die], [gss_xalloc_die], [Fix namespace of xalloc_die.])

# Test for Shishi.
AC_ARG_ENABLE(kerberos5,
  AC_HELP_STRING([--disable-kerberos5],
    [disable Kerberos V5 mechanism unconditionally]),
  kerberos5=$enableval)
if test "$kerberos5" != "no" ; then
  AC_LIB_HAVE_LINKFLAGS(shishi,, [#include <shishi.h>], [shishi ();])
  if test "$ac_cv_libshishi" = yes; then
    AC_DEFINE(USE_KERBEROS5, 1, [Define to 1 if you want Kerberos 5 mech.])
    INCLUDE_GSS_KRB5='#include <gss/krb5.h>'
    kerberos5=yes
  else
    kerberos5=no
  fi
fi
AC_MSG_CHECKING([if the Kerberos V5 mechanism should be supported])
AC_MSG_RESULT($kerberos5)
AM_CONDITIONAL(KRB5, test "$kerberos5" = "yes")
AC_SUBST(INCLUDE_GSS_KRB5)

# Check for gtk-doc.
GTK_DOC_CHECK(1.1)

# We are done.
AC_CONFIG_FILES(Makefile gss.pc lib/gss.h po/Makefile.in \
		doc/Makefile doc/reference/Makefile \
		gl/Makefile lib/Makefile src/Makefile tests/Makefile \
		lib/krb5/Makefile)
AC_OUTPUT
