dnl Process this file with autoconf to produce a configure script.

# Copyright (C) 2003 Simon Josefsson.
#
# This file is part of the Generic Security Service (GSS).
#
# GSS is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2, or (at your option) any later
# version.
#
# GSS is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GSS; see the file COPYING.  If not, write to the Free
# Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

AC_PREREQ(2.59)
AC_INIT([gss], [0.0.7], [bug-gss@gnu.org])

# Library code modified:                              REVISION++
# Interfaces changed/added/removed:   CURRENT++       REVISION=0
# Interfaces added:                             AGE++
# Interfaces removed:                           AGE=0
LT_CURRENT=0
LT_REVISION=7
LT_AGE=0
AC_SUBST(LT_CURRENT)
AC_SUBST(LT_REVISION)
AC_SUBST(LT_AGE)

AM_INIT_AUTOMAKE(gnits)
AC_CONFIG_HEADERS(config.h)

# Checks for programs.
AM_GNU_GETTEXT(external)
AM_GNU_GETTEXT_VERSION(0.12.1)
AC_PROG_CC
AC_PROG_LIBTOOL

# Checks for header files.
AC_HEADER_STDC

# For gnulib stuff in gl/.
gl_FUNC_GETHOSTNAME

# Test for Shishi.
sj_CHECK_HEADERLIB(shishi.h, shishi, shishi_check_version,
	kerberos5=yes, kerberos5=no)
AC_ARG_ENABLE(kerberos5,
	AS_HELP_STRING([--disable-kerberos5],
		[disable Kerberos V5 mechanism unconditionally]),
	kerberos5=$enableval)
if test "$kerberos5" != "no" ; then
	AC_DEFINE(USE_KERBEROS5, 1, [Define to 1 if you want Kerberos 5 mech.])
	INCLUDE_GSS_KRB5='#include <gss/krb5.h>'
fi
AC_MSG_CHECKING([if the Kerberos V5 mechanism should be supported])
AC_MSG_RESULT($kerberos5)
AM_CONDITIONAL(KRB5, test "$kerberos5" = "yes")
AC_SUBST(INCLUDE_GSS_KRB5)

# We are done.
AC_CONFIG_FILES(Makefile gss.pc lib/gss.h po/Makefile.in \
		doc/Makefile gl/Makefile lib/Makefile tests/Makefile)
AC_OUTPUT
