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

AC_PREREQ(2.50)
AC_INIT(gss, 0.0.0, bug-gss@josefsson.org)

# Interfaces removed:       CURRENT++ AGE=0 REVISION=0
# Interfaces added:         CURRENT++ AGE++ REVISION=0
# Interfaces changed:       CURRENT++       REVISION=0
# No interfaces changed:                    REVISION++
LT_CURRENT=0
LT_AGE=0
LT_REVISION=0
AC_SUBST(LT_CURRENT)
AC_SUBST(LT_AGE)
AC_SUBST(LT_REVISION)

AM_INIT_AUTOMAKE(gnits)
AM_CONFIG_HEADER(config.h)

# Checks for programs.
AM_GNU_GETTEXT(external)
AM_GNU_GETTEXT_VERSION(0.11.5)
AC_PROG_LIBTOOL
AC_PROG_CC
AM_MISSING_PROG(PERL, perl, $missing_dir)
AM_MISSING_PROG(HELP2MAN, help2man, $missing_dir)
AM_MISSING_PROG(TEXI2PDF, texi2pdf, $missing_dir)
AM_MISSING_PROG(ASN1PARSER, asn1Parser, $missing_dir)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADER(libtasn1.h,, AC_MSG_ERROR([[
You need libtasn1 from <ftp://ftp.gnutls.org/pub/gnutls/libtasn1/>.
]]))

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CHECK_LIB(tasn1, asn1_read_tag,, AC_MSG_ERROR([[
You need libtasn1 from <ftp://ftp.gnutls.org/pub/gnutls/libtasn1/>.
]]))

# Test for Shishi.
AC_ARG_ENABLE(kerberos5,
	AC_HELP_STRING([--disable-kerberos5],
                       [disable Kerberos V5 mechanism unconditionally]),
	kerberos5=$enableval)
if test "$kerberos5" != "no" ; then
	PKG_CHECK_MODULES(SHISHI, shishi >= 0.0.0, [kerberos5=yes])
	if test "$kerberos5" != "yes" ; then
		kerberos5=no
		AC_MSG_WARN([Shishi not found, required for Kerberos 5])
	else
		AC_DEFINE(USE_KERBEROS5, 1,
			[Define to 1 if you want the Kerberos 5 mechanism.])
	fi
fi
AC_MSG_CHECKING([if the Kerberos V5 mechanism should be supported])
AC_MSG_RESULT($kerberos5)

# Test if the libc includes a good enough argp.
AC_ARG_WITH(system-argp,
  AC_HELP_STRING([--without-system-argp], [Don't use the system's argp]))
if test "$with_system_argp" != "no" ; then
  AC_LIB_ARGP(,with_system_argp=no)
fi
if test "$with_system_argp" = "no" ; then
  ARGP_LIBS="\$(top_builddir)/argp/libargp.a"
  ARGP_CFLAGS="-I\$(top_srcdir)/argp"
  ARGP=argp
fi
AC_SUBST(ARGP)
AC_SUBST(ARGP_LIBS)
AC_SUBST(ARGP_CFLAGS)
AC_CONFIG_SUBDIRS(argp)

# We are done
AC_CONFIG_FILES(Makefile gss.pc lib/gss.h po/Makefile.in m4/Makefile \
		doc/Makefile lib/Makefile src/Makefile tests/Makefile)

AC_OUTPUT
