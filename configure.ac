dnl Process this file with autoconf to produce a configure script.

# Copyright (C) 2003 Simon Josefsson.
#
# This file is part of GPL GSS-API.
#
# GPL GSS-API is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# GPL GSS-API is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GPL GSS-API; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.

AC_PREREQ(2.50)
AC_INIT(ggssapi, 0.0.0, bug-ggssapi@josefsson.org)

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
AM_MISSING_PROG(DOCBOOK2TXT, docbook2txt, $missing_dir)
AM_MISSING_PROG(DOCBOOK2HTML, docbook2html, $missing_dir)
AM_MISSING_PROG(DOCBOOK2PS, docbook2ps, $missing_dir)
AM_MISSING_PROG(DOCBOOK2PDF, docbook2pdf, $missing_dir)
AM_WITH_DMALLOC

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(sys/socket.h unistd.h strings.h netdb.h math.h limits.h)
AC_CHECK_HEADERS(sys/poll.h sys/time.h sys/types.h sys/select.h sys/socket.h)
AC_CHECK_HEADERS(netinet/in.h errno.h)

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_HEADER_TIME
AC_CHECK_DECLS(errno)

# Checks for library functions.
AC_SEARCH_LIBS(gethostbyname, xnet)

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
AC_CONFIG_FILES(Makefile po/Makefile.in m4/Makefile \
		doc/Makefile doc/reference/Makefile lib/Makefile \
		ggssapi.pc src/Makefile tests/Makefile)
AC_OUTPUT
