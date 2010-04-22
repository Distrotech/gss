dnl Process this file with autoconf to produce a configure script.

# Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010  Simon Josefsson
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
AC_INIT([GNU Generic Security Service], [1.0.1], [bug-gss@gnu.org], [gss])

# Library code modified:                              REVISION++
# Interfaces changed/added/removed:   CURRENT++       REVISION=0
# Interfaces added:                             AGE++
# Interfaces removed:                           AGE=0
AC_SUBST(LT_CURRENT, 3)
AC_SUBST(LT_REVISION, 1)
AC_SUBST(LT_AGE, 0)

# Used when creating libgss-XX.def.
DLL_VERSION=`expr ${LT_CURRENT} - ${LT_AGE}`
AC_SUBST(DLL_VERSION)

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.10 -Wall -Werror -Wno-override])
AC_CONFIG_HEADERS(config.h)

# Checks for programs.
AC_PROG_CC
gl_EARLY
libgl_EARLY
srcgl_EARLY
AC_LIBTOOL_WIN32_DLL
AC_PROG_LIBTOOL
AM_MISSING_PROG(PERL, perl, $missing_dir)
AM_MISSING_PROG(HELP2MAN, help2man, $missing_dir)

# Internationalization.
AM_GNU_GETTEXT(external)
AM_GNU_GETTEXT_VERSION(0.17)

# For gnulib stuff.
gl_INIT
libgl_INIT
srcgl_INIT

# For gss.h.
VERSION_MAJOR=`echo $PACKAGE_VERSION | sed 's/\(.*\)\..*\..*/\1/g'`
VERSION_MINOR=`echo $PACKAGE_VERSION | sed 's/.*\.\(.*\)\..*/\1/g'`
VERSION_PATCH=`echo $PACKAGE_VERSION | sed 's/.*\..*\.\(.*\)/\1/g'`
AC_SUBST(VERSION_MAJOR)
AC_SUBST(VERSION_MINOR)
AC_SUBST(VERSION_PATCH)
VERSION_NUMBER=`printf "0x%02x%02x%02x" $VERSION_MAJOR $VERSION_MINOR $VERSION_PATCH`
AC_SUBST(VERSION_NUMBER)

# Test for Shishi.
AC_ARG_ENABLE(kerberos5,
  AC_HELP_STRING([--disable-kerberos5],
    [disable Kerberos V5 mechanism unconditionally]),
  kerberos5=$enableval)
if test "$kerberos5" != "no" ; then
  AC_LIB_HAVE_LINKFLAGS(shishi,, [#include <shishi.h>],
                        [shishi_key_timestamp (0);])
  if test "$ac_cv_libshishi" = yes; then
    AC_DEFINE([USE_KERBEROS5], 1, [Define to 1 if you want Kerberos 5 mech.])
    INCLUDE_GSS_KRB5='# include <gss/krb5.h>'
    INCLUDE_GSS_KRB5_EXT='# include <gss/krb5-ext.h>'
    kerberos5=yes
  else
    kerberos5=no
  fi
fi
AC_MSG_CHECKING([if the Kerberos V5 mechanism should be supported])
AC_MSG_RESULT($kerberos5)
AM_CONDITIONAL(KRB5, test "$kerberos5" = "yes")
AC_SUBST(INCLUDE_GSS_KRB5)
AC_SUBST(INCLUDE_GSS_KRB5_EXT)

# Check for gtk-doc.
GTK_DOC_CHECK(1.1)

sj_VALGRIND
sj_PO_SUFFIX($DLL_VERSION)

AC_ARG_ENABLE([gcc-warnings],
  [AS_HELP_STRING([--enable-gcc-warnings],
		  [turn on lots of GCC warnings (for developers)])],
  [case $enableval in
     yes|no) ;;
     *)      AC_MSG_ERROR([bad value $enableval for gcc-warnings option]) ;;
   esac
   gl_gcc_warnings=$enableval],
  [gl_gcc_warnings=no]
)

if test "$gl_gcc_warnings" = yes; then
  gl_WARN_ADD([-Werror], [WERROR_CFLAGS])

  nw="$nw -Wsystem-headers"            # Ignore errors in system headers
  nw="$nw -Wc++-compat"                # We don't care much about C++ compilers
  nw="$nw -Wconversion"                # Too many warnings for now
  nw="$nw -Wsign-conversion"           # Too many warnings for now
  nw="$nw -Wcast-qual"                 # Too many warnings for now
  nw="$nw -Wtraditional"               # Warns on #elif which we use often
  nw="$nw -Wunreachable-code"          # False positive on strcmp

  gl_MANYWARN_ALL_GCC([ws])
  gl_MANYWARN_COMPLEMENT(ws, [$ws], [$nw])
  for w in $ws; do
    gl_WARN_ADD([$w])
  done

  gl_WARN_ADD([-Wno-unused-parameter])
  gl_WARN_ADD([-Wno-stack-protector])  # Some functions cannot be protected
  gl_WARN_ADD([-fdiagnostics-show-option])
fi

AC_CONFIG_FILES([
  Makefile
  gss.pc
  doc/Makefile
  doc/cyclo/Makefile
  doc/reference/Makefile
  gl/Makefile
  lib/Makefile
  lib/gl/Makefile
  lib/headers/gss.h
  lib/krb5/Makefile
  po/Makefile.in
  po/Makevars
  src/Makefile
  src/gl/Makefile
  tests/Makefile
])
AC_OUTPUT

AC_MSG_NOTICE([summary of build options:

  version:            ${VERSION} shared $LT_CURRENT:$LT_REVISION:$LT_AGE
  Host type:          ${host}
  Install prefix:     ${prefix}
  Compiler:           ${CC}
  Warning flags:      errors: ${WERROR_CFLAGS} warnings: ${WARN_CFLAGS}
  Library types:      Shared=${enable_shared}, Static=${enable_static}
  Version script:     $have_ld_version_script
  Enable krb5 mech:   $kerberos5
  I18n domain suffix: ${PO_SUFFIX:-none}
])
