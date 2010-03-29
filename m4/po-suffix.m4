# po-suffix.m4 serial 1
dnl Copyright (C) 2010 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl From Simon Josefsson

# sj_PO_SUFFIX()
# --------------
# Allow user to add a suffix to translation domain, to get better
# co-installability of shared libraries.
AC_DEFUN([sj_PO_SUFFIX],
[
  AC_MSG_CHECKING([for gettext translation domain suffix to use])
  AC_ARG_WITH([po-suffix],
    AC_HELP_STRING([--with-po-suffix=STR],
      [add suffix to gettext translation domain]),
    po_suffix=$withval, po_suffix=no)
  if test "$po_suffix" = "yes"; then
    PO_SUFFIX=$1
  elif test "$po_suffix" != "no" ; then
    PO_SUFFIX=$po_suffix
  fi
  if test -n "$PO_SUFFIX"; then
    AC_MSG_RESULT([$PO_SUFFIX])
  else
    AC_MSG_RESULT([none])
  fi

  AC_SUBST([PO_SUFFIX])
  AC_DEFINE_UNQUOTED([PO_SUFFIX], "$PO_SUFFIX",
                     [Gettext translation domain suffix.])
])
