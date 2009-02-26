# DO NOT EDIT! GENERATED AUTOMATICALLY!
# Copyright (C) 2002-2009 Free Software Foundation, Inc.
#
# This file is free software, distributed under the terms of the GNU
# General Public License.  As a special exception to the GNU General
# Public License, this file may be distributed as part of a program
# that contains a configuration script generated by Autoconf, under
# the same distribution terms as the rest of that program.
#
# Generated by gnulib-tool.
#
# This file represents the compiled summary of the specification in
# gnulib-cache.m4. It lists the computed macro invocations that need
# to be invoked from configure.ac.
# In projects using CVS, this file can be treated like other built files.


# This macro should be invoked from ./configure.ac, in the section
# "Checks for programs", right after AC_PROG_CC, and certainly before
# any checks for libraries, header files, types and library functions.
AC_DEFUN([srcgl_EARLY],
[
  m4_pattern_forbid([^gl_[A-Z]])dnl the gnulib macro namespace
  m4_pattern_allow([^gl_ES$])dnl a valid locale name
  m4_pattern_allow([^gl_LIBOBJS$])dnl a variable
  m4_pattern_allow([^gl_LTLIBOBJS$])dnl a variable
  AC_REQUIRE([AC_PROG_RANLIB])
  dnl Some compilers (e.g., AIX 5.3 cc) need to be in c99 mode
  dnl for the builtin va_copy to work.  With Autoconf 2.60 or later,
  dnl AC_PROG_CC_STDC arranges for this.  With older Autoconf AC_PROG_CC_STDC
  dnl shouldn't hurt, though installers are on their own to set c99 mode.
  AC_REQUIRE([AC_PROG_CC_STDC])
])

# This macro should be invoked from ./configure.ac, in the section
# "Check for header files, types and library functions".
AC_DEFUN([srcgl_INIT],
[
  AM_CONDITIONAL([GL_COND_LIBTOOL], [true])
  gl_cond_libtool=true
  m4_pushdef([AC_LIBOBJ], m4_defn([srcgl_LIBOBJ]))
  m4_pushdef([AC_REPLACE_FUNCS], m4_defn([srcgl_REPLACE_FUNCS]))
  m4_pushdef([AC_LIBSOURCES], m4_defn([srcgl_LIBSOURCES]))
  m4_pushdef([srcgl_LIBSOURCES_LIST], [])
  m4_pushdef([srcgl_LIBSOURCES_DIR], [])
  gl_COMMON
  gl_source_base='src/gl'
  AC_SUBST([LIBINTL])
  AC_SUBST([LTLIBINTL])
  gl_STDARG_H
  m4_ifval(srcgl_LIBSOURCES_LIST, [
    m4_syscmd([test ! -d ]m4_defn([srcgl_LIBSOURCES_DIR])[ ||
      for gl_file in ]srcgl_LIBSOURCES_LIST[ ; do
        if test ! -r ]m4_defn([srcgl_LIBSOURCES_DIR])[/$gl_file ; then
          echo "missing file ]m4_defn([srcgl_LIBSOURCES_DIR])[/$gl_file" >&2
          exit 1
        fi
      done])dnl
      m4_if(m4_sysval, [0], [],
        [AC_FATAL([expected source file, required through AC_LIBSOURCES, not found])])
  ])
  m4_popdef([srcgl_LIBSOURCES_DIR])
  m4_popdef([srcgl_LIBSOURCES_LIST])
  m4_popdef([AC_LIBSOURCES])
  m4_popdef([AC_REPLACE_FUNCS])
  m4_popdef([AC_LIBOBJ])
  AC_CONFIG_COMMANDS_PRE([
    srcgl_libobjs=
    srcgl_ltlibobjs=
    if test -n "$srcgl_LIBOBJS"; then
      # Remove the extension.
      sed_drop_objext='s/\.o$//;s/\.obj$//'
      for i in `for i in $srcgl_LIBOBJS; do echo "$i"; done | sed "$sed_drop_objext" | sort | uniq`; do
        srcgl_libobjs="$srcgl_libobjs $i.$ac_objext"
        srcgl_ltlibobjs="$srcgl_ltlibobjs $i.lo"
      done
    fi
    AC_SUBST([srcgl_LIBOBJS], [$srcgl_libobjs])
    AC_SUBST([srcgl_LTLIBOBJS], [$srcgl_ltlibobjs])
  ])
  gltests_libdeps=
  gltests_ltlibdeps=
  m4_pushdef([AC_LIBOBJ], m4_defn([srcgltests_LIBOBJ]))
  m4_pushdef([AC_REPLACE_FUNCS], m4_defn([srcgltests_REPLACE_FUNCS]))
  m4_pushdef([AC_LIBSOURCES], m4_defn([srcgltests_LIBSOURCES]))
  m4_pushdef([srcgltests_LIBSOURCES_LIST], [])
  m4_pushdef([srcgltests_LIBSOURCES_DIR], [])
  gl_COMMON
  gl_source_base='src/gl/tests'
  m4_ifval(srcgltests_LIBSOURCES_LIST, [
    m4_syscmd([test ! -d ]m4_defn([srcgltests_LIBSOURCES_DIR])[ ||
      for gl_file in ]srcgltests_LIBSOURCES_LIST[ ; do
        if test ! -r ]m4_defn([srcgltests_LIBSOURCES_DIR])[/$gl_file ; then
          echo "missing file ]m4_defn([srcgltests_LIBSOURCES_DIR])[/$gl_file" >&2
          exit 1
        fi
      done])dnl
      m4_if(m4_sysval, [0], [],
        [AC_FATAL([expected source file, required through AC_LIBSOURCES, not found])])
  ])
  m4_popdef([srcgltests_LIBSOURCES_DIR])
  m4_popdef([srcgltests_LIBSOURCES_LIST])
  m4_popdef([AC_LIBSOURCES])
  m4_popdef([AC_REPLACE_FUNCS])
  m4_popdef([AC_LIBOBJ])
  AC_CONFIG_COMMANDS_PRE([
    srcgltests_libobjs=
    srcgltests_ltlibobjs=
    if test -n "$srcgltests_LIBOBJS"; then
      # Remove the extension.
      sed_drop_objext='s/\.o$//;s/\.obj$//'
      for i in `for i in $srcgltests_LIBOBJS; do echo "$i"; done | sed "$sed_drop_objext" | sort | uniq`; do
        srcgltests_libobjs="$srcgltests_libobjs $i.$ac_objext"
        srcgltests_ltlibobjs="$srcgltests_ltlibobjs $i.lo"
      done
    fi
    AC_SUBST([srcgltests_LIBOBJS], [$srcgltests_libobjs])
    AC_SUBST([srcgltests_LTLIBOBJS], [$srcgltests_ltlibobjs])
  ])
])

# Like AC_LIBOBJ, except that the module name goes
# into srcgl_LIBOBJS instead of into LIBOBJS.
AC_DEFUN([srcgl_LIBOBJ], [
  AS_LITERAL_IF([$1], [srcgl_LIBSOURCES([$1.c])])dnl
  srcgl_LIBOBJS="$srcgl_LIBOBJS $1.$ac_objext"
])

# Like AC_REPLACE_FUNCS, except that the module name goes
# into srcgl_LIBOBJS instead of into LIBOBJS.
AC_DEFUN([srcgl_REPLACE_FUNCS], [
  m4_foreach_w([gl_NAME], [$1], [AC_LIBSOURCES(gl_NAME[.c])])dnl
  AC_CHECK_FUNCS([$1], , [srcgl_LIBOBJ($ac_func)])
])

# Like AC_LIBSOURCES, except the directory where the source file is
# expected is derived from the gnulib-tool parameterization,
# and alloca is special cased (for the alloca-opt module).
# We could also entirely rely on EXTRA_lib..._SOURCES.
AC_DEFUN([srcgl_LIBSOURCES], [
  m4_foreach([_gl_NAME], [$1], [
    m4_if(_gl_NAME, [alloca.c], [], [
      m4_define([srcgl_LIBSOURCES_DIR], [src/gl])
      m4_append([srcgl_LIBSOURCES_LIST], _gl_NAME, [ ])
    ])
  ])
])

# Like AC_LIBOBJ, except that the module name goes
# into srcgltests_LIBOBJS instead of into LIBOBJS.
AC_DEFUN([srcgltests_LIBOBJ], [
  AS_LITERAL_IF([$1], [srcgltests_LIBSOURCES([$1.c])])dnl
  srcgltests_LIBOBJS="$srcgltests_LIBOBJS $1.$ac_objext"
])

# Like AC_REPLACE_FUNCS, except that the module name goes
# into srcgltests_LIBOBJS instead of into LIBOBJS.
AC_DEFUN([srcgltests_REPLACE_FUNCS], [
  m4_foreach_w([gl_NAME], [$1], [AC_LIBSOURCES(gl_NAME[.c])])dnl
  AC_CHECK_FUNCS([$1], , [srcgltests_LIBOBJ($ac_func)])
])

# Like AC_LIBSOURCES, except the directory where the source file is
# expected is derived from the gnulib-tool parameterization,
# and alloca is special cased (for the alloca-opt module).
# We could also entirely rely on EXTRA_lib..._SOURCES.
AC_DEFUN([srcgltests_LIBSOURCES], [
  m4_foreach([_gl_NAME], [$1], [
    m4_if(_gl_NAME, [alloca.c], [], [
      m4_define([srcgltests_LIBSOURCES_DIR], [src/gl/tests])
      m4_append([srcgltests_LIBSOURCES_LIST], _gl_NAME, [ ])
    ])
  ])
])

# This macro records the list of files which have been installed by
# gnulib-tool and may be removed by future gnulib-tool invocations.
AC_DEFUN([srcgl_FILE_LIST], [
  lib/gettext.h
  lib/progname.c
  lib/progname.h
  lib/stdarg.in.h
  lib/version-etc.c
  lib/version-etc.h
  m4/00gnulib.m4
  m4/gnulib-common.m4
  m4/include_next.m4
  m4/stdarg.m4
])
