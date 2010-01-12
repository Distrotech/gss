# Copyright (C) 2002-2010 Free Software Foundation, Inc.
#
# This file is free software, distributed under the terms of the GNU
# General Public License.  As a special exception to the GNU General
# Public License, this file may be distributed as part of a program
# that contains a configuration script generated by Autoconf, under
# the same distribution terms as the rest of that program.
#
# Generated by gnulib-tool.
#
# This file represents the specification of how gnulib-tool is used.
# It acts as a cache: It is written and read by gnulib-tool.
# In projects using CVS, this file is meant to be stored in CVS,
# like the configure.ac and various Makefile.am files.


# Specification in the form of a command-line invocation:
#   gnulib-tool --import --dir=. --local-dir=src/gl/override --lib=libgnu --source-base=src/gl --m4-base=src/gl/m4 --doc-base=doc --tests-base=src/gl/tests --aux-dir=build-aux --with-tests --libtool --macro-prefix=srcgl --no-vc-files getopt-gnu progname version-etc

# Specification in the form of a few gnulib-tool.m4 macro invocations:
gl_LOCAL_DIR([src/gl/override])
gl_MODULES([
  getopt-gnu
  progname
  version-etc
])
gl_AVOID([])
gl_SOURCE_BASE([src/gl])
gl_M4_BASE([src/gl/m4])
gl_PO_BASE([])
gl_DOC_BASE([doc])
gl_TESTS_BASE([src/gl/tests])
gl_WITH_TESTS
gl_LIB([libgnu])
gl_MAKEFILE_NAME([])
gl_LIBTOOL
gl_MACRO_PREFIX([srcgl])
gl_PO_DOMAIN([])
gl_VC_FILES([false])
