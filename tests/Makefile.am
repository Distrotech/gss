## Process this file with automake to produce Makefile.in
# Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010 Simon Josefsson
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

AM_CFLAGS = $(WARN_CFLAGS) $(WERROR_CFLAGS)
AM_CPPFLAGS = -I$(top_builddir)/lib/headers -I$(top_srcdir)/lib/headers
AM_LDFLAGS = -no-install
LDADD = ../lib/libgss.la @LTLIBINTL@

TESTS_ENVIRONMENT = \
	SHISHI_KEYS=$(srcdir)/krb5context.key \
	SHISHI_TICKETS=$(srcdir)/krb5context.tkt \
	SHISHI_CONFIG=ignore-this-warning \
	SHISHI_HOME=ignore-this-warning \
	SHISHI_USER=ignore-this-warning \
	THREADSAFETY_FILES="$(top_srcdir)/lib/*.c $(top_srcdir)/lib/krb5/*.c" \
	$(VALGRIND)

buildtests = basic
if KRB5
buildtests += krb5context
endif
TESTS = $(buildtests) threadsafety
check_PROGRAMS = $(buildtests)
dist_check_SCRIPTS = threadsafety

EXTRA_DIST = krb5context.key krb5context.tkt utils.c

localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@
