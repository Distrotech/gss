## Process this file with automake to produce Makefile.in
# Copyright (C) 2003, 2004 Simon Josefsson.
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
# Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# 02111-1307, USA.

AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_srcdir)/lib
if KRB5
AM_CPPFLAGS += -I$(top_srcdir)/lib/krb5
endif
AM_LDFLAGS = -no-install
LDADD = ../lib/libgss.la ../gl/libgl.la @LTLIBINTL@

TESTS_ENVIRONMENT = SHISHI_KEYS=$(srcdir)/krb5context.key \
	SHISHI_TICKETS=$(srcdir)/krb5context.tkt \
	SHISHI_CONFIG=ignore-this-warning \
	SHISHI_HOME=ignore-this-warning \
	SHISHI_USER=ignore-this-warning \
	THREADSAFETY_FILES="$(top_srcdir)/lib/*.c \
		$(top_srcdir)/lib/krb5/*.c"

buildtests = basic
if KRB5
buildtests += krb5context
endif
TESTS = $(buildtests) threadsafety
check_PROGRAMS = $(buildtests)
dist_check_SCRIPTS = threadsafety

EXTRA_DIST = krb5context.key krb5context.tkt

localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@

indent:
	indent $(SOURCES)
