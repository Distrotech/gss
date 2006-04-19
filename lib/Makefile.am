## Process this file with automake to produce Makefile.in
# Copyright (C) 2003, 2004, 2005, 2006 Simon Josefsson.
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

AM_CPPFLAGS = -I$(top_srcdir)/gl

lib_LTLIBRARIES = libgss.la
include_HEADERS = gss.h

gssincludedir=$(includedir)/gss
gssinclude_HEADERS = api.h ext.h

libgss_la_SOURCES = internal.h \
	meta.h meta.c \
	context.c cred.c error.c misc.c msg.c name.c obsolete.c oid.c \
	asn1.c ext.c version.c
libgss_la_LIBADD = @LTLIBINTL@ $(top_builddir)/gl/libgnu.la
libgss_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
	-export-symbols-regex '^(gss|GSS).*' -no-undefined

if KRB5
SUBDIRS = krb5
gssinclude_HEADERS += krb5/krb5.h
libgss_la_LIBADD += krb5/libgss-shishi.la
endif

localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@
