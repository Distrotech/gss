## Process this file with automake to produce Makefile.in
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

EXTRA_DIST = gss_asn1_tab.c

lib_LTLIBRARIES = libgss.la

INCLUDES = -I../intl

include_HEADERS = gssapi.h gss.h

libgss_la_SOURCES = internal.h version.c error.c \
	context.c cred.c misc.c msg.c name.c obsolete.c oid.c \
	asn1.c krb5.c

libgss_la_LIBADD = @LTLIBINTL@ @SHISHI_LIBS@
libgss_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

localedir = $(datadir)/locale

DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@

gss_asn1_tab.c: $(srcdir)/gss.asn1
	-@ASN1PARSER@ -o $@ $<

indent:
	indent $(libgss_la_SOURCES) gssapi.h gssapi.h.in
