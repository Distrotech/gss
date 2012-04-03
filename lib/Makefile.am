## Process this file with automake to produce Makefile.in
# Copyright (C) 2003-2012 Simon Josefsson
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

SUBDIRS = gl

AM_CFLAGS = $(WARN_CFLAGS) $(WERROR_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/lib/gl \
	-I$(top_builddir)/lib/headers -I$(top_srcdir)/lib/headers

lib_LTLIBRARIES = libgss.la
include_HEADERS = headers/gss.h

gssincludedir=$(includedir)/gss
gssinclude_HEADERS = headers/gss/api.h headers/gss/ext.h

libgss_la_SOURCES = libgss.map \
	internal.h \
	meta.h meta.c \
	context.c cred.c error.c misc.c msg.c name.c obsolete.c oid.c \
	asn1.c ext.c version.c \
	saslname.c
libgss_la_LIBADD = @LTLIBINTL@ gl/libgnu.la
libgss_la_LDFLAGS = -no-undefined \
	-version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

if HAVE_LD_VERSION_SCRIPT
libgss_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libgss.map
else
libgss_la_LDFLAGS += -export-symbols-regex '^(gss|GSS).*'
endif

if HAVE_LD_OUTPUT_DEF
libgss_la_LDFLAGS += -Wl,--output-def,libgss-$(DLL_VERSION).def
defexecdir = $(bindir)
defexec_DATA = libgss-$(DLL_VERSION).def
DISTCLEANFILES = $(defexec_DATA)
endif

if KRB5
SUBDIRS += krb5
gssinclude_HEADERS += headers/gss/krb5.h headers/gss/krb5-ext.h
libgss_la_LIBADD += krb5/libgss-shishi.la
endif

if OPENID20
SUBDIRS += openid20
gssinclude_HEADERS += headers/gss/openid20-ext.h
libgss_la_LIBADD += openid20/libgss-openid20.la
endif

if SAML20
SUBDIRS += saml20
gssinclude_HEADERS += headers/gss/saml20-ext.h
libgss_la_LIBADD += saml20/libgss-saml20.la
endif

localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@
