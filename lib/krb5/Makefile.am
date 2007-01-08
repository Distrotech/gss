## Process this file with automake to produce Makefile.in
# Copyright (C) 2003, 2004, 2005, 2006, 2007 Simon Josefsson.
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

noinst_LTLIBRARIES = libgss-shishi.la

libgss_shishi_la_SOURCES = k5internal.h krb5.h protos.h \
	context.c checksum.c checksum.h error.c name.c cred.c msg.c oid.c \
	utils.c 
libgss_shishi_la_LIBADD = @LTLIBINTL@ @LTLIBSHISHI@

localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@
