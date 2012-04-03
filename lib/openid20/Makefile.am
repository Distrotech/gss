## Process this file with automake to produce Makefile.in
# Copyright (C) 2012 Simon Josefsson
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
AM_CPPFLAGS = -I$(top_srcdir)/lib/gl \
	-I$(top_srcdir)/lib \
	-I$(top_builddir)/lib/headers -I$(top_srcdir)/lib/headers

noinst_LTLIBRARIES = libgss-openid20.la

libgss_openid20_la_SOURCES = oid.c
libgss_openid20_la_LIBADD = @LTLIBINTL@

localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@
