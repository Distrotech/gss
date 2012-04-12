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
AM_CPPFLAGS = -I$(top_srcdir)/gl \
	-I$(top_srcdir)/src/gl -I$(top_builddir)/src/gl \
	-I$(top_builddir)/lib/headers -I$(top_srcdir)/lib/headers

bin_PROGRAMS = gss gss-cli gss-serv

gss_SOURCES = gss.c
gss_LDADD = ../lib/libgss.la gl/libgnu.la @LTLIBINTL@ libcmd-gss.la
gss_BUILT_SOURCES = gss_cmd.c gss_cmd.h
gss.c: $(gss_BUILT_SOURCES)

gss_cli_SOURCES = gss-cli.c
gss_cli_LDADD = ../lib/libgss.la gl/libgnu.la @LTLIBINTL@ libcmd-gss-cli.la
gss_cli_BUILT_SOURCES = gss_cli_cmd.c gss_cli_cmd.h
gss-cli.c: $(gss_cli_BUILT_SOURCES)

gss_serv_SOURCES = gss-serv.c
gss_serv_LDADD = ../lib/libgss.la gl/libgnu.la @LTLIBINTL@ libcmd-gss-serv.la
gss_serv_BUILT_SOURCES = gss_serv_cmd.c gss_serv_cmd.h
gss-serv.c: $(gss_serv_BUILT_SOURCES)

MAINTAINERCLEANFILES = $(BUILT_SOURCES) \
	$(gss_cli_BUILT_SOURCES)	\
	$(gss_serv_BUILT_SOURCES)

$(gss_BUILT_SOURCES): gss.ggo
	gengetopt --no-handle-help --no-handle-version	\
			--input $^ --file-name gss_cmd

$(gss_cli_BUILT_SOURCES): gss-cli.ggo
	gengetopt --no-handle-help --no-handle-version	\
			--input $^ --file-name gss_cli_cmd

$(gss_serv_BUILT_SOURCES): gss-serv.ggo
	gengetopt --no-handle-help --no-handle-version	\
			--input $^ --file-name gss_serv_cmd

noinst_LTLIBRARIES = libcmd-gss.la libcmd-gss-cli.la libcmd-gss-serv.la

libcmd_gss_la_CFLAGS =
libcmd_gss_la_SOURCES = gss.ggo $(gss_BUILT_SOURCES)
libcmd_gss_la_LIBADD = gl/libgnu.la

libcmd_gss_cli_la_CFLAGS =
libcmd_gss_cli_la_SOURCES = gss-cli.ggo $(gss_cli_BUILT_SOURCES)
libcmd_gss_cli_la_LIBADD = gl/libgnu.la

libcmd_gss_serv_la_CFLAGS =
libcmd_gss_serv_la_SOURCES = gss-serv.ggo $(gss_serv_BUILT_SOURCES)
libcmd_gss_serv_la_LIBADD = gl/libgnu.la

# For gettext.
datadir = @datadir@
localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@
