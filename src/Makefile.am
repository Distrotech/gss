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
# Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

AM_CPPFLAGS = -I$(top_srcdir)/lib

bin_PROGRAMS = gss

BUILT_SOURCES = gss_cmd.c gss_cmd.h
gss_SOURCES = gss.c $(BUILT_SOURCES) gss.ggo
DISTCLEANFILES = $(BUILT_SOURCES)
gss_LDADD = ../lib/libgss.la

gss.c: $(BUILT_SOURCES)

$(BUILT_SOURCES): gss.ggo
	gengetopt --input $^ --file-name gss_cmd || \
		test -f gss_cmd.h -a -f gss_cmd.c || \
		cp $(srcdir)/gss_cmd.h $(srcdir)/gss_cmd.h .

# For gettext.
datadir = @datadir@
localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@

# Maintainer targets

indent:
	indent gss.c
