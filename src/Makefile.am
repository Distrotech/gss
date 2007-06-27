## Process this file with automake to produce Makefile.in
# Copyright (C) 2003, 2004, 2005, 2006, 2007 Simon Josefsson.
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

AM_CPPFLAGS = -I$(top_srcdir)/gl -I$(top_srcdir)/lib

bin_PROGRAMS = gss

BUILT_SOURCES = gss_cmd.c gss_cmd.h
gss_SOURCES = gss.c $(BUILT_SOURCES) gss.ggo
MAINTAINERCLEANFILES = $(BUILT_SOURCES)
gss_LDADD = ../lib/libgss.la ../gl/libgnu.la @LTLIBINTL@

gss.c: $(BUILT_SOURCES)

$(BUILT_SOURCES): gss.ggo
	gengetopt --input $^ --file-name gss_cmd || \
		test -f gss_cmd.h -a -f gss_cmd.c || \
		cp $(srcdir)/gss_cmd.h $(srcdir)/gss_cmd.h .

# For gettext.
datadir = @datadir@
localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@
