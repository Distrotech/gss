## Process this file with automake to produce Makefile.in
# Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008 Simon Josefsson.
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

if ENABLE_GTK_DOC
SUBDIRS = reference
endif

EXTRA_DIST = gss.html gss.ps gss.pdf \
	gdoc asciidoc asciidoc.conf texinfo.conf texinfo.css

info_TEXINFOS = gss.texi
gss_TEXINFOS = gpl-3.0.texi fdl-1.3.texi $(gdoc_TEXINFOS)

AM_MAKEINFOHTMLFLAGS = --no-split --number-sections --css-include=texinfo.css

dist_man_MANS = gss.1 $(gdoc_MANS)
MAINTAINERCLEANFILES = $(dist_man_MANS)

gss.1: $(top_srcdir)/src/gss.c $(top_srcdir)/src/gss.ggo \
		$(top_srcdir)/configure.ac
	$(HELP2MAN) \
		--name="Generic Security Service command line interface" \
		--output=$@ $(top_builddir)/src/gss

# GDOC

GDOC_SRC = $(top_srcdir)/lib/*.c
GDOC_TEXI_PREFIX = texi/
GDOC_MAN_PREFIX = man/
GDOC_MAN_EXTRA_ARGS = -module $(PACKAGE) -sourceversion $(VERSION) \
	-bugsto $(PACKAGE_BUGREPORT) -includefuncprefix -seeinfo $(PACKAGE) \
	-copyright "2003, 2004, 2005, 2006, 2007, 2008 Simon Josefsson" \
	-verbatimcopying
include $(srcdir)/Makefile.gdoci
