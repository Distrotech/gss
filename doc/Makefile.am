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

if ENABLE_GTK_DOC
SUBDIRS = reference
endif

EXTRA_DIST = gss.html gss.ps gss.pdf \
	gdoc asciidoc asciidoc.conf texinfo.conf texinfo.css

info_TEXINFOS = gss.texi
gss_TEXINFOS = gpl.texi fdl.texi $(gdoc_TEXINFOS)

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
	-copyright "2003, 2004 Simon Josefsson" -verbatimcopying
include $(srcdir)/Makefile.gdoci
