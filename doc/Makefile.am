## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003 Simon Josefsson.
#
# This file is part of GPL GSS-API.
#
# GPL GSS-API is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# GPL GSS-API is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GPL GSS-API; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.

man_MANS = ggssapi.1

ggssapi_texi_auto_deps = ggssapi-api-version.texi

EXTRA_DIST = gdoc gdoc-error $(man_MANS) $(ggssapi_texi_auto_deps) \
	ggssapi.html ggssapi.ps ggssapi.pdf

info_TEXINFOS = ggssapi.texi
ps_TEXINFOS = ggssapi.texi
pdf_TEXINFOS = ggssapi.texi
ggssapi_TEXINFOS = gpl.texi fdl.texi

ggssapi_api_version_deps = $(top_srcdir)/lib/version.c

ggssapi-api-version.texi: $(ggssapi_api_version_deps)
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

# Man page:

ggssapi.1: $(top_srcdir)/src/ggssapi.c $(top_builddir)/src/ggssapi
	$(HELP2MAN) \
		--name="GPL GSS-API library command line interface" \
		--output=$@ $(top_builddir)/src/ggssapi

ggssapi.html: ggssapi.texi
	$(MAKEINFO) --html --no-split --number-sections $<
