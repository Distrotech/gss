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

man_MANS = gss.1

gss_texi_auto_deps = gss-api-version.texi \
	gss-api-context.texi gss-api-cred.texi \
	gss-api-misc.texi gss-api-msg.texi gss-api-name.texi

EXTRA_DIST = gdoc gdoc-error $(man_MANS) $(gss_texi_auto_deps) \
	gss.html gss.ps gss.pdf

info_TEXINFOS = gss.texi
ps_TEXINFOS = gss.texi
pdf_TEXINFOS = gss.texi
gss_TEXINFOS = gpl.texi fdl.texi $(gss_texi_auto_deps)

gss_api_version_deps = $(top_srcdir)/lib/version.c

gss-api-version.texi: $(gss_api_version_deps)
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

gss-api-cred.texi: $(top_srcdir)/lib/cred.c
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

gss-api-context.texi: $(top_srcdir)/lib/context.c
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

gss-api-msg.texi: $(top_srcdir)/lib/msg.c
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

gss-api-name.texi: $(top_srcdir)/lib/name.c
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

gss-api-misc.texi: $(top_srcdir)/lib/misc.c
	$(PERL) $(srcdir)/gdoc -texinfo $^ > $@

# Man page:

gss.1: $(top_srcdir)/src/gss.c $(top_builddir)/src/gss
	$(HELP2MAN) \
		--name="GPL GSS-API library command line interface" \
		--output=$@ $(top_builddir)/src/gss

gss.html: gss.texi
	$(MAKEINFO) --html --no-split --number-sections $<
