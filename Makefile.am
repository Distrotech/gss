## Process this file with automake to produce Makefile.in
# Copyright (C) 2003 Simon Josefsson.
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

EXTRA_DIST = ANNOUNCE config.h.in config.rpath mkinstalldirs ggssapi.pc.in

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ggssapi.pc

SUBDIRS = m4 po argp lib src tests doc

ACLOCAL_AMFLAGS = -I m4 -I argp

# Maintainer targets

.PHONY: ChangeLog
ChangeLog:
	test ! -f .cvsusers || \
	cvs2cl --FSF --usermap .cvsusers \
		-I "ChangeLog|.cvs|autogen.sh|doc/specification"

indent:
	(cd lib && make indent)
	(cd src && make indent)
	(cd tests && make indent)

tag = $(PACKAGE)-`echo $(VERSION) | sed 's/\./-/g'`
shortname = ggssapi
htmldir = ../www-$(shortname)

release:
	cvs upd -p -r HEAD NEWS > /dev/null
	if cvs upd -p -r $(tag) NEWS > /dev/null; then false else true; fi
	rm -f ChangeLog && cvs upd ChangeLog
	cvs commit
	$(MAKE) distcheck
	cvs commit -m "" ChangeLog
	rm -f $(distdir).tar.gz.asc
	gpg -a --sign --detach $(distdir).tar.gz
	gpg --verify $(distdir).tar.gz.asc
	scp $(distdir).tar.gz* josefsson.org:/$(shortname)/
	test -d $(htmldir) && cp -v doc/$(shortname).{ps,pdf,html} $(htmldir)/
	test -d $(htmldir) && cd $(htmldir) && cvs commit -m "Update." \
		$(shortname).{ps,pdf,html}
	cvs rtag $(tag) $(shortname)
