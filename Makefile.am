## Process this file with automake to produce Makefile.in
# Copyright (C) 2003 Simon Josefsson.
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

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = gss.pc

SUBDIRS = po gl lib tests doc

ACLOCAL_AMFLAGS = -I m4 -I gl/m4

# Maintainer targets

indent:
	(cd lib && make indent)
	(cd tests && make indent)

ChangeLog:
	test ! -f .cvsusers || \
	(cvs2cl --fsf --FSF --usermap .cvsusers \
		-I "ChangeLog|.cvs|autogen.sh|doc/specification" && \
	cat .cvscopying >> ChangeLog)

tag = $(PACKAGE)-`echo $(VERSION) | sed 's/\./-/g'`
htmldir = ../www-$(PACKAGE)

release:
	cvs upd -p -r HEAD NEWS > /dev/null
	if cvs upd -p -r $(tag) NEWS > /dev/null; then false else true; fi
	rm -f ChangeLog && cvs upd ChangeLog
	cvs commit
	rm -f ChangeLog
	$(MAKE) ChangeLog distcheck
	cvs commit -m "" ChangeLog
	cvs rtag $(tag) $(PACKAGE)
	gpg -b $(distdir).tar.gz
	gpg --verify $(distdir).tar.gz.sig
	echo "directory: $(PACKAGE)" > $(distdir).tar.gz.directive
	gpg --clearsign $(distdir).tar.gz.directive
	cd doc && ./gendocs.sh -o ../$(htmldir)/manual/ $(PACKAGE) "GNU Generic Security Service Library"
	cd $(htmldir) && cvs commit -m "Update." manual/
	ncftpput ftp-upload.gnu.org /incoming/alpha $(distdir).tar.gz{,.sig,.directive.asc}
