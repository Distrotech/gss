## Process this file with automake to produce Makefile.in
# Copyright (C) 2003, 2004, 2005, 2006, 2007 Simon Josefsson.
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

DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = gss.pc

SUBDIRS = po gl lib src tests doc

ACLOCAL_AMFLAGS = -I m4 -I gl/m4

# Maintainer targets

update-po: refresh-po
	-cg-add `ls po/*.po | grep -v quot.po`
	cg-commit -m "Sync with TP." po/LINGUAS `ls po/*.po | grep -v quot.po`

ChangeLog:
	git log --pretty --numstat --summary | git2cl > ChangeLog
	cat .cvscopying >> ChangeLog

tag = $(PACKAGE)-`echo $(VERSION) | sed 's/\./-/g'`
htmldir = ../www-$(PACKAGE)

release:
	! git-tag -l $(tag) > /dev/null
	rm -f ChangeLog
	$(MAKE) ChangeLog distcheck
	git commit -m Generated. ChangeLog
	git-tag -u b565716f! -m $(VERSION) $(tag)
	cd doc && ../build-aux/gendocs.sh --html "--css-include=texinfo.css" \
		-o ../$(htmldir)/manual/ $(PACKAGE) \
		"GNU Generic Security Service Library"
	build-aux/gnupload --to alpha.gnu.org:gss $(distdir).tar.gz
	cp -v $(distdir).tar.gz{,.sig} $(htmldir)/releases/
	cp -v doc/reference/html/*.{html,png,devhelp,css} $(htmldir)/reference/
	cd $(htmldir) && cvs add -kb releases/$(distdir).tar.gz{,.sig} && \
		cvs commit -m "Update." manual/ reference/ releases/
