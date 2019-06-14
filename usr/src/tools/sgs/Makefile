#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

# Copyright 2019, Richard Lowe.

SUBDIRS =		\
	include		\
	ld		\
	libconv		\
	libelf		\
	libld		\
	liblddbg	\
	sgsmsg

all :=		TARGET= install
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber

ld: sgsmsg include libconv libelf libld
libconv: sgsmsg include
libelf: sgsmsg include
libld: sgsmsg libelf libconv liblddbg include
liblddbg: sgsmsg libconv include

all install clean clobber: $(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
