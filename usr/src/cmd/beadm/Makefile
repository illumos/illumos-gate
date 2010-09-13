#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

include ../Makefile.cmd

FILEMODE=0444

PYTHON=         $(PYTHON_26)
ROOTPYDIR=      $(ROOT)/usr/lib/python2.6/vendor-packages
ROOTMODDIR= 	$(ROOTPYDIR)/beadm

PYCMD=          beadm.py
PYCMDFILE=      $(PYCMD:%.py=%)

PYMODULES=	__init__.py BootEnvironment.py messages.py
PYMODOBJS=	$(PYMODULES:%.py=%.pyc)
PYMODFILES=	$(PYMODULES) $(PYMODOBJS)

ROOTCMDFILE=    $(PYCMDFILE:%=$(ROOTSBIN)/%)
$(ROOTCMDFILE) 	:= FILEMODE = 0555
ROOTMODFILES=	$(PYMODFILES:%=$(ROOTMODDIR)/%)
ROOTUSRSBINLINKS= $(PYCMDFILE:%=$(ROOTUSRSBIN)/%)

POFILE = 	beadm.po
MSGFILES = 	beadm.py messages.py
XGETTEXT = 	$(GNUXGETTEXT)
XGETFLAGS = 	$(GNUXGETFLAGS)

.KEEP_STATE:

all: $(PYCMDFILE) $(PYMODOBJS)

install: all $(ROOTCMDFILE) $(ROOTMODFILES) $(ROOTUSRSBINLINKS)

clean:
	$(RM) $(PYCMDFILE) $(PYMODOBJS)

clobber: clean

$(ROOTCMDDIR)/%: %
	$(INS.pyfile)

$(ROOTMODDIR)/%: %
	$(INS.pyfile)

$(ROOTUSRSBINLINKS):
	-$(RM) $@; $(SYMLINK) ../../sbin/$(@F) $@

$(POFILE): 	$(MSGFILES)
		$(BUILDPO.msgfiles)

_msg: 		$(MSGDOMAINPOFILE)

include $(SRC)/Makefile.msg.targ
include ../Makefile.targ
