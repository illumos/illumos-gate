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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include $(SRC)/Makefile.master
include $(SRC)/cmd/Makefile.cmd


.KEEP_STATE:
.SUFFIXES: .ksh


SCRIPTS  =	mkbootmedia.ksh
SCRIPTS +=	updatemedia.ksh
SCRIPTS +=	pkg2du.ksh
SCRIPTS +=	itu.ksh
ROOTUSR=	$(ROOT)/usr
ROOTUSRBIN=	$(ROOTUSR)/bin

POFILES=	$(SCRIPTS:%.ksh=%.po)
POFILE=		ituutils.po
PROGS=		$(SCRIPTS:%.ksh=%)
XGETFLAGS=	-a

all: $(PROGS) FRC

clean: FRC
	$(RM) $(PROGS) $(POFILE) $(POFILES)

clobber: clean

msg _msg: $(POFILE) FRC

FRC:


# Default rule for building ksh scripts.
.ksh:
	$(RM) $@
	cat $< > $@
	chmod +x $@

# we use the $SRC/Makefile.master sed script to generate the messages catalogs
$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) > $@


# installation rules
$(ROOTUSR):
	$(INS.dir)

$(ROOTUSRBIN):	$(ROOTUSR)
	$(INS.dir)

$(ROOTUSRBIN)/%: %
	$(INS.file)

install: all \
	$(ROOTUSRBIN)/itu \
	$(ROOTUSRBIN)/mkbootmedia \
	$(ROOTUSRBIN)/updatemedia \
	$(ROOTUSRBIN)/pkg2du


include ../Makefile.targ
