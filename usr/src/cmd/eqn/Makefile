#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright (c) 1989 by Sun Microsystems, Inc.
#
# cmd/eqn/Makefile
#

include ../Makefile.cmd

SUBDIR1 =       eqnchar.d
SUBDIR2 =                 neqn.d eqn.d
SUBDIRS =       $(SUBDIR1) $(SUBDIR2)




all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
strip :=	TARGET= strip

#
# for message catalog
#
_msg :=         TARGET= catalog
POFILE= eqn.po
POFILES= $(SUBDIR2:%=%/%.po)

.KEEP_STATE :

all :		$(SUBDIRS)

install clean clobber lint strip :	$(SUBDIRS)

$(POFILE):   $(SUBDIR2)
	$(RM)	$@
	cat     $(POFILES)      > $(POFILE)

$(SUBDIRS) :	FRC
		@cd $@; pwd; $(MAKE) $(TARGET)

FRC :

include ../Makefile.targ
