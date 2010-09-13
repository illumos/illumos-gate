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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

OBJS=			inityp2l ypmap2src

include $(SRC)/cmd/Makefile.cmd

# install directories
NETSVC = $(ROOTLIB)/netsvc
NETYP = $(NETSVC)/yp
ROOTNETYPFILES=		$(OBJS:%=$(NETYP)/%)

$(NETSVC) := FILEMODE=555

all: FRC $(OBJS)

install: all $(ROOTNETYPFILES)

clean:	FRC $(OBJS)
	$(RM) $(OBJS)

clobber: FRC $(OBJS)
	$(RM) $(OBJS)

clean: FRC

clobber: FRC

lint: FRC

$(NETYP)/ypmap2src: ypmap2src
	$(INS.file) ypmap2src

$(NETYP)/inityp2l: inityp2l
	$(INS.file) inityp2l

FRC:
