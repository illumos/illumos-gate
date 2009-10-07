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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include $(SRC)/lib/Makefile.lib
include $(SRC)/Makefile.psm

PLATFORM	=	sun4v

all		:=	TARGET= all
install		:=	TARGET= install
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber

TOUCH		= /usr/bin/touch

MODULE		= libc_psr.so.1

$(ROOT_PSM_LIB_DIR):
	-$(INS.dir)

$(ROOT_PSM_LIB_DIR)/$(MODULE):	$(ROOT_PSM_LIB_DIR) $(MODULE)
	$(RM) -r $@; $(INS) -s -m $(FILEMODE) -f $(@D) $(MODULE)

$(ROOT_PSM_LIB64_DIR):
	-$(INS.dir)

$(ROOT_PSM_LIB64_DIR)/$(MODULE):	$(ROOT_PSM_LIB64_DIR) $(MODULE)
	$(RM) -r $@; $(INS) -s -m $(FILEMODE) -f $(@D) $(MODULE)

all:	FRC
	@$(TOUCH) $(MODULE)

install:	all $(ROOT_PSM_LIB_DIR)/$(MODULE) $(ROOT_PSM_LIB64_DIR)/$(MODULE)

clean clobber : FRC
	$(RM) $(MODULE)

lint:
	@ $(ECHO) "Nothing to lint here: skipping"

FRC:
