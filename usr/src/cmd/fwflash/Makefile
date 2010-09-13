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
# cmd/fwflash/Makefile
#
include $(SRC)/Makefile.master

PROG=		fwflash
COMMON_SUBDIRS=	$(MACH)
IDF_SUBDIRS=	plugins/transport
VRF_SUBDIRS=	plugins 
SUBDIRS=	$(COMMON_SUBDIRS) .WAIT \
		$(IDF_SUBDIRS) .WAIT \
		$(VRF_SUBDIRS)

all :=          TARGET= all
clean :=        TARGET= clean
clobber :=      TARGET= clobber
check :=	TARGET= check
install :=      TARGET= install
install_h :=	TARGET= install_h
lint :=         TARGET= lint
_msg :=         TARGET= _msg
msg :=         	TARGET= msg


all clean clobber install lint msg _msg: $(SUBDIRS)
check install_h: $(COMMON_SUBDIRS)

$(SUBDIRS): FRC
	@if [ -f $@/Makefile ]; then \
       		cd $@; pwd; $(MAKE) $(TARGET); \
        else \
       		true; \
        fi

FRC:
