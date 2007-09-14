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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libtsalarm/sparc/Makefile

UTSBASE= ../../../uts

PLATINCS += -I$(USR_PLAT_DIR)/sun4v/include -I$(UTSBASE)/sun4v

PLATFORM_OBJECTS= tsalarm.o

#
# platform library directory (/usr/platform/SUNW,Netra-T5220/lib)
#
PLATFORM=SUNW,Netra-T5220

include ../Makefile.com

#
# install rules
#

$(PLATLIBS)/libtsalarm.so:
	$(RM) -r $@; $(SYMLINK) libtsalarm.so.1 $@ $(CHOWNLINK) $(CHGRPLINK)

$(USR_PSM_LIB_DIR)/% := FILEMODE= 644

$(USR_PSM_LIB_DIR)/%: % $(USR_PSM_LIB_DIR)
	$(INS.file)

$(USR_PSM_LIB_DIR):
	$(INS.dir.root.sys)

$(USR_PSM_INCL_DIR)/%:	../common/% $(USR_PSM_INCL_DIR)
	$(INS.file)

$(USR_PSM_INCL_DIR):
	$(INS.dir.root.sys)

install: all install_h $(USR_PSM_LIBS) $(PLATLIBS)/libtsalarm.so

install_h: $(USR_PSM_INCL_DIR)/tsalarm.h
