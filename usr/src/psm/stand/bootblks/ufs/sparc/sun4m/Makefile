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
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 1994, 2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# psm/stand/bootblks/ufs/sparc/sun4m/Makefile
#

#
# Platform specific Makefile for the boot block.
#
# PLATFORM is the target for the binary installation.
#
# PROM_TYPE is the type of prom OBP, IEEE1275, etc...
#
BASEDIR		= ../../..
PLATFORM	= sun4m
PROM_TYPE	= OBPDEP

include $(BASEDIR)/ufs/Makefile.ufs
include $(BASEDIR)/obp-c/Makefile.rules

CPPINCS		+= -I$(SRC)/uts/common
CPPINCS		+= -I$(SRC)/uts/sun
CPPINCS		+= -I$(SRC)/uts/sparc

.KEEP_STATE:

all:	$(MKBOOT) $(PROG).elf
	./$(MKBOOT) $(PROG).elf $(PROG); chmod -x $(PROG)

include $(BASEDIR)/obp-c/Makefile.targ
include $(BASEDIR)/Makefile.targ
