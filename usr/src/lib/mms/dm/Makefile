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
#

SUBDIRS = \
	libdefault		\
	libDISK_ARCHIVING	\
	libHP_Ultrium_3-SCSI	\
	libIBM_ULTRIUM-TD1	\
	libIBM_ULTRIUM-TD2	\
	libIBM_ULTRIUM-TD3	\
	libIBM_ULTRIUM-TD4	\
	libQUANTUM_SDLT600	\
	libSEAGATE_ULTRIUM06242-XXX \
	libSTK_9840		\
	libSTK_T9840B		\
	libSTK_T9840C		\
	libSTK_T9940A		\
	libSTK_T9940B

.KEEP_STATE:

.PARALLEL:

all := TARGET = all
clean := TARGET = clean
clobber := TARGET = clobber
install := TARGET = install
lint := TARGET = lint

all clean clobber install lint: $(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
