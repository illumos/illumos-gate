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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include $(SRC)/lib/Makefile.lib

SUBDIRS =	$(MACH)
$(BLD_JAVA_8)SUBDIRS = $(MACH64)

all :=		TARGET = all
clean :=	TARGET = clean
clobber :=	TARGET = clobber
install :=	TARGET = install
lint :=		TARGET = lint

JNI_CLASSES = \
	com.sun.solaris.service.locality.LocalityDomain \
	com.sun.solaris.service.locality.LocalityGroup

JNI_GENERATED_HEADERS = \
	jlgrp.h

CLEANFILES += $(JNI_GENERATED_HEADERS)

all install lint: $(JNI_GENERATED_HEADERS) .WAIT $(SUBDIRS)

clean clobber:		$(SUBDIRS)

$(JNI_GENERATED_HEADERS): $(SRC)/cmd/pools/poold/JPool.jar
	$(JAVAH) -classpath $? -o $@ $(JNI_CLASSES)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include $(SRC)/lib/Makefile.targ
include $(SRC)/Makefile.msg.targ
