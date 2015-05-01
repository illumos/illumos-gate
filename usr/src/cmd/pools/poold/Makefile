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
# cmd/pools/poold/Makefile

PROG =		poold
OBJS =		poold.o
SRCS =		$(OBJS:%.o=%.c)

MANIFEST=	poold.xml
SVCMETHOD=	svc-poold

include $(SRC)/cmd/Makefile.cmd

JAVA_SUBDIRS =	com/sun/solaris/service/exception \
		com/sun/solaris/service/kstat \
		com/sun/solaris/service/locality \
		com/sun/solaris/service/logging \
		com/sun/solaris/service/pools \
		com/sun/solaris/service/timer \
		com/sun/solaris/domain/pools

SUBDIRS =	libjkstat \
		libjlgrp \
		libjpool \
		libjsyslog

ROOTMANIFESTDIR=	$(ROOTSVCSYSTEM)

all :=		TARGET = all
install :=	TARGET = install
clean :=	TARGET = clean
clobber :=	TARGET = clobber
lint :=		TARGET = lint
msg :=		TARGET = msg

$(ROOTMANIFEST):=	FILEMODE= 444
JARFILE =	JPool.jar

# JAVA_SUBDIRS and PACKAGEDOCS must be synchronized to ensure 
# javadoc documentation is generated for all packages.

PACKAGEDOCS =	com.sun.solaris.service.exception \
		com.sun.solaris.service.kstat \
		com.sun.solaris.service.locality \
		com.sun.solaris.service.logging \
		com.sun.solaris.service.pools \
		com.sun.solaris.service.timer \
		com.sun.solaris.domain.pools
DOCDIR =	doc
ROOTUSRLIBDRP = $(ROOTLIB)/pool
INCS =		-I../common \
		-I$(JAVA_ROOT)/include \
		-I$(JAVA_ROOT)/include/solaris
LDLIBS +=	-lpool -L$(JAVA_ROOT)/jre/lib/$(MACH)/client -ljvm
# runpath should point to runtime JAVA_HOME
LDFLAGS +=	-R$(JAVA_HOME)/jre/lib/$(MACH)/client
LINTFLAGS +=	-erroff=E_NAME_USED_NOT_DEF2
LINTLIBS +=	-L$(ROOTLIB) -lpool

CPPFLAGS +=	$(INCS)
ROOTCMDDIR =	$(ROOT)/usr/lib/pool

CLOBBERFILES +=	$(JARFILE)

#
# Definitions for message catalogue
#
POFILES =	$(OBJS:.o=.po)

#
# Definitions for Java installs
#

JFILES =	poold.properties $(JARFILE)
ROOTJAVA =	$(JFILES:%=$(ROOTUSRLIBDRP)/%)

$(ROOTJAVA) :=	FILEMODE = 444

all:	$(PROG) $(JAVA_SUBDIRS) $(JARFILE) \
		    .WAIT $(SUBDIRS)

clean :	$(JAVA_SUBDIRS) $(SUBDIRS) clean_local
clean_local:
	$(RM) $(OBJS)

clobber : $(JAVA_SUBDIRS) $(SUBDIRS) clobber_local
clobber_local: clean_local
	$(RM) $(CLOBBERFILES)

lint: $(SUBDIRS)

msg: $(POFILES)

install: $(ROOTCMD) $(JAVA_SUBDIRS) $(JARFILE) \
		    .WAIT $(SUBDIRS) $(ROOTJAVA) $(ROOTMANIFEST) \
		    $(ROOTSVCMETHOD)

check:	$(CHKMANIFEST)

$(JAVA_SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)
	if [ "$(TARGET)" != "clean" ] && [ "$(TARGET)" != "clobber" ]; \
	then \
		if [ ! -f $(JARFILE) ]; \
		then \
			$(JAR) -cf $(JARFILE) $@/*class; \
		else \
			$(JAR) -uf $(JARFILE) $@/*class; \
		fi \
	fi

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

doc:	all
	$(JAVADOC) -private -classpath $(JARFILE): -sourcepath . \
	    -source 1.4 -d $(DOCDIR) $(PACKAGEDOCS)

$(PROG):	$(OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

$(ROOTUSRLIBDRP)/%: %
	$(INS.file)

FRC:

lint:
	$(LINT.c) $(PROG).c $(LINTLIBS)

include $(SRC)/cmd/Makefile.targ
