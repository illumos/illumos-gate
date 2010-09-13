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
#
#ident	"%Z%%M%	%I%	%E% SMI"
# lib/libadt_jni/com/sun/audit/Makefile

include ../Makefile.com

ADT_PKG = com.sun.audit

TOP = $(SRC)/lib/libadt_jni
CLASSPATH = $(TOP):com/sun/audit

JAVAFLAGS +=	-source 1.4 -target 1.4

SOURCE:sh = ls *.java

CLASSES = $(SOURCE:java=class)

JNIH    = AuditSession.h

JAR_FILE=Audit.jar

INSTALL_JAR = $(ROOTAUDITHOME)/$(JAR_FILE)

CLEAN_FILES = *.class $(JNIH) *.jar AuditEvent*.java

DEFINES=

INCLUDES=	-I${JAVA_HOME}/include	\
		-I${JAVA_HOME}/include/solaris

.KEEP_STATE:

all:	$(JNIH) $(CLASSES)

install:	$(CLASSES) $(ROOTAUDITHOME)	\
		$(JAR_FILE) $(INSTALL_JAR)	\
		$(JNIH)

$(JNIH): $(CLASSES)
	@for class_name in $(CLASSES) ; do \
		k=`/bin/basename $$class_name .class`; \
		class="$$class $(ADT_PKG).$$k"; \
	done; \
	JC="$(JAVAH) -classpath $(CLASSPATH) -jni -o $(JNIH) $$class"; \
	echo $$JC; \
	$$JC

clean clobber:
	$(RM) $(CLEAN_FILES)

$(ROOTAUDITHOME):
	$(INS.dir)

$(ROOTAUDITHOME)/%: %
	$(INS.file)

$(JAR_FILE): $(CLASSES)
	cd $(TOP); \
	pwd; \
	$(JAR) -cvf $(TOP)/com/sun/audit/$(JAR_FILE) com/sun/audit/*.class
