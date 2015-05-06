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
# Copyright (c) 1999-2001 by Sun Microsystems, Inc.
# All rights reserved.
#
# usr/src/cmd/krb5/kadmin/gui/native/Makefile
#

include		$(SRC)/lib/Makefile.lib

SUBDIRS=	$(MACH)

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install
lint :=		TARGET= lint


CLASSES=Kadmin

JFILES=$(CLASSES:%=%.java)
CLFILES=$(CLASSES:%=../classdir/%.class)

CLOBBERFILES +=	$(CLFILES) $(HFILES)

GUI=$(SRC)/cmd/krb5/kadmin/gui
JARFILES=$(GUI)/visualrt.jar:$(JAVA_ROOT)/jre/lib/rt.jar:$(JAVA_ROOT)/jre/lib/i18n.jar
GUISUBDIRS=$(GUI)/classdir:$(GUI)/util:$(GUI)/dataclasses:$(GUI)/dchanger:$(GUI)/native:$(GUI)/visualrt

CLASSPATH=$(GUI):$(GUISUBDIRS):$(JARFILES)

.KEEP_STATE:

all lint install: $(HFILES) $(CLFILES) $(SUBDIRS)

../classdir/%.class: %.java
	$(JAVAC) $(JAVAFLAGS) -d ../classdir -classpath $(CLASSPATH) $<

test: Test.class
	/bin/env LD_LIBRARY_PATH=$(MACH):$(ROOT)/usr/lib/krb5 $(JAVA_ROOT)/bin/java \
	-classpath $(CLASSPATH) Test

clean clobber: $(SUBDIRS)

$(MACH): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
