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

include ../../../../../Makefile.master
include ../../../../Makefile.cmd


GUIDIR=$(SRC)/cmd/krb5/kadmin/gui

CLASSES= PrintUtil Krb5Conf Filter PrincipalList PolicyList Principal Policy Flags Defaults

JFILES=$(CLASSES:%=%.java)

CLFILES=$(CLASSES:%=../classdir/%.class)

.SUFFIXES: .java .class $(SUFFIXES)

CLASSPATH=$(GUIDIR):$(GUIDIR)/classdir:$(GUIDIR)/util:$(GUIDIR)/dataclasses:$(GUIDIR)/dchanger:$(GUIDIR)/native:$(GUIDIR)/visualrt:$(GUIDIR)/visualrt.jar:$(JAVA_ROOT)/jre/lib/rt.jar:$(JAVA_ROOT)/jre/lib/i18n.jar

../classdir/%.class: %.java
	$(JAVAC) $(JAVAFLAGS) -d ../classdir -classpath $(CLASSPATH) $<

all:  $(CLFILES)

install: all

echo:
	@echo $(CLASSES)
	@echo $(JFILES)
	@echo $(CLFILES)
	@echo $(SUFFIXES)

clobber : clobber_local

clean: clean_local

clobber_local: clean_local

clean_local:
	$(RM) $(CLFILES)
	$(RM) ./*.class
FRC:
