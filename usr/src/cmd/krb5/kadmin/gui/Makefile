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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include $(SRC)/Makefile.master
include $(SRC)/cmd/Makefile.cmd

GUIDIR=$(SRC)/cmd/krb5/kadmin/gui

TOGETHER= KdcGui KdcGuiMain KdcGuiOps KdcGuiRoot
TOGETHERJ=$(TOGETHER:%=%.java)
TOGETHERC=$(TOGETHER:%=classdir/%.class)

OTHER=GuiResource GuiResource_en_US HelpData HelpData_en_US
OTHERJ=$(OTHER:%=%.java)
OTHERC=$(OTHER:%=classdir/%.class)

CLASSES=$(TOGETHER) $(OTHER)
JFILES=$(CLASSES:%=%.java)
CLFILES=$(CLASSES:%=%.class)

GKADMIN=gkadmin
JARFILE=gkadmin.jar
VISLIB=visualrt.jar
HTML=HelpIndex.html
MSGBUNDLEDIR=$(ROOT)/usr/lib/krb5/ListResourceBundle

NONEXFILEMODE=444

#
# Set $KRB5GUILIB
#
KRB5GUILIB=	$(ROOT)/usr/lib/krb5

$(KRB5GUILIB)/$(JARFILE)	:=	FILEMODE= 444
$(KRB5GUILIB)/$(VISLIB)		:=	FILEMODE= 444
$(KRB5GUILIB)/$(HTML)		:=	FILEMODE= 444

$(KRB5GUILIB)/%:	%
		$(INS.file)

.SUFFIXES: .java .class $(SUFFIXES)

CLASSPATH=$(GUIDIR):$(GUIDIR)/classdir:$(GUIDIR)/util:$(GUIDIR)/dataclasses:$(GUIDIR)/dchanger:$(GUIDIR)/native:$(GUIDIR)/visualrt:$(GUIDIR)/visualrt.jar:$(JAVA_ROOT)/jre/lib/rt.jar:$(JAVA_ROOT)/jre/lib/i18n.jar

VISRT_CLASSPATH=$(GUIDIR)/visualrt:$(JAVA_ROOT)/jre/lib/rt.jar:$(JAVA_ROOT)/jre/lib/i18n.jar

classdir/%.class: %.java
	$(JAVAC) $(JAVAFLAGS) -d classdir -classpath $(CLASSPATH) $<

SUBDIRS= util dataclasses dchanger native
VISDIR= visualrt

def             :=      TARGET= def
all             :=      TARGET= all
install         :=      TARGET= install
install_h       :=      TARGET= install_h
clean           :=      TARGET= clean
clobber         :=      TARGET= clobber
javadoc         :=      TARGET= javadoc
lint            :=      TARGET= lint
clean.lint      :=      TARGET= clean.lint
check           :=      TARGET= check
_msg            :=      TARGET= _msg

.KEEP_STATE:

all: $(VISDIR) .WAIT KdcGui.java classdir $(SUBDIRS) all_local

all_local: $(TOGETHERC) $(OTHERC) $(KRB5SBIN)/$(GKADMIN) \
	$(KRB5GUILIB)/$(JARFILE) $(KRB5GUILIB)/$(VISLIB) \
	$(KRB5GUILIB)/$(HTML)

$(TOGETHERC): $(TOGETHERJ) $(VISLIB)
	$(JAVAC) $(JAVAFLAGS) -d classdir -classpath $(CLASSPATH) $(TOGETHERJ)

$(VISLIB):
	cd $(VISDIR); $(MAKE) CLASSPATH=$(VISRT_CLASSPATH) install

$(GKADMIN): $(GKADMIN).template
	cat $? | sed -e 's/version_number/$(SEAM_VERS)/' > $@

classdir: FRC
	mkdir -p classdir

$(VISDIR): FRC
	cd $@; $(MAKE) CLASSPATH=$(VISRT_CLASSPATH) $(TARGET)

$(SUBDIRS): FRC
	cd $@; $(MAKE) CLASSPATH=$(CLASSPATH) $(TARGET)

GuiResource_en_US.java: GuiResource.java
	cat $? | sed -e 's/GuiResource/GuiResource_en_US/' > $@

HelpData_en_US.java: HelpData.java
	cat $? | sed -e 's/HelpData/HelpData_en_US/' > $@

$(JARFILE): classdir/*.class
	-$(RM) $(JARFILE)
	(cd classdir; $(JAR) cf ../$(JARFILE) *.class)

KdcGui.java: KdcGuiMain.java KdcGuiOps.java KdcGuiRoot.java

install: $(VISDIR) .WAIT classdir $(SUBDIRS) install_local

lint:	native

ROOTSBINPROGS=	$(KRB5SBIN)/$(GKADMIN)
LIBPROGS=	$(JARFILE) $(VISLIB) $(GIF) $(HTML)
ROOTLIBPROGS=	$(LIBPROGS:%=$(KRB5LIB)/%)
$(ROOTLIBPROGS):=	FILEMODE = 444

install_local: all_local

_msg: $(MSGBUNDLEDIR) $(MSGBUNDLEDIR)/GuiResource.java $(MSGBUNDLEDIR)/HelpData.java

$(MSGBUNDLEDIR)/GuiResource.java $(MSGBUNDLEDIR)/HelpData.java:= FILEMODE = 444

$(MSGBUNDLEDIR)/%: %
	$(INS.file)

$(MSGBUNDLEDIR):
	$(INS.dir)

javadoc:
	$(RM) -rf javadoc
	mkdir javadoc
	$(JAVADOC) -classpath $(CLASSPATH) -d javadoc *.java \
	dataclasses/*.java dchanger/*.java native/*.java util/*.java
	cd visualrt ; $(MAKE) CLASSPATH=$(VISRT_CLASSPATH) $@

test: all
	/bin/env \
	LD_LIBRARY_PATH=/usr/java/lib:/usr/dt/lib:$(SRC)/cmd/kadmin/gui/native \
	/usr/bin/java -classpath \
	.:classdir:native:$(VISLIB):)$(ROOT)/usr/java/lib/rt.jar \
	KdcGuiMain &

echo:
	@echo $(CLASSES)
	@echo $(JFILES)
	@echo $(CLFILES)
	@echo $(SUFFIXES)

clobber: $(VISDIR) $(SUBDIRS) clobber_local
	-$(RM) visualrt.jar
	-$(RM) -rf javadoc

clean: $(VISDIR) $(SUBDIRS) clean_local

clobber_local: clean_local

clean_local:
	$(RM) classdir/*.class $(JARFILE) $(GKADMIN) GuiResource_en_US.java HelpData_en_US.java

FRC:
