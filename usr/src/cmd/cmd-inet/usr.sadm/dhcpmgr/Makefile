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
# cmd/cmd-inet/usr.sadm/dhcpmgr/Makefile

include $(SRC)/Makefile.master

SUBDIRS =	com lib bin help

all	:=	TARGET= all
install	:=	TARGET= install
clean	:=	TARGET= clean
clobber	:=	TARGET= clobber
lint	:=	TARGET= lint
_msg	:=	TARGET= _msg

GUI_JAR= 	dhcpmgr.jar
GUI_JARFILES=	com/sun/dhcpmgr/client/*.class \
		com/sun/dhcpmgr/ui/*.class \
		com/sun/dhcpmgr/ui/*.gif \
		com/sun/dhcpmgr/client/*.properties \
		com/sun/dhcpmgr/ui/*.properties

SERVER_JAR= 		dhcpsvc.jar
SERVER_JARFILES=	com/sun/dhcpmgr/server/*.class \
			com/sun/dhcpmgr/bridge/*.class \
			com/sun/dhcpmgr/bridge/*.properties


CLI_JAR= 	dhcpcli.jar
CLI_JARFILES=	com/sun/dhcpmgr/cli/*/*.class \
		com/sun/dhcpmgr/cli/*/*.properties

COMMON_JAR= 		dhcpcommon.jar
COMMON_JARFILES=	com/sun/dhcpmgr/data/*.class \
			com/sun/dhcpmgr/data/qualifier/*.class \
			com/sun/dhcpmgr/common/*.class \
			com/sun/dhcpmgr/data/*.properties \
			com/sun/dhcpmgr/common/*.properties

SUNWFILES_JAR=		SUNWfiles.jar
SUNWFILES_JARFILES=	com/sun/dhcpmgr/client/SUNWfiles/*.class \
			com/sun/dhcpmgr/client/SUNWfiles/*.properties
SUNWFILES_MANIFEST=	SUNWfiles.manifest

SUNWBINFILES_JAR= 	SUNWbinfiles.jar
SUNWBINFILES_JARFILES= 	com/sun/dhcpmgr/client/SUNWbinfiles/*.class \
			com/sun/dhcpmgr/client/SUNWbinfiles/*.properties
SUNWBINFILES_MANIFEST=	SUNWbinfiles.manifest

CLI_JARS=${CLI_JAR} ${SERVER_JAR} ${COMMON_JAR}
GUI_JARS=$(GUI_JAR) ${SUNWFILES_JAR} ${SUNWBINFILES_JAR}
ALL_JARS= ${GUI_JARS} ${CLI_JARS}

MANIFEST_FILES= $(SUNWFILES_MANIFEST) $(SUNWBINFILES_MANIFEST)

ROOTGUIDIR = $(ROOT)/usr/sadm/admin/dhcpmgr
ROOTCLIDIR = $(ROOT)/usr/lib/inet/dhcp/svcadm
ROOTDIRS= $(ROOT)/usr/sadm/admin $(ROOTGUIDIR) $(ROOTCLIDIR)

ROOTCLIFILES = ${CLI_JARS}
ROOTGUIFILES = ${GUI_JARS}
ROOTCLIDIRJAR = $(ROOTCLIFILES:%=$(ROOTCLIDIR)/%)
ROOTGUIDIRJAR = $(ROOTGUIFILES:%=$(ROOTGUIDIR)/%)

JAVADOC_PKGS=	com.sun.dhcpmgr.client \
		com.sun.dhcpmgr.ui \
		com.sun.dhcpmgr.data \
		com.sun.dhcpmgr.data.qualifier \
		com.sun.dhcpmgr.server \
		com.sun.dhcpmgr.bridge \
		com.sun.dhcpmgr.cli.common \
		com.sun.dhcpmgr.cli.dhcpconfig \
		com.sun.dhcpmgr.cli.dhtadm \
		com.sun.dhcpmgr.cli.pntadm \
		com.sun.dhcpmgr.common

FILEMODE =	0444
DIRMODE =	0755

.KEEP_STATE:

all: $(SUBDIRS) $(ALL_JARS)

install: all $(ROOTDIRS) $(SUBDIRS) $(ROOTCLIDIRJAR) $(ROOTGUIDIRJAR)

clean clobber: $(SUBDIRS)
	-$(RM) $(MANIFEST_FILES)
	-$(RM) $(ALL_JARS)

lint:	lib

_msg:	$(SUBDIRS)

strip:

#
# The javadocs target is non-standard; used for creating API reference docs
# The javadocs will be placed in $(CODEMGR_WS}/javadocs
#
javadocs:
	$(RM) -r $(CODEMGR_WS)/$@; mkdir $(CODEMGR_WS)/$@
	$(JAVADOC) -classpath $(CLASSPATH) -sourcepath . -d $(CODEMGR_WS)/$@ $(JAVADOC_PKGS) -windowtitle "DHCP Administration packages"

$(GUI_JAR): FRC
	$(JAR) cf $@ $(GUI_JARFILES)

$(SERVER_JAR): FRC
	$(JAR) cf $@ $(SERVER_JARFILES)

$(CLI_JAR): FRC
	$(JAR) cf $@ $(CLI_JARFILES)

$(COMMON_JAR): FRC
	$(JAR) cf $@ $(COMMON_JARFILES)

$(SUNWFILES_JAR): $(SUNWFILES_MANIFEST) FRC
	$(JAR) cmf $(SUNWFILES_MANIFEST) $@ $(SUNWFILES_JARFILES)

$(SUNWBINFILES_JAR): $(SUNWBINFILES_MANIFEST) FRC
	$(JAR) cmf $(SUNWBINFILES_MANIFEST) $@ $(SUNWBINFILES_JARFILES)

$(SUNWFILES_MANIFEST):
	@$(ECHO) "Name: com/sun/dhcpmgr/client/SUNWfiles/SUNWfiles.class" > $@;
	@$(ECHO) "Java-Bean: True" >> $@;

$(SUNWBINFILES_MANIFEST):
	@$(ECHO) "Name: com/sun/dhcpmgr/client/SUNWbinfiles/SUNWbinfiles.class" > $@;
	@$(ECHO) "Java-Bean: True" >> $@;

$(ROOTCLIDIR)/%:	%
	$(INS.file)

$(ROOTGUIDIR)/%: %
	$(INS.file)

$(ROOTDIRS):
	$(INS.dir)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
