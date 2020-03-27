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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Makefile for building SLP API and slpd.

include $(SRC)/Makefile.master
include Makefile.conf

#Compile and create basic library.

# The most efficient parallelization factor is 2. Any more than this
# slows the build down. A factor of 1 is more efficient than > 2, so
# use the PARALELL directive only if you can restrict the factor to 2.
.NO_PARALLEL:

all:            $(CLASSES) $(ALL_SLP_CLASSES)

clean:
		-$(RM) $(CLASSES)/$(PKGPATH)/*.class $(CLASSES)/$(PKGPATH)/*.properties
		-$(RM) $(CLASSES)/manifest*
		-$(RM) -r $(DOC)/*
		-$(RM) manifest_slpd.template manifest_slp.template

clobber:	clean
		-$(RM) $(CLASSES)/*.jar
		-$(RM) -r $(CLASSES)/META_INF

# Make the class dir, if it doesn't exist
$(CLASSES):
		-@mkdir -p $@

#Make docs for the API only.
docs:
		-@mkdir -p $(DOC)
		cd $(SLPJAVASRC); $(JAVADOC) -public -author -version -classpath $(SLPCLASSPATH) -d $(DOC) $(PKGNAME)

$(CLASSES)/$(PKGPATH):
		$(INS.dir)

message_files:	$(CLASSES)/$(PKGPATH) $(CLASSES)/$(PKGPATH)/$(CLIENT_MSGS) $(CLASSES)/$(PKGPATH)/$(SERVER_MSGS)

$(CLASSES)/$(PKGPATH)/$(CLIENT_MSGS): $(PKGPATH)/$(CLIENT_MSGS)
	cp -f $? $@

$(CLASSES)/$(PKGPATH)/$(SERVER_MSGS): $(PKGPATH)/$(SERVER_MSGS)
	cp -f $? $@

_msg:		$(MSGDIRS) $(MSGFILES)

$(MSGDIRS):
		$(INS.dir)

$(MSGDIR)/%:	$(PKGPATH)/%
		$(INS.file)

$(CLASSES)/$(SLPDJAR): $(ALL_SLP_CLASSES) $(SLPDMANI)
		cd $(CLASSES); $(JAR) cmf manifest.slpd $@ $(PKGPATH)

$(CLASSES)/$(SLPJAR): $(ALL_SLP_CLASSES) $(SLPMANI)
		cd $(CLASSES); $(JAR) cmf manifest.slp $@ $(UA_SA_SUBSET_CLASSES) $(PKGPATH)/$(CLIENT_MSGS)

$(JARDESTDIR):
		$(INS.dir)

manifests:
	$(MAKE) -f Makefile.manifest CLASSES=$(CLASSES) PKGPATH=$(PKGPATH)

install:	all message_files manifests $(JARDESTDIR) $(INSJARS)

# empty targets for top-level building compatability
install_h:

# jstyle check -- more for developer's convenience since the checks are
# not automated in the build.
check:
	$(JSTYLE) -p $(PKGPATH)/*.java
