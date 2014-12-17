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
# Copyright (c) 1999-2000 by Sun Microsystems, Inc.
# All rights reserved.
#

include $(SRC)/Makefile.master
JAVAFLAGS = -source 1.5 -target 1.6 -nowarn -O
GUIDIR=$(SRC)/cmd/krb5/kadmin/gui

def             :=      TARGET= def
all             :=      TARGET= all
install         :=      TARGET= install
install_h       :=      TARGET= install_h
clean           :=      TARGET= clean
clobber         :=      TARGET= clobber
lint            :=      TARGET= lint
javadoc         :=      TARGET= javadoc
clean.lint      :=      TARGET= clean.lint
check           :=      TARGET= check
_msg            :=      TARGET= _msg

CLASSPATH=$(GUIDIR)/visualrt:$(JAVA_ROOT)/jre/lib/rt.jar:$(JAVA_ROOT)/jre/lib/i18n.jar

SUBDIRS=props base type shadow awt encoding

$(SUBDIRS):
	cd $@; $(MAKE) CLASSPATH=$(CLASSPATH) $(TARGET)

.KEEP_STATE:

all: $(SUBDIRS)

clean: $(SUBDIRS)

clobber: $(SUBDIRS)

install: all

javadoc: $(SUBDIRS)

_msg: $(SUBDIRS)

