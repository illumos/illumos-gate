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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/SUNWdtrt
JAR_DSTDIR = $(ROOTOPTPKG)/tst/common/java_api
JAR_SRCDIR = $(SRC)/cmd/dtrace/test/tst/common/java_api

# Use the proto dtrace.jar if it exists, otherwise use whatever is
# installed on the system. It should be possible to build
# usr/src/cmd/dtrace/test independently, even if only on systems that
# have a compatible dtrace.jar installed.
DTRACE_JAR=usr/share/lib/java/dtrace.jar
PROTO_DTRACE_JAR=$(ROOT)/$(DTRACE_JAR)
INSTALLED_DTRACE_JAR=/$(DTRACE_JAR)
CLASSPATH=$(PROTO_DTRACE_JAR):$(INSTALLED_DTRACE_JAR)
SRCDIR=src
CLASSDIR=classes
MANIFESTDIR=manifest
MANIFEST=$(MANIFESTDIR)/test.jar-manifest
TEST_JAR=$(JAR_SRCDIR)/test.jar
PROTO_TEST_JAR=$(JAR_DSTDIR)/test.jar

default: $(TEST_JAR)

clean:
	$(RM) $(CLASSDIR)/*.class

clobber: clean
	$(RM) $(TEST_JAR)

all: default

lint:

install: all $(PROTO_TEST_JAR)

JFLAGS= -g -cp $(CLASSPATH) -d $(CLASSDIR)
JFLAGS += -source 1.5 -target 1.6 -Xlint:all,-options,-rawtypes
COMPILE.java=$(JAVAC) $(JFLAGS)

$(TEST_JAR): $(SRCDIR)/*.java
	@mkdir -p $(CLASSDIR)
	$(COMPILE.java) $(SRCDIR)/*.java
	$(JAR) -cmf $(MANIFEST) $(TEST_JAR) -C $(CLASSDIR) .

$(PROTO_TEST_JAR): $(JAR_DSTDIR)

$(JAR_DSTDIR):
	$(INS.dir)

$(JAR_DSTDIR)/%: $(JAR_SRCDIR)/%
	$(INS.file)
