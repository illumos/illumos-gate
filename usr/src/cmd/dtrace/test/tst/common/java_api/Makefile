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
#ident	"%Z%%M%	%I%	%E% SMI"

include $(SRC)/Makefile.master

ROOTOPTPKG = $(ROOT)/opt/SUNWdtrt
JAR_DSTDIR = $(ROOTOPTPKG)/tst/common/java_api
DTEST_DIR=$(SRC)/cmd/dtrace/test
JARDIR = $(DTEST_DIR)/tst/common/java_api

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
JAR=$(JARDIR)/test.jar
JAR_DST=$(JAR_DSTDIR)/test.jar

default: $(JAR)

clean:
	rm -f $(CLASSDIR)/*.class

clobber: clean
	rm -f $(JAR)

all: default

lint:

install: all $(JAR_DST)

$(JAR): $(SRCDIR)/*.java
	mkdir -p $(CLASSDIR)
	javac -cp $(CLASSPATH) -d $(CLASSDIR) $(SRCDIR)/*.java
	jar -cmf $(MANIFEST) $(JAR) -C $(CLASSDIR) .

$(JAR_DST): $(JAR_DSTDIR)

$(JAR_DSTDIR):
	$(INS.dir)

$(JAR_DSTDIR)/%: $(JARDIR)/%
	$(INS.file)
