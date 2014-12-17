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

PROG = jdtrace
SRCS = jdtrace.c

include $(SRC)/cmd/Makefile.cmd

ROOTOPTPKG = $(ROOT)/opt/SUNWdtrt
ROOTBIN = $(ROOTOPTPKG)/bin
ROOTLIB = $(ROOTOPTPKG)/lib
ROOTLIBJAVA = $(ROOTLIB)/java

# Use the proto dtrace.jar if it exists, otherwise use whatever is
# installed on the system. It should be possible to build
# usr/src/cmd/dtrace/test independently, even if only on systems that
# have a compatible dtrace.jar installed.
DTRACE_JAR=usr/share/lib/java/dtrace.jar
PROTO_DTRACE_JAR=$(ROOT)/$(DTRACE_JAR)
INSTALLED_DTRACE_JAR=/$(DTRACE_JAR)
CLASSPATH=$(PROTO_DTRACE_JAR):$(INSTALLED_DTRACE_JAR)
DTEST_DIR=$(SRC)/cmd/dtrace/test
CLASSDIR=classes
LIBDIR=lib
MANIFESTDIR=manifest
MANIFEST=$(MANIFESTDIR)/jdtrace.jar-manifest
JDTRACE_JAR=$(LIBDIR)/jdtrace.jar

PROTO_JDTRACE_JAR=$(ROOTLIBJAVA)/jdtrace.jar
CMD = $(ROOTBIN)/jdtrace
XLIST = $(ROOTBIN)/exception.lst

$(PROTO_JDTRACE_JAR) := FILEMODE = 0644
$(CMD) := FILEMODE = 0555
$(XLIST) := FILEMODE = 0444

all: $(JDTRACE_JAR) $(PROG)

clean:
	-$(RM) $(CLASSDIR)/*.class

clobber: clean
	-$(RM) $(JDTRACE_JAR)
	-$(RM) $(PROG)

lint:

install: all $(PROTO_JDTRACE_JAR) $(CMD) $(XLIST)

$(PROG): $(SRCS)
	$(LINK.c) -o $@ $(SRCS) $(LDLIBS)
	$(POST_PROCESS) ; $(STRIP_STABS)

JFLAGS= -g -cp $(CLASSPATH) -d $(CLASSDIR)
JFLAGS += -source 1.5 -target 1.6 -Xlint:all,-options
COMPILE.java=$(JAVAC) $(JFLAGS)
JAVASRC= JDTrace.java Getopt.java

$(JDTRACE_JAR): $(JAVASRC)
	@mkdir -p $(CLASSDIR)
	@mkdir -p $(LIBDIR)
	$(COMPILE.java) $(JAVASRC)
	$(JAR) -cmf $(MANIFEST) $(JDTRACE_JAR) -C $(CLASSDIR) .

$(PROTO_JDTRACE_JAR): $(ROOTLIBJAVA)

$(CMD): $(ROOTBIN)

$(XLIST): $(ROOTBIN)

$(ROOTBIN):
	$(INS.dir)

$(ROOTLIB):
	$(INS.dir)

$(ROOTLIBJAVA): $(ROOTLIB)
	$(INS.dir)

$(ROOTLIBJAVA)/%.jar: $(LIBDIR)/%.jar
	$(INS.file)

$(ROOTBIN)/%: %
	$(INS.file)
