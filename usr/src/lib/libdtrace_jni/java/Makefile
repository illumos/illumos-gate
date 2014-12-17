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

# The Java DTrace API package

PKGPATH=org/opensolaris/os/dtrace
PKGNAME=org.opensolaris.os.dtrace

# The Java DTrace API directories

APIDIR=$(SRC)/lib/libdtrace_jni/java
CLASSES=$(APIDIR)/classes
JNI=$(APIDIR)/native
JARS=$(APIDIR)/lib
DOCS=$(APIDIR)/docs
DOCAPI=$(DOCS)/api
DOCEXAMPLES=$(DOCS)/examples
DOCHTML=$(DOCS)/html
DOCIMAGES=$(DOCS)/images
MANIFEST=$(APIDIR)/manifest
APIJAVASRC=$(APIDIR)/src

# Java DTrace API jar file, its ultimate destination, and packaging details
APIJAR=dtrace.jar
JARDESTDIR=$(ROOT)/usr/share/lib/java
INSJARS=$(JARDESTDIR)/$(APIJAR)
# javadoc
DOCDESTDIR=$(ROOT)/usr/share/lib/java/javadoc/dtrace
DOCAPIDESTDIR=$(DOCDESTDIR)/api
DOCEXAMPLESDESTDIR=$(DOCDESTDIR)/examples
DOCHTMLDESTDIR=$(DOCDESTDIR)/html
DOCIMAGESDESTDIR=$(DOCDESTDIR)/images

$(JARDESTDIR)/%: $(JARS)/%
	$(INS.file)

$(DOCEXAMPLESDESTDIR)/%: $(DOCEXAMPLES)/%
	$(INS.file)

$(DOCHTMLDESTDIR)/%: $(DOCHTML)/%
	$(INS.file)

$(DOCIMAGESDESTDIR)/%: $(DOCIMAGES)/%
	$(INS.file)

# Manifest files
APIMANI= $(MANIFEST)/dtrace.mf
MANIFESTS= $(APIMANI)

# Controlled CLASSPATH for making
APICLASSPATH=$(CLASSES):$(APIJAVASRC)

# javac flags
JFLAGS= -g -d $(CLASSES) -sourcepath $(APICLASSPATH)
JFLAGS += -source 1.5 -target 1.6
JFLAGS += -Xlint:all,-rawtypes,-options

# The default make rule for Java files
COMPILE.java=$(JAVAC) $(JFLAGS)

$(CLASSES)/$(PKGPATH)/%.class:	$(APIJAVASRC)/$(PKGPATH)/%.java
				$(COMPILE.java) $<

# javah generated headers
APIHDR= LocalConsumer.h
JNIHDRS=$(JNI)/$(APIHDR)

# API classes with native methods
JNI_CLASSNAMES=\
    LocalConsumer

JNI_CLASSES=${JNI_CLASSNAMES:%=%.class}
DTRACE_JNI_CLASSES=${JNI_CLASSES:%=$(CLASSES)/$(PKGPATH)/%}
JNI_FULL_CLASSNAMES=${JNI_CLASSNAMES:%=$(PKGNAME).%}

# All API classes
API_CLASSNAMES=\
	AbstractAggregationValue \
	Aggregate \
	AggregateSpec \
	Aggregation \
	AggregationRecord \
	AggregationValue \
	AvgValue \
	Consumer \
	ConsumerAdapter \
	ConsumerEvent \
	ConsumerException \
	ConsumerListener \
	CountValue \
	DTraceException \
	DataEvent \
	Distribution \
	Drop \
	DropEvent \
	Error \
	ErrorEvent \
	ExceptionHandler \
	ExitRecord \
	Flow \
	InterfaceAttributes \
	KernelStackRecord \
	KernelSymbolRecord \
	LinearDistribution \
	LocalConsumer \
	LogDistribution \
	LogLinearDistribution \
	MaxValue \
	MinValue \
	NativeException \
	Option \
	PrintaRecord \
	PrintfRecord \
	Probe \
	ProbeData \
	ProbeDescription \
	ProbeInfo \
	ProcessEvent \
	ProcessState \
	Program \
	ProgramInfo \
	Record \
	ResourceLimitException \
	ScalarRecord \
	StackFrame \
	StackValueRecord \
	StddevValue \
	SumValue \
	SymbolValueRecord \
	Tuple \
	UserStackRecord \
	UserSymbolRecord \
	Utility \
	ValueRecord

API_CLASSES=${API_CLASSNAMES:%=%.class}
DTRACE_API_CLASSES=${API_CLASSES:%=$(CLASSES)/$(PKGPATH)/%}


all:            $(CLASSES) $(DTRACE_API_CLASSES) $(JNI)/$(APIHDR)

clean:
		-$(RM) $(CLASSES)/$(PKGPATH)/*.class
		-$(RM) $(JNI)/*.h
		-$(RM) -r $(DOCAPI)

clobber:	clean
		-$(RM) $(JARS)/*.jar

# Make the class dir, if it doesn't exist
$(CLASSES):
		-@mkdir -p $@

# Make the directory for javah-generated headers, if it doesn't exist
$(JNI):
		-@mkdir -p $@

$(JNI)/$(APIHDR): $(JNI) $(DTRACE_JNI_CLASSES)
		$(JAVAH) -o $@ -classpath $(CLASSES) $(JNI_FULL_CLASSNAMES)
		-@touch $@

# Rule for installing API javadoc.
$(DOCAPIDESTDIR)/index.html: $(DTRACE_API_CLASSES)
		-@mkdir -p $(DOCAPIDESTDIR)
		-$(RM) -r $(DOCAPIDESTDIR)/*
		cd $(APIJAVASRC); umask 022; \
		$(JAVADOC) -protected -use -notimestamp \
		-classpath $(APICLASSPATH) -d $(DOCAPIDESTDIR) \
		$(PKGNAME)

$(CLASSES)/$(PKGPATH):
		$(INS.dir)

$(JARS)/$(APIJAR): $(DTRACE_API_CLASSES) $(APIMANI)
		-@mkdir -p $(JARS)
		$(JAR) cfm $@ $(APIMANI) -C $(CLASSES) .

$(JARDESTDIR):
		$(INS.dir)

$(DOCDESTDIR):
		$(INS.dir)

$(DOCAPIDESTDIR):
		$(INS.dir)

$(DOCEXAMPLESDESTDIR):
		$(INS.dir)

$(DOCHTMLDESTDIR):
		$(INS.dir)

$(DOCIMAGESDESTDIR):
		$(INS.dir)

install:	all $(JARDESTDIR) $(INSJARS) $(DOCDESTDIR) \
	$(DOCAPIDESTDIR) \
	$(DOCAPIDESTDIR)/index.html \
	$(DOCEXAMPLESDESTDIR) \
	$(DOCEXAMPLESDESTDIR)/TestAPI.java \
	$(DOCEXAMPLESDESTDIR)/TestAPI2.java \
	$(DOCEXAMPLESDESTDIR)/TestTarget.java \
	$(DOCEXAMPLESDESTDIR)/hello.d \
	$(DOCEXAMPLESDESTDIR)/intrstat.d \
	$(DOCEXAMPLESDESTDIR)/syscall.d \
	$(DOCEXAMPLESDESTDIR)/target.d \
	$(DOCHTMLDESTDIR) \
	$(DOCHTMLDESTDIR)/JavaDTraceAPI.html \
	$(DOCHTMLDESTDIR)/fast.html \
	$(DOCIMAGESDESTDIR) \
	$(DOCIMAGESDESTDIR)/JavaDTraceAPI.gif

# empty targets for top-level building compatability

install_h lint:

# create API javadoc

doc:
		-@mkdir -p $(DOCAPI)
		cd $(APIJAVASRC); umask 022; \
		$(JAVADOC) -protected -use -notimestamp \
		-classpath $(APICLASSPATH) -d $(DOCAPI) \
		$(PKGNAME)
