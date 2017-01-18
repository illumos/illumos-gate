#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright (c) 2016, 2017 by Delphix. All rights reserved.
#

# The following file name generation rules allow the addition of tests,
# libraries and other miscellaneous files without having to specify them
# all individually in lower level Makefiles.
PROGS:sh = find . -maxdepth 1 -type f \( \
    -name "*.ksh" -o \
    -name "*.sh" \)
FILES:sh = find . -maxdepth 1 -type f \( \
    -name "*.Z" -o \
    -name "*.bz2" -o \
    -name "*.cfg" -o \
    -name "*.d" -o \
    -name "*.err" -o \
    -name "*.fio" -o \
    -name "*.out" -o \
    -name "*.run" -o \
    -name "*shlib" -o \
    -name "*.txt" -o \
    -name "*.zcp" \)

CMDS = $(PROGS:%.sh=$(TARGETDIR)/%)
CMDS += $(PROGS:%.ksh=$(TARGETDIR)/%)
$(CMDS) := FILEMODE = 0555

LIBS = $(FILES:%=$(TARGETDIR)/%)
$(LIBS) := FILEMODE = 0444

all lint clean clobber:

install: $(CMDS) $(LIBS)

$(CMDS): $(TARGETDIR)

$(LIBS): $(TARGETDIR)

$(TARGETDIR):
	$(INS.dir)

$(TARGETDIR)/%: %.sh
	$(INS.rename)

$(TARGETDIR)/%: %.ksh
	$(INS.rename)

$(TARGETDIR)/%: %
	$(INS.file)

.PARALLEL: $(SUBDIRS)
SUBDIRS:sh = find ./* -maxdepth 0 -type d
