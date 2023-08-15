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
# cmd/dispadmin/Makefile
#

PROG= dispadmin
MANIFEST= scheduler.xml
SVCMETHOD= svc-scheduler
SDC=  SDC$(PROG)
RT=   RT$(PROG)
TS=   TS$(PROG)
IA=   IA$(PROG)
FSS=  FSS$(PROG)
FX=   FX$(PROG)
PROGS= $(PROG) $(RT) $(TS) $(IA) $(FSS) $(FX) $(SDC)

include ../Makefile.cmd

CFLAGS +=	$(CCVERBOSE)
CERRWARN +=	$(CNOWARN_UNINIT)

ROOTDIR=	$(ROOT)/usr/lib/class
ROOTDIRS=	$(ROOTDIR)	\
		$(ROOTDIR)/FSS	\
		$(ROOTDIR)/FX	\
		$(ROOTDIR)/IA	\
		$(ROOTDIR)/RT	\
		$(ROOTDIR)/SDC	\
		$(ROOTDIR)/TS

ROOTPROG=	$(PROG:%=$(ROOTUSRSBIN)/%)
ROOTFSS=	$(FSS:%=$(ROOTDIR)/FSS/%)
ROOTFX=		$(FX:%=$(ROOTDIR)/FX/%)
ROOTIA=		$(IA:%=$(ROOTDIR)/IA/%)
ROOTRT=		$(RT:%=$(ROOTDIR)/RT/%)
ROOTSDC=	$(SDC:%=$(ROOTDIR)/SDC/%)
ROOTTS=		$(TS:%=$(ROOTDIR)/TS/%)
ROOTMANIFESTDIR=	$(ROOTSVCSYSTEM)

# this would be simpler if we renamed rtdispadmin.c and tsdispadmin.c
OBJECTS= $(PROG).o rt$(PROG).o ts$(PROG).o ia$(PROG).o \
		fss$(PROG).o fx$(PROG).o sdc$(PROG).o subr.o

# conditional assignments, because of above names
$(PROG):=	OBJ= $(PROG).o
$(FSS):=	OBJ= fss$(PROG).o
$(FX):=		OBJ= fx$(PROG).o
$(IA):=		OBJ= ia$(PROG).o
$(RT):=		OBJ= rt$(PROG).o
$(SDC):=	OBJ= sdc$(PROG).o
$(TS):=		OBJ= ts$(PROG).o

# install rules
$(ROOTDIR)/% \
$(ROOTDIR)/FSS/% \
$(ROOTDIR)/FX/% \
$(ROOTDIR)/IA/% \
$(ROOTDIR)/RT/% \
$(ROOTDIR)/SDC/% \
$(ROOTDIR)/TS/% : %
	$(INS.file)

.KEEP_STATE:

all: $(PROGS)

$(PROGS): $$(OBJ) subr.o
	$(LINK.c) -o $@ $(OBJ) subr.o $(LDLIBS)
	$(POST_PROCESS)

llib-lsubr.ln:	subr.c
	$(LINT.c) -y -o subr subr.c

lint :=	LDLIBS += -L. -lsubr

install: all $(ROOTPROG) $(ROOTRT) $(ROOTTS) $(ROOTIA) $(ROOTFSS) $(ROOTFX) \
		$(ROOTSDC) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

# Don't re-install directories already installed by Targetdirs
#$(ROOTDIRS):
#	$(INS.dir)

check: $(CHKMANIFEST)

clean:
	$(RM) $(OBJECTS) $(PROGS) llib-lsubr.ln

lint:	llib-lsubr.ln
	$(LINT.c) dispadmin.c $(LDLIBS)
	$(LINT.c) fssdispadmin.c $(LDLIBS)
	$(LINT.c) fxdispadmin.c $(LDLIBS)
	$(LINT.c) iadispadmin.c $(LDLIBS)
	$(LINT.c) rtdispadmin.c $(LDLIBS)
	$(LINT.c) sdcdispadmin.c $(LDLIBS)
	$(LINT.c) tsdispadmin.c $(LDLIBS)

include ../Makefile.targ
