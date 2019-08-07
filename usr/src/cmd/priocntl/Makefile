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

PROG= priocntl

PRIOCNTLOBJ=	$(PROG).o subr.o

PRIOCNTLSRC= $(PRIOCNTLOBJ:%.o=%.c)
OBJS= $(PRIOCNTLOBJ) rt$(PROG).o ts$(PROG).o ia$(PROG).o fss$(PROG).o \
	fx$(PROG).o sdc$(PROG).o
SRCS= $(OBJ:%.o=%.c)

include ../Makefile.cmd

LDLIBS += -lcontract
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += $(CNOWARN_UNINIT)

CLASSD = $(ROOTLIB)/class
RTD = $(CLASSD)/RT
SDCD = $(CLASSD)/SDC
TSD = $(CLASSD)/TS
IAD = $(CLASSD)/IA
FSSD = $(CLASSD)/FSS
FXD = $(CLASSD)/FX
DIRS = $(CLASSD) $(RTD) $(SDCD) $(TSD) $(IAD) $(FSSD) $(FXD)

RTPROG = RT$(PROG)
SDCPROG = SDC$(PROG)
TSPROG = TS$(PROG)
IAPROG = IA$(PROG)
FSSPROG = FSS$(PROG)
FXPROG = FX$(PROG)

ROOTRTPROG = $(RTD)/$(RTPROG)
ROOTSDCPROG = $(SDCD)/$(SDCPROG)
ROOTTSPROG = $(TSD)/$(TSPROG)
ROOTIAPROG = $(IAD)/$(IAPROG)
ROOTFSSPROG = $(FSSD)/$(FSSPROG)
ROOTFXPROG = $(FXD)/$(FXPROG)

$(ROOTUSRSBINPROG) := FILEMODE = 04555
$(DIRS) := FILEMODE = 0775
CLOBBERFILES += $(RTPROG) $(SDCPROG) $(TSPROG) $(IAPROG) $(FSSPROG) $(FXPROG)

# installation rules
$(RTD)/% : %
	$(INS.file)

$(SDCD)/% : %
	$(INS.file)

$(TSD)/% : %
	$(INS.file)

$(IAD)/% : %
	$(INS.file)

$(FSSD)/% : %
	$(INS.file)

$(FXD)/% : %
	$(INS.file)

.KEEP_STATE:

all: $(PROG) $(RTPROG) $(SDCPROG) $(TSPROG) $(IAPROG) $(FSSPROG) $(FXPROG)

$(PROG): $(PRIOCNTLOBJ)
	$(LINK.c) $(PRIOCNTLOBJ) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(RTPROG): rt$(PRIOCNTLOBJ)
	$(LINK.c) rt$(PRIOCNTLOBJ) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(SDCPROG): sdc$(PRIOCNTLOBJ)
	$(LINK.c) sdc$(PRIOCNTLOBJ) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(TSPROG): ts$(PRIOCNTLOBJ)
	$(LINK.c) ts$(PRIOCNTLOBJ) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(IAPROG): ia$(PRIOCNTLOBJ)
	$(LINK.c) ia$(PRIOCNTLOBJ) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(FSSPROG): fss$(PRIOCNTLOBJ)
	$(LINK.c) fss$(PRIOCNTLOBJ) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(FXPROG): fx$(PRIOCNTLOBJ)
	$(LINK.c) fx$(PRIOCNTLOBJ) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all $(DIRS) 	\
	$(ROOTPROG)	\
	$(ROOTRTPROG)	\
	$(ROOTSDCPROG)	\
	$(ROOTTSPROG)	\
	$(ROOTIAPROG)	\
	$(ROOTFSSPROG)	\
	$(ROOTFXPROG)

$(DIRS):
	$(INS.dir)

clean:
	$(RM) $(OBJS)

lint:
	$(LINT.c) $(PRIOCNTLSRC) $(LDLIBS)
	$(LINT.c) rt$(PRIOCNTLSRC) $(LDLIBS)
	$(LINT.c) sdc$(PRIOCNTLSRC) $(LDLIBS)
	$(LINT.c) ts$(PRIOCNTLSRC) $(LDLIBS)
	$(LINT.c) ia$(PRIOCNTLSRC) $(LDLIBS)
	$(LINT.c) fss$(PRIOCNTLSRC) $(LDLIBS)
	$(LINT.c) fx$(PRIOCNTLSRC) $(LDLIBS)

include ../Makefile.targ
