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
# Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright (c) 2018, Joyent, Inc.

ETCTSOLFILES =	devalloc_defaults

include		../Makefile.cmd

CERRWARN +=	-_gcc=-Wno-unused-value
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-clobbered

# not linted
SMATCH=off

ROOTSEC =	$(ROOTETC)/security
ROOTSECDEV =	$(ROOTSEC)/dev
ROOTSECLIB =	$(ROOTSEC)/lib
ROOTSECAUD =	$(ROOTSEC)/audio
ROOTDIRS =	$(ROOTSECDEV) $(ROOTSECLIB) $(ROOTSECAUD)

ROOTMANIFESTDIR=	$(ROOTSVCSYSTEMDEVICE)
SVCMETHOD =	svc-allocate	
MANIFEST =	allocate.xml

RTLCKS =	audio fd0 sr0 st0 st1
CLEANfd =	fd_clean
CLEANsr =	sr_clean
CLEANst =	st_clean
CLEANaudio =	audio_clean
CLEANdisk =	disk_clean
CLEAN_SCRIPTS =	$(CLEANfd) $(CLEANsr) $(CLEANst) $(CLEANaudio) $(CLEANdisk)
WDW_SCRIPTS =	wdwmsg wdwwrapper
WDW_LINKS =	$(CLEANaudio) $(CLEANdisk) $(CLEANst)
SCRIPTS =	$(CLEAN_SCRIPTS) $(WDW_SCRIPTS)
ALLSCRIPTS =	allscripts.sh

PROGalloc =	allocate
PROGmkdevalloc =	mkdevalloc
PROGdminfo =	dminfo
PROGaddalloc =	add_allocatable
PROG =		$(PROGalloc) $(PROGmkdevalloc) $(PROGdminfo) \
	$(PROGaddalloc)

LINKPROGalloc =	deallocate list_devices
LINKPROGmkdevalloc = mkdevmaps
LINKPROGaddalloc = remove_allocatable

POFILE =	allocate_all.po
POFILES =	$(OBJS:%.o=%.po) $(ALLSCRIPTS:%.sh=%.po)

DFLAGS +=	-D_REENTRANT
CPPFLAGS +=	$(DFLAGS)

ROOTLOCKS =	$(RTLCKS:%=$(ROOTSECDEV)/%)
ROOTSCRIPTS =	$(SCRIPTS:%=$(ROOTSECLIB)/%)
ROOTWDWLINKS =	$(WDW_LINKS:%=$(ROOTSECLIB)/%.windowing)

ROOTPROG =	$(PROGallocate:%=$(ROOTUSRSBIN)/%) \
		$(PROGmkdevalloc:%=$(ROOTUSRSBIN)/%) \
		$(PROGdminfo:%=$(ROOTUSRSBIN)/%) \
		$(PROGaddaloc:%=$(ROOTUSRSBIN)/%)
ROOTLINKalloc =	$(LINKPROGalloc:%=$(ROOTUSRSBIN)/%)
ROOTLINKmkdevalloc = $(LINKPROGmkdevalloc:%=$(ROOTUSRSBIN)/%)
ROOTLINKaddalloc = $(LINKPROGaddalloc:%=$(ROOTUSRSBIN)/%)
ROOTLINKS =	$(ROOTLINKalloc) $(ROOTLINKmkdevalloc) $(ROOTLINKaddalloc)

PROGallocOBJS =		allocate.o allocate3.o
PROGmkdevallocOBJS =	mkdevalloc.o
PROGdminfoOBJS =	dminfo.o
PROGaddallocOBJS =	add_allocatable.o

OBJS =		$(PROGallocOBJS) \
		$(PROGmkdevallocOBJS) \
		$(PROGdminfoOBJS) \
		$(PROGaddallocOBJS)

SRCS =		$(OBJS:%.o=%.c)

$(ROOTUSRSBIN)/% :=	FILEMODE = 555
$(ROOTUSRSBIN)/allocate :=	FILEMODE = 4555
$(ROOTSECDEV)/% :=	FILEMODE = 0400
$(ROOTSECLIB)/% :=	FILEMODE = 0555

lint :=			LDLIBS += -lbsm -lsec -lsecdb -ldevinfo -ltsol

$(PROGalloc) :=		LDLIBS += -lbsm -lsec -lsecdb -ldevinfo -ltsol
$(PROGmkdevalloc) :=	LDLIBS += -lbsm
$(PROGdminfo) :=	LDLIBS += -lbsm
$(PROGaddalloc) :=	LDLIBS += -lbsm -lsecdb -ltsol

CLOBBERFILES +=	$(SCRIPTS)

.KEEP_STATE:

all :		$(PROG) $(RTLCKS) $(SCRIPTS)

install :	$(PROG) $(ROOTDIRS) $(ROOTPROG) $(ROOTLOCKS) \
		$(ROOTSCRIPTS) $(ROOTLINKS) $(ROOTWDWLINKS) \
		$(ROOTETCTSOLFILES) $(ROOTMANIFEST) $(ROOTSVCMETHOD)
$(RTLCKS):
		$(TOUCH) $@

$(ROOTSECLIB)/%: %.sh
		$(INS.rename)

$(PROGalloc) :	$(PROGallocOBJS)
		$(LINK.c) $(PROGallocOBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

$(PROGaddalloc) :	$(PROGaddallocOBJS)
		$(LINK.c) $(PROGaddallocOBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

$(PROGmkdevalloc) :	$(PROGmkdevallocOBJS)
			$(LINK.c) $(PROGmkdevallocOBJS) -o $@ $(LDLIBS)
			$(POST_PROCESS)

$(PROGdminfo) :	$(PROGdminfoOBJS)
		$(LINK.c) $(PROGdminfoOBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

$(ROOTDIRS) :
		$(INS.dir)

$(ROOTSECDEV)/%: %
		$(INS.file)

$(ROOTSECLIB)/%: %
		$(RM) $@
		$(INS.file)

$(ROOTLINKalloc) :	$(PROGalloc:%=$(ROOTUSRSBIN)/%)
			$(RM) $@
			$(LN) $(PROGalloc:%=$(ROOTUSRSBIN)/%) $@

$(ROOTLINKaddalloc) :	$(PROGaddalloc:%=$(ROOTUSRSBIN)/%)
			$(RM) $@
			$(LN) $(PROGaddalloc:%=$(ROOTUSRSBIN)/%) $@

$(ROOTLINKmkdevalloc) :	$(PROGmkdevalloc:%=$(ROOTUSRSBIN)/%)
			$(RM) $@
			$(LN) $(PROGmkdevalloc:%=$(ROOTUSRSBIN)/%) $@


$(ROOTETCSECLIB)/%.windowing: %
	$(RM) $@
	$(SYMLINK) $< $@

$(POFILE):      $(POFILES)
		$(RM) $@
		$(CAT) $(POFILES) > $@

#
# Concatenate all the scripts into one before we build the catalogue.
# Done to shrink the catalogue since some messages are shared between
# the various scripts.
#
$(ALLSCRIPTS):	$(SCRIPTS:%=%.sh)
		$(CAT) $(SCRIPTS:%=%.sh) > $@

clean :
		$(RM) $(PROG) $(RTLCKS) $(OBJS) \
		$(SCRIPTS) $(ALLSCRIPTS) $(POFILE) $(POFILES)

lint :		lint_SRCS

strip :
		$(STRIP) $(PROG)

include		../Makefile.targ
