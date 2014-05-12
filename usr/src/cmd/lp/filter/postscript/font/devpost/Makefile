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
# Copyright (c) 1989 by Sun Microsystems, Inc.
# Copyright 2014 Garrett D'Amore
#
# cmd/lp/filter/postscript/font/devpost/Makefile
#

include			../../../../Makefile.lp

FONTFILES =		AB AI AR AX BI CB CI CO	\
			CW CX GR HB HI HX JB JI	\
			JR JX KB KI KR KX NB NI	\
			NR NX PA PB PI PX S1 VB	\
			VI VR VX ZD ZI B  H  I	\
			R  S	
FONTLNK1 =		G HM HK HL
FONTLNK2 =		GI
DESCFILE =		DESC

FONTNAMES =		$(FONTFILES:%=%.name)
FONTLNK1OUTS =		$(FONTLNK1:%=%.out)
FONTLNK2OUTS =		$(FONTLNK2:%=%.out)
FONTOUTS =		$(FONTFILES:%=%.out) $(DESCFILE:%=%.out)

SUBDIRS =		charlib fontmaps

NATIVEMAKEDEV =		../native/makedev

ROOTLIBFONT =		$(ROOT)/usr/lib/font
ROOTDEVPOST =		$(ROOTLIBFONT)/devpost

ROOTFONTFILES =		$(FONTFILES:%=$(ROOTDEVPOST)/%) \
			$(ROOTDEVPOST)/$(DESCFILE)
ROOTFONTNAMES =		$(FONTNAMES:%=$(ROOTDEVPOST)/%)
ROOTFONTOUTS =		$(FONTOUTS:%=$(ROOTDEVPOST)/%)		\
			$(FONTLNK1OUTS:%=$(ROOTDEVPOST)/%)	\
			$(FONTLNK2OUTS:%=$(ROOTDEVPOST)/%)
		
FILEMODE =		0444

.KEEP_STATE:

all :			$(FONTOUTS) $(FONTNAMES) $(SUBDIRS)

install:		$(FONTOUTS) $(FONTNAMES) \
			$(ROOTDEVPOST) $(ROOTFONTFILES) $(ROOTFONTNAMES) \
			$(ROOTFONTOUTS) $(SUBDIRS)
		
$(FONTOUTS) :		$$(@:%.out=%) $(NATIVEMAKEDEV)
			@$(RM) $@; $(NATIVEMAKEDEV) $(@:%.out=%)

$(ROOTDEVPOST) :
			$(INS.dir)
	
$(NATIVEMAKEDEV) :
			@cd ..; $(MAKE) native/makedev

$(FONTLNK1OUTS) :	H.out
			@$(RM) $@; $(LN) H.out $@

$(FONTLNK2OUTS) :	HI.out
			@$(RM) $@; $(LN) HI.out $@

$(ROOTDEVPOST)/% :	% $(ROOTDEVPOST)
			$(INS.file)

clean strip lint :	$(SUBDIRS)

clobber:		$(SUBDIRS)
			$(RM) $(FONTOUTS) $(FONTLNK1OUTS) $(FONTLNK2OUTS)

$(SUBDIRS):		FRC
			@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
