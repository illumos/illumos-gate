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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1990,1998 by Sun Microsystems, Inc.
# All rights reserved.
#
# cmd/face/src/filecab/fileb/Makefile

PROG=		chkperm creaserve delserve face listserv \
		mnucheck modserv termtest
SCRIPTS=	basename chexec chkterm color_chk dir_copy \
		dir_creat dir_move frame_chk ichexec \
		identify setenv
DATAFILE=	.facerc

include		../../../../Makefile.cmd

SRCS=		$(PROG:%=%.c)


CPPFLAGS = 	-I../inc $(CPPFLAGS.master)
CLOBBERFILES=	$(SCRIPTS)

# include common face definitions and install rules
include ../../Makefile.com

VMLIBF=		services
OAPROG=		termtest identify setenv
VMPROG=		face dir_move dir_copy dir_creat chkperm creaserve \
		listserv delserve ichexec chexec chkterm basename \
		mnucheck modserv color_chk frame_chk

ROOTDATAFILE=	$(DATAFILE:%=$(ROOTVMLIB)/%)
ROOTVMLIBF=	$(VMLIBF:%=$(ROOTVMLIB)/%)
ROOTVMPROG=	$(VMPROG:%=$(ROOTVMBIN)/%)
ROOTOAPROG=	$(OAPROG:%=$(ROOTOABIN)/%)

FILEMODE=	755

$(ROOTVMLIBF):=		FILEMODE=	644
$(ROOTDATAFILE):=	FILEMODE=	600
$(ROOTDATAFILE):=	OWNER=		bin
$(ROOTVMBIN)/chkperm:=	FILEMODE=	6555
$(ROOTVMBIN)/chkperm:=	OWNER=		bin
$(ROOTVMLIB):=		OWNER=		root
$(ROOTVMBIN):=		OWNER=		root

.KEEP_STATE:

all: $(PROG) $(SCRIPTS) $(DATAFILE) $(VMLIBF) 

$(DATAFILE):
	$(RM) $@; touch $@

install: all .WAIT $(ROOTVMLIBF) $(ROOTVMPROG) $(ROOTOAPROG) \
	$(ROOTDATAFILE)

$(ROOTDATAFILE) $(ROOTVMLIBF): $(ROOTVMLIB)

$(ROOTVMPROG): $(ROOTVMBIN)

$(ROOTOAPROG): $(ROOTOABIN)

clean:

lint:	lint_SRCS

include ../../../../Makefile.targ
