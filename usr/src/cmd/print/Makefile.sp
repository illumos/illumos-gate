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
# cmd/print/Makefile.sp
# Common makefile definitions (should be) used by all print(lp) makefiles
#

include		$(SRC)/cmd/Makefile.cmd

LPROOT=		$(SRC)/cmd/lp
NPRTROOT=	$(LPROOT)
ROOTVAR=	$(ROOT)/var
ROOTVARSP=	$(ROOT)/var/spool
ROOTVARSPOOLPRINT=	$(ROOTVARSP)/print

ROOTINIT_D=	$(ROOTETC)/init.d
ROOTRC0_D=	$(ROOTETC)/rc0.d
ROOTRCS_D=	$(ROOTETC)/rcS.d
ROOTRC1_D=	$(ROOTETC)/rc1.d
ROOTRC2_D=	$(ROOTETC)/rc2.d


ROOTETCLP=	$(ROOTETC)/lp
ROOTLIBLP=	$(ROOTLIB)/lp
ROOTBINLP=	$(ROOTBIN)/lp
ROOTLIBLPPOST =	$(ROOTLIBLP)/postscript
ROOTLOCALLP=	$(ROOTLIBLP)/local
ROOTLIBPRINT=	$(ROOTLIB)/print
ROOTLIBPRINTBIN=	$(ROOTLIBPRINT)/bin

ROOTUSRUCB=	$(ROOT)/usr/ucb


#
# $(EMODES): Modes for executables
# $(SMODES): Modes for setuid executables
# $(DMODES): Modes for directories
#
EMODES	=	0555
SMODES	=	04555
DMODES	=	0755


INC	=	$(ROOT)/usr/include
INCSYS  =       $(INC)/sys

LPINC	=	$(SRC)/include
#NPRTINC	=	$(NPRTROOT)/include
NPRTINC	=	$(SRC)/lib/print/libprint/common
LPLIB	=	$(SRC)/lib
LDLIBS +=	-L$(LPLIB)


LIBNPRT =       -L$(ROOT)/usr/lib -lprint

# lint definitions

LINTFLAGS	+=	-L $(SRC)/lib/print -lprint -lnsl -lsocket 

all	:=TARGET= all
install	:=TARGET= install
clean	:=TARGET= clean
clobber	:=TARGET= clobber
lint	:=TARGET= lint
strip	:=TARGET= strip
_msg	:=TARGET= _msg

ROOTLIBLPPROG=	$(PROG:%=$(ROOTLIBLP)/%)
ROOTBINLPPROG=	$(PROG:%=$(ROOTBINLP)/%)
ROOTETCLPPROG=	$(PROG:%=$(ROOTETCLP)/%)
ROOTUSRUCBPROG=	$(PROG:%=$(ROOTUSRUCB)/%)
ROOTLOCALLPPROG=	$(PROG:%=$(ROOTLOCALLP)/%)
ROOTLIBLPPOSTPROG=	$(PROG:%=$(ROOTLIBLPPOST)/%)
ROOTLIBPRINTPROG=	$(PROG:%=$(ROOTLIBPRINT)/%)

$(ROOTLIBLP)/%	\
$(ROOTBINLP)/%	\
$(ROOTETCLP)/%	\
$(ROOTUSRUCB)/%	\
$(ROOTLOCALLP)/% \
$(ROOTLIBLPPOST)/% \
$(ROOTLIBPRINT)/% :	%
		$(INS.file)
