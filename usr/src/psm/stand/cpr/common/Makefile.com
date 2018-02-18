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
# psm/stand/cpr/common/Makefile.com
#
GREP	=	egrep
WC	=	wc
TOPDIR	=	../../../../..

include $(TOPDIR)/Makefile.master
include $(TOPDIR)/Makefile.psm
include $(TOPDIR)/psm/stand/lib/Makefile.lib

SYSDIR	=  	$(TOPDIR)/uts
COMDIR	=  	../../common
OSDIR  =	$(SYSDIR)/common/os
ARCHDIR	= 	$(SYSDIR)/$(ARCH)
MACHDIR	= 	$(SYSDIR)/$(MACH)
MMUDIR	=	$(SYSDIR)/$(MMU)
PROMLIBDIR=	$(TOPDIR)/psm/stand/lib/promif/$(ARCH_PROMDIR)
PROMLIB	=	$(PROMLIBDIR)/libprom.a

SALIBS +=	$(PROMLIB)
LDLIBS +=	-L$(PROMLIBDIR) -lprom
LDFLAGS =	-dn -M mapfile $(MAP_FLAG)

LINTLIBS +=	$(PROMLIBDIR)/llib-lprom.ln
LINTFLAGS.lib =	-ysxmun

CPRBOOTOBJ +=	support.o compress.o

L_SRCS	=	$(COMDIR)/support.c $(OSDIR)/compress.c
L_COBJ	=	$(CPRBOOTOBJ:%.o=%.ln)

CPPDEFS =	$(ARCHOPTS) -D$(ARCH) -D__$(ARCH) -D$(MACH) -D__$(MACH)
CPPDEFS +=	-D_KERNEL -D_MACHDEP -D__ELF

CPPINCS =	-I. -I$(ARCHDIR) -I$(MMUDIR) -I$(MACHDIR)
CPPINCS +=	-I$(MACHDIR)/$(ARCHVER)	-I$(SYSDIR)/sun
CPPINCS +=	-I$(SYSDIR)/sun4 -I$(SYSDIR)/common -I$(TOPDIR)/head

CPPFLAGS =	$(CPPDEFS) $(CPPINCS) $(CPPFLAGS.master)
CPPFLAGS +=	$(CCYFLAG)$(SYSDIR)/common

CSTD =	$(CSTD_GNU99)
CFLAGS =	$(CCVERBOSE) -O $(CSTD)

ASFLAGS = 	-P -D_ASM $(CPPDEFS) -DLOCORE -D_LOCORE -D__STDC__
AS_CPPFLAGS =	$(CPPINCS) $(CPPFLAGS.master)

# install values
CPRFILES=	$(ALL:%=$(ROOT_PSM_DIR)/$(ARCH)/%)
FILEMODE=	644

# lint stuff
LINTFLAGS += -Dlint
LOPTS = -hbxn

# install rule
$(ROOT_PSM_DIR)/$(ARCH)/%: %
	$(INS.file)


all:	$(ALL)

install: all $(CPRFILES)


LINT.c=	$(LINT) $(LINTFLAGS.c) $(LINT_DEFS) $(CPPFLAGS) -c
LINT.s=	$(LINT) $(LINTFLAGS.s) $(LINT_DEFS) $(CPPFLAGS) -c

# build rule

compress.o: $(OSDIR)/compress.c
	$(COMPILE.c) $(OSDIR)/compress.c

support.o: $(COMDIR)/support.c
	$(COMPILE.c) $(COMDIR)/support.c

compress.ln: $(OSDIR)/compress.c
	@$(LHEAD) $(LINT.c) $(OSDIR)/compress.c $(LTAIL)

support.ln: $(COMDIR)/support.c
	@$(LHEAD) $(LINT.c) $(COMDIR)/support.c $(LTAIL)

%.ln: %.c
	@$(LHEAD) $(LINT.c) $< $(LTAIL)

%.ln: %.s
	@$(LHEAD) $(LINT.s) $< $(LTAIL)

.KEEP_STATE:

.PARALLEL:	$(CPRBOOTOBJ) $(L_COBJ)

cprboot: $(CPRBOOT_MAPFILE) $(CPRBOOTOBJ) $(SALIBS)
	$(LD) $(LDFLAGS) -o $@ $(CPRBOOTOBJ) $(LDLIBS)
	$(POST_PROCESS)
	$(CHK4UBINARY)

$(SALIBS): FRC
	@cd $(@D); $(MAKE) $(MFLAGS)

$(LINTLIBS): FRC
	@cd $(@D); $(MAKE) $(MFLAGS) $(@F)

$(ROOTDIR):
	$(INS.dir)

lint: $(L_COBJ) $(LINTLIBS)
	@$(ECHO) "\n$@: global crosschecks:"
	@$(LINT.2) $(L_COBJ) $(LDLIBS)

clean.lint:
	$(RM) *.ln

clean:
	$(RM) *.o *.ln

clobber:
	$(RM) *.o *.ln $(ALL)

FRC:
