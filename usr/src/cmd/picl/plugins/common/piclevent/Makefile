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

LIBRARY=	libpiclevent.a
VERS=		.1

OBJECTS=	piclevent.o

# include library definitions
include $(SRC)/lib/Makefile.lib

include $(SRC)/cmd/picl/plugins/Makefile.com

MODULES = picl_slm.so
MOD_SRCS = picl_slm.c
MOD_OBJS = picl_slm.o
MOD_LDLIBS = -L$(ROOT)/usr/lib -lsysevent -lnvpair -lc

# sysevent SLM dirs
SYSEVENT = sysevent
MODDIR = modules
ROOTLIBSYSEVENTDIR = $(ROOTLIB)/$(SYSEVENT)
ROOTLIBSYSEVENTMODDIR = $(ROOTLIBSYSEVENTDIR)/$(MODDIR)
ROOTLIBSYSEVENTMODULES = $(MODULES:%=$(ROOTLIBSYSEVENTMODDIR)/%)
ROOTETCSYSEVENTDIR = $(ROOTETC)/$(SYSEVENT)

SRCS=		$(OBJECTS:%.o=%.c)

LIBS =		$(DYNLIB)

ROOTLIBDIR =	$(USR_LIB_PLUGINDIR)
ROOTETC	=	$(ROOT)/etc
ROOTLIB =	$(ROOT)/usr/lib

CLEANFILES=	$(MOD_OBJS)
CLOBBERFILES += $(LIBLINKS)
CLOBBERFILES += $(MODULES)

CPPFLAGS +=	-I$(SRC)/lib/libsysevent -I$(SRC)/uts/sun

CFLAGS +=	$(CCVERBOSE) $(C_PICFLAGS)
CPPFLAGS +=	-D_REENTRANT
LDFLAGS +=	$(BDIRECT)
LDLIBS +=	-L$(SRC)/lib/libsysevent -L$(SRC)/lib/libpicltree/$(MACH)
LDLIBS +=	-lc -lpicltree -lnvpair

.KEEP_STATE:

SUBDIRS=

POFILE=	piclevent.po

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
_msg :=		TARGET= _msg

all: $(LIBS) $(LIBLINKS) $(MODULES)

install:	$(ROOTLIBDIR) all $(ROOTLIBS) $(ROOTLINKS) \
	$(ROOTETCSYSEVENTDIR)		\
	$(ROOTLIBSYSEVENTDIR)		\
	$(ROOTLIBSYSEVENTMODDIR)	\
	$(ROOTLIBSYSEVENTMODULES)

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)


$(MSGDOMAIN):
	$(INS.dir)

$(LIBLINKS):	FRC
	$(RM) $@; $(SYMLINK) $(DYNLIB) $@

# include library targets
include $(SRC)/cmd/picl/plugins/Makefile.targ
include $(SRC)/lib/Makefile.targ

%.so: %.o
	$(LINK.c) -o $@ $(GSHARED) -h $@ $< $(MOD_LDLIBS)

%.o: %.c
	$(COMPILE.c) -o $@ $<

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

$(ROOTLIBSYSEVENTDIR):
	$(INS.dir)

$(ROOTETCSYSEVENTDIR):
	$(INS.dir)

$(ROOTLIBSYSEVENTDIR)/%: %
	$(INS.file)

$(ROOTLIBSYSEVENTMODDIR):
	$(INS.dir)

$(ROOTLIBSYSEVENTMODDIR)/%.so: %.so
	$(INS.file)

FRC:
