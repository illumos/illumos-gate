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

LIBRARY=	libpiclfrudata.a
VERS=		.1
OBJECTS=	fru_data.o

# include library definitions
include $(SRC)/Makefile.psm
include $(SRC)/lib/Makefile.lib

ROOT_PLATFORM =	$(USR_PLAT_DIR)/sun4u

include $(SRC)/cmd/picl/plugins/Makefile.com

LIBLINKS=	libpiclfrudata.so

SRCS=		$(OBJECTS:%.o=%.c)

LIBS =		$(DYNLIB)

ROOTLIBDIR =	$(ROOT_PLAT_PLUGINDIR)

CLOBBERFILES += $(LIBLINKS)
CSTYLE	=	cstyle -p -P
HDRCHK	=	hdrchk


CPPFLAGS +=	-I$(SRC)/lib/libfru/include -I../lib/fruaccess
CPPFLAGS +=	-I$(SRC)/cmd/picl/plugins/lib/picld_pluginutil
CPPFLAGS +=	-I$(SRC)/lib/libfruutils/
CFLAGS +=	$(CCVERBOSE)
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/sun4u/lib/fruaccess
LDLIBS +=	-L$(SRC)/lib/libfruutils/$(MACH)
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/common/frutree
LDLIBS +=	-L$(ROOT)/usr/lib/picl/plugins
LDLIBS +=	-lc -lnvpair -lfruutils
LDLIBS +=	-lpicltree -lpiclfrutree -lfruaccess -lpicld_pluginutil
LDLIBS +=	-R/usr/platform/\$$PLATFORM/lib/picl/plugins:/usr/platform/\$$PLATFORM/lib:/usr/platform/sun4u/lib/picl/plugins:/usr/lib/picl/plugins:/usr/platform/sun4u/lib
.KEEP_STATE:


SUBDIRS=

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
_msg :=		TARGET= _msg

POFILE=		$(LIBRARY:.a=.po)
POFILES=	frudata.po

all:  $(LIBS) $(LIBLINKS) $(CONF)

install:	$(ROOTLIBDIR) all $(ROOTLIBS) $(ROOTLINKS)

check-style :
	$(CSTYLE) *.c *.h
	$(HDRCHK) *.h

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(MSGDOMAIN):
	$(INS.dir)

$(POFILE): .WAIT $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

$(POFILES):
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) *.[ch]* */*.[ch]*
	$(SED) -e '/^# msg/d' -e '/^domain/d' messages.po > $@
	$(RM) messages.po

$(LIBLINKS):	FRC
	$(RM) $@; $(SYMLINK) $(DYNLIB) $@

# include library targets
include $(SRC)/cmd/picl/plugins/Makefile.targ
include $(SRC)/lib/Makefile.targ

lint :

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
