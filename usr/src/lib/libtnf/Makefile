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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#

LIBRARY=	libtnf.a
VERS=		.1
OBJECTS=	$(MACH)dep.o	\
		ref.o		\
		abi.o		\
		util.o		\
		info.o		\
		datum.o		\
		record.o	\
		scalar.o	\
		array.o		\
		struct.o	\
		type.o		\
		error.o		\
		access.o	\
		reader.o

include ../Makefile.lib

SRCDIR =	.

TEXT_DOMAIN=	SUNW_OST_OSLIB
XGETFLAGS=	-a
POFILE=		$(LIBRARY:%.a=%.po)
POFILES=	_error.po

SED=	sed
GREP=	grep

LIBS=		$(DYNLIB)

LDLIBS += -lc

HDRS=		tnf.h
ROOTHDRDIR=	$(ROOT)/usr/include/tnf
ROOTHDRS=	$(HDRS:%=$(ROOTHDRDIR)/%)
CHECKHDRS=	$(HDRS:%.h=%.check)
$(ROOTHDRS) :=	FILEMODE = 0644
CHECKHDRS =	$(HDRS:%.h=%.check)

$(ROOTHDRS) :=	FILEMODE = 644

CPPFLAGS +=	-D_DATUM_MACROS -D_REENTRANT


CERRWARN +=	-_gcc=-Wno-unused-variable

.KEEP_STATE:

all: $(LIBS)

install: all $(ROOTLIBDIR) $(ROOTLIBS) $(ROOTLINKS)

install_h: $(ROOTHDRDIR) $(ROOTHDRS)


check: $(CHECKHDRS)

$(ROOTLIBDIR) $(ROOTHDRDIR):
	$(INS.dir)

$(ROOTHDRDIR)/% : %
	$(INS.file)

ASFLAGS=	$(AS_PICFLAGS) -P -D_SYS_SYS_S -D_LOCORE -D_ASM -DPIC -DLOCORE $(CPPFLAGS)
BUILD.s=	$(AS) $(ASFLAGS) $< -o $@

pics/%.o:	./%.s
		$(BUILD.s)
		$(POST_PROCESS_O)

objs/%.o:	./%.s
		$(BUILD.s)
		$(POST_PROCESS_O)

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

$(POFILES):
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext *.[ch]*`
	$(SED) -e '/^# msg/d' -e '/^domain/d' messages.po > $@
	$(RM) messages.po

include ../Makefile.targ
