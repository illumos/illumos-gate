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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include $(SRC)/tools/Makefile.tools
include $(SRC)/lib/libscf/Makefile.shared.com

SRCDIR =	$(SRC)/lib/libscf/common
COMDIR =	$(SRC)/common/svc
LIBUUTIL =	../libuutil

CPPFLAGS +=	-DNATIVE_BUILD $(DTEXTDOM) \
		-I$(SRC)/lib/libscf/inc -I$(COMDIR) -I$(LIBUUTIL)/common
LDLIBS =	-R '$$ORIGIN/../../lib/$(MACH)' -L$(ROOTONBLDLIBMACH) \
		-luutil -lc -lgen -lnvpair -lsmbios
NATIVE_LIBS +=	libsmbios.so libnvpair.so libgen.so libc.so

include $(SRC)/Makefile.native

.KEEP_STATE:

all: $(LIBS)

install: all $(ROOTONBLDLIBMACH)/$(DYNLIB) $(ROOTONBLDLIBMACH)/$(LIBLINKS)

$(ROOTONBLDLIBMACH)/$(DYNLIB): $(DYNLIB)
	$(INS.file) $(DYNLIB)

$(ROOTONBLDLIBMACH)/$(LIBLINKS): $(ROOTONBLDLIBMACH)/$(DYNLIB)
		@$(RM) $(ROOTONBLDLIBMACH)/$(LIBLINKS)
		$(SYMLINK) $(DYNLIB) $(ROOTONBLDLIBMACH)/$(LIBLINKS)

include $(SRC)/lib/Makefile.targ
