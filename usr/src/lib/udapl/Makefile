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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

include ../Makefile.lib

SUBDIRS =	libdat

# EXPORT DELETE START
$(CLOSED_BUILD)SUBDIRS += $(CLOSED)/lib/udapl/udapl_tavor
# EXPORT DELETE END

HDRSUBDIRS = 	libdat

all	:= TARGET = all
clean	:= TARGET = clean
clobber	:= TARGET = clobber
check	:= TARGET = check
install	:= TARGET = install
install_h := TARGET = install_h
lint	:= TARGET = lint
debug := TARGET = debug

.KEEP_STATE:

all debug clean clobber lint: $(SUBDIRS)

install: $(ROOTDIRS) $(SUBDIRS)

check install_h: $(HDRSUBDIRS)

# EXPORT DELETE START
# Special targets to clean up the source tree for export distribution
# These targets change teh source tree
EXPORT_SRC:
	$(RM) Makefile+
	$(SED) -e "/^# EXPORT DELETE START/,/^# EXPORT DELETE END/d" \
		< Makefile > Makefile+
	$(MV) Makefile+ Makefile
	$(CHMOD) 444 Makefile

# EXPORT DELETE END

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include $(SRC)/lib/Makefile.targ
