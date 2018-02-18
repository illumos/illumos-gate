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

HAL_PROGS =	hal-system-lcd-set-brightness-sunos \
		hal-system-lcd-get-brightness-sunos

HAL_SCRIPTS =	hal-system-power-reboot-sunos hal-system-power-suspend-sunos \
		hal-system-power-hibernate-sunos hal-system-power-shutdown-sunos

OBJS =		$(HAL_PROG:%=%.o)

CLOBBERFILES += $(HAL_PROGS)

include ../../../Makefile.cmd
include ../../Makefile.hal

$(HAL_PROGS) :=		LDLIBS += -lc $(ZIGNORE) -lglib-2.0

CPPFLAGS += $(HAL_DBUS_CPPFLAGS) $(HAL_GLIB_CPPFLAGS) $(HAL_CONFIG_CPPFLAGS)
CPPFLAGS += -I$(ROOT)/usr/include/hal
CPPFLAGS += -I$(ROOT)/usr/include/libpolkit
CSTD = $(CSTD_GNU99)

ROOTCMDDIR =		$(ROOTLIB_HAL)/sunos 
ROOTCMD =		$(HAL_PROGS:%=$(ROOTCMDDIR)/%) \
			$(HAL_SCRIPTS:%=$(ROOTCMDDIR)/%)

.KEEP_STATE:

all: $(HAL_PROGS) $(HAL_SCRIPTS)

install: all $(ROOTCMD)

clean:
	$(RM) $(OBJS) $(HAL_PROGS) $(HAL_SCRIPTS)

include ../../../Makefile.targ
