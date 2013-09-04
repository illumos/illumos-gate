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

include ../Makefile.cmd
include Makefile.hal

SUBDIRS1 =	hald hald-runner addons probing tools
SUBDIRS2 =	fdi
SUBDIRS	=	$(SUBDIRS1) $(SUBDIRS2)

HAL_CONF =		hal.conf
ROOT_DBUS_CONF_DIR =	$(ROOT)/etc/dbus-1/system.d
ROOT_HAL_CONF =		$(HAL_CONF:%=$(ROOT_DBUS_CONF_DIR)/%)

CLOBBERFILES +=	$(HAL_CONF)

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber

$(ROOT_HAL_CONF) :=	FILEMODE = 644

.KEEP_STATE:

all: $(SUBDIRS) $(HAL_CONF)

clean clobber: $(SUBDIRS)

install: $(SUBDIRS) $(ROOT_HAL_CONF)

$(ROOT_DBUS_CONF_DIR):
	$(INS.dir)

$(ROOT_HAL_CONF): $(ROOT_DBUS_CONF_DIR) $(HAL_CONF)
	$(INS.file) $(HAL_CONF)

$(HAL_CONF): $(HAL_CONF).in
	$(SED) -e "s@\@HAL_USER\@@$(HAL_USER)@" \
		< $(HAL_CONF).in > $(HAL_CONF)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include ../Makefile.targ
