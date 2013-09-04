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
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
#

# Path to the base of the uts directory tree (usually /usr/src/uts).
UTSBASE	= ../../../../..

#
#	Include common rules.
#
include $(SRC)/Makefile.master

FWTABLE          = ql_fw_table.c
FWIMAGES         = 2200
FWIMAGES        += 2300
FWIMAGES        += 2400
FWIMAGES        += 2500
FWIMAGES        += 6322
FWIMAGES        += 8100

FWMODULES_SRC    = $(FWIMAGES:%=ql_fw_%.c)

all_h install_h : $(FWTABLE)

check:

clean:
	$(RM) $(FWTABLE)

clobber: clean

$(FWTABLE): $(FWMODULES_SRC)
	$(RM) $@
	echo '#include <ql_apps.h>'             >> $@
	echo '#include <ql_api.h>'              >> $@
	echo 'struct fw_table fw_table[] = {'   >> $@
	grep FW_VERSION_STRING $(FWMODULES_SRC) |\
	grep '#define'                          |\
	sed 's/[0-9]"/& },/'                    |\
	sed 's/.*ql_fw_/{ 0x/'                  |\
	sed 's/.c:#define/,/'                   |\
	sed 's/FW_VERSION_STRING//'             >> $@
	echo '{ 0, NULL }'                      >> $@
	echo '};'                               >> $@

.KEEP_STATE:
