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
#
# uts/common/sys/lvm/Makefile
#
#       This makefile derive some .h files via rpcgen
#
#       architecture independent
#

UTSBASE = ../../..

include $(UTSBASE)/../Makefile.master

.KEEP_STATE:

DERIVED_FILES = \
	md_basic.h \
	mdmed.h \
	md_mdiox.h \
	md_mhdx.h \
	mdmn_commd.h

RPCGENFLAGS	+=	-C -M -D_KERNEL -DSYSV


def all install lint modlintlib clean.lint:	$(DERIVED_FILES)
all_h install_h: $(DERIVED_FILES)

clean:
	$(RM) $(DERIVED_FILES)

clobber: clean

md_basic.h:	meta_basic.x
	$(RPCGEN) $(RPCGENFLAGS) -h meta_basic.x  | \
	awk '/<synch.h>/ { print "#ifdef _REENTRANT"; print $$0; print "#endif\t/* _REENTRANT */"; next } \
	/<thread.h>/ { print "#ifdef _REENTRANT"; print $$0; print "#endif\t/* _REENTRANT */"; next } \
		{ print $0 } \
	' > $@

md_mhdx.h:	mhdx.x
	$(RPCGEN) $(RPCGENFLAGS) -h mhdx.x | \
	awk '/<synch.h>/ { print "#ifdef _REENTRANT"; print $$0; print "#endif\t/* _REENTRANT */"; next } \
	/<thread.h>/ { print "#ifdef _REENTRANT"; print $$0; print "#endif\t/* _REENTRANT */"; next } \
		{ print $0 } \
	' > $@

mdmed.h:	metamed.x
	$(RPCGEN) $(RPCGENFLAGS) -h metamed.x | \
	awk '/<synch.h>/ { print "#ifdef _REENTRANT"; print $$0; print "#endif\t/* _REENTRANT */"; next } \
	/<thread.h>/ { print "#ifdef _REENTRANT"; print $$0; print "#endif\t/* _REENTRANT */"; next } \
		{ print $0 } \
	' > $@

md_mdiox.h:	mdiox.x
	$(RPCGEN) $(RPCGENFLAGS) -h mdiox.x | \
	awk '/<synch.h>/ { print "#ifdef _REENTRANT"; print $$0; print "#endif\t/* _REENTRANT */"; next } \
	/<thread.h>/ { print "#ifdef _REENTRANT"; print $$0; print "#endif\t/* _REENTRANT */"; next } \
		{ print $0 } \
	' > $@

mdmn_commd.h:	mdmn_commd.x
	$(RPCGEN) -h mdmn_commd.x > $@
