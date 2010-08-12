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
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
#

include ../Makefile.cmd

.KEEP_STATE:

all := TARGET = all
clean := TARGET = clean
clobber := TARGET = clobber
install := TARGET = install
lint := TARGET = lint
_msg := TARGET = _msg
check := TARGET = check

SUBDIRS = fpsd compilercheck fptest

all clean clobber install lint _msg: $(SUBDIRS)

check: fpsd

#
# The compilation of fptest is forced to be done with the Sun
# Studio compiler.  This is because fptest is dependent on some Sun
# performance libraries provided as part of the Sun Studio compiler
# installation.  fptest statically links libsunperf.a, libfui.a,
# libfai.a, libfsu.a, and libsunmath.a.  The other SUBDIRS will be
# compiled normally.
#

$(SUBDIRS): FRC
	@case $(TARGET)							\
	in								\
		clean|clobber|lint|_msg)				\
			cd $@; pwd; VERSION='$(VERSION)' $(MAKE) $(TARGET);\
			;;						\
		*)							\
			if [ $@ != fptest ];				\
			then						\
				cd $@; pwd; VERSION='$(VERSION)'	\
				$(MAKE) $(TARGET);			\
			else						\
				cd $@; pwd; VERSION='$(VERSION)'	\
				$(MAKE) __GNUC=$(POUND_SIGN) $(TARGET);	\
			fi						\
			;;						\
	esac

FRC:
