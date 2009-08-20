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
# tools/abi/Makefile
#

# This directory contains baseline interface definition files representing
# the shared object interfaces from the most recent official Solaris release.
# Builds in this workspace are compared to these baselines when the nightly
# -A (ABI) flag is set, in order to ensure that new interfaces evolve
# in a backward compatible manner.
#
# This makefile is used to generate new baseline definitions. This
# is necessary when a backport modifies the versioning details
# of a given object:
#
#	- Activate the workspace
#	- Move to this directory
#	- Run 'make'. Note that this can take awhile if the proto is
#	  being accessed via NFS, which is the usual case.
#	- The new baseline definitions are found in interface_new.XXX,
#	  where XXX is i386/sparc.
#
# To replace the existing baseline files, rename the 'interface_new.XXX' files
# to 'interface.XXX' Before you do so, it is important to verify the
# following:
#
#	- This makefile builds definitions for all architectures. The
#	  architecture of the system you are using to run this makefile
#	  is not important. However, you must be sure that the proto
#	  referenced by BASE_PROTO has complete sparc and i386 trees.
#
#	- You should ensure that you don't run this when the
#	  BASE_PROTO is in the middle of a build. To double check,
#	  diff the old and new interface files, and ensure that
#	  the changes are what you expect:
#
#		% diff interface.i386 interface_new.i386
#		% diff interface.sparc interface_new.sparc
#


# Currently, we use the Solaris 10 feature gate as our baseline
BASE_PROTO=/ws/on10-feature-patch/gates/on10-feature-patch/proto

baseline : interface_new.i386 interface_new.sparc

object_list.% :
	find_elf -frs $(BASE_PROTO)/root_$* > object_list.$*

interface_new.% : object_list.%
	interface_check -o -i $@ -E $@.err -f object_list.$*

clean clobber:
	rm -f interface_new.* object_list.*
