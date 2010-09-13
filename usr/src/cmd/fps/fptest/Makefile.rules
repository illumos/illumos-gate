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
# ident	"%Z%%M%	%I%	%E% SMI"
#

iflush.o sparcv9/iflush.o : iflush.s
	$(AS) $(AS_FLAGS) iflush.s -o $@

ch_sdc_g1.o sparcv9/ch_sdc_g1.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS) -DGLOBALS -DG1 cheetah_sdc.s -o $@

ch_sdc_g2.o sparcv9/ch_sdc_g2.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS) -DGLOBALS -DG2 cheetah_sdc.s -o $@

ch_sdc_g3.o sparcv9/ch_sdc_g3.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS) -DGLOBALS -DG3 cheetah_sdc.s -o $@

ch_sdc_g4.o sparcv9/ch_sdc_g4.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS) -DGLOBALS -DG4 cheetah_sdc.s -o $@

ch_sdc_l0.o sparcv9/ch_sdc_l0.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS) -DLOCALS -DL0 cheetah_sdc.s -o $@

ch_sdc_l1.o sparcv9/ch_sdc_l1.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS) -DLOCALS -DL1 cheetah_sdc.s -o $@

ch_sdc_l2.o sparcv9/ch_sdc_l2.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS) -DLOCALS -DL2 cheetah_sdc.s -o $@

ch_sdc_l3.o sparcv9/ch_sdc_l3.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS) -DLOCALS -DL3 cheetah_sdc.s -o $@

ch_sdc_l4.o sparcv9/ch_sdc_l4.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS) -DLOCALS -DL4 cheetah_sdc.s -o $@

ch_sdc_l5.o sparcv9/ch_sdc_l5.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS) -DLOCALS -DL5 cheetah_sdc.s -o $@

ch_sdc_l6.o sparcv9/ch_sdc_l6.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS) -DLOCALS -DL6 cheetah_sdc.s -o $@

ch_sdc_l7.o sparcv9/ch_sdc_l7.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS) -DLOCALS -DL7 cheetah_sdc.s -o $@

ch_sdc_o0.o sparcv9/ch_sdc_o0.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS) -DOUTS -DO0 cheetah_sdc.s -o $@

ch_sdc_o1.o sparcv9/ch_sdc_o1.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS) -DOUTS -DO1 cheetah_sdc.s -o $@

ch_sdc_o2.o sparcv9/ch_sdc_o2.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS) -DOUTS -DO2 cheetah_sdc.s -o $@

ch_sdc_o3.o sparcv9/ch_sdc_o3.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS) -DOUTS -DO3 cheetah_sdc.s -o $@

ch_sdc_o4.o sparcv9/ch_sdc_o4.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS) -DOUTS -DO4 cheetah_sdc.s -o $@

ch_sdc_o5.o sparcv9/ch_sdc_o5.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS) -DOUTS -DO5 cheetah_sdc.s -o $@

ch_sdc_o7.o sparcv9/ch_sdc_o7.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS) -DOUTS -DO7 cheetah_sdc.s -o $@

iflush_v9b.o sparcv9/iflush_v9b.o : iflush.s
	$(AS) $(AS_FLAGS_V9B) iflush.s -o $@

ch_sdc_g1_v9b.o sparcv9/ch_sdc_g1_v9b.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS_V9B) -DGLOBALS -DG1 cheetah_sdc.s -o $@

ch_sdc_g2_v9b.o sparcv9/ch_sdc_g2_v9b.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS_V9B) -DGLOBALS -DG2 cheetah_sdc.s -o $@

ch_sdc_g3_v9b.o sparcv9/ch_sdc_g3_v9b.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS_V9B) -DGLOBALS -DG3 cheetah_sdc.s -o $@

ch_sdc_g4_v9b.o sparcv9/ch_sdc_g4_v9b.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS_V9B) -DGLOBALS -DG4 cheetah_sdc.s -o $@

ch_sdc_l0_v9b.o sparcv9/ch_sdc_l0_v9b.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS_V9B) -DLOCALS -DL0 cheetah_sdc.s -o $@

ch_sdc_l1_v9b.o sparcv9/ch_sdc_l1_v9b.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS_V9B) -DLOCALS -DL1 cheetah_sdc.s -o $@

ch_sdc_l2_v9b.o sparcv9/ch_sdc_l2_v9b.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS_V9B) -DLOCALS -DL2 cheetah_sdc.s -o $@

ch_sdc_l3_v9b.o sparcv9/ch_sdc_l3_v9b.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS_V9B) -DLOCALS -DL3 cheetah_sdc.s -o $@

ch_sdc_l4_v9b.o sparcv9/ch_sdc_l4_v9b.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS_V9B) -DLOCALS -DL4 cheetah_sdc.s -o $@

ch_sdc_l5_v9b.o sparcv9/ch_sdc_l5_v9b.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS_V9B) -DLOCALS -DL5 cheetah_sdc.s -o $@

ch_sdc_l6_v9b.o sparcv9/ch_sdc_l6_v9b.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS_V9B) -DLOCALS -DL6 cheetah_sdc.s -o $@

ch_sdc_l7_v9b.o sparcv9/ch_sdc_l7_v9b.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS_V9B) -DLOCALS -DL7 cheetah_sdc.s -o $@

ch_sdc_o0_v9b.o sparcv9/ch_sdc_o0_v9b.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS_V9B) -DOUTS -DO0 cheetah_sdc.s -o $@

ch_sdc_o1_v9b.o sparcv9/ch_sdc_o1_v9b.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS_V9B) -DOUTS -DO1 cheetah_sdc.s -o $@

ch_sdc_o2_v9b.o sparcv9/ch_sdc_o2_v9b.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS_V9B) -DOUTS -DO2 cheetah_sdc.s -o $@

ch_sdc_o3_v9b.o sparcv9/ch_sdc_o3_v9b.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS_V9B) -DOUTS -DO3 cheetah_sdc.s -o $@

ch_sdc_o4_v9b.o sparcv9/ch_sdc_o4_v9b.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS_V9B) -DOUTS -DO4 cheetah_sdc.s -o $@

ch_sdc_o5_v9b.o sparcv9/ch_sdc_o5_v9b.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS_V9B) -DOUTS -DO5 cheetah_sdc.s -o $@

ch_sdc_o7_v9b.o sparcv9/ch_sdc_o7_v9b.o : cheetah_sdc.s cheetah_sdc.h
	$(AS) $(AS_FLAGS_V9B) -DOUTS -DO7 cheetah_sdc.s -o $@
