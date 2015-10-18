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
#ident	"%Z%%M%	%I%	%E% SMI"
#

include ../../../Makefile.master

HDRS=  \
	archsystm.h	\
	asm_linkage.h	\
	cmpregs.h	\
	cpu.h		\
	ddi_isa.h	\
	fasttrap_isa.h	\
	frame.h		\
	fsr.h		\
	inline.h	\
	kdi_machimpl.h	\
	machlock.h	\
	machsig.h	\
	machtypes.h	\
	old_procfs.h	\
	pcb.h		\
	procfs_isa.h	\
	psw.h		\
	reg.h		\
	regset.h	\
	spl.h		\
	stack.h		\
	stat_impl.h	\
	synch32.h	\
	trap.h		\
	ucontext.h      \
	utrap.h		\
	vmparam.h	\
	sysconfig_impl.h

FPUHDRS= \
	fpu_simulator.h \
	fpusystm.h \
	globals.h \
	ieee.h

FMCPUHDRS= \
	UltraSPARC-II.h \
	UltraSPARC-III.h \
	UltraSPARC-T1.h \
	SPARC64-VI.h

ROOTDIR=	$(ROOT)/usr/include/sys
ROOTDIRS= \
	$(ROOTDIR) \
	$(ROOTDIR)/fm/cpu \
	$(ROOTDIR)/fpu

ROOTHDRS= $(HDRS:%=$(ROOTDIR)/%)
ROOTFPUHDRS= $(FPUHDRS:%=$(ROOTDIR)/fpu/%)
ROOTFMCPUHDRS= $(FMCPUHDRS:%=$(ROOTDIR)/fm/cpu/%)

fpu/%.check:	fpu/%.h
	$(DOT_H_CHECK)

fm/cpu/%.check:	fm/cpu/%.h
	$(DOT_H_CHECK)

CHECKHDRS= \
	$(HDRS:%.h=%.check) \
	$(FPUHDRS:%.h=fpu/%.check) \
	$(FMCPUHDRS:%.h=fm/cpu/%.check)

# install rules
$(ROOTDIR)/%: %
	$(INS.file)

$(ROOTDIR)/fpu/%: fpu/%
	$(INS.file)

$(ROOTDIR)/fm/cpu/%: fm/cpu/%
	$(INS.file)

.KEEP_STATE:

.PARALLEL: $(CHECKHDRS) $(ROOTHDRS) $(ROOTFPUHDRS) $(ROOTFMCPUHDRS)

install_h: $(ROOTDIRS) .WAIT $(ROOTHDRS) $(ROOTFPUHDRS) $(ROOTFMCPUHDRS)

$(ROOTDIRS):
	$(INS.dir)

check:	$(CHECKHDRS)
