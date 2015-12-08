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

include ../../../Makefile.master

# NOTE: hrtcntl.h and hrtsys.h are present in this directory so that the
#	hrtsys system call can be built to facilitate transportability of
#	stock SVr4 programs.  Every effort is to be made to prevent objects
#	from being built, so these headers are not exported (installed).

HDRS	=			\
	archsystm.h		\
	asm_linkage.h		\
	bootconf.h		\
	bootregs.h		\
	bootsvcs.h		\
	controlregs.h		\
	cpu.h			\
	ddi_isa.h		\
	debugreg.h		\
	fasttrap_isa.h		\
	fp.h			\
	frame.h			\
	inline.h		\
	iommulib.h		\
	hypervisor.h		\
	kdi_machimpl.h		\
	kdi_regs.h		\
	machlock.h		\
	machsig.h		\
	machtypes.h		\
	mc.h			\
	mc_amd.h		\
	mc_intel.h		\
	mca_amd.h		\
	mca_x86.h		\
	mcontext.h		\
	mutex_impl.h		\
	obpdefs.h		\
	old_procfs.h		\
	pcb.h			\
	pmem.h			\
	privmregs.h		\
	privregs.h		\
	procfs_isa.h		\
	prom_emul.h		\
	prom_isa.h		\
	prom_plat.h		\
	promif.h		\
	promimpl.h		\
	psw.h			\
	pte.h			\
	reg.h			\
	regset.h		\
	segment.h		\
	segments.h		\
	spl.h			\
	stack.h			\
	stat_impl.h		\
	synch32.h		\
	sysconfig_impl.h	\
	sysi86.h		\
	trap.h			\
	traptrace.h		\
	tss.h			\
	ucontext.h		\
	utrap.h			\
	vmparam.h		\
	x86_archext.h		\
	xen_errno.h

ROOTDIR=	$(ROOT)/usr/include/sys
SCSIDIR=	$(ROOTDIR)/scsi
SCSIDIRS=	$(SCSIDIR) $(SCSIDIR)/conf $(SCSIDIR)/generic \
		$(SCSIDIR)/impl $(SCSIDIR)/targets
ROOTFSDIR=	$(ROOTDIR)/fs
ROOTDIRS=	$(ROOTDIR) $(ROOTFSDIR)

ROOTHDRS= $(HDRS:%=$(ROOTDIR)/%)

CHECKHDRS= 			\
	$(HDRS:%.h=%.check)

# install rules
$(ROOTDIR)/%: %
	$(INS.file)

.KEEP_STATE:

.PARALLEL: $(CHECKHDRS) $(ROOTHDRS)

install_h: $(ROOTDIRS) .WAIT $(ROOTHDRS)

$(ROOTDIRS):
	$(INS.dir)

check:	$(CHECKHDRS)
