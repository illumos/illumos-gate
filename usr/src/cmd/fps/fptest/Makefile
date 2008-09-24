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

# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

include ../../Makefile.cmd
include ../../Makefile.cmd.64

PROG = fptest

ROOTLIBFPS= $(ROOTLIB)/fps/sun4u/UltraSPARC-III
ROOTLIBFPSIIIi= $(ROOTLIB)/fps/sun4u/UltraSPARC-IIIi
ROOTLIBFPSIIIPLUS= $(ROOTLIB)/fps/sun4u/UltraSPARC-III+
ROOTLIBFPSIV= $(ROOTLIB)/fps/sun4u/UltraSPARC-IV
ROOTLIBFPSIVPLUS= $(ROOTLIB)/fps/sun4u/UltraSPARC-IV+

ROOTLIBFPSTEST= $(PROG:%=$(ROOTLIBFPS)/%)
ROOTLIBFPSTESTIIIi= $(PROG:%=$(ROOTLIBFPSIIIi)/%)
ROOTLIBFPSTESTIIIPLUS= $(PROG:%=$(ROOTLIBFPSIIIPLUS)/%)
ROOTLIBFPSTESTIV= $(PROG:%=$(ROOTLIBFPSIV)/%)
ROOTLIBFPSTESTIVPLUS= $(PROG:%=$(ROOTLIBFPSIVPLUS)/%)

SUNPERF = $(SPRO_VROOT)/prod/lib

SUNPV9B = $(SUNPERF)/v9b
SUNPV9  = $(SUNPERF)/v9
VISARCH = -m64 -xarch=sparcvis2

CHIP = -xchip=ultra3

INCLUDES = -I. -I$(SPRO_VROOT)/prod/include/cc \
           -I../../fm/modules/sun4u/fps-transport

CFLAGS64 += $(INCLUDES) -D_sparc64 -DV9B -g -xO3 -xildoff -_cc=-W2,-whole \
            $(CHIP) -_cc=-fsimple=0 $(VISARCH) \
            -erroff=E_ASM_DISABLES_OPTIMIZATION

LDLIBS  += -lc -lsysevent -lnvpair -lkstat -lm -lnsl

FBEFLAGS = -xildoff -D_sparc64 -DV9B $(VISARCH)

SRCS = benchmarks.c fptest.c fps_ereport_mod.c cbbcopy.c fputest.c linpack.c \
       fpu_fsr_test.c cheetah_sdc.c util.c cheetah_sdc.s fpu_if64.s \
       fpu_test64.s fsr_test.s iflush.s

LINOBJS = S.linpack.o D.linpack.o

EXTRA_LIBS_CPU = -_cc=-xprefetch=auto -_cc=-xopenmp $(SUNPV9B)/libsunperf.a \
                 $(SUNPV9)/libfui.a $(SUNPV9)/libfai.a $(SUNPV9)/libfsu.a \
                 $(SUNPV9)/libsunmath.a $(VISARCH)

SDCOBJS = cheetah_sdc.o iflush.o ch_sdc_g1.o ch_sdc_g2.o ch_sdc_g3.o \
          ch_sdc_g4.o ch_sdc_l0.o ch_sdc_l1.o ch_sdc_l2.o ch_sdc_l3.o \
          ch_sdc_l4.o ch_sdc_l5.o ch_sdc_l6.o ch_sdc_l7.o ch_sdc_o0.o \
          ch_sdc_o1.o ch_sdc_o2.o ch_sdc_o3.o ch_sdc_o4.o ch_sdc_o5.o \
          ch_sdc_o7.o

FPUOBJS = $(SDCOBJS) fputest.o fpu_fsr_test.o fsr_test.o \
          cbbcopy.o fptest.o $(LINOBJS) fpu_if64.o fpu_test64.o \
          benchmarks.o fps_ereport_mod.o util.o

AS_FLAGS += $(VISARCH) -P -D_ASM -D_sparc64
LINTFLAGS64 += $(INCLUDES) -D_sparc64 -DV9B

.KEEP_STATE:

########## beginning of dependency lines #################

all: $(PROG)

.c.o:
	$(COMPILE.c) $<
	$(CTFCONVERT_O)
	$(POST_PROCESS_O)

$(PROG): $(FPUOBJS)
	$(LINK.c) -o $@ $(FPUOBJS) $(LDFLAGS) $(LDLIBS) $(TSTLIB.A) \
        $(EXTRA_LIBS_CPU)
	$(POST_PROCESS)

include Makefile.rules

benchmarks.o: benchmarks.c visfps.il
	$(COMPILE.c) -DFPU visfps.il benchmarks.c
	$(CTFCONVERT_O)
	$(POST_PROCESS_O)

S.linpack.o: linpack.c
	$(COMPILE.c) linpack.c -o $@
	$(CTFCONVERT_O)
	$(POST_PROCESS_O)

D.linpack.o: linpack.c
	$(COMPILE.c) linpack.c -DDP -o $@
	$(CTFCONVERT_O)
	$(POST_PROCESS_O)

fpu_if64.o:  fpu_if64.s
	$(COMPILE.c) $(FBEFLAGS) -Wa,-s,-P,-D_ASM fpu_if64.s
	$(CTFCONVERT_O)
	$(POST_PROCESS_O)

fpu_test64.o: fpu_test64.s
	$(COMPILE.c) $(FBEFLAGS) -Wa,-s,-P,-D_ASM fpu_test64.s
	$(CTFCONVERT_O)
	$(POST_PROCESS_O)

fsr_test.o: fsr_test.s
	$(COMPILE.c) $(FBEFLAGS) -Wa,-s,-P,-D_ASM fsr_test.s
	$(CTFCONVERT_O)
	$(POST_PROCESS_O)

install : all $(ROOTLIBFPS) $(ROOTLIBFPSTEST) $(ROOTLIBFPSIIIi) \
          $(ROOTLIBFPSTESTIIIi) $(ROOTLIBFPSIIIPLUS) $(ROOTLIBFPSTESTIIIPLUS) \
          $(ROOTLIBFPSIV) $(ROOTLIBFPSTESTIV) $(ROOTLIBFPSIVPLUS) \
          $(ROOTLIBFPSTESTIVPLUS)

clean:
	$(RM) $(LINOBJS) $(FPUOBJS)

lint: lint_SRCS

$(ROOTLIBFPS):
	$(INS.dir)

$(ROOTLIBFPS)/%:      %
	$(INS.file)

$(ROOTLIBFPSIIIi):
	$(INS.dir)

$(ROOTLIBFPSIIIi)/%:      %
	$(RM) $@
	$(SYMLINK) ../UltraSPARC-III/fptest $@

$(ROOTLIBFPSIIIPLUS):
	$(INS.dir)

$(ROOTLIBFPSIIIPLUS)/%:      %
	$(RM) $@
	$(SYMLINK) ../UltraSPARC-III/fptest $@

$(ROOTLIBFPSIV):
	$(INS.dir)

$(ROOTLIBFPSIV)/%:      %
	$(RM) $@
	$(SYMLINK) ../UltraSPARC-III/fptest $@

$(ROOTLIBFPSIVPLUS):
	$(INS.dir)

$(ROOTLIBFPSIVPLUS)/%:      %
	$(RM) $@
	$(SYMLINK) ../UltraSPARC-III/fptest $@

include ../../Makefile.targ
