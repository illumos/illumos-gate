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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

include ../Makefile.inc
include ../../Makefile.cmd

PROGRAMv9b = fptest
PROGBINv9b = $(OBJ_DIR)/$(PROGRAMv9b)
FPST_LOC = ../../fm/modules/sun4u/fps-transport
INCLUDESv9b = -I. -I$(SPRO_VROOT)/prod/include/cc
INCLUDESv9b += -I$(FPST_LOC)

SUNPERF = $(SPRO_VROOT)/prod/lib

SUNPV9B = $(SUNPERF)/v9b
SUNPV9  = $(SUNPERF)/v9
VISARCH = -xarch=v9b

bits64:= CHIP = -xchip=ultra3

bits64:= CFLAGSv9b = $(DBX) -xildoff -D_sparc64 -DV9B -_cc=-W2,-whole $(CHIP) -_cc=-fsimple=0 $(VISARCH)

bits64:= FBEFLAGSv9b = -xildoff -D_sparc64 -DV9B $(VISARCH)

CSRCS = benchmarks.c fptest.c fps_ereport_mod.c \
       cbbcopy.c fputest.c linpack.c fpu_fsr_test.c cheetah_sdc.c \
       util.c

LINOBJSv9b = $(OBJ_DIR)/S.linpackv9b.o $(OBJ_DIR)/D.linpackv9b.o

bits64:= EXTRA_LIBS_CPUv9b = -_cc=-xprefetch=auto -_cc=-xopenmp $(SUNPV9B)/libsunperf.a  $(SUNPV9)/libfui.a $(SUNPV9)/libfai.a $(SUNPV9)/libfsu.a $(SUNPV9)/libsunmath.a $(VISARCH)

SDCOBSV9B = cheetah_sdc_v9b.o iflush_v9b.o ch_sdc_g1_v9b.o ch_sdc_g2_v9b.o ch_sdc_g3_v9b.o ch_sdc_g4_v9b.o \
	ch_sdc_l0_v9b.o ch_sdc_l1_v9b.o ch_sdc_l2_v9b.o ch_sdc_l3_v9b.o ch_sdc_l4_v9b.o \
	ch_sdc_l5_v9b.o ch_sdc_l6_v9b.o ch_sdc_l7_v9b.o ch_sdc_o0_v9b.o ch_sdc_o1_v9b.o \
	ch_sdc_o2_v9b.o ch_sdc_o3_v9b.o ch_sdc_o4_v9b.o ch_sdc_o5_v9b.o ch_sdc_o7_v9b.o

SDCOBJSV9B = $(SDCOBSV9B:%.o=$(OBJ_DIR)/%.o)

FPUOBS64v9b = $(SDCOBJSV9B) $(OBJ_DIR)/fputestv9b.o $(OBJ_DIR)/fpu_fsr_testv9b.o $(OBJ_DIR)/fsr_testv9b.o $(OBJ_DIR)/cbbcopyv9b.o $(OBJ_DIR)/fptestv9b.o $(LINOBJSv9b)  \
	$(OBJ_DIR)/fpu_if64v9b.o $(OBJ_DIR)/fpu_test64v9b.o  $(OBJ_DIR)/benchmarksv9b.o $(OBJ_DIR)/fps_ereport_modv9b.o $(OBJ_DIR)/utilv9b.o

bits64:= AS_FLAGS_V9B = $(VISARCH) -P -D_ASM -D_sparc64

.KEEP_STATE:

########## beginning of dependency lines #################

bits64: $$(PROGBIN) $$(FPUOBS64v9b) $$(PROGRAMv9b)


./%v9b.o sparcv9/%v9b.o : %.c $(INCLUDESv9b)
	@$(BIT64_SETUP)
	$(CC) -c $(CFLAGSv9b) $< -o $@

./$(PROGRAMv9b) sparcv9/$(PROGRAMv9b) : $$(FPUOBS64v9b)  
	( unset LD_LIBRARY_PATH LD_RUN_PATH ; \
	$(CC)  $(CFLAGSv9b) ${FPUOBS64v9b} -o $@ -lc -zignore -lsysevent -lnvpair -lkstat  -lm -lnsl  ${TSTLIB.A} $(EXTRA_LIBS_CPUv9b) $(LDFLAGS))
	$(POST_PROCESS)
include Makefile.sdc

##### V9B

utilv9b.o  sparcv9/utilv9b.o: util.c
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b) ${CFLAGSv9b} -DFPU -c util.c -o $@

fps_ereport_modv9b.o sparcv9/fps_ereport_modv9b.o: fps_ereport_mod.c fps_defines.h
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b) ${CFLAGSv9b} -DFPU -c fps_ereport_mod.c -o $@

cheetah_sdc_v9b.o sparcv9/cheetah_sdc_v9b.o : cheetah_sdc.c fp.h
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b) ${CFLAGSv9b} -DFPU -c cheetah_sdc.c -o $@

fputestv9b.o sparcv9/fputestv9b.o : fputest.c externs.h
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b) ${CFLAGSv9b} -DFPU -c fputest.c -o $@

fpu_fsr_testv9b.o sparcv9/fpu_fsr_testv9b.o : fpu_fsr_test.c externs.h
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b) ${CFLAGSv9b} -DFPU -c fpu_fsr_test.c -o $@

cbbcopyv9b.o sparcv9/cbbcopyv9b.o : cbbcopy.c fp.h
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b) ${CFLAGSv9b} -DFPU -c cbbcopy.c -o $@

fptestv9b.o sparcv9/fptestv9b.o : fptest.c fp.h
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b) ${CFLAGSv9b} -DFPU -c fptest.c -o $@

benchmarksv9b.o sparcv9/benchmarksv9b.o : benchmarks.c
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b) ${CFLAGSv9b} -DFPU visfps.il -c benchmarks.c -o $@

fputest64v9b.o sparcv9/fputest64v9b.o : fputest64.c
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b) ${CFLAGSv9b} -DFPU -c fputest64.c -o $@

S.linpackv9b.o sparcv9/S.linpackv9b.o : linpack.c
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b) ${CFLAGSv9b} -DV9B -c linpack.c -o $@ 

D.linpackv9b.o sparcv9/D.linpackv9b.o : linpack.c
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b) ${CFLAGSv9b} -DV9B -DDP -c linpack.c -o $@ 

S.cparanoiav9b.o sparcv9/S.cparanoiav9b.o : cparanoia.c
	${CC} $(INCLUDESv9b) ${CFLAGSv9b} -DSP -c cparanoia.c -o $@

D.cparanoiav9b.o sparcv9/D.cparanoiav9b.o : cparanoia.c
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b) ${CFLAGSv9b} -DDP -c cparanoia.c -o $@

Q.cparanoiav9b.o sparcv9/Q.cparanoiav9b.o : cparanoia.c
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b) ${CFLAGSv9b} -DQP -c cparanoia.c -o $@

D.clorenzv9b.o sparcv9/D.clorenzv9b.o : clorenz.c
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b) ${CFLAGSv9b} -DDP -c clorenz.c -o $@

Q.clorenzv9b.o sparcv9/Q.clorenzv9b.o : clorenz.c
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b) ${CFLAGSv9b} -DQP -c clorenz.c -o $@

Q.cvectorv9b.o sparcv9/Q.cvectorv9b.o : cvector.c
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b) ${CFLAGSv9b} -DQUADPREC -Dsparc -Dsun -c cvector.c -o $@

S.kcsqrtv9b.o sparcv9/S.kcsqrtv9b.o : kcsqrt.c
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b) ${CFLAGSv9b}  ${FBEFLAGS} -DSP -c kcsqrt.c -o $@

D.kcsqrtv9b.o sparcv9/D.kcsqrtv9b.o : kcsqrt.c
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b) ${CFLAGSv9b}  ${FBEFLAGS} -DDP -c kcsqrt.c -o $@

S.kcdivv9b.o sparcv9/S.kcdivv9b.o : kcdiv.c
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b) ${CFLAGSv9b}  ${FBEFLAGS} -DSP -c kcdiv.c -o $@

D.kcdivv9b.o sparcv9/D.kcdivv9b.o : kcdiv.c
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b) ${CFLAGSv9b} -c kcdiv.c -o $@

E.kcdivv9b.o sparcv9/E.kcdivv9b.o : kcdiv.c
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b) ${CFLAGSv9b} -DEXTENDED -c kcdiv.c -o $@

fpu_if64v9b.o sparcv9/fpu_if64v9b.o :  fpu_if64.s
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b)  ${FBEFLAGSv9b} -c -Wa,-s,-P,-D_ASM fpu_if64.s -o $@

fpu_test64v9b.o sparcv9/fpu_test64v9b.o : fpu_test64.s
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b)  ${FBEFLAGSv9b} -c -Wa,-s,-P,-D_ASM fpu_test64.s -o $@

fsr_testv9b.o sparcv9/fsr_testv9b.o : fsr_test.s
	@$(BIT64_SETUP)
	${CC} $(INCLUDESv9b)  ${FBEFLAGSv9b} -c -Wa,-s,-P,-D_ASM fsr_test.s -o $@

all install : install64
install64 : $$(BITS) FRC
	    install -m 755 -d $(INSTBINDIR)/sun4u/UltraSPARC-III;
	    install -m 755 -d $(INSTBINDIR)/sun4u/UltraSPARC-IIIi;
	    install -m 755 -d $(INSTBINDIR)/sun4u/UltraSPARC-III+;
	    install -m 755 -d $(INSTBINDIR)/sun4u/UltraSPARC-IV;
	    install -m 755 -d $(INSTBINDIR)/sun4u/UltraSPARC-IV+;
	    $(RM) $(INSTBINDIR)/sun4u/UltraSPARC-III/$(PROGRAMv9b);
	    install -m 755 -f $(INSTBINDIR)/sun4u/UltraSPARC-III $(PROGRAMv9b);
	    $(RM) $(INSTBINDIR)/sun4u/UltraSPARC-IIIi/$(PROGRAMv9b);
	    $(SYMLINK) ../UltraSPARC-III/$(PROGRAMv9b) $(INSTBINDIR)/sun4u/UltraSPARC-IIIi/$(PROGRAMv9b);
	    $(RM) $(INSTBINDIR)/sun4u/UltraSPARC-III+/$(PROGRAMv9b);
	    $(SYMLINK) ../UltraSPARC-III/$(PROGRAMv9b) $(INSTBINDIR)/sun4u/UltraSPARC-III+/$(PROGRAMv9b);
	    $(RM) $(INSTBINDIR)/sun4u/UltraSPARC-IV/$(PROGRAMv9b);
	    $(SYMLINK) ../UltraSPARC-III/$(PROGRAMv9b) $(INSTBINDIR)/sun4u/UltraSPARC-IV/$(PROGRAMv9b);
	    $(RM) $(INSTBINDIR)/sun4u/UltraSPARC-IV+/$(PROGRAMv9b);
	    $(SYMLINK) ../UltraSPARC-III/$(PROGRAMv9b) $(INSTBINDIR)/sun4u/UltraSPARC-IV+/$(PROGRAMv9b);

clean:
	rm -f *.o errs t.? *.so .make.state; rm -rf sparcv9
clobber: clean
	rm -f ${PROGRAMv9b}
lintclean:
	rm -f *.ln

info: FRC
	sccs info
FRC:


LINTSOURCES = benchmarks.c fps_ereport_mod.c fputest.c cbbcopy.c fptest.c linpack.c cheetah_sdc.c fpu_fsr_test.c util.c
LINTFILES = $(LINTSOURCES:.c=.ln)
LINTFLAGS = -I$(INCDIR) -I$(FPST_LOC) -Xarch=v9 -Dunix -uxn -errchk=longptr64,sizematch -Ncheck=macro -errhdr=`pwd` -Nlevel=2 -errtags=yes -errsecurity=core -DDP -D_sparc64

lint: $(LINTFILES)
	$(LINT) $(LINTFLAGS) $(LINTFILES)
