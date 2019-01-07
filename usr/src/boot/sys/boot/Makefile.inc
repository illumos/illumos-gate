#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2017 Toomas Soome <tsoome@me.com>
#

# Default Console font setup.
# We want it to be the same as kernel.
# We build compressed, stripped down version of the default font, so we have
# bare minimum for case we can not load font from the OS root.

FONT=		8x16
FONT_SRC=	ter-u16n.bdf
FONT_DIR=	$(SRC)/data/consfonts

#.if ${MACHINE_CPUARCH} == "arm"
# Do not generate movt/movw, because the relocation fixup for them does not
# translate to the -Bsymbolic -pie format required by self_reloc() in loader(8).
# Also, the fpu is not available in a standalone environment.
#CFLAGS.clang+=  -mllvm -arm-use-movt=0
#CFLAGS.clang+=  -mfpu=none
#.endif
