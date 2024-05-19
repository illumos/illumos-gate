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
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2019 RackTop Systems.

include ../../Makefile.cmd

TARGETS		= library

CPPFLAGS += -I../include

CERRWARN += $(CNOWARN_UNINIT)
CCERRWARN += -_gcc=-Wno-switch

# not linted
SMATCH=off

COBJS =		\
	device_ctl.o	\
	filehdr.o	\
	hdr_misc.o	\
	g711.o		\
	g721.o		\
	g723.o		\
	g72x_tables.o	\
	zmalloc.o

CCOBJS =			\
	Audio.o			\
	AudioBuffer.o		\
	AudioCopy.o		\
	AudioDebug.o		\
	AudioError.o		\
	AudioExtent.o		\
	AudioFile.o		\
	AudioGain.o		\
	AudioHdr.o		\
	AudioHdrParse.o		\
	AudioLib.o		\
	AudioList.o		\
	AudioPipe.o		\
	AudioRawPipe.o		\
	AudioStream.o		\
	AudioTypeChannel.o	\
	AudioTypeG72X.o		\
	AudioTypeMux.o		\
	AudioTypePcm.o		\
	AudioTypeSampleRate.o	\
	AudioUnixfile.o		\
	Fir.o			\
	Resample.o

.PARALLEL:      $(COBJS) $(CCOBJS)

libaudio=	libaudio.a

.KEEP_STATE:

install all: $(libaudio)

$(libaudio): $(COBJS) $(CCOBJS)
	$(RM) $@
	$(AR) cq $@ $(COBJS) $(CCOBJS)

clean:
	$(RM) $(COBJS) $(CCOBJS)

clobber: clean
	$(RM) $(libaudio)

_msg:
