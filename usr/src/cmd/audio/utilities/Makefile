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
# Makefile for C++ Audio Library (libAudio.a) 

include ../../Makefile.cmd

TARGETS		= library

INCLUDES += -I../include

CPPFLAGS += $(INCLUDES)

CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-parentheses

LINTFLAGS += -m -v -u

AR=     /usr/ccs/bin/ar
RANLIB= /usr/ccs/bin/ranlib
RM=     /usr/bin/rm -f

LIBCSRCS        = device_ctl.c \
		  filehdr.c \
		  hdr_misc.c \
		  g711.c \
		  g721.c \
		  g723.c \
		  g72x_tables.c \
		  zmalloc.c

LIBCCSRCS	= Audio.cc \
		  AudioBuffer.cc \
		  AudioCopy.cc \
		  AudioDebug.cc \
		  AudioError.cc \
		  AudioExtent.cc \
		  AudioFile.cc \
		  AudioGain.cc \
		  AudioHdr.cc \
		  AudioHdrParse.cc \
		  AudioLib.cc \
		  AudioList.cc \
		  AudioPipe.cc \
		  AudioRawPipe.cc \
		  AudioStream.cc \
		  AudioTypeChannel.cc \
		  AudioTypeG72X.cc \
		  AudioTypeMux.cc \
		  AudioTypePcm.cc \
		  AudioTypeSampleRate.cc \
		  AudioUnixfile.cc \
		  Fir.cc \
		  Resample.cc

COBJS= $(LIBCSRCS:%.c=%.o)
CCOBJS= $(LIBCCSRCS:%.cc=%.o)

.PARALLEL:      $(COBJS) $(CCOBJS)

libaudio=	libaudio.a

.KEEP_STATE:

install all: $(libaudio)

$(libaudio): $(COBJS) $(CCOBJS)
	$(RM) -f $@
	$(AR) cq $@ $(COBJS) $(CCOBJS)
	test ! -f $(RANLIB) || $(RANLIB) $@

clean:
	$(RM) $(COBJS) $(CCOBJS)

clobber: clean
	$(RM) $(libaudio)

lint:
	$(LINT.c) $(LIBCSRCS) $(LDLIBS)

_msg:
