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
# cmd/audio/samples/au/Makefile
#

include ../../../Makefile.cmd

AUFILES=	bark.au \
		bong.au \
		bubbles.au \
		busy.au \
		chirp.au \
		clink.au \
		computer.au \
		cowbell.au \
		crash.au \
		cuckoo.au \
		dialtone.au \
		doorbell.au \
		drip.au \
		fastbusy.au \
		flush.au \
		gong.au \
		laugh.au \
		laughter.au \
		ring.au \
		rooster.au \
		spacemusic.au \
		splat.au \
		touchtone.1.au \
		touchtone.2.au \
		touchtone.3.au \
		touchtone.4.au \
		touchtone.5.au \
		touchtone.6.au \
		touchtone.7.au \
		touchtone.8.au \
		touchtone.9.au \
		touchtone.0.au \
		touchtone.pound.au \
		touchtone.star.au \
		train.au \
		whistle.au

.KEEP_STATE:

FILEMODE=	444

ROOTAUDIOAU=	$(ROOTAUDIOSAMP)/au
ROOTAUDIOAUFILES= $(AUFILES:%=$(ROOTAUDIOAU)/%)

AUDIR= $(ROOT)/usr/share/audio/samples/au

all:

install:	$(AUDIR) .WAIT $(ROOTAUDIOAUFILES)

$(AUDIR):
	$(INS.dir)

$(ROOTAUDIOAU)/%.au: %.au
	$(INS.file)

clean clobber:

lint:

_msg:
