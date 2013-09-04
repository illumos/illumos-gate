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
# Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
#

include ../../Makefile.cmd

i386_DFILES = \
	iprb.d

DFILES = \
	applicat.d \
	badopen.d \
	begin.d \
	callout.d \
	clause.d \
	clear.d \
	countdown.d \
	counter.d \
	dateprof.d \
	delay.d \
	denorm.d \
	end.d \
	error.d \
	errorpath.d \
	find.d \
	firebird.d \
	hello.d \
	howlong.d \
	interp.d \
	interval.d \
	intr.d \
	iocpu.d \
	iosnoop.d \
	iothrough.d \
	iotime.d \
	ipio.d \
	ipproto.d \
	tcprst.d \
	kstat.d \
	ksyms.d \
	libc.d \
	lquantize.d \
	lwptime.d \
	normalize.d \
	nscd.d \
	pri.d \
	printa.d \
	pritime.d \
	prof.d \
	profpri.d \
	progtime.d \
	putnext.d \
	qlen.d \
	qtime.d \
	renormalize.d \
	restest.d \
	ring.d \
	rtime.d \
	rwinfo.d \
	rwtime.d \
	sig.d \
	soffice.d \
	spec.d \
	specopen.d \
	ssd.d \
	syscall.d \
	tcp1stbyte.d \
	tcpbytes.d \
	tcpbytesstat.d \
	tcpconnlat.d \
	tcpio.d \
	tcpioflags.d \
	tcpsnoop.d \
	tcpstate.d \
	tcptop.d \
	tick.d \
	ticktime.d \
	time.d \
	tracewrite.d \
	trunc.d \
	trussrw.d \
	udpbytes.d \
	udpbytesstat.d \
	udpio.d \
	udpsnoop.d \
	udptop.d \
	userfunc.d \
	whatfor.d \
	whatlock.d \
	where.d \
	whererun.d \
	whoexec.d \
	whofor.d \
	whoio.d \
	whopreempt.d \
	whoqueue.d \
	whosteal.d \
	whowrite.d \
	writes.d \
	writesbycmd.d \
	writesbycmdfd.d \
	writetime.d \
	writetimeq.d \
	xioctl.d \
	xterm.d \
	xwork.d \
	$($(MACH)_DFILES)

HTMLFILES = index.html

DEMOFILES = \
	$(DFILES) \
	$(HTMLFILES)

MKDEMO	= mkdemo
CLEANFILES += $(DFILES) $(MKDEMO)
CLOBBERFILES = $(HTMLFILES)

ROOTDEMODIR = $(ROOT)/usr/demo/dtrace
ROOTDEMOFILES = $(DEMOFILES:%=$(ROOTDEMODIR)/%)

all:	$(DEMOFILES)

clean:
	$(RM) $(CLEANFILES)

clobber: clean
	$(RM) $(CLOBBERFILES)

clean.lint install_h lint:

install: $(ROOTDEMOFILES)

$(ROOTDEMODIR):
	$(INS.dir)

$(ROOTDEMODIR)/%: %
	$(INS.file)

$(HTMLFILES):	$(DFILES) $(MKDEMO)	
	./$(MKDEMO) $@

$(DFILES):	$(MKDEMO)	
	./$(MKDEMO) $@

$(ROOTDEMOFILES): $(ROOTDEMODIR)

$(ROOTDEMODIR) := DIRMODE = 755

$(ROOTDEMOFILES) := FILEMODE = 644
