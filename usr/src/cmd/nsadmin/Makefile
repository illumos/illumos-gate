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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2019 Joyent, Inc.
#

ETCFILES = profile .login ksh.kshrc system zshrc
ETCSKELFILES = .profile .kshrc .bashrc
ETCBASHFILES = bash_completion
ETCBASHCOMPLETIONDFILES = dladm zones zone_alias
ROOTFILES = .profile .bashrc .bash_profile

include ../Makefile.cmd

ROOTETCFILES = $(ETCFILES:%=$(ROOTETC)/%)
ROOTETCSKEL= $(ROOTETC)/skel
ROOTETCSKELFILES = $(ETCSKELFILES:%=$(ROOTETCSKEL)/%)
ETCBASHDIR = $(ROOTETC)/bash
ROOTETCBASHFILES = $(ETCBASHFILES:%=$(ETCBASHDIR)/%)
ETCBASHCOMPLETIONDDIR = $(ETCBASHDIR)/bash_completion.d
ROOTETCBASHCOMPLETIONDFILES = \
    $(ETCBASHCOMPLETIONDFILES:%=$(ETCBASHCOMPLETIONDDIR)/%)
ROOTROOT= $(ROOT)/root
ROOTROOTFILES = $(ROOTFILES:%=$(ROOTROOT)/%)

FILES = $(ROOTETCFILES) $(ROOTETCSKELFILES) \
    $(ROOTETCBASHFILES) $(ROOTETCBASHCOMPLETIONDFILES) \
    $(ROOTROOTFILES)

FILEMODE= 0644

.KEEP_STATE:

all:

# Use $^ instead of $< - it's broken without %
INS.file = $(RM) $@; $(INS) -s -m $(FILEMODE) -f $(@D) $^
INS.rename = $(INS.file); $(MV) $(@D)/$(^F) $@

$(ROOTETC)/profile: etc-profile.sh
	$(INS.rename)

$(ROOTETC)/.login: login.csh
	$(INS.rename)

# skel file and root's default
$(ROOTROOT)/.kshrc $(ROOTETCSKEL)/.kshrc: dot-kshrc.sh
	$(INS.rename)

# skel file and root's default
$(ROOTROOT)/.profile $(ROOTETCSKEL)/.profile: dot-profile.sh
	$(INS.rename)

$(ROOTETCSKEL)/.bashrc: etc-skel-bashrc.sh
	$(INS.rename)

$(ROOTROOT)/.bash_profile: dot-bash_profile.sh
	$(INS.rename)

$(ROOTROOT)/.bashrc: dot-bashrc.sh
	$(INS.rename)

$(ROOTETCBASHDIR)/%: %
	$(INS.file)

$(ROOTETCBASHCOMPLETIONDDIR)/%: %
	$(INS.file)

install: all $(FILES)

clean:

clobber:
	$(RM) $(CLOBBERFILES)

lint:
