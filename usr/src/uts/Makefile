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
# Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2012 Nexenta Systems, Inc. All rights reserved.
#
# include global definitions
include ../Makefile.master

#
# List of architectures to build as part of the standard build.
#
# Some of these architectures are built in parallel (see i386_PARALLEL and
# sparc_PARALLEL). This requires building some parts first before parallel build
# can start. Platform make files know what should be built as a prerequisite for
# the parallel build to work. The i386_PREREQ and sparc_PREREQ variables tell
# which platform directory to enter to start making prerequisite dependencies.
#
sparc_ARCHITECTURES = sun4v sun4u sparc

i386_ARCHITECTURES = i86pc i86xpv intel

#
# For i386 all architectures can be compiled in parallel.
#
# intel/Makefile knows how to build prerequisites needed for parallel build.
#
i386_PREREQ = intel
i386_PARALLEL = $(i386_ARCHITECTURES)

#
# For sparc all architectures can be compiled in parallel.
#
# sun4/Makefile knows how to build prerequisites needed for parallel build.
# can start.
#
sparc_PREREQ = sun4
sparc_PARALLEL = $(sparc_ARCHITECTURES)

#
# Platforms defined in $(MACH)_PARALLEL are built in parallel. DUMMY is placed
# at the end in case $(MACH)_PARALLEL is empty to prevent everything going in
# parallel.
#
.PARALLEL: $($(MACH)_PARALLEL) DUMMY

#
# For build prerequisites we use a special target which is constructed by adding
# '.prereq' suffix to the $(MACH)_PREREQ.
#
PREREQ_TARGET = $($(MACH)_PREREQ:%=%.prereq)


def		:=	TARGET= def
all		:=	TARGET= all
install		:=	TARGET= install
install_h	:=	TARGET= install_h
clean		:=	TARGET= clean
clobber		:=	TARGET= clobber
clobber_h	:=	TARGET= clobber
lint		:=	TARGET= lint
clean.lint	:=	TARGET= clean.lint
check		:=	TARGET= check
modlist		:=	TARGET= modlist
modlist		:=	NO_STATE= -K $$MODSTATE$$$$

.KEEP_STATE:

def all lint: all_h $(PMTMO_FILE) $($(MACH)_ARCHITECTURES)

install: all_h install_dirs $(PMTMO_FILE) $($(MACH)_ARCHITECTURES)

install_dirs:
	@cd ..; pwd; $(MAKE) rootdirs
	@pwd

#
# Rule to build prerequisites. The left part of the pattern will match
# PREREQ_TARGET.
#
# The location of the Makefile is determined by strippinng '.prereq' suffix from
# the target name. We add '.prereq' suffix to the target passed to the child
# Makefile so that it can distinguish prerequisite build from the regular one.
#
#
%.prereq:
	@cd $(@:%.prereq=%); pwd; $(MAKE) $(NO_STATE) $(TARGET).prereq

#
# Rule to build architecture files. Build all required prerequisites and then
# build the rest (potentially in parallel).
#
$($(MACH)_ARCHITECTURES): $(PREREQ_TARGET) FRC
	@cd $@; pwd; $(MAKE) $(NO_STATE) $(TARGET)

$(PMTMO_FILE) pmtmo_file: $(PATCH_MAKEUP_TABLE)
	@if [ -z "$(PATCH_MAKEUP_TABLE)" ] ; then \
		echo 'ERROR: $$(PATCH_MAKEUP_TABLE) not set' \
		    'in environment' >&2 ; \
		exit 1 ; \
	fi
	RELEASE="$(RELEASE)" MACH="$(MACH)" \
	    $(CTFCVTPTBL) -o $(PMTMO_FILE) $(PATCH_MAKEUP_TABLE)

#
# The following is the list of directories which contain Makefiles with
# targets to install header file. The machine independent headers are
# installed by invoking the Makefile in the directory containing the
# header files. Machine and architecture dependent headers are installed
# by invoking the main makefile for that architecture/machine which,
# in turn, is responsible for invoking the Makefiles which install headers.
# It is done this way so as not to assume that all of the header files in
# the architecture/machine dependent subdirectories are in completely
# isomorphic locations.
#
COMMON_HDRDIRS= common/avs \
		common/c2 \
		common/des \
		common/fs \
		common/gssapi \
		common/idmap \
		common/klm \
		common/inet \
		common/inet/ipf/netinet \
		common/inet/kssl \
		common/inet/nca \
		common/inet/sockmods/netpacket \
		common/io/bpf/net \
		common/io/fibre-channel/fca/qlc \
		common/ipp \
		common/net \
		common/netinet \
		common/nfs \
		common/pcmcia/sys \
		common/rpc \
		common/rpcsvc \
		common/sharefs \
		common/smb \
		common/smbsrv \
		common/sys \
		common/vm


#
# Subset of COMMON_HDRDIRS in which at least one header is generated
# at runtime (e.g., rpcgen), and in which "make clean" should run.
# Other directories should be included here, but do not yet have the
# necessary Makefile support (make clean).  See 6414855.
#
DYNHDRDIRS =	common/avs \
		common/gssapi \
		common/idmap \
		common/io/fibre-channel/fca/qlc \
		common/klm \
		common/rpc \
		common/rpcsvc \
		common/sys

sparc_HDRDIRS= sun/sys
i386_HDRDIRS= i86pc/vm i86xpv/vm

HDRDIRS= $(COMMON_HDRDIRS) $($(MACH)_HDRDIRS)
install_h check: $(HDRDIRS) $($(MACH)_ARCHITECTURES)

$(HDRDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

# ensures that headers made by rpcgen and others are available in uts source
# for kernel builds to reference without building install_h
#
all_h: FRC
	@cd common/sys; pwd; $(MAKE) $@
	@cd common/rpc; pwd; $(MAKE) $@
	@cd common/rpcsvc; pwd; $(MAKE) $@
	@cd common/gssapi; pwd; $(MAKE) $@
	@cd common/idmap; pwd; $(MAKE) $@
	@cd common/klm; pwd; $(MAKE) $@

clean clobber: $($(MACH)_ARCHITECTURES) $(DYNHDRDIRS)
	@if [ '$(PATCH_BUILD)' != '#' ] ; then \
		echo $(RM) $(PMTMO_FILE) ; \
		$(RM) $(PMTMO_FILE) ; \
	fi

# testing convenience
clobber_h: $(DYNHDRDIRS)

clean.lint modlist: $($(MACH)_ARCHITECTURES)

#
# Cross-reference customization: build a cross-reference over all of
# the supported architectures.  Although there's no correct way to set
# the include path (since we don't know what architecture is the one
# the user will be interested in), it's historically been set to
# mirror the $(XRDIRS) list, and that works kinda sorta okay.
#
XRDIRS = $(sparc_ARCHITECTURES) $(i386_ARCHITECTURES) sun4 sfmmu	\
	sun common

XRINCDIRS = $(XRDIRS)

cscope.out tags: FRC
	$(XREF) -x $@

FRC:
