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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

#
# Note:  Hidden command and dependency checking plays havoc with perl module
# makefiles, so we make sure to always unset the KEEP_STATE and
# SUNPRO_DEPENDENCIES environment variables before calling any subsidiary makes.
#

.KEEP_STATE:

include ../../Makefile.cmd

# To turn KEEP_STATE off the following two environment variables must be unset.
KEEP_STATE_OFF = unset KEEP_STATE SUNPRO_DEPENDENCIES

# Configuration files needed from the architecture-specific subdirectories.
MACH_CONFIG_FILES = config.sh

# Where the configuration files need to be copied to.
DISTRIB_CONFIG_FILES = $(MACH_CONFIG_FILES:%=distrib/%)

# Generated Makefiles, derived from config.sh.
GEN_MAKEFILES = Makefile.perlcfg distrib/ext/Makefile

all	:= TARGET = all
install	:= TARGET = install
clobber := TARGET = clobber
clean	:= TARGET = clean
test	:= TARGET = test

# Compiler replacement rules
SED_CC		= -e "s!'cc'!'$(CC) -_gcc=-w'!"
SED_CC_E	= -e "s!'cc -E'!'$(REAL_CC) -E'!"

# distrib holds the perl source, contrib holds the SMI modules.
all clean test: configure FRC
	@ cd distrib; pwd; $(KEEP_STATE_OFF); $(MAKE) $(TARGET)
	@ cd contrib; pwd; $(KEEP_STATE_OFF); $(MAKE) $(TARGET)

# distrib/Makefile copies both distrib and contrib to the proto area.
install: all
	@ cd distrib; pwd; $(KEEP_STATE_OFF); $(MAKE) install_files

configure: $(DISTRIB_CONFIG_FILES) $(GEN_MAKEFILES)

# Modify config.sh to refer to the compiler used for the build.
distrib/config.sh: $(MACH)/config.sh
	$(SED)	$(SED_CC) $(SED_CC_E) $(MACH)/config.sh > $@

Makefile.perlcfg: extract_config $(MACH)/config.sh
	./extract_config $(MACH)/config.sh > Makefile.perlcfg

distrib/ext/Makefile: extract_makeext $(MACH)/config.sh
	./extract_makeext $(MACH)/config.sh > distrib/ext/Makefile

.PARALLEL: extract_config extract_makeext distrib/config.sh Makefile.perlcfg \
    distrib/ext/Makefile

#
# Subsidiary makefiles include the generated Makefiles,
# so make sure they exist first and then delete them afterwards.
#
clobber: $(GEN_MAKEFILES) FRC
	@ cd distrib; pwd; $(KEEP_STATE_OFF); $(MAKE) $(TARGET)
	@ cd contrib; pwd; $(KEEP_STATE_OFF); $(MAKE) $(TARGET)
	- $(RM) $(DISTRIB_CONFIG_FILES) $(GEN_MAKEFILES) \
	extract_config extract_makeext

FRC:
