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

LIBRARY= libc.a
VERS= .1.9

# include common library definitions
include ../Makefile.lib

# There should be a mapfile here
MAPFILES =

CSTD=	$(CSTD_GNU89)

# the bcp libraries go in /usr/4lib. override ROOTLIBDIR from ../Makefile.lib
ROOTLIBDIR=     $(ROOT)/usr/4lib

DYNLIBS5= libc.so.2.9

#DYNLIBS5 is also defined in sparc/Makefile

LIBS = $(DYNLIB) $(DYNLIBS5)

# dynamic libraries should have executable file mode
FILEMODE= 755

.KEEP_STATE:

all clean clobber: links FRC
	@cd $(MACH); pwd; $(MAKE) $@

install: links $(MACHLIBS) $(ROOTLIBS)

#
# NOTE:  all of these processor specific links have been hardcoded
#        into this Makefile.  This is because the libbc library
#     	 is for the Binary Compatiblity Package.  The BCP is
#	 only relevant for Sun4 machines.  Future architectures will
#	 not use this package!!!
#
links:
	-$(RM) sparc/inc/machine 
	$(SYMLINK) sparc sparc/inc/machine 
	-$(RM) inc/include/machine
	$(SYMLINK) sun4 inc/include/machine 
	-$(RM) mach
	$(SYMLINK) sparc mach
	-$(RM) sparc/inc/sun4
	$(SYMLINK) sparc sparc/inc/sun4
	
# include MACH-specific library targets
include ../Makefile.mach
