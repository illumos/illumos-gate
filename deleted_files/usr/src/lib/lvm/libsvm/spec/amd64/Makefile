#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

.KEEP_STATE:

# To enable apptrace, comment out the following line
DISABLE_APPTRACE=   $(POUND_SIGN)

include	../Makefile.targ

# Add arch specific objects here
OBJECTS	+=

include	$(SRC)/lib/Makefile.lib

# Uncomment the following if the linker complains
#amd64_C_PICFLAGS = $(amd64_C_BIGPICFLAGS)

include	$(SRC)/lib/Makefile.spec

$(DISABLE_APPTRACE)install: $(SPECMAP) $(ABILIB)
$(DISABLE_APPTRACE)	$(INS) -s -d -m $(DIRMODE) -u $(OWNER) \
$(DISABLE_APPTRACE)		-g $(GROUP) $(SNADMINLIB_ABI)/amd64
$(DISABLE_APPTRACE)	$(INS) -s -m $(FILEMODE) -u $(OWNER) \
$(DISABLE_APPTRACE)		-g $(GROUP) -f $(SNADMINLIB_ABI)/amd64 $(ABILIB)
