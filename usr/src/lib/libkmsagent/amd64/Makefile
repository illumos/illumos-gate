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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#


include ../Makefile.com
include $(SRC)/lib/Makefile.lib.64

#
# CCNEEDED must be modified for 64-bit because the default only includes
# -lCrun
#
CCNEEDED = -lCstd -lCrun

#
# If linking with gcc, we must fix the CCNEEDED and LDLIBS64
# to get a clean link without duplicates.
#
$(__GNUC)CCNEEDED       = -L$(SFWLIBDIR) -R$(SFWLIBDIR) -lstdc++ -lgcc_s
$(__GNUC)LDLIBS64 += $(CCNEEDED)

install: all $(ROOTLIBS64) $(ROOTLINKS64)
