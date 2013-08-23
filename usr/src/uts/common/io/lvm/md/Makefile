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
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
#

# Path to the base of the uts directory tree (usually /usr/src/uts).
UTSBASE	= ../../../..

#
#	Include common rules.
#
include $(SRC)/Makefile.master

MD_XDR_CSRC	=	$(UTSBASE)/common/io/lvm/md
MD_XDR_XSRC	=	$(UTSBASE)/common/sys/lvm
RPCGENFLAGS	+=	-C -M -D_KERNEL -DSYSV

DERIVED_FILES	=	meta_basic_xdr.c metamed_xdr.c

all_h install_h : $(DERIVED_FILES)

check:

clean:
	$(RM) $(DERIVED_FILES)

clobber: clean

%_xdr.c:	$(MD_XDR_XSRC)/%.x
	$(RPCGEN) $(RPCGENFLAGS) -c -i 100 $(MD_XDR_XSRC)/$*.x | \
$(NAWK) '/^#include/ {\
    sub(/(\.\.\/)*common\//,"");\
    sub(/meta_basic.h/, "md_basic.h");\
    sub(/metamed.h/, "mdmed.h");\
}\
{   print $0; }' > $@

.KEEP_STATE:
