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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# include global definitions

AVS_SUBDIRS = ncall \
	      ns \
	      ns/dsw \
	      ns/nsctl \
	      ns/rdc \
	      ns/sdbc \
	      ns/solaris \
	      ns/sv \
	      ns/unistat

# install rules
install_h:= TARGET= install_h
check:=	    TARGET= check
clobber:=   TARGET= clobber

# standards checking rules

install_h check: $(AVS_SUBDIRS)

clobber: ns/rdc

$(AVS_SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
