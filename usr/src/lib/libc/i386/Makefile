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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2019, Joyent, Inc.

LIBCBASE=../i386

EXTN_CPPFLAGS =
EXTN_XFLAGS =

LIBRARY =	libc.a

# Special postprocessing for 32-bit fpcw.o: strip the SSE HWCAP attribute
# from the object file; the internal functions with SSE instructions are
# called conditionally on systems which have SSE instruction support
pics/fpcw.o := POST_PROCESS_O += ; \
	if $(ELFDUMP) -H $@ | grep " SSE "; then \
		$(ELFEDIT) -e 'cap:hw1 -and -cmp SSE' $@; \
	fi

include Makefile.com
