#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libbsm/spec/getauclassent.spec

function	getauclassnam
include		<sys/param.h>, <bsm/libbsm.h>
declaration	struct au_class_ent *getauclassnam(char *name)
version		SUNW_0.7
errno		
exception	($return == 0)
end

function	getauclassnam_r
include		<sys/param.h>, <bsm/libbsm.h>
declaration	struct au_class_ent *getauclassnam_r( \
			au_class_ent_t *class_int, char *name)
version		SUNW_0.8
errno		
exception	($return == 0)
end

function	getauclassent
include		<sys/param.h>, <bsm/libbsm.h>
declaration	struct au_class_ent *getauclassent( void)
version		SUNW_0.7
errno		
exception	($return == 0)
end

function	getauclassent_r
include		<sys/param.h>, <bsm/libbsm.h>
declaration	struct au_class_ent *getauclassent_r( \
			au_class_ent_t * class_int)
version		SUNW_0.8
errno		
exception	($return == 0)
end

function	setauclass
include		<sys/param.h>, <bsm/libbsm.h>
declaration	void setauclass(void)
version		SUNW_0.7
errno		
end

function	endauclass
include		<sys/param.h>, <bsm/libbsm.h>
declaration	void endauclass(void)
version		SUNW_0.7
errno		
end
