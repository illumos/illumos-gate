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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libproject/spec/project.spec
#

function	project_walk
include		<project.h>
declaraction	int project_walk(int (*)(projid_t, void *), void *)
version		SUNW_1.2
end

function	setproject
include		<project.h>
declaration	projid_t setproject(const char *, const char *, int)
version		SUNW_1.2
end

function	setprojent
include		<project.h>
declaration	void setprojent(void)
version		SUNW_1.1
end

function	endprojent
include		<project.h>
declaration	void endprojent(void);
version		SUNW_1.1
end

function	getprojent
include		<project.h>
declaration	struct project *getprojent(struct project *, void *, size_t)
version		SUNW_1.1
end

function	getprojbyname
include		<project.h>
declaration	struct project *getprojbyname(const char *, struct project *, void *, size_t)
version		SUNW_1.1
end

function	getprojbyid
include		<project.h>
declaration	struct project *getprojbyid(projid_t, struct project *, void *, size_t)
version		SUNW_1.1
end

function	getdefaultproj
include		<project.h>
declaration	struct project *getdefaultproj(const char *, struct project *, void *, size_t)
version		SUNW_1.1
end

function	fgetprojent
include		<project.h>
declaration	struct project *fgetprojent(FILE *, struct project *, void *, size_t)
version		SUNW_1.1
end

function	inproj
include		<project.h>
declaration	int inproj(const char *, const char *, void *, size_t)
version		SUNW_1.1
end

function	getprojidbyname
include		<project.h>
declaration	projid_t getprojidbyname(const char *)
version		SUNW_1.1
end

function        setproject_proc
version         SUNWprivate_1.1
end

function        setproject_initpriv
version         SUNWprivate_1.1
end
