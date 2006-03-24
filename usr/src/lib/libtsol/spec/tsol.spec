#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#

function	label_to_str
include		<tsol/label.h>
declaration	int label_to_str(const m_label_t *label, char **string, \
			const m_label_str_t conversion_type, uint_t flags);
version		SUNW_2.1
end

function	m_label_alloc
include		<tsol/label.h>
declaration	m_label_t m_label_dup(const m_label_type_t *type);
version		SUNW_2.1
end

function	m_label_dup
include		<tsol/label.h>
declaration	int m_label_dup(m_label_t **dst, const m_label_t *src);
version		SUNW_2.1
end

function	m_label_free
include		<tsol/label.h>
declaration	void m_label_free(m_label_t *label);
version		SUNW_2.1
end

function	str_to_label
include		<tsol/label.h>
declaration	int str_to_label(const char *str, m_label_t **label, \
			const m_label_type_t type, unit_t flags, int *error);
version		SUNW_2.1
end

function	bldominates
include		<tsol/label.h>
declaration	int bldominates(const m_label_t *label1, \
		    const m_label_t *label2);
version		SUNW_2.1
end

function	blequal
include		<tsol/label.h>
declaration	int blequal(const m_label_t *label1, const m_label_t *label2);
version		SUNW_2.1
end

function	blstrictdom
include		<tsol/label.h>
declaration	int blstrictdom(const m_label_t *label1, \
		    const m_label_t *label2);
version		SUNW_2.1
end

function	getlabel
include		<tsol/label.h>
declaration	int getlabel(const char *path, m_label_t *label);
version		SUNW_2.1
end

function	fgetlabel
include		<tsol/label.h>
declaration	int fgetlabel(int fd, m_label_t *label);
version		SUNW_2.1
end

function	getplabel
include		<tsol/label.h>
declaration	int getplabel(m_label_t *label_p);
version		SUNW_2.1
end

function	getzoneidbylabel
include		<tsol/label.h>
declaration	zoneid_t getzoneidbylabel(const m_label_t *label);
version		SUNW_2.1
end

function	getzonelabelbyid
include		<tsol/label.h>
declaration	m_label_t *getzonelabelbyid(zoneid_t zoneid);
version		SUNW_2.1
end

function	getzonelabelbyname
include		<tsol/label.h>
declaration	m_label_t *getzonelabelbyname(char *zone);
version		SUNW_2.1
end

function	getzonerootbyid
include		<tsol/label.h>
declaration	char *getzonerootbyid(zoneid_t zoneid);
version		SUNW_2.1
end

function	getzonerootbylabel
include		<tsol/label.h>
declaration	char *getzonerootbylabel(m_label_t *label);
version		SUNW_2.1
end

function	getzonerootbyname
include		<tsol/label.h>
declaration	char *getzonerootbyname(char *zone);
version		SUNW_2.1
end

function	setflabel
include		<tsol/label.h>
declaration	int setflabel(const char *path, m_label_t *label);
version		SUNW_2.1
end

function	getuserrange
include		<tsol/label.h>
declaration	m_range_t *getuserrange(const char *username);
version		SUNW_2.1
end
