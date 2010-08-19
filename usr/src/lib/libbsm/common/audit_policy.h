/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_AUDIT_POLICY_H
#define	_AUDIT_POLICY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <bsm/audit.h>
#include <bsm/libbsm.h>

#define	ALL_POLICIES   (AUDIT_AHLT|\
			AUDIT_ARGE|\
			AUDIT_ARGV|\
			AUDIT_CNT|\
			AUDIT_GROUP|\
			AUDIT_SEQ|\
			AUDIT_TRAIL|\
			AUDIT_PATH|\
			AUDIT_PUBLIC|\
			AUDIT_ZONENAME|\
			AUDIT_PERZONE|\
			AUDIT_WINDATA_DOWN|\
			AUDIT_WINDATA_UP)

#define	NO_POLICIES  (0)

struct policy_entry {
	char *policy_str;
	uint32_t policy_mask;
	char *policy_desc;
};
typedef struct policy_entry policy_entry_t;

static policy_entry_t policy_table[] = {
	{"ahlt",  AUDIT_AHLT,   "halt machine if it can not record an "
	    "async event"},
	{"all",   ALL_POLICIES,	"all policies"},
	{"arge",  AUDIT_ARGE,   "include exec environment args in audit recs"},
	{"argv",  AUDIT_ARGV,   "include exec command line args in audit recs"},
	{"cnt",   AUDIT_CNT,    "when no more space, drop recs and keep a cnt"},
	{"group", AUDIT_GROUP,	"include supplementary groups in audit recs"},
	{"none",  NO_POLICIES,	"no policies"},
	{"path",  AUDIT_PATH,	"allow multiple paths per event"},
	{"perzone", AUDIT_PERZONE,      "use a separate queue and auditd per "
	    "zone"},
	{"public",  AUDIT_PUBLIC,    "audit public files"},
	{"seq",   AUDIT_SEQ,    "include a sequence number in audit recs"},
	{"trail", AUDIT_TRAIL,	"include trailer token in audit recs"},
	{"windata_down", AUDIT_WINDATA_DOWN,  "include downgraded window "
	    "information in audit recs"},
	{"windata_up",  AUDIT_WINDATA_UP,     "include upgraded window "
	    "information in audit recs"},
	{"zonename", AUDIT_ZONENAME,    "include zonename token in audit recs"}
};

#define	POLICY_TBL_SZ (sizeof (policy_table) / sizeof (policy_entry_t))

#ifdef __cplusplus
}
#endif

#endif	/* _AUDIT_POLICY_H */
