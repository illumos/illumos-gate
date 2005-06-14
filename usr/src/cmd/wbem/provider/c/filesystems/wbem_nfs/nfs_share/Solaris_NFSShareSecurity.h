/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SOLARIS_NFSSHARESECURITY_H
#define	_SOLARIS_NFSSHARESECURITY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <cimapi.h>
#include <cp_required.h>
#include <cp_instance.h>
#include <cp_associator.h>
#include <cp_method.h>
#include <cp_property.h>
#include "nfsprov_include.h"

static nfs_prov_prop_t nfsShareSecProps[] = {

#define	MAXLIFE 0
	{"MaxLife", cim_false, uint32},

#define	PATH (MAXLIFE + 1)
	{"SettingId", cim_true, string},

#define	READONLY (PATH + 1)
	{"ReadOnly", cim_false, boolean},

#define	READWRITELIST (READONLY + 1)
	{"ReadWriteList", cim_false, string_array},

#define	READONLYLIST (READWRITELIST + 1)
	{"ReadOnlyList", cim_false, string_array},

#define	ROOTSERVERS (READONLYLIST + 1)
	{"RootServers", cim_false, string_array},

#define	SEC_MODE (ROOTSERVERS + 1)
	{"Mode", cim_true, string}
};

/*
 * PROPCOUNT must be set using the last define in the nfsShareSecProps list.
 */
#define	PROPCOUNT (SEC_MODE + 1)

#ifdef __cplusplus
}
#endif

#endif /* _SOLARIS_NFSSHARESECURITY_H */
