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

#ifndef _SOLARIS_PERSISTENTSHARE_H
#define	_SOLARIS_PERSISTENTSHARE_H

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

static nfs_prov_prop_t nfsPersistProps[] = {

#define	COMMAND 0
	{"Command", cim_false, string},

#define	CREATIONCLASSNAME (COMMAND + 1)
	{"CreationClassName", cim_true, string},

#define	SETTINGID (CREATIONCLASSNAME + 1)
	{"SettingID", cim_true, string},

#define	SYSTEMCREATIONCLASSNAME (SETTINGID + 1)
	{"SystemCreationClassName", cim_true, string},

#define	SYSTEMNAME (SYSTEMCREATIONCLASSNAME + 1)
	{"SystemName", cim_true, string}
};

/*
 * PROPCOUNT must be set using the last define in the nfsPersistProps list.
 */
#define	PROPCOUNT (SYSTEMNAME + 1)

#ifdef __cplusplus
}
#endif

#endif /* _SOLARIS_PERSISTENTSHARE_H */
