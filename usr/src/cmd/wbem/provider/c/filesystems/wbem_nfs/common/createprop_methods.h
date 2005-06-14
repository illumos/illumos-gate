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

#ifndef	_CREATEPROP_METHODS_H
#define	_CREATEPROP_METHODS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <cimapi.h>

/*
 * Method declarations
 */
CIMBool		add_property_to_instance(cimchar *pName, CIMType pType,
			cimchar *pValue, CCIMObjectPath *pOP, CIMBool pIsKey,
			CCIMInstance *pInst);

CCIMPropertyList	*add_property_to_list(cimchar *pName, CIMType pType,
				cimchar *pValue, CCIMObjectPath *pOP,
				CIMBool pIsKey, CCIMPropertyList *propList);

cimchar		*get_property_from_opt_string(char *mntopts, char *option,
			boolean_t optHasEquals, int defaultValue);
CIMBool		set_dir_keyProperties_to_true(CCIMInstance *dirInst);
CIMBool		set_share_keyProperties_to_true(CCIMInstance *nfsShareInst);
CIMBool		set_shareSec_keyProperties_to_true(
			CCIMInstance *nfsShareSecInst);

#ifdef __cplusplus
}
#endif

#endif /* _CREATEPROP_METHODS_H */
