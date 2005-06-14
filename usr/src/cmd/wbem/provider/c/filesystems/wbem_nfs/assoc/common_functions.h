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

#ifndef	_COMMON_FUNCTIONS_H
#define	_COMMON_FUNCTIONS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <cimapi.h>

/*
 * Method declaration
 */

/*
 * Method: create_association_instList
 *
 * Description: This method creates instances of the association <pClassName>
 * out of the <pObjectName> and <pObjPathList> parameters.  The roles of
 * <pObjectName> and <pObjPathList> are defined by <pObjectNameRole> and
 * <pRole> respectively.
 *
 * Parameters:
 * cimchar *pClassName - The name of the association class of which to create
 * 	the instances of.
 * CCIMObjectPath *pObjectName - One of the association keys that will is to be
 *	associated to one or more objects.
 * cimchar *pObjectNameRole - The role of <pObjectName> in the association.
 *	For example, this could be "Antecedent", "Dependent", "Element", etc.
 * CCIMObjectPathList *pObjPathList - The other association keys that will
 * be associated to <pObjectName>.
 * cimchar *pRole - The role of <pObjPathList> in the association.
 * int *errp - The error pointer.
 *
 * Returns:
 * An instance list filled with instances of the <pClassName> association.
 */
CCIMInstanceList	*create_association_instList(cimchar *pClassName,
				CCIMObjectPath *pObjectName,
				cimchar *pObjectNameRole,
				CCIMObjectPathList *pObjPathList,
				cimchar *pRole, int *errp);

#ifdef __cplusplus
}
#endif

#endif /* _COMMON_FUNCTIONS_H */
