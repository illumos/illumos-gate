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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * this is a place holder file
 * for the following functions.
 * They should never be called
 */
/* everything is in here */

#include <cimapi.h>
#include <cp_associator.h>

/* ARGSUSED */
CCIMInstanceList*
cp_enumInstances_libWBEMnfs(CCIMObjectPath* pOP)
{
	return ((CCIMInstanceList*) NULL);
}

/* ARGSUSED */
CCIMObjectPathList*
cp_enumInstanceNames_libWBEMnfs(CCIMObjectPath* pOP)
{
	return ((CCIMObjectPathList*) NULL);
}

/* creates an instance */
/* ARGSUSED */
CCIMObjectPath*
cp_createInstance_libWBEMnfs(CCIMObjectPath* pOP, CCIMInstance* pInst)
{
	return ((CCIMObjectPath*)NULL);
}

/* ARGSUSED */
CCIMProperty*
cp_invokeMethod_libWBEMnfs(CCIMObjectPath* pOP, cimchar* pName,
	CCIMPropertyList* pInParams,
	CCIMPropertyList* pInOutParams)
{
	return ((CCIMProperty*)NULL);
}

/* ARGSUSED */
CIMBool
cp_setInstance_libWBEMnfs(CCIMObjectPath* pOP, CCIMInstance* pInst)
{
	return (cim_false);
}

/* ARGSUSED */
CCIMInstance *
cp_getInstance_libWBEMnfs(CCIMObjectPath * pOP)
{
	return ((CCIMInstance *)NULL);
}


/* deletes an instance */
/* ARGSUSED */
CIMBool
cp_deleteInstance_libWBEMnfs(CCIMObjectPath *pOP)
{
	return (cim_false);
}

/* ARGSUSED */
CIMBool
cp_setProperty_libWBEMnfs(CCIMObjectPath* pObjPath, CCIMProperty* pProp)
{
	return (cim_false);
}

/* ARGSUSED */
CCIMProperty*
cp_getProperty_libWBEMnfs(CCIMObjectPath *pOP, char *pPropName)
{
	return ((CCIMProperty*) NULL);
}

/* ARGSUSED */
CCIMInstanceList*
cp_execQuery_libWBEMnfs(CCIMObjectPath *pOP, char *selectList,
	char *nonJoinExp, char *queryExp, char *queryType)
{
	return ((CCIMInstanceList *) NULL);
}

/* ARGSUSED */
CCIMInstanceList*
cp_associators_libWBEMnfs(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, char *pResultClass, char *pRole,
	char *pResultRole)
{
	return ((CCIMInstanceList *) NULL);
}

/* ARGSUSED */
CCIMObjectPathList*
cp_associatorNames_libWBEMnfs(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, char *pResultClass, char *pRole,
	char *pResultRole)
{
	return ((CCIMObjectPathList *) NULL);
}

/* ARGSUSED */
CCIMInstanceList*
cp_references_libWBEMnfs(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, char *pRole)
{
	return ((CCIMInstanceList *) NULL);
}

/* ARGSUSED */
CCIMObjectPathList*
cp_referenceNames_libWBEMnfs(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, char *pRole)
{
	return ((CCIMObjectPathList *) NULL);
}
