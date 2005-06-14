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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <pthread.h>

#include "master.h"
#include "util.h"
#include "providerNames.h"
#include "messageStrings.h"

/* local function declarations */
static int FindClassEntry(char *className);
static int FindAssocClassEntry(char *className);


/*
 * Encodes the CIM schema and provider version
 * into an unsigned long, use
 * getProviderVersion & getCimVersion to decode
 */

unsigned long
cp_getVersion()
{
	return (MAKEVERSION(1.0, 2.3));
}


/*
 * The function will take CCIMObjectPath
 * and search the classNameTable[]
 * for a className match, and then
 * call the corresponding cp_enumInstance
 * for that provider
 */

CCIMInstanceList*
cp_enumInstances(CCIMObjectPath* pOP)
{
	CCIMInstanceList	*instList = NULL;
	int 			index = 0;
	int    			error;

	/* Check if ObjectPath is NULL before continuing */
	if (pOP == NULL) {
	    /* Set error exception with localized message */
	    util_handleError(ENUM_INSTANCES, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return (NULL);
	}

	/* Object path is NOT NULL, so find the entry in the table */
	index = FindClassEntry(pOP->mName);

	/* check for error (-1) */
	if (index < 0) {
	    util_handleError(ENUM_INSTANCES, CIM_ERR_INVALID_CLASS,
		NULL, NULL, &error);
	    return (NULL);
	}

	/* OK, Find enumInstance */
	instList = (*enumInstanceTable[index])(pOP);
	return ((CCIMInstanceList*)instList);

}  /* cp_enumInstances */

/* creates an instance */

/*
 * The function will take CCIMObjectPath & CCIMInstance
 * and search the classNameTable[]
 * for a className match, and then
 * call the corresponding cp_createInstance
 * for that provider
 */

CCIMObjectPath*
cp_createInstance(CCIMObjectPath* pOP, CCIMInstance* pInst)
{
	CCIMObjectPath *objPath = NULL;
	int index = 0;
	int error;

	/* check if NULL before finding the Instance to create */
	if (pInst == NULL) {
	    util_handleError(CREATE_INSTANCE,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return (NULL);
	}

	/* find entry in the table */
	index = FindClassEntry(pInst->mClassName);

	/* check for error (-1) */
	if (index < 0) {
	    util_handleError(CREATE_INSTANCE,
		CIM_ERR_INVALID_CLASS, NULL, NULL, &error);
	    return (NULL);
	}

	objPath = (*createInstanceTable[index])(pOP, pInst);

	return ((CCIMObjectPath*) objPath);

} /* cp_createInstances */


/*
 * returns an array of CCIMObjectPaths for the class
 * params:
 * char* - the classname to enum
 */

CCIMObjectPathList*
cp_enumInstanceNames(CCIMObjectPath* pOP)
{
	CCIMObjectPathList	*objList = NULL;
	CCIMInstanceList	*instList = NULL;
	int			error = 0;

	/*
	 * create an instance list which contains all of the
	 * instances this provider will produce First check
	 * for valid ObjectPath
	 */
	if (pOP == NULL) {
	    util_handleError(ENUM_INSTANCENAMES,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return (NULL);
	}

	instList = cp_enumInstances(pOP);

	if (instList == NULL) {
	    return ((CCIMObjectPathList *)NULL);
	}

	objList = cim_createObjectPathList(instList);

	/*
	 * we no longer need the instList so free
	 * the memory allocated for it
	 */

	cim_freeInstanceList(instList);
	return (objList);
}

/* get an instance */

CCIMInstance*
cp_getInstance(CCIMObjectPath* pOP)
{
	CCIMInstance* inst = NULL;
	int	index = 0;
	int	error;

	/* Check if ObjectPath is NULL before continuing */
	if (pOP == NULL) {
	    util_handleError(GET_INSTANCE, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return (NULL);
	}

	/* Object path is NOT NULL, so find the entry in the table */
	index = FindClassEntry(pOP->mName);

	/* check for error (-1) */
	if (index < 0) {
	    util_handleError(GET_INSTANCE, CIM_ERR_INVALID_CLASS, NULL,
		NULL, &error);
	    return (NULL);
	}

	inst = (*getInstanceTable[index])(pOP);
	return ((CCIMInstance *)inst);
}

/*
 * returns the specified property,
 * should return NULL if not found
 *
 * params:
 * CCIMObjectPath* - ObjectPath to get the property from
 * char* - The property name to get
 *
 */

CCIMProperty*
cp_getProperty(CCIMObjectPath *pOP, char *pPropName)
{
	CCIMProperty*	prop = NULL;
	CCIMInstance*	inst = NULL;
	int		error;

	/* See if ObjectPath is OK */
	if (pOP == NULL) {
	    util_handleError(GET_PROPERTY, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return (NULL);
	}

	/* Make sure property name isn't NULL */
	if (pPropName == NULL) {
	    util_handleError(GET_PROPERTY, CIM_ERR_INVALID_CLASS,
		NULL, NULL, &error);
	    return (NULL);
	}

	/* see if we have any instances which match the obj path */
	inst = cp_getInstance(pOP);

	/* check for valid instance */
	if (inst == NULL) {
	    util_handleError(GET_PROPERTY, CIM_ERR_FAILED,
		NULL, NULL, &error);
	    return (NULL);
	}

	/* see if it has the specified property */
	prop = cim_getProperty(inst, pPropName);

	/* free memory allocated for the instance */
	cim_freeInstance(inst);

	/* return the property */
	return ((CCIMProperty *)prop);
}

/*
 * Sets the property in the passed in
 * instance to the new values of the
 * passed in property
 *
 * params:
 * CCIMObjectPath* - the Object Path in which the property should be changed
 * CCIMProperty* - a property structure which contains the new values
 *
 * return:
 * cim_true if property was updated otherwise cim_false
 *
 *
 * The function will take CCIMObjectPath & CCIMProperty
 * and search the classNameTable[]
 * for a className match, and then
 * call the corresponding setProperty
 * for that provider
 */

CIMBool
cp_setProperty(CCIMObjectPath* pObjPath, CCIMProperty* pProp)
{
	CIMBool retVal;
	int index = 0;
	int	error;

	if (pObjPath == NULL) {
	    util_handleError(SET_PROPERTY, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return (NULL);
	}

	index = FindClassEntry(pObjPath->mName);

	/* check for error (-1) */
	if (index < 0) {
	    util_handleError(SET_PROPERTY, CIM_ERR_INVALID_CLASS,
		NULL, NULL, &error);
	    return (NULL);
	}

	retVal = (*setPropertyTable[index])(pObjPath, pProp);
	return ((CIMBool)retVal);
}


/* sets an instance */

/*
 * The function will take CCIMObjectPath & CCIMInstance
 * and search the classNameTable[]
 * for a className match, and then
 * call the corresponding cp_setInstance
 * for that provider
 */

CIMBool
cp_setInstance(CCIMObjectPath* pOP, CCIMInstance* pInst)
{
	CIMBool retVal;
	int index = 0;
	int	error;

	if (pOP == NULL) {
	    util_handleError(SET_INSTANCE, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return (NULL);
	}

	if (pInst == NULL) {
	    util_handleError(SET_INSTANCE, CIM_ERR_INVALID_CLASS,
		NULL, NULL, &error);
	    return (NULL);
	}

	/* get the index into the table */
	index = FindClassEntry(pInst->mClassName);

	/* check for error (-1) */
	if (index < 0) {
	    util_handleError(SET_INSTANCE, CIM_ERR_INVALID_CLASS,
		NULL, NULL, &error);
	    return (NULL);
	}

	retVal = (*setInstanceTable[index])(pOP, pInst);
	return ((CIMBool)retVal);
}


/*
 * deletes an instance
 *
 * The function will take CCIMObjectPath
 * and search the classNameTable[]
 * for a className match, and then
 * call the corresponding cp_deleteInstance
 * for that provider
 */

CIMBool
cp_deleteInstance(CCIMObjectPath* pOP)
{
	CIMBool retVal;
	int index = 0;
	int	error;

	/* Verify ObjectPath is NOT NULL */
	if (pOP == NULL) {
	    util_handleError(DELETE_INSTANCE, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return (NULL);
	}

	/* find Entry in table */
	index = FindClassEntry(pOP->mName);

	/* check for error (-1) */
	if (index < 0) {
	    util_handleError(DELETE_INSTANCE, CIM_ERR_INVALID_CLASS,
		NULL, NULL, &error);
	    return (NULL);
	}

	retVal = (*deleteInstanceTable[index])(pOP);
	return ((CIMBool)retVal);
}

/*
 * Invokes the method and returns the results
 *   The caller is responsible for freeing the
 * memory allocated for the returned object
 *
 *  params:
 * CCIMObjectPath* - An object path of the instance
 *		to invoke the function on
 *  char* - name of the method to invoke
 * CCIMPropertyList* - input parameters to the function
 * CCIMPropertyList* - input/output parameters to the function
 *
 * returns:
 * NULL if it failed otherwise a CCIMProperty*
 *    which represents the return value of the function
 */

CCIMProperty*
cp_invokeMethod(CCIMObjectPath* pOP, cimchar* pName,
    CCIMPropertyList* pInParams, CCIMPropertyList* pInOutParams)
{
	CCIMProperty *prop;
	int index = 0;
	int error;

	/* First check for valid ObjectPath */
	if (pOP == NULL) {
	    util_handleError(INVOKE_METHOD, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return (NULL);
	}

	/* find entry in the table */
	index = FindClassEntry(pOP->mName);

	/* check for error (-1) */
	if (index < 0) {
	    util_handleError(INVOKE_METHOD, CIM_ERR_INVALID_CLASS,
		NULL, NULL, &error);
	    return (NULL);
	}

	prop = (*cpInvokeMethodTable[index])
	    (pOP, pName, pInParams, pInOutParams);

	return ((CCIMProperty*)prop);
}

/*
 * cp_execQuery
 */

CCIMInstanceList*
cp_execQuery(CCIMObjectPath *pOP, char *selectList,
    char *nonJoinExp, char *queryExp, char *queryType)
{
	CCIMInstanceList 	*instList = NULL;
	int			index = 0;
	int			error = 0;


	/* First check for valid ObjectPath */
	if (pOP == NULL) {
	    util_handleError(EXEC_QUERY, CIM_ERR_INVALID_PARAMETER, NULL, NULL,
		&error);
	    return ((CCIMInstanceList *)NULL);
	}

	/* find entry in the table */
	index = FindClassEntry(pOP->mName);

	/* check for error (-1) */
	if (index < 0) {
	    /* Set error exception with localized message */
	    util_handleError(EXEC_QUERY, CIM_ERR_INVALID_CLASS, NULL,
		NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}
	instList = (*execQueryTable[index])(pOP, selectList, nonJoinExp,
	    queryExp, queryType);

	return (instList);
}

/*
 * cp_associators
 */

CCIMInstanceList*
cp_associators(CCIMObjectPath *pAssocName, CCIMObjectPath *pObjectName,
    char *pResultClass, char *pRole, char *pResultRole)
{
	CCIMInstanceList 	*instList;
	int			index = 0;
	int			error = 0;

	/* First check for valid ObjectPath */
	if (pAssocName == NULL) {
	    /* Set error exception with localized message */
	    util_handleError(ASSOCIATORS, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	/* find entry in the table */
	index = FindAssocClassEntry(pAssocName->mName);

	/* check for error (-1) */
	if (index < 0) {
	    /* Set error exception with localized message */
	    util_handleError(ASSOCIATORS, CIM_ERR_INVALID_CLASS, NULL,
		NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Call the appropriate associator function. Let the specific function
	 * in the c provider handle the checking for correctness of the
	 * other parameters.
	 */

	instList = (*associatorsTable[index])(pAssocName, pObjectName,
	    pResultClass, pRole, pResultRole);
	return ((CCIMInstanceList *)instList);
}

/*
 * cp_associatorNames
 */

CCIMObjectPathList*
cp_associatorNames(CCIMObjectPath *pAssocName, CCIMObjectPath *pObjectName,
    char *pResultClass, char *pRole, char *pResultRole)
{
	CCIMObjectPathList 	*objList;
	int			index = 0;
	int			error = 0;

	/* First check for valid ObjectPath */
	if (pAssocName == NULL) {
	    /* Set error exception with localized message */
	    util_handleError(ASSOCIATORS, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMObjectPathList *)NULL);
	}

	/* find entry in the table */
	index = FindAssocClassEntry(pAssocName->mName);

	/* check for error (-1) */
	if (index < 0) {
	    /* Set error exception with localized message */
	    util_handleError(ASSOCIATORS, CIM_ERR_INVALID_CLASS, NULL,
		NULL, &error);
	    return ((CCIMObjectPathList *)NULL);
	}

	/*
	 * Call the appropriate associatorName function. Let the specific
	 * function in the c provider handle the checking for correctness of
	 * the other parameters.
	 */

	objList = (*associatorNamesTable[index])(pAssocName, pObjectName,
	    pResultClass, pRole, pResultRole);
	return ((CCIMObjectPathList *)objList);
}

/*
 * cp_references
 */

CCIMInstanceList*
cp_references(CCIMObjectPath *pAssocName, CCIMObjectPath *pObjectName,
    char *pRole)
{
	CCIMInstanceList 	*instList;
	int			index = 0;
	int			error = 0;

	/* First check for valid ObjectPath */
	if (pAssocName == NULL) {
	    /* Set error exception with localized message */
	    util_handleError(REFERENCES, CIM_ERR_INVALID_PARAMETER, NULL,
		NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	/* find entry in the table */
	index = FindAssocClassEntry(pAssocName->mName);

	/* check for error (-1) */
	if (index < 0) {
	    /* Set error exception with localized message */
	    util_handleError(REFERENCES, CIM_ERR_INVALID_CLASS, NULL,
		NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Call the appropriate references function. Let the specific function
	 * in the c provider handle the checking for correctness of the
	 * other parameters.
	 */

	instList = (*referencesTable[index])(pAssocName, pObjectName, pRole);
	return ((CCIMInstanceList *)instList);
}

/*
 * InParam: Class Name
 * Returns: Index into Name Table
 * If it hit libWBEMdisk, then we
 * have hit bottom, return err (-1)
 */

static int
FindClassEntry(char *className)
{
	int i = 0;

	while (strcasecmp(className, classNameTable[i])) {
		if (!strcasecmp(classNameTable[i], "libWBEMdisk")) {
			i = -1;
			break;
		}
		i++;
	}

	return (i);
}
/*
 * InParam: Class Name
 * Returns: Index into Name Table
 * If it hit libWBEMdisk, then we
 * have hit bottom, return err (-1)
 */

static int
FindAssocClassEntry(char *className)
{
	int i = 0;

	while (strcasecmp(className, assocclassNameTable[i])) {
		if (!strcasecmp(assocclassNameTable[i], "libWBEMdisk")) {
			i = -1;
			break;
		}
		i++;
	}

	return (i);
}

/*
 * cp_referenceNames
 */

CCIMObjectPathList*
cp_referenceNames(CCIMObjectPath *pAssocName, CCIMObjectPath *pObjectName,
    char *pRole)
{
	CCIMObjectPathList 	*objList;
	int			index = 0;
	int			error = 0;

	/* First check for valid ObjectPath */
	if (pAssocName == NULL) {
	    /* Set error exception with localized message */
	    util_handleError(REFERENCE_NAMES, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMObjectPathList *)NULL);
	}

	/* find entry in the table */
	index = FindAssocClassEntry(pAssocName->mName);

	/* check for error (-1) */
	if (index < 0) {
	    /* Set error exception with localized message */
	    util_handleError(REFERENCE_NAMES, CIM_ERR_INVALID_CLASS,
		NULL, NULL, &error);
	    return ((CCIMObjectPathList *)NULL);
	}

	/*
	 * Call the appropriate referenceName function. Let the specific
	 * function in the c provider handle the checking for correctness of
	 * the other parameters.
	 */

	objList = (*referenceNamesTable[index])(pAssocName, pObjectName, pRole);
	return ((CCIMObjectPathList *)objList);
}

CIMBool
cp_isAssociatorProvider(CCIMObjectPath *pOp)
{

	int 		index = 0;
	int			error = 0;

	/*
	 * If the object path coming in matches any in the associator table,
	 * return true, otherwise, return false.
	 */

	/* First check for valid ObjectPath */
	if (pOp == NULL) {
	    /* Set error exception with localized message */
	    util_handleError(REFERENCE_NAMES, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return (cim_false);
	}

	/* find entry in the table */
	index = FindAssocClassEntry(pOp->mName);

	if (index < 0) {
	    return (cim_false);
	}
	return (cim_true);
}
