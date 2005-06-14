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

#include <unistd.h>
#include <netdb.h>
#include <errno.h>

#include "util.h"
#include "cimKeys.h"
#include "providerNames.h"
#include "messageStrings.h"
#include "partbasedon_descriptors.h"
#include "partition_descriptors.h"
#include "logicaldisk_descriptors.h"
#include "Solaris_DiskPartitionBasedOnDisk.h"

#define	DISKPART_GETINSTANCE		"DISKPART_BASEDONDISK,GET_INSTANCE"
#define	DISKPART_ENUMINSTANCES		"DISKPART_BASEDONDISK,ENUM_INSTANCES"
#define	DISKPART_ENUMINSTANCENAMES \
	"DISKPART_BASEDONDISK,ENUM_INSTANCENAMES"
#define	DISKPART_CREATEINSTANCE		"DISKPART_BASEDONDISK,CREATE_INSTANCE"
#define	DISKPART_DELETEINSTANCE		"DISKPART_BASEDONDISK,DELETE_INSTANCE"
#define	DISKPART_SETINSTANCE		"DISKPART_BASEDONDISK,SET_INSTANCE"
#define	DISKPART_SETPROPERTY		"DISKPART_BASEDONDISK,SET_PROPERTY"
#define	DISKPART_GETPROPERTY		"DISKPART_BASEDONDISK,GET_PROPERTY"
#define	DISKPART_INVOKEMETHOD		"DISKPART_BASEDONDISK,INVOKE_METHOD"
#define	DISKPART_EXECQUERY		"DISKPART_BASEDONDISK,EXEC_QUERY"
#define	DISKPART_ASSOCIATORS		"DISKPART_BASEDONDISK,ASSOCIATORS"
#define	DISKPART_ASSOCIATORNAMES	"DISKPART_BASEDONDISK,ASSOCIATOR_NAMES"
#define	DISKPART_REFERENCES		"DISKPART_BASEDONDISK,REFERENCES"
#define	DISKPART_REFERENCENAMES		"DISKPART_BASEDONDISK,REFERENCE_NAMES"

static CCIMInstanceList  *createDiskPartBasedOnRefList(
    CCIMObjectPath *pObjectName, cimchar *pObjectNameRole,
	CCIMObjectPathList *objList, cimchar *objRole, int *error);

/*
 * Solaris_DiskPartitionBasedOnDisk provider
 *
 * It is important to note that all memory allocated by these functions
 * and passed to the CIMOM, is freed by the door process prior to
 * sending a copy of the data to the CIMOM.
 */

/*
 * Name: cp_getInstance_Solaris_DiskPartitionBasedOnDisk
 *
 * Description: Returns an instance which matches the passed in object path
 * if found.
 *
 * Parameters:
 *	pOP - An CCIMObjectPath * which contains the information on
 *	the class for which to find the instance.
 * Returns:
 *	CCIMInstance * if matched instance is found. Otherwise, NULL.
 */

CCIMInstance*
cp_getInstance_Solaris_DiskPartitionBasedOnDisk(CCIMObjectPath* pOP)
{
	CCIMInstance		*inst = NULL;
	CCIMPropertyList	*pCurPropList;
	dm_descriptor_t		d_descriptor;
	dm_descriptor_t		p_descriptor;
	CCIMObjectPath		*antOp = NULL;
	CCIMObjectPath		*depOp = NULL;
	char			*name;
	int			error;


	if (pOP == NULL) {
	    util_handleError(DISKPART_GETINSTANCE,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	if ((pCurPropList = pOP->mKeyProperties) == NULL) {
	    util_handleError(DISKPART_GETINSTANCE,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMInstance*)NULL);
	}

	antOp = (CCIMObjectPath *)util_getKeyValue(
	    pCurPropList, reference, ANTECEDENT, &error);

	if (error == 0) {
	    depOp = (CCIMObjectPath *)util_getKeyValue(
		pCurPropList, reference, DEPENDENT, &error);
	}

	if (error != 0) {
	    util_handleError(DISKPART_GETINSTANCE, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	/*
	 * Now, get the name of the antecedent from the object path.
	 */

	if ((pCurPropList = antOp->mKeyProperties) == NULL ||
		((pCurPropList = depOp->mKeyProperties) == NULL)) {
	    util_handleError(DISKPART_GETINSTANCE, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}

	pCurPropList = antOp->mKeyProperties;
	name = (cimchar *)util_getKeyValue(pCurPropList, string, DEVICEID,
	    &error);

	if (error != 0) {
	    util_handleError(DISKPART_GETINSTANCE, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}
	d_descriptor = dm_get_descriptor_by_name(DM_MEDIA, name, &error);
	/*
	 * Not found. Return a null instance.
	 */

	if (error == ENODEV || d_descriptor == NULL) {
	    return ((CCIMInstance *)NULL);
	}

	if (error != 0) {
	    util_handleError(DISKPART_GETINSTANCE, CIM_ERR_FAILED,
		DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
	    return ((CCIMInstance*)NULL);
	}

	/*
	 * Now, get the name of the dependent from the object path.
	 */

	pCurPropList = depOp->mKeyProperties;
	name = (cimchar *)util_getKeyValue(pCurPropList, string,
	    DEVICEID, & error);

	if (error != 0) {
	    util_handleError(DISKPART_GETINSTANCE, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMInstance *)NULL);
	}
	p_descriptor = dm_get_descriptor_by_name(DM_SLICE, name,
	    &error);

	/*
	 * Not found. Return a null instance.
	 */

	if (error == ENODEV || p_descriptor == NULL) {
	    return ((CCIMInstance *)NULL);
	}

	if (error != 0) {
	    util_handleError(DISKPART_GETINSTANCE, CIM_ERR_FAILED,
		DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
	    return ((CCIMInstance*)NULL);
	}

	/* Turn these descriptors in to a disk part based on instance */

	inst = partbasedon_descriptor_toCCIMInstance(
	    hostName, d_descriptor, p_descriptor, DISKPART_BASEDONDISK, &error);
	dm_free_descriptor(d_descriptor);
	dm_free_descriptor(p_descriptor);

	if (error != 0) {
	    util_handleError(DISKPART_GETINSTANCE, CIM_ERR_FAILED,
		PARTBASEDON_DESC_TO_INSTANCE_FAILURE, NULL, &error);
	    return ((CCIMInstance*)NULL);
	}

	return (inst);
}

/*
 * Name: cp_enumInstances_Solaris_DiskPartitionBasedOnDisk
 *
 * Description: Returns a linked list of instances of
 *      Solaris_DiskPartitionBasedOnDisk if found.
 *
 * Parameters:
 *	pOP - An CCIMObjectPath * which contains the information on
 *	the class for which to find the instances.
 * Returns:
 *	CCIMInstanceList * if instances are found. Otherwise,
 *	NULL is returned.
 */

/* ARGSUSED */
CCIMInstanceList*
cp_enumInstances_Solaris_DiskPartitionBasedOnDisk(CCIMObjectPath* pOP)
{
	CCIMInstanceList* 	instList = NULL;
	CCIMInstance*		inst;
	CCIMException*		ex;
	dm_descriptor_t		*disk_descriptorp = NULL;
	dm_descriptor_t		*part_descriptorp = NULL;
	int			error = 0;
	int			filter[2];
	int			i = 0;
	int			j = 0;

	filter[0] = DM_MT_FIXED;
	filter[1] = DM_FILTER_END;

	disk_descriptorp = dm_get_descriptors(DM_MEDIA, filter, &error);

	if (disk_descriptorp == NULL ||
		disk_descriptorp[0] == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}
	if (error != 0) {
	    util_handleError(DISKPART_ENUMINSTANCES, CIM_ERR_FAILED,
		DM_GET_DESCRIPTORS, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	/*
	 * For each one of the disks found, get the associated partitions.
	 */

	instList = cim_createInstanceList();
	if (instList == NULL) {
	    ex = cim_getLastError();
	    util_handleError(DISKPART_ENUMINSTANCES, CIM_ERR_FAILED,
		CREATE_INSTANCE_LIST_FAILURE, ex,
		&error);
	    dm_free_descriptors(disk_descriptorp);
	    return ((CCIMInstanceList *)NULL);
	}

	for (i = 0; disk_descriptorp[i] != NULL; i ++) {
	    part_descriptorp = dm_get_associated_descriptors(
		disk_descriptorp[i], DM_SLICE, &error);

	    /* If no partitions associated with this disk, continue */

	    if (part_descriptorp == NULL) {
		continue;
	    }

	    if (error != 0) {
		util_handleError(DISKPART_ENUMINSTANCES, CIM_ERR_FAILED,
		    DM_GET_ASSOC_FAILURE, NULL, &error);
		dm_free_descriptors(disk_descriptorp);
		cim_freeInstanceList(instList);
		return ((CCIMInstanceList *)NULL);
	    }


	    for (j = 0; part_descriptorp[j] != NULL; j ++) {
		inst = partbasedon_descriptor_toCCIMInstance(hostName,
		    disk_descriptorp[i], part_descriptorp[j],
			DISKPART_BASEDONDISK, &error);
		if (error != 0) {
		    util_handleError(DISKPART_ENUMINSTANCES, CIM_ERR_FAILED,
			PARTBASEDON_DESC_TO_INSTANCE_FAILURE, NULL, &error);
		    dm_free_descriptors(disk_descriptorp);
		    dm_free_descriptors(part_descriptorp);
		    cim_freeInstanceList(instList);
		    return ((CCIMInstanceList *)NULL);
		}

		instList = cim_addInstance(instList, inst);
		if (instList == NULL) {
		    ex = cim_getLastError();
		    util_handleError(DISKPART_ENUMINSTANCES, CIM_ERR_FAILED,
			ADD_INSTANCE_FAILURE, ex, &error);
		    dm_free_descriptors(disk_descriptorp);
		    dm_free_descriptors(part_descriptorp);
		    cim_freeInstance(inst);
		    return ((CCIMInstanceList *)NULL);
		}
	    }

	    dm_free_descriptors(part_descriptorp);
	}

	dm_free_descriptors(disk_descriptorp);
	return (instList);
}

/*
 * Name: cp_enumInstanceNames_Solaris_DiskPartitionBasedOnDisk
 *
 * Description: Returns a linked list of CCIMObjectPath *
 *      of Solaris_DiskPartitionBasedOnDisk if found.
 *
 * Parameters:
 *	pOP - An CCIMObjectPath * which contains the information on
 *	the class for which to find the instances.
 * Returns:
 *	CCIMObjectPathList * if objects are found.
 *	Otherwise NULL is returned.
 */

CCIMObjectPathList*
cp_enumInstanceNames_Solaris_DiskPartitionBasedOnDisk(CCIMObjectPath * pOP) {

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objList = NULL;
	int			error;

	if (pOP == NULL) {
	    util_handleError(DISKPART_ENUMINSTANCENAMES,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	}
	/*
	 * Call in to enumInstances and then convert the instance list in
	 * to an object list.
	 */

	instList = cp_enumInstances_Solaris_DiskPartitionBasedOnDisk(pOP);

	if (instList != NULL) {
	    objList = cim_createObjectPathList(instList);
	    cim_freeInstanceList(instList);
	}

	return (objList);
}

/*
 * Creating an instance of a Solaris_DiskPartitionBasedOnDisk is not supported.
 */

/* ARGSUSED */
CCIMObjectPath*
cp_createInstance_Solaris_DiskPartitionBasedOnDisk(
    CCIMObjectPath* pOP, CCIMInstance* pInst)
{
	int	error;

	util_handleError(DISKPART_CREATEINSTANCE,
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &error);
	return ((CCIMObjectPath *)NULL);
}

/*
 * Deleting an instance of a Solaris_DiskPartitionBasedOnDisk is not supported.
 */

/* ARGSUSED */
CIMBool
cp_deleteInstance_Solaris_DiskPartitionBasedOnDisk(CCIMObjectPath* pInst)
{
	int	error;

	util_handleError(DISKPART_DELETEINSTANCE,
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &error);
	return (cim_false);
}

/*
 * Name: cp_getProperty_Solaris_DiskPartitionBasedOnDisk
 *
 * Description: Returns the property requested, if found.
 *
 * Parameters:
 *	pOP - An CCIMObjectPath * which contains the information on
 *	the class for which to find the instances.
 * Returns:
 *	CCIMProperty * if found.
 */

/* ARGSUSED */
CCIMProperty	*
cp_getProperty_Solaris_DiskPartitionBasedOnDisk(CCIMObjectPath *pOP,
    char *pPropName)
{

	CCIMProperty	*prop = NULL;
	CCIMInstance	*inst = NULL;
	int		error = 0;

	if (pOP == NULL) {
	    util_handleError(DISKPART_GETPROPERTY,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMProperty *)NULL);
	}

	inst = cp_getInstance_Solaris_DiskPartitionBasedOnDisk(pOP);
	if (inst == NULL) {
	    return ((CCIMProperty *)NULL);
	}

	prop = cim_getProperty(inst, pPropName);
	cim_freeInstance(inst);
	return (prop);
}

/*
 * Setting an instance of a Solaris_DiskPartitionBasedOnDisk is not supported.
 */

/* ARGSUSED */
CIMBool
cp_setInstance_Solaris_DiskPartitionBasedOnDisk(
    CCIMObjectPath* pOP, CCIMInstance* pInst)
{
	int	error;

	util_handleError(DISKPART_SETINSTANCE,
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &error);
	return (cim_false);
}



/*
 * Setting a property on a Solaris_DiskPartitionBasedOnDisk is not supported.
 */

/* ARGSUSED */
CIMBool
cp_setProperty_Solaris_DiskPartitionBasedOnDisk(
    CCIMObjectPath* pOP, CCIMProperty* pProp)
{
	int	error;

	util_handleError(DISKPART_SETPROPERTY,
	    CIM_ERR_NOT_SUPPORTED, NULL, NULL, &error);
	return (cim_false);
}

/*
 * No Methods for Solaris_DiskPartitionBasedOnDisk.
 */

/* ARGSUSED */
CCIMProperty*
cp_invokeMethod_Solaris_DiskPartitionBasedOnDisk(
    CCIMObjectPath* op, cimchar* methodName,
	CCIMPropertyList* inParams, CCIMPropertyList* outParams)
{
	CCIMProperty	*retVal = (CCIMProperty	*)NULL;
	return (retVal);
}

/*
 * Name: cp_execQuery_Solaris_DiskPartitionBasedOnDisk
 *
 * Description:
 * Returns an instance list which matches the query if any are found.
 *
 * Parameters:
 *	CCIMObjectPath *op - An CCIMObjectPath * which contains the
 *	information on the class for which to find the instances.
 *
 * 	selectList - Not used
 *	nonJoinExp - Not used
 *
 * Returns:
 *	CCIMInstance * if matched instance is found. Otherwise, NULL.
 */
/*
 * Currently, there is no WQL parser for the C providers. As a result,
 * what is returned to the CIMOM is a list of instances with
 * a NULL value at the beginning of the list. This NULL value indicates
 * to the CIMOM that it must do the filtering for the client.
 */

/* ARGSUSED */
CCIMInstanceList*
cp_execQuery_Solaris_DiskPartitionBasedOnDisk(
    CCIMObjectPath *op, cimchar *selectList, cimchar *nonJoinExp,
	cimchar *queryExp, int queryType)
{
	CCIMInstanceList	*instList = NULL;
	CCIMInstanceList	*result;
	CCIMInstance		*emptyInst;
	CCIMException		*ex;
	int			error;

	if (op == NULL) {
	    util_handleError(DISKPART_EXECQUERY,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	instList = cp_enumInstances_Solaris_DiskPartitionBasedOnDisk(op);

	if (instList == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Create a null instance and add it to the beginning
	 * of the list to indicate to the CIMOM that no filtering
	 * was done.
	 */

	emptyInst = cim_createInstance("");
	if (emptyInst == NULL) {
	    ex = cim_getLastError();
	    util_handleError(DISKPART_EXECQUERY, CIM_ERR_FAILED,
		CREATE_INSTANCE_FAILURE, ex, &error);
	    cim_freeInstanceList(instList);
	    return ((CCIMInstanceList *)NULL);
	}

	result = cim_createInstanceList();
	if (result == NULL) {
	    ex = cim_getLastError();
	    util_handleError(DISKPART_EXECQUERY, CIM_ERR_FAILED,
		CREATE_INSTANCE_LIST_FAILURE, ex, &error);
	    cim_freeInstance(emptyInst);
	    cim_freeInstanceList(instList);
	    return ((CCIMInstanceList *)NULL);
	}

	result = cim_addInstance(result, emptyInst);
	if (result == NULL) {
	    ex = cim_getLastError();
	    util_handleError(DISKPART_EXECQUERY, CIM_ERR_FAILED,
		ADD_INSTANCE_FAILURE, ex, &error);
	    cim_freeInstance(emptyInst);
	    cim_freeInstanceList(instList);
	    return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Since copying the original list to the new list will
	 * leave no way to free the original list, manually
	 * concatenate the original list to the new one.
	 */

	result->mNext = instList;
	return (result);
}

/*
 * Name: cp_associators_Solaris_DiskPartitionBasedOnDisk
 *
 * Description:
 * Returns instances of objects associated with the passed in
 * object if there are any.
 *
 * Parameters:
 *
 *	CCIMObjectPath *pAssocName - The name of the association that
 *	the client wants information about.
 *
 *	CCIMObjectPath *pObjectName - An CCIMObjectPath * which contains the
 *	information on the class for which to find the associated instances.
 *
 *	cimchar *pResultClass - If specified, only return instances that
 *	are of this class type.
 *
 *      cimchar *pRole - If specified, must be valid for the object path
 *	passed in requesting the associated instances.
 *
 *	cimchar *pResultRole - If specified, only return instances that
 *	are playing this role in the association.
 *
 *
 * Returns:
 *	CCIMInstanceList * if associated objects are found.
 *	Otherwise NULL is returned.
 */

/* ARGSUSED */
CCIMInstanceList *
cp_associators_Solaris_DiskPartitionBasedOnDisk(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, cimchar *pResultClass, cimchar *pRole,
	cimchar *pResultRole)
{
	CCIMPropertyList	*pCurPropList;
	CCIMInstanceList	*instList = NULL;
	CCIMInstance		*inst;
	CCIMException		*ex;
	dm_descriptor_t		*assoc_descriptors;
	dm_descriptor_t		obj_desc;
	char			*name;
	int			error = 0;
	int			isAntecedent = 0;
	int			i;


	if (pObjectName == NULL || pObjectName->mName == NULL) {
	    util_handleError(DISKPART_ASSOCIATORS,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	if (strcasecmp(pObjectName->mName, LOGICAL_DISK) == 0) {
	    isAntecedent = 1;
	}

	if (pRole != NULL) {
	    if (strcasecmp(pRole, ANTECEDENT) == 0) {
		if (isAntecedent != 1) {
		    util_handleError(DISKPART_ASSOCIATORS,
			CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
		    return ((CCIMInstanceList *)NULL);
		}
	    }
	}

	if ((pCurPropList = pObjectName->mKeyProperties) == NULL) {
	    util_handleError(DISKPART_ASSOCIATORS, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Both logical disk and disk partition have deviceid as the
	 * key.
	 */

	name = (cimchar *)util_getKeyValue(pCurPropList, string, DEVICEID,
	    &error);

	if (error != 0) {
	    util_handleError(DISKPART_ASSOCIATORS, CIM_ERR_INVALID_PARAMETER,
		NULL, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	if (isAntecedent) {
	    obj_desc = dm_get_descriptor_by_name(DM_MEDIA, name, &error);
	} else {
	    obj_desc = dm_get_descriptor_by_name(DM_SLICE, name, &error);
	}

	/* No device found. */

	if (error == ENODEV || obj_desc == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}

	if (error != 0) {
	    util_handleError(DISKPART_ASSOCIATORS, CIM_ERR_FAILED,
		DM_GET_DESC_BYNAME_FAILURE, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}

	if (isAntecedent == 1) {
		/*
		 * Logical disk calling this method, return instances of the
		 * partitions associated with this disk.
		 */

	    /* Get associated descriptors. */

	    assoc_descriptors = dm_get_associated_descriptors(obj_desc,
		DM_SLICE, &error);
	    dm_free_descriptor(obj_desc);

	    if (assoc_descriptors == NULL) {
		return ((CCIMInstanceList *)NULL);
	    }

	    if (assoc_descriptors[0] == NULL) {
		dm_free_descriptors(assoc_descriptors);
		return ((CCIMInstanceList *)NULL);
	    }

	    if (error != 0) {
		util_handleError(DISKPART_ASSOCIATORS,  CIM_ERR_FAILED,
		    DM_GET_ASSOC_FAILURE, NULL, &error);
		return ((CCIMInstanceList *)NULL);
	    }

	    instList = cim_createInstanceList();
	    if (instList == NULL) {
		ex = cim_getLastError();
		util_handleError(DISKPART_ASSOCIATORS, CIM_ERR_FAILED,
		    CREATE_INSTANCE_FAILURE, ex, &error);
		dm_free_descriptors(assoc_descriptors);
		return ((CCIMInstanceList *)NULL);
	    }

	    /* Traverse the list and create instances of associated objects. */

	    for (i = 0; assoc_descriptors[i] != NULL; i ++) {
		inst = partition_descriptor_toCCIMInstance(hostName,
		    assoc_descriptors[i], DISK_PARTITION, &error);

		if (error != 0) {
		    util_handleError(DISKPART_ASSOCIATORS, CIM_ERR_FAILED,
			PART_DESC_TO_INSTANCE_FAILURE, NULL, &error);
		    dm_free_descriptors(assoc_descriptors);
		    cim_freeInstanceList(instList);
		    return ((CCIMInstanceList *)NULL);
		}
		instList = cim_addInstance(instList, inst);
		if (instList == NULL) {
		    ex = cim_getLastError();
		    util_handleError(DISKPART_ASSOCIATORS, CIM_ERR_FAILED,
			ADD_INSTANCE_FAILURE, ex, &error);
		    cim_freeInstance(inst);
		    dm_free_descriptors(assoc_descriptors);
		    return ((CCIMInstanceList *)NULL);
		}
	    } /* End for */
	} else {
		/*
		 * This is the partition calling this function. Return the
		 * logical disk that this belongs to.
		 */
	    assoc_descriptors = dm_get_associated_descriptors(obj_desc,
		DM_MEDIA, &error);
	    dm_free_descriptor(obj_desc);

	    if (assoc_descriptors == NULL) {
		return ((CCIMInstanceList *)NULL);
	    }

	    if (assoc_descriptors[0] == NULL) {
		dm_free_descriptors(assoc_descriptors);
		return ((CCIMInstanceList *)NULL);
	    }

	    if (error != 0) {
		util_handleError(DISKPART_ASSOCIATORS,  CIM_ERR_FAILED,
		    DM_GET_ASSOC_FAILURE, NULL, &error);
		return ((CCIMInstanceList *)NULL);
	    }

	    instList = cim_createInstanceList();
	    if (instList == NULL) {
		ex = cim_getLastError();
		util_handleError(DISKPART_ASSOCIATORS, CIM_ERR_FAILED,
		    CREATE_INSTANCE_FAILURE, ex, &error);
		return ((CCIMInstanceList *)NULL);
	    }
	    for (i = 0; assoc_descriptors[i] != NULL; i ++) {
		inst = logicaldisk_descriptor_toCCIMInstance(hostName,
		    assoc_descriptors[i], LOGICAL_DISK, &error);

		if (error != 0) {
		    util_handleError(DISKPART_ASSOCIATORS, CIM_ERR_FAILED,
			LOGICALDISK_DESC_TO_INSTANCE_FAILURE,
			    NULL, &error);
		    dm_free_descriptors(assoc_descriptors);
		    cim_freeInstanceList(instList);
		    return ((CCIMInstanceList *)NULL);
		}

		instList = cim_addInstance(instList, inst);
		if (instList == NULL) {
		    ex = cim_getLastError();
		    util_handleError(DISKPART_ASSOCIATORS, CIM_ERR_FAILED,
			ADD_INSTANCE_FAILURE, ex, &error);
		    dm_free_descriptors(assoc_descriptors);
		    return ((CCIMInstanceList *)NULL);
		}
	    } /* End for */
	}
	dm_free_descriptors(assoc_descriptors);
	return (instList);
}

/*
 * Name: cp_associatorNames_Solaris_DiskPartitionBasedOnDisk
 *
 * Description:
 * Returns a list of objects associated with the passed in
 * object if there are any via the object CCIMObjectPath.
 *
 * Parameters:
 *
 *	CCIMObjectPath *pAssocName - The name of the association that
 *	the client wants information about.
 *
 *	CCIMObjectPath *pObjectName - An CCIMObjectPath * which contains the
 *	information on the class for which to find the associated instances.
 *
 *	cimchar *pResultClass - If specified, only return instances that
 *	are of this class type.
 *
 *      cimchar *pRole - If specified, must be valid for the object path
 *	passed in requesting the associated instances.
 *
 *	cimchar *pResultRole - If specified, only return instances that
 *	are playing this role in the association.
 *
 *
 * Returns:
 *	CCIMObjectPathList * if associated objects are found.
 *	Otherwise, NULL is returned.
 */

/* ARGSUSED */
CCIMObjectPathList *
cp_associatorNames_Solaris_DiskPartitionBasedOnDisk(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, cimchar *pResultClass, cimchar *pRole,
	cimchar *pResultRole)
{

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objList = NULL;
	int			error;

	if (pObjectName == NULL) {
	    util_handleError(DISKPART_ASSOCIATORNAMES,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMObjectPathList *)NULL);
	}

	instList =
	    cp_associators_Solaris_DiskPartitionBasedOnDisk(
		pAssocName, pObjectName, pResultClass, pRole, pResultRole);

	if (instList != NULL) {
	    objList = cim_createObjectPathList(instList);
	    cim_freeInstanceList(instList);
	}

	return (objList);
}

/*
 * Name: cp_references_Solaris_DiskPartitionBasedOnDisk
 *
 * Description:
 * Returns instances of objects that have references to the passed in
 * object if there are any.
 *
 * Parameters:
 *
 *	CCIMObjectPath *pAssocName - The name of the association that
 *	the client wants information about.
 *
 *	CCIMObjectPath *pObjectName - An CCIMObjectPath * which contains the
 *	information on the class for which to find the associated instances.
 *
 *      cimchar *pRole - If specified, must be valid for the object path
 *	passed in requesting the associated instances.
 *
 * Returns:
 *	CCIMInstanceList * if associated objects are found.
 *	Otherwise, NULL is returned.
 */

/* ARGSUSED */
CCIMInstanceList *
cp_references_Solaris_DiskPartitionBasedOnDisk(CCIMObjectPath *pAssocName,
CCIMObjectPath *pObjectName, char *pRole)
{

	CCIMInstanceList	*instList = NULL;
	CCIMObjectPathList	*objList;
	int			error;


	if (pObjectName == NULL) {
	    util_handleError(DISKPART_REFERENCES,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMInstanceList *)NULL);
	}
	/*
	 * Get the list of those objects that are referred to by
	 * the calling object.
	 */

	objList =
	    cp_associatorNames_Solaris_DiskPartitionBasedOnDisk(
		pAssocName, pObjectName, NULL, NULL, NULL);

	if (objList == NULL) {
	    return ((CCIMInstanceList *)NULL);
	}

	/*
	 * Now generate the list of instances to return.
	 */

	if (strcasecmp(pObjectName->mName, LOGICAL_DISK) == 0) {
	    instList = createDiskPartBasedOnRefList(pObjectName,
		ANTECEDENT, objList, DEPENDENT, &error);
	} else {
	    instList = createDiskPartBasedOnRefList(pObjectName,
		DEPENDENT, objList, ANTECEDENT, &error);
	}

	cim_freeObjectPathList(objList);
	return (instList);
}

/*
 * Name: cp_referenceNames_Solaris_DiskPartitionBasedOnDisk
 *
 * Description:
 * Returns a instances of objects that have references to the passed in
 * object if there are any.
 *
 * Parameters:
 *
 *	CCIMObjectPath *pAssocName - The name of the association that
 *	the client wants information about.
 *
 *	CCIMObjectPath *pObjectName - An CCIMObjectPath * which contains the
 *	information on the class for which to find the associated instances.
 *
 *      cimchar *pRole - If specified, must be valid for the object path
 *	passed in requesting the associated instances.
 *
 *
 * Returns:
 *	CCIMInstanceList * if associated objects are found.
 *	Otherwise, NULL is returned.
 *
 */

/* ARGSUSED */
CCIMObjectPathList *
cp_referenceNames_Solaris_DiskPartitionBasedOnDisk(CCIMObjectPath *pAssocName,
    CCIMObjectPath *pObjectName, cimchar *pRole)
{

	CCIMInstanceList	*instList;
	CCIMObjectPathList	*objList = NULL;
	int			error;

	if (pObjectName == NULL) {
	    util_handleError(DISKPART_REFERENCENAMES,
		CIM_ERR_INVALID_PARAMETER, NULL, NULL, &error);
	    return ((CCIMObjectPathList *)NULL);
	}

	instList =
	    cp_references_Solaris_DiskPartitionBasedOnDisk(
		pAssocName, pObjectName, pRole);

	if (instList != NULL) {
	    objList = cim_createObjectPathList(instList);
	    cim_freeInstanceList(instList);
	}

	return (objList);
}

/*
 * Create the association class with the passed in attributes.
 */
static
CCIMInstanceList  *
createDiskPartBasedOnRefList(CCIMObjectPath *pObjectName,
    cimchar *pObjectNameRole,
	CCIMObjectPathList *objList, cimchar *objRole, int *error)
{

	CCIMObjectPathList	*tmpList;
	CCIMInstanceList	*instList = NULL;
	CCIMInstance		*inst;
	CCIMObjectPath		*obj1;
	CCIMObjectPath		*obj2;
	CCIMException		*ex;

	*error	= 0;
	instList = cim_createInstanceList();
	if (instList == NULL) {
	    ex = cim_getLastError();
	    util_handleError(DISKPART_BASEDONDISK, CIM_ERR_FAILED,
		CREATE_INSTANCE_FAILURE, ex, error);
	    return ((CCIMInstanceList *)NULL);
	}

	/*
	 * If no objects associated with this one, return an empty list.
	 */
	if (objList == NULL) {
	    cim_freeInstanceList(instList);
	    return ((CCIMInstanceList *)instList);
	}

	tmpList = objList;
	while (tmpList != NULL) {
	    obj1 = tmpList->mDataObject;
	    obj2 = cim_copyObjectPath(pObjectName);
	    if (obj2 == NULL) {
		ex = cim_getLastError();
		util_handleError(DISKPART_BASEDONDISK, CIM_ERR_FAILED,
		    COPY_OBJPATH_FAILURE, ex, error);
		cim_freeInstanceList(instList);
		return ((CCIMInstanceList *)NULL);
	    }

	    inst = cim_createInstance(DISKPART_BASEDONDISK);
	    if (inst == NULL) {
		ex = cim_getLastError();
		util_handleError(DISKPART_BASEDONDISK, CIM_ERR_FAILED,
		    CREATE_INSTANCE_FAILURE, ex, error);
		cim_freeObjectPath(obj2);
		cim_freeInstanceList(instList);
		return ((CCIMInstanceList *)NULL);
	    }
	    util_doReferenceProperty(pObjectNameRole, obj2, cim_true, inst,
		error);
	    util_doReferenceProperty(objRole, obj1, cim_true, inst, error);
	    cim_freeObjectPath(obj2);

	    if (*error != 0) {
		ex = cim_getLastError();
		util_handleError(DISKPART_BASEDONDISK, CIM_ERR_FAILED,
		    CREATE_REFPROP_FAILURE, ex, error);
		cim_freeInstance(inst);
		cim_freeInstanceList(instList);
		return ((CCIMInstanceList *)NULL);
	    }

	    instList = cim_addInstance(instList, inst);
	    if (instList == NULL) {
		ex = cim_getLastError();
		util_handleError(DISKPART_BASEDONDISK, CIM_ERR_FAILED,
		    ADD_INSTANCE_FAILURE, ex, error);
		cim_freeInstance(inst);
		return ((CCIMInstanceList *)NULL);
	    }

	    tmpList = tmpList->mNext;
	}
	return (instList);
}
