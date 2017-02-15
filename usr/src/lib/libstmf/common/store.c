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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <libscf.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <strings.h>
#include <libstmf.h>
#include <store.h>
#include <syslog.h>
#include <signal.h>
#include <pthread.h>
#include <libnvpair.h>
#include <limits.h>
#include <unistd.h>

/*
 * This file's functions are responsible for all store and retrieve operations
 * against the STMF smf(5) database. The following shows the currently defined
 * schema for the STMF database:
 *
 * Description of property groups for service: svc:/system/stmf
 *
 * Stability: Volatile
 *
 * 1. Property Group: host_groups
 *        Properties: group_name-<N> where <N> is an unsigned integer
 *                        type: ustring
 *                        contains: group name
 *                    group_name-<N>-member_list where <N> is an unsigned
 *                            integer matching a group_name-<N> property.
 *                        type: ustring
 *                        contains: list of members
 *
 *        Description:
 *             Contains the host group names as well as the host group members
 *             for each host group.
 *
 * 2. Property Group: target_groups
 *        Properties: group_name-<N> where <N> is an unsigned integer
 *                        type: ustring
 *                        contains: group name
 *                    group_name-<N>-member_list where <N> is an unsigned
 *                            integer matching a group_name-<N> property.
 *                        type: ustring
 *                        contains: list of members
 *
 *        Description:
 *             Contains the target group names as well as the target group
 *             members for each target group.
 *
 * 3. Property Group: lu-<GUID>
 *                        where <GUID> is a 32 character hexadecimal string.
 *        Properties: ve_cnt
 *                        type: count
 *                        contains: the number of current view entries
 *                    view-entry-<N>-<GUID> where <N> is an unsigned integer
 *                        type: ustring
 *                        contains: nothing. Used as reference to the view
 *                                  entry property group
 *
 *        Description:
 *             Contains the references to each view entry. One lu-<GUID>
 *             property group will exist for each logical unit with 1 or more
 *             view entries.
 *             Potentially can hold any other data that can be managed on a per
 *             logical unit basis.
 *
 * 4. Property Group: view_entry-<N>-<GUID> (matches property in lu-<GUID>
 *                    property group)
 *        Properties: all_hosts
 *                        type: boolean
 *                        contains: when true, the value of host_group is
 *                                  ignored
 *                    all_targets
 *                        type: boolean
 *                        contains: when true, the value of target_group is
 *                                  ignored
 *                    host_group
 *                        type: ustring
 *                        contains: host group for logical unit mapping and
 *                                  masking purposes
 *                    target_group
 *                        type: ustring
 *                        contains: target group for logical unit mapping and
 *                                  masking purposes
 *                    lu_nbr
 *                        type: opaque
 *                        contains: the 8-byte SCSI logical unit number for
 *                                  mapping and masking purposes
 *        Description:
 *             One "view_entry-<N>-<GUID>" property group will exist for each
 *             view entry in the system. This property group name maps
 *             directly to the "lu-<GUID>" property group with a matching
 *             <GUID>.
 *
 * 5. Property Group: provider_data_pg_<provider-name>
 *                        where <provider-name> is the name of the provider
 *                           registered with stmf.
 *        Properties: provider_data_prop-<N>
 *                        where <N> is a sequential identifier for the data
 *                           chunk.
 *                        type: opaque
 *                        contains: up to STMF_PROVIDER_DATA_PROP_SIZE bytes
 *                                  of nvlist packed data.
 *                    provider_data_count
 *                        type: count
 *                        contains: the number of provider data chunks
 *                    provider_data_type
 *                        type: integer
 *                        contains: STMF_PORT_PROVIDER_TYPE or
 *                                  STMF_LU_PROVIDER_TYPE
 *
 *        Description:
 *             Holds the nvlist packed provider data set via
 *             stmfSetProviderData and retrieved via stmfGetProviderData. Data
 *             is stored in STMF_PROVIDER_DATA_PROP_SIZE chunks. On retrieve,
 *             these chunks are reassembled and unpacked.
 *
 */

static int iPsInit(scf_handle_t **, scf_service_t **);
static int iPsCreateDeleteGroup(char *, char *, int);
static int iPsAddRemoveGroupMember(char *, char *, char *, int);
static int iPsGetGroupList(char *, stmfGroupList **);
static int iPsGetGroupMemberList(char *, char *, stmfGroupProperties **);
static int iPsAddViewEntry(char *, char *, stmfViewEntry *);
static int iPsAddRemoveLuViewEntry(char *, char *, int);
static int iPsGetViewEntry(char *, stmfViewEntry *);
static int iPsGetActualGroupName(char *, char *, char *);
static int iPsGetServiceVersion(uint64_t *, scf_handle_t *, scf_service_t *);
static int iPsGetSetPersistType(uint8_t *, scf_handle_t *, scf_service_t *,
    int);
static int iPsGetSetStmfProp(int, char *, int);
static int viewEntryCompare(const void *, const void *);
static int holdSignal(sigset_t *);
static int releaseSignal(sigset_t *);
static void sigHandler();

static pthread_mutex_t sigSetLock = PTHREAD_MUTEX_INITIALIZER;

sigset_t sigSet;
sigset_t signalsCaught;

struct sigaction currentActionQuit;
struct sigaction currentActionTerm;
struct sigaction currentActionInt;

boolean_t actionSet = B_FALSE;

/*
 * Version info for the SMF schema
 */
#define	STMF_SMF_VERSION    1

/*
 * Note: Do not change these property names and size values.
 * They represent fields in the persistent config and once modified
 * will have a nasty side effect of invalidating the existing store.
 * If you do need to change them, you'll need to use the versioning above
 * to retain backward compatiblity with the previous configuration schema.
 */

/* BEGIN STORE PROPERTY DEFINITIONS */
/*
 * Property Group Names and prefixes
 */
#define	STMF_HOST_GROUPS	"host_groups"
#define	STMF_TARGET_GROUPS	"target_groups"
#define	STMF_VE_PREFIX		"view_entry"
#define	STMF_LU_PREFIX		"lu"
#define	STMF_DATA_GROUP		"stmf_data"

/*
 * Property names and prefix for logical unit property group
 */
#define	STMF_VE_CNT		"ve_cnt"
#define	STMF_GROUP_PREFIX	"group_name"
#define	STMF_MEMBER_LIST_SUFFIX	"member_list"
#define	STMF_VERSION_NAME	"version_name"
#define	STMF_PERSIST_TYPE	"persist_method"

/* Property names for stmf properties */

#define	DEFAULT_LU_STATE		"default_lu_state"
#define	DEFAULT_TARGET_PORT_STATE	"default_target_state"

/*
 * Property names for view entry
 */
#define	STMF_VE_ALLHOSTS	    "all_hosts"
#define	STMF_VE_HOSTGROUP	    "host_group"
#define	STMF_VE_ALLTARGETS	    "all_targets"
#define	STMF_VE_TARGETGROUP	    "target_group"
#define	STMF_VE_LUNBR		    "lu_nbr"

/* Property group suffix for provider data */
#define	STMF_PROVIDER_DATA_PREFIX "provider_data_pg_"
#define	STMF_PROVIDER_DATA_PROP_PREFIX "provider_data_prop"
#define	STMF_PROVIDER_DATA_PROP_NAME_SIZE 256
#define	STMF_PROVIDER_DATA_PROP_TYPE "provider_type"
#define	STMF_PROVIDER_DATA_PROP_SET_COUNT "provider_data_set_cnt"
#define	STMF_PROVIDER_DATA_PROP_COUNT "provider_data_cnt"


#define	STMF_SMF_READ_ATTR	"solaris.smf.read.stmf"

#define	STMF_PS_PERSIST_NONE	"none"
#define	STMF_PS_PERSIST_SMF	"smf"
#define	STMF_PROVIDER_DATA_PROP_SIZE 4000

#define	STMF_PS_LU_ONLINE		"default_lu_online"
#define	STMF_PS_LU_OFFLINE		"default_lu_offline"
#define	STMF_PS_TARGET_PORT_ONLINE	"default_target_online"
#define	STMF_PS_TARGET_PORT_OFFLINE	"default_target_offline"

/* END STORE PROPERTY DEFINITIONS */

/* service name */
#define	STMF_SERVICE	"system/stmf"

/* limits and flag values */
#define	GROUP_MEMBER_ALLOC 100
#define	VIEW_ENTRY_STRUCT_CNT 6
#define	VIEW_ENTRY_PG_SIZE 256
#define	LOGICAL_UNIT_PG_SIZE 256
#define	VIEW_ENTRY_MAX UINT32_MAX
#define	GROUP_MAX UINT64_MAX
#define	ADD 0
#define	REMOVE 1
#define	GET 0
#define	SET 1

/*
 * sigHandler
 *
 * Catch the signal and set the global signalsCaught to the signal received
 *
 * signalsCaught will be used by releaseSignal to raise this signal when
 * we're done processing our critical code.
 *
 */
static void
sigHandler(int sig)
{
	(void) sigaddset(&signalsCaught, sig);
}

/*
 * iPsAddRemoveGroupMember
 *
 * Add or remove a member for a given group
 *
 * pgName - Property group name
 * groupName - group name to which the member is added/removed
 * memberName - member to be added/removed
 * addRemoveFlag - ADD/REMOVE
 *
 * returns:
 *  STMF_PS_SUCCESS on success
 *  STMF_PS_ERROR_* on failure
 */
static int
iPsAddRemoveGroupMember(char *pgName, char *groupName, char *memberName,
    int addRemoveFlag)
{
	scf_handle_t *handle = NULL;
	scf_service_t *svc = NULL;
	scf_propertygroup_t *pg = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *valueLookup = NULL;
	scf_value_t **valueSet = NULL;
	scf_iter_t *valueIter = NULL;
	scf_transaction_t *tran = NULL;
	scf_transaction_entry_t *entry = NULL;
	int i = 0;
	int lastAlloc;
	int valueArraySize = 0;
	int ret = STMF_PS_SUCCESS;
	char buf[STMF_IDENT_LENGTH];
	int commitRet;
	boolean_t found = B_FALSE;

	assert(pgName != NULL && groupName != NULL && memberName != NULL);

	/*
	 * Init the service handle
	 */
	ret = iPsInit(&handle, &svc);
	if (ret != STMF_PS_SUCCESS) {
		goto out;
	}

	/*
	 * Allocate scf resources
	 */
	if (((pg = scf_pg_create(handle)) == NULL) ||
	    ((tran = scf_transaction_create(handle)) == NULL) ||
	    ((entry = scf_entry_create(handle)) == NULL) ||
	    ((prop = scf_property_create(handle)) == NULL) ||
	    ((valueIter = scf_iter_create(handle)) == NULL)) {
		syslog(LOG_ERR, "scf alloc resource failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * Get the service property group handle
	 */
	if (scf_service_get_pg(svc, pgName, pg) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			ret = STMF_PS_ERROR_NOT_FOUND;
		} else {
			ret = STMF_PS_ERROR;
		}
		syslog(LOG_ERR, "get pg %s failed - %s",
		    pgName, scf_strerror(scf_error()));

		goto out;
	}

	/*
	 * Begin the transaction
	 */
	if (scf_transaction_start(tran, pg) == -1) {
		syslog(LOG_ERR, "start transaction for %s failed - %s",
		    pgName, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * We're changing an existing property by adding a propval
	 * There are no add semantics in libscf for a property value. We'll
	 * need to read in the current properties and apply them all to the
	 * set and then add the one we were asked to add or omit the one
	 * we were asked to remove.
	 */
	if (scf_transaction_property_change(tran, entry, groupName,
	    SCF_TYPE_USTRING) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			ret = STMF_PS_ERROR_GROUP_NOT_FOUND;
		} else {
			ret = STMF_PS_ERROR;
			syslog(LOG_ERR, "tran property change %s/%s "
			    "failed - %s", pgName, groupName,
			    scf_strerror(scf_error()));
		}
		goto out;
	}

	/*
	 * Get the property handle
	 */
	if (scf_pg_get_property(pg, groupName, prop) == -1) {
		syslog(LOG_ERR, "get property %s/%s failed - %s",
		    pgName, groupName, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * Value lookup is used to lookup the existing values
	 */
	valueLookup = scf_value_create(handle);
	if (valueLookup == NULL) {
		syslog(LOG_ERR, "scf value alloc for %s failed - %s",
		    pgName, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * valueIter is the iterator handle, create the resource
	 */
	if (scf_iter_property_values(valueIter, prop) == -1) {
		syslog(LOG_ERR, "iter values for %s/%s failed - %s",
		    pgName, groupName, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * Allocate value resource pointers.
	 * We need a value resource for each value as value pointers passed
	 * to libscf cannot be destroyed until the commit or destroy on the
	 * transaction is done.
	 *
	 * We're using GROUP_MEMBER_ALLOC initially. If it's not large
	 * enough, we'll realloc on the fly
	 */
	valueSet = (scf_value_t **)calloc(1, sizeof (*valueSet)
	    * (lastAlloc = GROUP_MEMBER_ALLOC));
	if (valueSet == NULL) {
		ret = STMF_PS_ERROR_NOMEM;
		goto out;
	}

	/*
	 * Iterate through the existing values
	 */
	while (scf_iter_next_value(valueIter, valueLookup) == 1) {
		bzero(buf, sizeof (buf));
		if (scf_value_get_ustring(valueLookup, buf, MAXNAMELEN) == -1) {
			syslog(LOG_ERR, "iter %s/%s value failed - %s",
			    pgName, groupName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}

		/*
		 * Check for existing
		 * If we're adding, it's an error
		 * If we're removing, we skip it and simply not
		 * add it to the set. Subtraction by omission.
		 */
		if ((strlen(buf) == strlen(memberName)) &&
		    bcmp(buf, memberName, strlen(buf)) == 0) {
			if (addRemoveFlag == ADD) {
				ret = STMF_PS_ERROR_EXISTS;
				break;
			} else {
				found = B_TRUE;
				continue;
			}
		}

		/*
		 * Create the value resource for this iteration
		 */
		valueSet[i] = scf_value_create(handle);
		if (valueSet[i] == NULL) {
			syslog(LOG_ERR, "scf value alloc for %s failed - %s",
			    pgName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}

		/*
		 * Set the value
		 */
		if (scf_value_set_ustring(valueSet[i], buf) == -1) {
			syslog(LOG_ERR, "set value for %s/%s failed - %s",
			    pgName, groupName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}

		/*
		 * Now add the value
		 */
		if (scf_entry_add_value(entry, valueSet[i]) == -1) {
			syslog(LOG_ERR, "add value for %s/%s failed - %s",
			    pgName, groupName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}

		i++;

		/*
		 * realloc if we've hit the previous alloc size
		 */
		if (i >= lastAlloc) {
			lastAlloc += GROUP_MEMBER_ALLOC;
			valueSet = realloc(valueSet,
			    sizeof (*valueSet) * lastAlloc);
			if (valueSet == NULL) {
				ret = STMF_PS_ERROR;
				break;
			}
		}
	}

	/*
	 * set valueArraySize to final allocated length
	 * so we can use it to destroy the resources correctly
	 */
	valueArraySize = i;

	if (!found && (addRemoveFlag == REMOVE)) {
		ret = STMF_PS_ERROR_MEMBER_NOT_FOUND;
	}

	if (ret != STMF_PS_SUCCESS) {
		goto out;
	}

	/*
	 * If we're adding, we have one more step. Add the member to the
	 * propval list
	 */
	if (addRemoveFlag == ADD) {
		/*
		 * Now create the new entry
		 */
		valueSet[i] = scf_value_create(handle);
		if (valueSet[i] == NULL) {
			syslog(LOG_ERR, "scf value alloc for %s/%s failed - %s",
			    pgName, groupName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		} else {
			valueArraySize++;
		}

		/*
		 * Set the new member name
		 */
		if (scf_value_set_ustring(valueSet[i], memberName) == -1) {
			syslog(LOG_ERR, "set value for %s/%s failed - %s",
			    pgName, groupName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		/*
		 * Add the new member
		 */
		if (scf_entry_add_value(entry, valueSet[i]) == -1) {
			syslog(LOG_ERR, "add value for %s/%s failed - %s",
			    pgName, groupName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
	}

	/*
	 * Yes, we're finally done. We actually added or removed one entry
	 * from the list.
	 * Woohoo!
	 */
	if ((commitRet = scf_transaction_commit(tran)) != 1) {
		syslog(LOG_ERR, "transaction commit for %s failed - %s",
		    pgName, scf_strerror(scf_error()));
		if (commitRet == 0) {
			ret = STMF_PS_ERROR_BUSY;
		} else {
			ret = STMF_PS_ERROR;
		}
		goto out;
	}

out:
	/*
	 * Free resources
	 */
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}
	if (tran != NULL) {
		scf_transaction_destroy(tran);
	}
	if (entry != NULL) {
		scf_entry_destroy(entry);
	}
	if (prop != NULL) {
		scf_property_destroy(prop);
	}
	if (valueLookup != NULL) {
		scf_value_destroy(valueLookup);
	}
	if (valueIter != NULL) {
		scf_iter_destroy(valueIter);
	}

	/*
	 * Free valueSet scf resources
	 */
	if (valueArraySize > 0) {
		for (i = 0; i < valueArraySize; i++) {
			scf_value_destroy(valueSet[i]);
		}
	}
	/*
	 * Now free the pointer array to the resources
	 */
	if (valueSet != NULL) {
		free(valueSet);
	}

	return (ret);
}

/*
 * iPsAddRemoveLuViewEntry
 *
 * Adds or removes a view entry name property for a given logical unit
 * property group. There is one logical unit property group for every logical
 * unit that has one or more associated view entries.
 *
 * luPgName - Property group name of logical unit
 * viewEntryPgName - Property group name of view entry
 * addRemoveFlag - ADD_VE/REMOVE_VE
 *
 * returns:
 *  STMF_PS_SUCCESS on success
 *  STMF_PS_ERROR_* on failure
 */
static int
iPsAddRemoveLuViewEntry(char *luPgName, char *viewEntryPgName,
    int addRemoveFlag)
{
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;
	scf_propertygroup_t	*pg = NULL;
	scf_property_t	*prop = NULL;
	scf_value_t	*value = NULL;
	scf_transaction_t   *tran = NULL;
	scf_transaction_entry_t *entry = NULL;
	scf_transaction_entry_t *entryVeName = NULL;
	boolean_t createVeCnt = B_FALSE;
	uint64_t veCnt = 0;
	int ret = STMF_PS_SUCCESS;
	int commitRet;

	assert(luPgName != NULL || viewEntryPgName != NULL);
	assert(!(addRemoveFlag != ADD && addRemoveFlag != REMOVE));

	/*
	 * Init the service handle
	 */
	ret = iPsInit(&handle, &svc);
	if (ret != STMF_PS_SUCCESS) {
		goto out;
	}

	/*
	 * Allocate scf resources
	 */
	if (((pg = scf_pg_create(handle)) == NULL) ||
	    ((tran = scf_transaction_create(handle)) == NULL) ||
	    ((entry = scf_entry_create(handle)) == NULL) ||
	    ((prop = scf_property_create(handle)) == NULL) ||
	    ((value = scf_value_create(handle)) == NULL)) {
		syslog(LOG_ERR, "scf alloc resource failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/* get the LU property group */
	if (scf_service_get_pg(svc, luPgName, pg) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND &&
		    addRemoveFlag == ADD) {
			/* if it doesn't exist, create it */
			if (scf_service_add_pg(svc, luPgName,
			    SCF_GROUP_APPLICATION, 0, pg) == -1) {
				syslog(LOG_ERR, "add pg %s failed - %s",
				    luPgName, scf_strerror(scf_error()));
				ret = STMF_PS_ERROR;
			} else {
				/* we need to create the VE_CNT property */
				createVeCnt = B_TRUE;
				ret = STMF_PS_SUCCESS;
			}
		} else if (scf_error() == SCF_ERROR_NOT_FOUND) {
			ret = STMF_PS_ERROR_NOT_FOUND;
		} else {
			syslog(LOG_ERR, "get lu pg %s failed - %s",
			    luPgName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
		}
		if (ret != STMF_PS_SUCCESS) {
			goto out;
		}
	}


	/*
	 * Begin the transaction
	 */
	if (scf_transaction_start(tran, pg) == -1) {
		syslog(LOG_ERR, "start transaction for %s failed - %s",
		    luPgName, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}


	if (createVeCnt) {
		/*
		 * Create the STMF_VE_CNT property. This will keep the current
		 * total view entries for this logical unit.
		 */
		if (scf_transaction_property_new(tran, entry, STMF_VE_CNT,
		    SCF_TYPE_COUNT) == -1) {
			if (scf_error() == SCF_ERROR_EXISTS) {
				ret = STMF_PS_ERROR_EXISTS;
			} else {
				syslog(LOG_ERR,
				    "transaction property new %s/%s "
				    "failed - %s", luPgName, STMF_VE_CNT,
				    scf_strerror(scf_error()));
				ret = STMF_PS_ERROR;
			}
			goto out;
		}
	} else {
		/*
		 * The STMF_VE_CNT property already exists. Just update
		 * it.
		 */
		if (scf_transaction_property_change(tran, entry,
		    STMF_VE_CNT, SCF_TYPE_COUNT) == -1) {
			syslog(LOG_ERR, "transaction property %s/%s change "
			    "failed - %s", luPgName, STMF_VE_CNT,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		/*
		 * Get the STMF_VE_CNT property
		 */
		if (scf_pg_get_property(pg, STMF_VE_CNT, prop) == -1) {
			syslog(LOG_ERR, "get property %s/%s failed - %s",
			    luPgName, STMF_VE_CNT, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		/*
		 * Get the STMF_VE_CNT value
		 */
		if (scf_property_get_value(prop, value) == -1) {
			syslog(LOG_ERR, "get property %s/%s value failed - %s",
			    luPgName, STMF_VE_CNT, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		/*
		 * Now get the actual value from the value handle
		 */
		if (scf_value_get_count(value, &veCnt) == -1) {
			syslog(LOG_ERR, "get count value %s/%s failed - %s",
			    luPgName, STMF_VE_CNT, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		/*
		 * Reset the value resource as it is used below
		 */
		scf_value_reset(value);
	}

	if (addRemoveFlag == ADD) {
		veCnt++;
	} else {
		/* Check if this is the last one being removed */
		if (veCnt == 1) {
			/*
			 * Delete the pg and get out if this is the last
			 * view entry
			 */
			if (scf_pg_delete(pg) == -1) {
				syslog(LOG_ERR, "delete pg %s failed - %s",
				    luPgName, scf_strerror(scf_error()));

				ret = STMF_PS_ERROR;
			}
			goto out;
		} else {
			veCnt--;
		}
	}


	/*
	 * Set the view entry count
	 */
	scf_value_set_count(value, veCnt);

	/*
	 * Add the value to the transaction entry
	 */
	if (scf_entry_add_value(entry, value) == -1) {
		syslog(LOG_ERR, "add value %s/%s failed - %s",
		    luPgName, STMF_VE_CNT, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * Create a transaction entry resource for the view entry name
	 */
	entryVeName = scf_entry_create(handle);
	if (entryVeName == NULL) {
		syslog(LOG_ERR, "scf transaction entry alloc %s/%s failed - %s",
		    luPgName, viewEntryPgName, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	if (addRemoveFlag == ADD) {
		/*
		 * If adding, create a property with the view entry name
		 */
		if (scf_transaction_property_new(tran, entryVeName,
		    viewEntryPgName, SCF_TYPE_USTRING) == -1) {
			if (scf_error() == SCF_ERROR_EXISTS) {
				ret = STMF_PS_ERROR_EXISTS;
			} else {
				syslog(LOG_ERR,
				    "transaction property new %s/%s "
				    "failed - %s", luPgName, viewEntryPgName,
				    scf_strerror(scf_error()));
				ret = STMF_PS_ERROR;
			}
			goto out;
		}
	} else {
		/*
		 * If removing, delete the existing property with the view
		 * entry name
		 */
		if (scf_transaction_property_delete(tran, entryVeName,
		    viewEntryPgName) == -1) {
			if (scf_error() == SCF_ERROR_NOT_FOUND) {
				ret = STMF_PS_ERROR_NOT_FOUND;
			} else {
				syslog(LOG_ERR,
				    "transaction property delete %s/%s "
				    "failed - %s", luPgName, viewEntryPgName,
				    scf_strerror(scf_error()));
				ret = STMF_PS_ERROR;
			}
			goto out;
		}
	}

	/*
	 * Commit property transaction
	 */
	if ((commitRet = scf_transaction_commit(tran)) != 1) {
		syslog(LOG_ERR, "transaction commit for %s failed - %s",
		    luPgName, scf_strerror(scf_error()));
		if (commitRet == 0) {
			ret = STMF_PS_ERROR_BUSY;
		} else {
			ret = STMF_PS_ERROR;
		}
		goto out;
	}

out:
	/*
	 * Free resources
	 */
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}
	if (tran != NULL) {
		scf_transaction_destroy(tran);
	}
	if (entry != NULL) {
		scf_entry_destroy(entry);
	}
	if (entryVeName != NULL) {
		scf_entry_destroy(entryVeName);
	}
	if (prop != NULL) {
		scf_property_destroy(prop);
	}
	if (value != NULL) {
		scf_value_destroy(value);
	}

	return (ret);
}

/*
 * iPsAddViewEntry
 *
 * Add a view entry property group and optionally, a logical unit property
 * group if it does not exist.
 *
 * luName - ascii hexadecimal logical unit identifier
 * viewEntryName - name of view entry (VIEW_ENTRY_nn)
 * viewEntry - pointer to stmfViewEntry structure
 */
static int
iPsAddViewEntry(char *luPgName, char *viewEntryPgName, stmfViewEntry *viewEntry)
{
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;
	scf_propertygroup_t	*pg = NULL;
	scf_value_t	*value[VIEW_ENTRY_STRUCT_CNT];
	scf_transaction_t   *tran = NULL;
	scf_transaction_entry_t *entry[VIEW_ENTRY_STRUCT_CNT];
	int i = 0;
	int j = 0;
	int ret;
	uint8_t scfBool;
	boolean_t createdVePg = B_FALSE;
	int backoutRet;
	int commitRet;

	assert(luPgName != NULL || viewEntryPgName != NULL ||
	    viewEntry == NULL);

	bzero(value, sizeof (value));
	bzero(entry, sizeof (entry));

	/*
	 * Init the service handle
	 */
	ret = iPsInit(&handle, &svc);
	if (ret != STMF_PS_SUCCESS) {
		goto out;
	}

	/*
	 * Allocate scf resources
	 */
	if (((pg = scf_pg_create(handle)) == NULL) ||
	    ((tran = scf_transaction_create(handle)) == NULL)) {
		syslog(LOG_ERR, "scf alloc resource failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * allocate value and entry resources for scf
	 */
	for (i = 0; i < VIEW_ENTRY_STRUCT_CNT; i++) {
		if (((value[i] = scf_value_create(handle)) == NULL) ||
		    ((entry[i] = scf_entry_create(handle)) == NULL)) {
			syslog(LOG_ERR, "scf alloc resource failed - %s",
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
	}

	i = 0;

	/*
	 * Create the View Entry property group
	 */
	if (scf_service_add_pg(svc, viewEntryPgName, SCF_GROUP_APPLICATION,
	    0, pg) == -1) {
		if (scf_error() == SCF_ERROR_EXISTS) {
			ret = STMF_PS_ERROR_EXISTS;
		} else {
			syslog(LOG_ERR, "add pg %s failed - %s",
			    viewEntryPgName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
		}
		goto out;
	}

	createdVePg = B_TRUE;

	/*
	 * Add the view entry as properties on the view entry group
	 */

	/*
	 * Begin property update transaction
	 */
	if (scf_transaction_start(tran, pg) == -1) {
		syslog(LOG_ERR, "start transaction for add %s failed - %s",
		    viewEntryPgName, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * Add allHosts property
	 */
	if (scf_transaction_property_new(tran, entry[i],
	    STMF_VE_ALLHOSTS, SCF_TYPE_BOOLEAN) == -1) {
		if (scf_error() == SCF_ERROR_EXISTS) {
			ret = STMF_PS_ERROR_EXISTS;
		} else {
			syslog(LOG_ERR, "transaction property new %s/%s "
			    "failed - %s", viewEntryPgName, STMF_VE_ALLHOSTS,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
		}
		goto out;
	}

	/* Set the allHosts value */
	scfBool = viewEntry->allHosts;
	scf_value_set_boolean(value[i], scfBool);

	/*
	 * Add the allHosts value to the transaction
	 */
	if (scf_entry_add_value(entry[i], value[i]) == -1) {
		syslog(LOG_ERR, "add value %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_ALLHOSTS,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	i++;

	/*
	 * Create hostGroup property
	 */
	if (scf_transaction_property_new(tran, entry[i],
	    STMF_VE_HOSTGROUP, SCF_TYPE_USTRING) == -1) {
		if (scf_error() == SCF_ERROR_EXISTS) {
			ret = STMF_PS_ERROR_EXISTS;
		} else {
			syslog(LOG_ERR, "transaction property new %s/%s "
			    "failed - %s", viewEntryPgName, STMF_VE_HOSTGROUP,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
		}
		goto out;
	}

	/*
	 * Set the value for hostGroup
	 */
	if (scf_value_set_ustring(value[i], viewEntry->hostGroup) == -1) {
		syslog(LOG_ERR, "set value %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_HOSTGROUP,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * Add the hostGroup value to the transaction entry
	 */
	if (scf_entry_add_value(entry[i], value[i]) == -1) {
		syslog(LOG_ERR, "add value %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_HOSTGROUP,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	i++;

	/*
	 * Create the allTargets property
	 */
	if (scf_transaction_property_new(tran, entry[i],
	    STMF_VE_ALLTARGETS, SCF_TYPE_BOOLEAN) == -1) {
		if (scf_error() == SCF_ERROR_EXISTS) {
			ret = STMF_PS_ERROR_EXISTS;
		} else {
			syslog(LOG_ERR, "transaction property new %s/%s "
			    "failed - %s", viewEntryPgName, STMF_VE_ALLTARGETS,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
		}
		goto out;
	}

	/*
	 * Set the allTargets value
	 */
	scfBool = viewEntry->allTargets;
	scf_value_set_boolean(value[i], scfBool);

	/*
	 * Add the allTargets value to the transaction
	 */
	if (scf_entry_add_value(entry[i], value[i]) == -1) {
		syslog(LOG_ERR, "add value %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_ALLTARGETS,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	i++;

	/*
	 * Create targetGroup property
	 */
	if (scf_transaction_property_new(tran, entry[i],
	    STMF_VE_TARGETGROUP, SCF_TYPE_USTRING) == -1) {
		if (scf_error() == SCF_ERROR_EXISTS) {
			ret = STMF_PS_ERROR_EXISTS;
		} else {
			syslog(LOG_ERR, "transaction property new %s/%s "
			    "failed - %s", viewEntryPgName,
			    STMF_VE_TARGETGROUP, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
		}
		goto out;
	}

	/*
	 * Set the value for targetGroup
	 */
	if (scf_value_set_ustring(value[i], viewEntry->targetGroup) == -1) {
		syslog(LOG_ERR, "set value %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_TARGETGROUP,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * Add targetGroup value to the transaction
	 */
	if (scf_entry_add_value(entry[i], value[i]) == -1) {
		syslog(LOG_ERR, "add value %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_TARGETGROUP,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	i++;

	/*
	 * Create the luNbr property
	 */
	if (scf_transaction_property_new(tran, entry[i], STMF_VE_LUNBR,
	    SCF_TYPE_OPAQUE) == -1) {
		if (scf_error() == SCF_ERROR_EXISTS) {
			ret = STMF_PS_ERROR_EXISTS;
		} else {
			syslog(LOG_ERR, "transaction property new %s/%s "
			    "failed - %s", viewEntryPgName, STMF_VE_LUNBR,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
		}
		goto out;
	}

	/*
	 * Set the luNbr
	 */
	if (scf_value_set_opaque(value[i], (char *)viewEntry->luNbr,
	    sizeof (viewEntry->luNbr)) == -1) {
		syslog(LOG_ERR, "set value %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_LUNBR, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * Add luNbr to the transaction entry
	 */
	if (scf_entry_add_value(entry[i], value[i]) == -1) {
		syslog(LOG_ERR, "add value %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_LUNBR, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * Now that we've successfully added the view entry,
	 * update the logical unit property group or create
	 * it if it does not exist
	 */
	ret = iPsAddRemoveLuViewEntry(luPgName, viewEntryPgName, ADD);

	/*
	 * If we did not add the view entry name to the logical unit,
	 * make sure we do not commit the transaction
	 */
	if (ret != STMF_PS_SUCCESS) {
		goto out;
	}

	/*
	 * Commit property transaction
	 */
	if ((commitRet = scf_transaction_commit(tran)) != 1) {
		syslog(LOG_ERR, "transaction commit for add %s failed - %s",
		    viewEntryPgName, scf_strerror(scf_error()));
		if (commitRet == 0) {
			ret = STMF_PS_ERROR_BUSY;
		} else {
			ret = STMF_PS_ERROR;
		}
	}

	if (ret != STMF_PS_SUCCESS) {
		/*
		 * If we did not commit, try to remove the view entry name
		 * from the logical unit.
		 * If that fails, we're now inconsistent.
		 */
		backoutRet = iPsAddRemoveLuViewEntry(luPgName, viewEntryPgName,
		    REMOVE);

		if (backoutRet != STMF_PS_SUCCESS) {
			syslog(LOG_ERR, "remove lu view entry %s failed"
			    "possible inconsistency - %s", luPgName,
			    scf_strerror(scf_error()));
		}
		/*
		 * We are still in an error scenario even though the remove
		 * lu view entry succeeded.
		 */
		goto out;
	}

out:
	/*
	 * Free resources
	 */
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	/* if there was an error, delete the created pg if one was created */
	if ((ret != STMF_PS_SUCCESS) && createdVePg) {
		if (scf_pg_delete(pg) == -1) {
			syslog(LOG_ERR, "delete VE pg %s failed - %s",
			    viewEntryPgName, scf_strerror(scf_error()));
		}
	}
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}
	if (tran != NULL) {
		scf_transaction_destroy(tran);
	}
	/*
	 * Free value and entry scf resources
	 */
	if (i > 0) {
		for (j = 0; j < VIEW_ENTRY_STRUCT_CNT; j++) {
			if (value[j] != NULL)
				scf_value_destroy(value[j]);
			if (entry[j] != NULL)
				scf_entry_destroy(entry[j]);
		}
	}

	return (ret);
}
/*
 * psClearProviderData
 *
 * providerName - name of provider data to clear
 */
int
psClearProviderData(char *providerName, int providerType)
{
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;
	scf_propertygroup_t	*pg = NULL;
	char pgName[MAXPATHLEN];
	int ret = STMF_PS_SUCCESS;
	boolean_t pgNotFound = B_FALSE;

	if (providerName == NULL || (providerType != STMF_LU_PROVIDER_TYPE &&
	    providerType != STMF_PORT_PROVIDER_TYPE)) {
		ret = STMF_PS_ERROR_INVALID_ARG;
		goto out;
	}

	ret = iPsInit(&handle, &svc);
	if (ret != STMF_PS_SUCCESS) {
		goto out;
	}

	/*
	 * Allocate scf resources
	 */
	if ((pg = scf_pg_create(handle)) == NULL) {
		syslog(LOG_ERR, "scf alloc resource failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * create the property group name
	 */
	(void) snprintf(pgName, sizeof (pgName), "%s%s",
	    STMF_PROVIDER_DATA_PREFIX, providerName);

	/*
	 * delete provider property group
	 */
	if (scf_service_get_pg(svc, pgName, pg) == -1) {
		if (scf_error() != SCF_ERROR_NOT_FOUND) {
			syslog(LOG_ERR, "get pg %s failed - %s",
			    pgName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		} else {
			pgNotFound = B_TRUE;
		}
	}

	if (!pgNotFound && (scf_pg_delete(pg) == -1)) {
		syslog(LOG_ERR, "delete pg %s failed - %s",
		    pgName, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	if (pgNotFound) {
		ret = STMF_PS_ERROR_NOT_FOUND;
	}

out:
	/*
	 * Free resources
	 */
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}

	return (ret);
}

/*
 * iPsCreateDeleteGroup
 *
 * Creates or deletes a group (target or host)
 *
 * When creating a group, two properties are created. One to hold the group
 * name and the other to hold the group members.
 *
 * pgName - Property group name
 * groupName - group name to create
 * addRemoveFlag - ADD_GROUP/REMOVE_GROUP
 *
 * returns:
 *  STMF_PS_SUCCESS on success
 *  STMF_PS_ERROR_* on failure
 */
static int
iPsCreateDeleteGroup(char *pgRefName, char *groupName, int addRemoveFlag)
{
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;
	scf_propertygroup_t	*pg = NULL;
	scf_property_t	*prop = NULL;
	scf_iter_t	*propIter = NULL;
	scf_transaction_t   *tran = NULL;
	scf_transaction_entry_t *entry1 = NULL;
	scf_transaction_entry_t *entry2 = NULL;
	scf_value_t *value = NULL;
	uint64_t groupIdx;
	char buf1[MAXNAMELEN];
	char buf2[MAXNAMELEN];
	char tmpbuf[MAXNAMELEN];
	boolean_t found = B_FALSE;
	int ret = STMF_PS_SUCCESS;
	int commitRet;

	assert(groupName != NULL);

	ret = iPsInit(&handle, &svc);
	if (ret != STMF_PS_SUCCESS) {
		goto out;
	}

	/*
	 * Allocate scf resources
	 */
	if (((pg = scf_pg_create(handle)) == NULL) ||
	    ((tran = scf_transaction_create(handle)) == NULL) ||
	    ((entry1 = scf_entry_create(handle)) == NULL) ||
	    ((entry2 = scf_entry_create(handle)) == NULL) ||
	    ((prop = scf_property_create(handle)) == NULL) ||
	    ((propIter = scf_iter_create(handle)) == NULL) ||
	    ((value = scf_value_create(handle)) == NULL)) {
		syslog(LOG_ERR, "scf alloc resource failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * Get the property group being modified
	 */
	if (scf_service_get_pg(svc, pgRefName, pg) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND &&
		    addRemoveFlag == ADD) {
			if (scf_service_add_pg(svc, pgRefName,
			    SCF_GROUP_APPLICATION, 0, pg) == -1) {
				syslog(LOG_ERR, "add pg %s failed - %s",
				    pgRefName, scf_strerror(scf_error()));
				ret = STMF_PS_ERROR;
			}
		} else if (scf_error() == SCF_ERROR_NOT_FOUND) {
			syslog(LOG_ERR, "get pg %s failed - %s",
			    pgRefName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR_NOT_FOUND;
		} else {
			syslog(LOG_ERR, "get pg %s failed - %s",
			    pgRefName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
		}
		if (ret != STMF_PS_SUCCESS) {
			goto out;
		}
	}

	/*
	 * propIter is the iterator handle
	 */
	if (scf_iter_pg_properties(propIter, pg) == -1) {
		syslog(LOG_ERR, "iter properties for %s failed - %s",
		    pgRefName, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * Iterate through the group names.
	 * If we find it in the list, it's an error when addRemoveFlag == ADD.
	 */
	while (scf_iter_next_property(propIter, prop) == 1) {
		if (scf_property_get_name(prop, buf1, sizeof (buf1)) == -1) {
			syslog(LOG_ERR, "get name from %s iter failed - %s",
			    pgRefName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}
		/*
		 * Skip over member list properties
		 */
		if (strstr(buf1, STMF_MEMBER_LIST_SUFFIX)) {
			continue;
		}
		if (scf_property_get_value(prop, value) == -1) {
			syslog(LOG_ERR, "get property value %s/%s failed - %s",
			    pgRefName, buf1, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}
		if (scf_value_get_ustring(value, tmpbuf,
		    sizeof (tmpbuf)) == -1) {
			syslog(LOG_ERR, "get ustring %s/%s failed - %s",
			    pgRefName, buf1, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}

		if ((strlen(tmpbuf) == strlen(groupName)) &&
		    bcmp(tmpbuf, groupName, strlen(tmpbuf)) == 0) {
			if (addRemoveFlag == ADD) {
				ret = STMF_PS_ERROR_EXISTS;
			}
			found = B_TRUE;
			/*
			 * buf1 contains the name for REMOVE
			 */
			break;
		}
	}

	if (ret != STMF_PS_SUCCESS) {
		goto out;
	}

	scf_value_reset(value);

	if (!found && addRemoveFlag == REMOVE) {
		ret = STMF_PS_ERROR_NOT_FOUND;
		goto out;
	}

	/*
	 * If we're adding, we need to create a new property name for the
	 * new group
	 */
	if (addRemoveFlag == ADD) {
		for (groupIdx = 0; groupIdx < GROUP_MAX; groupIdx++) {
			if (snprintf(buf1, sizeof (buf1), "%s-%lld",
			    STMF_GROUP_PREFIX, groupIdx) > sizeof (buf1)) {
				syslog(LOG_ERR,
				    "buffer overflow on property name %s",
				    buf1);
				ret = STMF_PS_ERROR;
				break;
			}
			if (scf_pg_get_property(pg, buf1, prop) == -1) {
				if (scf_error() != SCF_ERROR_NOT_FOUND) {
					syslog(LOG_ERR, "get property %s/%s "
					    "failed - %s", pgRefName, buf1,
					    scf_strerror(scf_error()));
					ret = STMF_PS_ERROR;
				}
				break;
			}
		}
	}

	/*
	 * Now create the new member list property for the new group
	 */
	if (snprintf(buf2, sizeof (buf2), "%s-%s", buf1,
	    STMF_MEMBER_LIST_SUFFIX) > sizeof (buf2)) {
		syslog(LOG_ERR, "buffer overflow on property name %s",
		    buf1);
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * buf1 now contains the name of the property if it was found in the
	 * list in the case of delete or the next available property name
	 * in the case of create
	 *
	 * buf2 now contains the member list property name
	 */
	if (scf_transaction_start(tran, pg) == -1) {
		syslog(LOG_ERR, "start transaction for %s failed - %s",
		    pgRefName, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	if (addRemoveFlag == ADD) {
		/*
		 * Create the property 'group name'
		 * This is the container for the group name
		 */
		if (scf_transaction_property_new(tran, entry1, buf1,
		    SCF_TYPE_USTRING) == -1) {
			syslog(LOG_ERR, "transaction property new %s/%s "
			    "failed - %s", pgRefName, buf1,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
		if (scf_value_set_ustring(value, groupName) == -1) {
			syslog(LOG_ERR, "set ustring %s/%s failed - %s",
			    pgRefName, buf1, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
		if (scf_entry_add_value(entry1, value) == -1) {
			syslog(LOG_ERR, "add value %s/%s failed - %s",
			    pgRefName, buf1, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
		/*
		 * Create the property 'group list'
		 * This is the container for the group members
		 */
		if (scf_transaction_property_new(tran, entry2, buf2,
		    SCF_TYPE_USTRING) == -1) {
			syslog(LOG_ERR, "transaction property new %s/%s "
			    "failed - %s", pgRefName, buf2,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
	} else {
		/*
		 * Delete the property 'group name'
		 */
		if (scf_transaction_property_delete(tran, entry1, buf1)
		    == -1) {
			syslog(LOG_ERR,
			    "transaction property delete %s/%s failed - %s",
			    pgRefName, buf1, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
		/*
		 * Delete the property 'group list'
		 */
		if (scf_transaction_property_delete(tran, entry2, buf2)
		    == -1) {
			syslog(LOG_ERR, "transaction property delete %s/%s "
			    "failed - %s", pgRefName, buf2,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
	}

	if (ret != STMF_PS_SUCCESS) {
		goto out;
	}

	if ((commitRet = scf_transaction_commit(tran)) != 1) {
		syslog(LOG_ERR, "transaction commit for %s failed - %s",
		    pgRefName, scf_strerror(scf_error()));
		if (commitRet == 0) {
			ret = STMF_PS_ERROR_BUSY;
		} else {
			ret = STMF_PS_ERROR;
		}
	}

out:
	/*
	 * Free resources
	 */
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}
	if (tran != NULL) {
		scf_transaction_destroy(tran);
	}
	if (entry1 != NULL) {
		scf_entry_destroy(entry1);
	}
	if (entry2 != NULL) {
		scf_entry_destroy(entry2);
	}
	if (prop != NULL) {
		scf_property_destroy(prop);
	}
	if (propIter != NULL) {
		scf_iter_destroy(propIter);
	}
	if (value != NULL) {
		scf_value_destroy(value);
	}

	return (ret);
}

/*
 * iPsGetGroupList
 *
 * pgName - Property group name
 * groupList - pointer to pointer to stmfGroupList structure. On success,
 * contains the list of groups
 *
 * returns:
 *  STMF_PS_SUCCESS on success
 *  STMF_PS_ERROR_* on failure
 */
static int
iPsGetGroupList(char *pgName, stmfGroupList **groupList)
{
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;
	scf_propertygroup_t	*pg = NULL;
	scf_property_t	*prop = NULL;
	scf_iter_t	*propIter = NULL;
	scf_value_t	*value = NULL;
	char buf[MAXNAMELEN];
	int memberCnt = 0;
	int i = 0;
	int ret = STMF_PS_SUCCESS;

	assert(groupList != NULL);

	ret = iPsInit(&handle, &svc);
	if (ret != STMF_PS_SUCCESS) {
		goto out;
	}

	/*
	 * Allocate scf resources
	 */
	if (((pg = scf_pg_create(handle)) == NULL) ||
	    ((prop = scf_property_create(handle)) == NULL) ||
	    ((propIter = scf_iter_create(handle)) == NULL) ||
	    ((value = scf_value_create(handle)) == NULL)) {
		syslog(LOG_ERR, "scf alloc resource failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	if (scf_service_get_pg(svc, pgName, pg) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			syslog(LOG_ERR, "get pg %s failed - %s",
			    pgName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR_NOT_FOUND;
		} else {
			syslog(LOG_ERR, "get pg %s failed - %s",
			    pgName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
		}
		goto out;
	}

	/*
	 * propIter is the iterator handle
	 */
	if (scf_iter_pg_properties(propIter, pg) == -1) {
		syslog(LOG_ERR, "iter properties for %s failed - %s",
		    pgName, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	while (scf_iter_next_property(propIter, prop) == 1) {
		if (scf_property_get_name(prop, buf, sizeof (buf)) == -1) {
			syslog(LOG_ERR, "get name from %s iter failed - %s",
			    pgName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}
		/*
		 * Skip over member list properties
		 */
		if (strstr(buf, STMF_MEMBER_LIST_SUFFIX)) {
			continue;
		}
		memberCnt++;
	}

	/*
	 * propIter is the iterator handle
	 */
	if (scf_iter_pg_properties(propIter, pg) == -1) {
		syslog(LOG_ERR, "iter properties for %s failed - %s",
		    pgName, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	*groupList = (stmfGroupList *)calloc(1, sizeof (stmfGroupList) +
	    memberCnt * sizeof (stmfGroupName));

	if (*groupList == NULL) {
		ret = STMF_PS_ERROR_NOMEM;
		goto out;
	}

	/*
	 * In order to get a list of groups, simply get all of the
	 * properties that are not member list properties, i.e. the group
	 * name properties.
	 * It's possible for this list to grow beyond what was originally
	 * read so just ensure we're not writing beyond our allocated buffer
	 * by ensuring i < memberCnt
	 */
	while ((scf_iter_next_property(propIter, prop) == 1) &&
	    (i < memberCnt)) {
		if (scf_property_get_name(prop, buf, sizeof (buf)) == -1) {
			syslog(LOG_ERR, "get name from %s iter failed - %s",
			    pgName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}
		/*
		 * Skip over member list properties
		 */
		if (strstr(buf, STMF_MEMBER_LIST_SUFFIX)) {
			continue;
		}
		if (scf_property_get_value(prop, value) == -1) {
			syslog(LOG_ERR, "get property value %s/%s failed - %s",
			    pgName, buf, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}
		if (scf_value_get_ustring(value, buf, sizeof (buf)) == -1) {
			syslog(LOG_ERR, "get ustring %s/%s failed - %s",
			    pgName, buf, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}
		bcopy(buf, (*groupList)->name[i++], strlen(buf));
		(*groupList)->cnt++;
	}

	if (ret != STMF_PS_SUCCESS) {
		free(*groupList);
		goto out;
	}

out:
	/*
	 * Free resources
	 */
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}
	if (propIter != NULL) {
		scf_iter_destroy(propIter);
	}
	if (prop != NULL) {
		scf_property_destroy(prop);
	}
	if (value != NULL) {
		scf_value_destroy(value);
	}

	return (ret);
}

/*
 * iPsGetGroupMemberList
 *
 * pgName - Property group name
 * groupName - group name (host group or target group)
 * groupMemberList - pointer to pointer to stmfGroupProperties structure. On
 * success, contains the list of group members
 *
 * returns:
 *  STMF_PS_SUCCESS on success
 *  STMF_PS_ERROR_* on failure
 */
static int
iPsGetGroupMemberList(char *pgName, char *groupName,
    stmfGroupProperties **groupMemberList)
{
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;
	scf_propertygroup_t	*pg = NULL;
	scf_property_t	*prop = NULL;
	scf_value_t	*valueLookup = NULL;
	scf_iter_t	*valueIter = NULL;
	int i = 0;
	int memberCnt;
	int len;
	int ret = STMF_PS_SUCCESS;
	char buf[MAXNAMELEN];

	assert(pgName != NULL && groupName != NULL);

	/*
	 * init the service handle
	 */
	ret = iPsInit(&handle, &svc);
	if (ret != STMF_PS_SUCCESS) {
		goto out;
	}

	/*
	 * Allocate scf resources
	 */
	if (((pg = scf_pg_create(handle)) == NULL) ||
	    ((prop = scf_property_create(handle)) == NULL) ||
	    ((valueIter = scf_iter_create(handle)) == NULL) ||
	    ((valueLookup = scf_value_create(handle)) == NULL)) {
		syslog(LOG_ERR, "scf alloc resource failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * get the service property group handle
	 */
	if (scf_service_get_pg(svc, pgName, pg) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			ret = STMF_PS_ERROR_NOT_FOUND;
		} else {
			ret = STMF_PS_ERROR;
		}
		syslog(LOG_ERR, "get pg %s failed - %s",
		    pgName, scf_strerror(scf_error()));
		goto out;
	}

	/*
	 * Get the property handle
	 * based on the target or host group name
	 */
	if (scf_pg_get_property(pg, groupName, prop) == -1) {
		syslog(LOG_ERR, "get property %s/%s failed - %s",
		    pgName, groupName, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * valueIter is the iterator handle
	 */
	if (scf_iter_property_values(valueIter, prop) == -1) {
		syslog(LOG_ERR, "iter value %s/%s failed - %s",
		    pgName, groupName, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	while (scf_iter_next_value(valueIter, valueLookup) == 1) {
		if (scf_value_get_ustring(valueLookup, buf, MAXNAMELEN) == -1) {
			syslog(LOG_ERR, "iter value %s/%s failed - %s",
			    pgName, groupName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}
		i++;
	}

	/*
	 * valueIter is the iterator handle
	 */
	if (scf_iter_property_values(valueIter, prop) == -1) {
		syslog(LOG_ERR, "iter value %s/%s failed - %s",
		    pgName, groupName, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	memberCnt = i;

	*groupMemberList = (stmfGroupProperties *)calloc(1,
	    sizeof (stmfGroupProperties) + memberCnt * sizeof (stmfDevid));
	if (*groupMemberList == NULL) {
		ret = STMF_PS_ERROR_NOMEM;
		goto out;
	}

	i = 0;
	while ((scf_iter_next_value(valueIter, valueLookup) == 1) &&
	    (i < memberCnt)) {
		if ((len = scf_value_get_ustring(valueLookup, buf, MAXNAMELEN))
		    == -1) {
			syslog(LOG_ERR, "iter value %s/%s failed - %s",
			    pgName, groupName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}
		if (len < sizeof (stmfDevid) - 1) {
			(*groupMemberList)->name[i].identLength = len;
			bcopy(buf,
			    (*groupMemberList)->name[i++].ident, len);
			(*groupMemberList)->cnt++;
		} else {
			ret = STMF_PS_ERROR;
			break;
		}
	}

	if (ret != STMF_PS_SUCCESS) {
		free(*groupMemberList);
		goto out;
	}

out:
	/*
	 * Free resources
	 */
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}
	if (prop != NULL) {
		scf_property_destroy(prop);
	}
	if (valueLookup != NULL) {
		scf_value_destroy(valueLookup);
	}
	if (valueIter != NULL) {
		scf_iter_destroy(valueIter);
	}

	return (ret);
}

int
psGetServicePersist(uint8_t *persistType)
{
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;
	int ret;


	ret = iPsInit(&handle, &svc);
	if (ret != STMF_PS_SUCCESS) {
		return (STMF_PS_ERROR);
	}

	ret = iPsGetSetPersistType(persistType, handle, svc, GET);

	/*
	 * Free resources
	 */
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	return (ret);
}

int
psSetServicePersist(uint8_t persistType)
{
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;
	int ret;


	ret = iPsInit(&handle, &svc);
	if (ret != STMF_PS_SUCCESS) {
		return (STMF_PS_ERROR);
	}

	ret = iPsGetSetPersistType(&persistType, handle, svc, SET);

	/*
	 * Free resources
	 */
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	return (ret);
}

static int
iPsGetSetPersistType(uint8_t *persistType, scf_handle_t *handle,
    scf_service_t *svc, int getSet)
{
	scf_propertygroup_t	*pg = NULL;
	scf_property_t	*prop = NULL;
	scf_value_t	*value = NULL;
	scf_transaction_t *tran = NULL;
	scf_transaction_entry_t *entry = NULL;
	char iPersistTypeGet[MAXNAMELEN] = {0};
	char *iPersistType;
	int ret = STMF_PS_SUCCESS;
	int commitRet;

	if (((pg = scf_pg_create(handle)) == NULL) ||
	    ((prop = scf_property_create(handle)) == NULL) ||
	    ((entry = scf_entry_create(handle)) == NULL) ||
	    ((tran = scf_transaction_create(handle)) == NULL) ||
	    ((value = scf_value_create(handle)) == NULL)) {
		syslog(LOG_ERR, "scf alloc resource failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	if (getSet == GET) {
		/* set to default */
		*persistType = STMF_PERSIST_SMF;
		iPersistType = STMF_PS_PERSIST_SMF;
	}

	if (getSet == SET) {
		if (*persistType == STMF_PERSIST_SMF) {
			iPersistType = STMF_PS_PERSIST_SMF;
		} else if (*persistType == STMF_PERSIST_NONE) {
			iPersistType = STMF_PS_PERSIST_NONE;
		} else {
			ret = STMF_PS_ERROR;
			goto out;
		}
	}

	/*
	 * get stmf data property group
	 */
	if (scf_service_get_pg(svc, STMF_DATA_GROUP, pg) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			ret = STMF_PS_ERROR_NOT_FOUND;
		} else {
			ret = STMF_PS_ERROR;
		}
		syslog(LOG_ERR, "get pg %s failed - %s",
		    STMF_DATA_GROUP, scf_strerror(scf_error()));

		goto out;
	}

	/* find persistence property */
	/*
	 * Get the persistence property
	 */
	if (scf_pg_get_property(pg, STMF_PERSIST_TYPE, prop) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			ret = STMF_PS_ERROR_NOT_FOUND;
		} else {
			syslog(LOG_ERR, "get property %s/%s failed - %s",
			    STMF_DATA_GROUP, STMF_PERSIST_TYPE,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
	}

	/* no persist property found */
	if (ret == STMF_PS_ERROR_NOT_FOUND || getSet == SET) {
		/*
		 * If we have no persistType property, go ahead
		 * and create it with the user specified value or
		 * the default value.
		 */
		/*
		 * Begin the transaction
		 */
		if (scf_transaction_start(tran, pg) == -1) {
			syslog(LOG_ERR, "start transaction for %s failed - %s",
			    STMF_DATA_GROUP, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		/* is this a SET or GET w/error? */
		if (ret) {
			if (scf_transaction_property_new(tran, entry,
			    STMF_PERSIST_TYPE, SCF_TYPE_ASTRING) == -1) {
				syslog(LOG_ERR, "transaction property new "
				    "%s/%s failed - %s", STMF_DATA_GROUP,
				    STMF_PERSIST_TYPE,
				    scf_strerror(scf_error()));
				ret = STMF_PS_ERROR;
				goto out;
			}
		} else {
			if (scf_transaction_property_change(tran, entry,
			    STMF_PERSIST_TYPE, SCF_TYPE_ASTRING) == -1) {
				syslog(LOG_ERR, "transaction property change "
				    "%s/%s failed - %s", STMF_DATA_GROUP,
				    STMF_PERSIST_TYPE,
				    scf_strerror(scf_error()));
				ret = STMF_PS_ERROR;
				goto out;
			}
		}

		/*
		 * set the persist type
		 */
		if (scf_value_set_astring(value, iPersistType) == -1) {
			syslog(LOG_ERR, "set value %s/%s failed - %s",
			    STMF_DATA_GROUP, STMF_PERSIST_TYPE,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		/*
		 * add the value to the transaction
		 */
		if (scf_entry_add_value(entry, value) == -1) {
			syslog(LOG_ERR, "add value %s/%s failed - %s",
			    STMF_DATA_GROUP, STMF_PERSIST_TYPE,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
		if ((commitRet = scf_transaction_commit(tran)) != 1) {
			syslog(LOG_ERR, "transaction commit for %s failed - %s",
			    STMF_DATA_GROUP, scf_strerror(scf_error()));
			if (commitRet == 0) {
				ret = STMF_PS_ERROR_BUSY;
			} else {
				ret = STMF_PS_ERROR;
			}
			goto out;
		}
		/* reset return value */
		ret = STMF_PS_SUCCESS;
	} else if (getSet == GET) {
		/* get the persist property */
		if (scf_property_get_value(prop, value) == -1) {
			syslog(LOG_ERR, "get property value %s/%s failed - %s",
			    STMF_DATA_GROUP, STMF_PERSIST_TYPE,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		/*
		 * Get the value of the persist property
		 */
		if (scf_value_get_astring(value, iPersistTypeGet, MAXNAMELEN)
		    == -1) {
			syslog(LOG_ERR, "get string value %s/%s failed - %s",
			    STMF_DATA_GROUP, STMF_PERSIST_TYPE,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
	}

	if (getSet == GET) {
		if (strcmp(iPersistTypeGet, STMF_PS_PERSIST_NONE) == 0) {
			*persistType = STMF_PERSIST_NONE;
		} else if (strcmp(iPersistTypeGet, STMF_PS_PERSIST_SMF) == 0) {
			*persistType = STMF_PERSIST_SMF;
		} else {
			ret = STMF_PS_ERROR;
			goto out;
		}
	}
out:
	/*
	 * Free resources.
	 * handle and svc should not be free'd here. They're
	 * free'd elsewhere
	 */
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}
	if (prop != NULL) {
		scf_property_destroy(prop);
	}
	if (entry != NULL) {
		scf_entry_destroy(entry);
	}
	if (tran != NULL) {
		scf_transaction_destroy(tran);
	}
	if (value != NULL) {
		scf_value_destroy(value);
	}
	return (ret);
}

int
psSetStmfProp(int propType, char *propVal)
{
	return (iPsGetSetStmfProp(propType, propVal, SET));
}

int
psGetStmfProp(int propType, char *propVal)
{
	return (iPsGetSetStmfProp(propType, propVal, GET));
}

static int
iPsGetSetStmfProp(int propType, char *propVal, int getSet)
{
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;
	scf_property_t *prop = NULL;
	scf_propertygroup_t	*pg = NULL;
	scf_transaction_t *tran = NULL;
	scf_transaction_entry_t *entry = NULL;
	scf_value_t	*value = NULL;
	char *psStmfPropVal = NULL;
	char *psStmfProp = NULL;
	char stmfPropGet[MAXNAMELEN] = {0};
	int ret = STMF_PS_SUCCESS;
	int commitRet;

	if (propVal == NULL || (getSet != GET && getSet != SET)) {
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * Init the service handle
	 */

	ret = iPsInit(&handle, &svc);
	if (ret != STMF_PS_SUCCESS) {
		goto out;
	}

	/*
	 * Allocate scf resources
	 */

	if (((pg = scf_pg_create(handle)) == NULL) ||
	    ((prop = scf_property_create(handle)) == NULL) ||
	    ((entry = scf_entry_create(handle)) == NULL) ||
	    ((tran = scf_transaction_create(handle)) == NULL) ||
	    ((value = scf_value_create(handle)) == NULL)) {
		syslog(LOG_ERR, "scf alloc resource failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}
	if (getSet == GET) {
		switch (propType) {
			case STMF_DEFAULT_LU_STATE :
				psStmfProp = DEFAULT_LU_STATE;
				psStmfPropVal = STMF_PS_LU_ONLINE;
				(void) strcpy(stmfPropGet, psStmfPropVal);
				break;
			case STMF_DEFAULT_TARGET_PORT_STATE :
				psStmfProp = DEFAULT_TARGET_PORT_STATE;
				psStmfPropVal = STMF_PS_TARGET_PORT_ONLINE;
				(void) strcpy(stmfPropGet, psStmfPropVal);
				break;
			default :
				ret = STMF_PS_ERROR;
				goto out;
		}
	}
	if (getSet == SET) {
		switch (propType) {
			case STMF_DEFAULT_LU_STATE :
				psStmfProp = DEFAULT_LU_STATE;
				if (strcasecmp(propVal, "online") == 0) {
					psStmfPropVal = STMF_PS_LU_ONLINE;
				} else if (strcasecmp(propVal,
				    "offline") == 0) {
					psStmfPropVal = STMF_PS_LU_OFFLINE;
				} else {
					ret = STMF_PS_ERROR;
					goto out;
				}
				break;
			case STMF_DEFAULT_TARGET_PORT_STATE :
				psStmfProp = DEFAULT_TARGET_PORT_STATE;
				if (strcasecmp(propVal, "online") == 0) {
					psStmfPropVal =
					    STMF_PS_TARGET_PORT_ONLINE;
				} else if (strcasecmp(propVal,
				    "offline") == 0) {
					psStmfPropVal =
					    STMF_PS_TARGET_PORT_OFFLINE;
				} else {
					ret = STMF_PS_ERROR;
					goto out;
				}
				break;
			default :
				ret = STMF_PS_ERROR;
				goto out;
		}
	}

	/*
	 * get stmf data property group
	 */

	if (scf_service_get_pg(svc, STMF_DATA_GROUP, pg) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			ret = STMF_PS_ERROR_NOT_FOUND;
		} else {
			ret = STMF_PS_ERROR;
		}
		syslog(LOG_ERR, "get pg %s failed - %s",
		    STMF_DATA_GROUP, scf_strerror(scf_error()));
		goto out;
	}

	/*
	 * get the stmf props property, if exists
	 */

	if (scf_pg_get_property(pg, psStmfProp, prop) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			ret = STMF_PS_ERROR_NOT_FOUND;
		} else {
			syslog(LOG_ERR, "start transaction for %s/%s "
			    "failed - %s", STMF_DATA_GROUP, psStmfProp,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
	}

	/* if stmf prop is not found or while setting the prop */

	if (ret == STMF_PS_ERROR_NOT_FOUND || getSet == SET) {
		/*
		 * Begin the transaction
		 */
		if (scf_transaction_start(tran, pg) == -1) {
			syslog(LOG_ERR, "start transaction for %s failed - %s",
			    STMF_DATA_GROUP, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
		if (ret) {
			if (scf_transaction_property_new(tran, entry,
			    psStmfProp, SCF_TYPE_ASTRING) == -1) {
				syslog(LOG_ERR, "transaction property new "
				    "%s/%s failed - %s", STMF_DATA_GROUP,
				    psStmfProp, scf_strerror(scf_error()));
				ret = STMF_PS_ERROR;
				goto out;
			}
		} else {
			if (scf_transaction_property_change(tran, entry,
			    psStmfProp, SCF_TYPE_ASTRING) == -1) {
					syslog(LOG_ERR,
					    "transaction property change "
					    "%s/%s failed - %s",
					    STMF_DATA_GROUP, psStmfProp,
					    scf_strerror(scf_error()));
					ret = STMF_PS_ERROR;
					goto out;
			}
		}

		/*
		 * set stmf prop value
		 */

		if (scf_value_set_astring(value, psStmfPropVal) == -1) {
			syslog(LOG_ERR, "set value %s/%s failed - %s",
			    STMF_DATA_GROUP, psStmfProp,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		/*
		 * add the value to the transaction
		 */

		if (scf_entry_add_value(entry, value) == -1) {
			syslog(LOG_ERR, "add value %s/%s failed - %s",
			    STMF_DATA_GROUP, psStmfProp,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
		if ((commitRet = scf_transaction_commit(tran)) != 1) {
			syslog(LOG_ERR, "transaction commit for %s"
			    "failed - %s", STMF_DATA_GROUP,
			    scf_strerror(scf_error()));
			if (commitRet == 0) {
				ret = STMF_PS_ERROR_BUSY;
			} else {
				ret = STMF_PS_ERROR;
			}
			goto out;
		}
		ret = STMF_PS_SUCCESS;
	} else if (getSet == GET) {
		if (scf_property_get_value(prop, value) == -1) {
			syslog(LOG_ERR, "get property value "
			    "%s/%s failed - %s",
			    STMF_DATA_GROUP, psStmfProp,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		/* get stmfProp */

		if (scf_value_get_astring(value, stmfPropGet, MAXNAMELEN)
		    == -1) {
			syslog(LOG_ERR, "get string value %s/%s failed - %s",
			    STMF_DATA_GROUP, psStmfProp,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
	}
	if (getSet == GET) {
		if (strcmp(stmfPropGet, STMF_PS_LU_ONLINE) == 0) {
			(void) strcpy(propVal, "online");
		} else if (strcmp(stmfPropGet, STMF_PS_LU_OFFLINE) == 0) {
			(void) strcpy(propVal, "offline");
		} else if (strcmp(stmfPropGet, STMF_PS_TARGET_PORT_ONLINE)
		    == 0) {
			(void) strcpy(propVal, "online");
		} else if (strcmp(stmfPropGet, STMF_PS_TARGET_PORT_OFFLINE)
		    == 0) {
			(void) strcpy(propVal, "offline");
		} else {
			ret = STMF_PS_ERROR;
			goto out;
		}
	}
out:
	/*
	 * Free resources.
	 */

	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}
	if (prop != NULL) {
		scf_property_destroy(prop);
	}
	if (entry != NULL) {
		scf_entry_destroy(entry);
	}
	if (tran != NULL) {
		scf_transaction_destroy(tran);
	}
	if (value != NULL) {
		scf_value_destroy(value);
	}
	return (ret);
}

/*
 * Initialize scf stmf service access
 * handle - returned handle
 * service - returned service handle
 *
 * Both handle and service must be destroyed by the caller
 */
static int
iPsInit(scf_handle_t **handle, scf_service_t **service)
{
	scf_scope_t	*scope = NULL;
	uint64_t version;
	int ret;

	assert(handle != NULL && service != NULL);

	if ((*handle = scf_handle_create(SCF_VERSION)) == NULL) {
		syslog(LOG_ERR, "scf_handle_create failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto err;
	}

	if (scf_handle_bind(*handle) == -1) {
		syslog(LOG_ERR, "scf_handle_bind failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto err;
	}

	if ((*service = scf_service_create(*handle)) == NULL) {
		syslog(LOG_ERR, "scf_service_create failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto err;
	}

	if ((scope = scf_scope_create(*handle)) == NULL) {
		syslog(LOG_ERR, "scf_scope_create failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto err;
	}

	if (scf_handle_get_scope(*handle, SCF_SCOPE_LOCAL, scope) == -1) {
		syslog(LOG_ERR, "scf_handle_get_scope failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto err;
	}

	if (scf_scope_get_service(scope, STMF_SERVICE, *service) == -1) {
		syslog(LOG_ERR, "scf_scope_get_service failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR_SERVICE_NOT_FOUND;
		goto err;
	}


	/*
	 * Get and check the version number
	 */
	ret = iPsGetServiceVersion(&version, *handle, *service);
	if (ret != STMF_PS_SUCCESS) {
		goto err;
	}

	if (version != STMF_SMF_VERSION) {
		ret = STMF_PS_ERROR_VERSION_MISMATCH;
		goto err;
	}

	/* we only need destroy the scope here */
	scf_scope_destroy(scope);

	return (STMF_PS_SUCCESS);

err:
	if (*handle != NULL) {
		scf_handle_destroy(*handle);
	}
	if (*service != NULL) {
		scf_service_destroy(*service);
		*service = NULL;
	}
	if (scope != NULL) {
		scf_scope_destroy(scope);
	}
	return (ret);
}


/*
 * called by iPsInit only
 * iPsGetServiceVersion
 */
static int
iPsGetServiceVersion(uint64_t *version, scf_handle_t *handle,
    scf_service_t *svc)
{
	scf_propertygroup_t	*pg = NULL;
	scf_property_t	*prop = NULL;
	scf_value_t	*value = NULL;
	scf_transaction_t *tran = NULL;
	scf_transaction_entry_t *entry = NULL;
	int ret = STMF_PS_SUCCESS;
	int commitRet;

	if (((pg = scf_pg_create(handle)) == NULL) ||
	    ((prop = scf_property_create(handle)) == NULL) ||
	    ((entry = scf_entry_create(handle)) == NULL) ||
	    ((tran = scf_transaction_create(handle)) == NULL) ||
	    ((value = scf_value_create(handle)) == NULL)) {
		syslog(LOG_ERR, "scf alloc resource failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	*version = STMF_SMF_VERSION;

	/*
	 * get stmf data property group
	 */
	if (scf_service_get_pg(svc, STMF_DATA_GROUP, pg) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			ret = STMF_PS_ERROR_NOT_FOUND;
		} else {
			syslog(LOG_ERR, "get pg %s failed - %s",
			    STMF_DATA_GROUP, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
	}

	/* create the group */
	if (ret == STMF_PS_ERROR_NOT_FOUND) {
		/*
		 * create the property group.
		 */
		if (scf_service_add_pg(svc, STMF_DATA_GROUP,
		    SCF_GROUP_APPLICATION, 0, pg) == -1) {
			syslog(LOG_ERR, "add pg %s failed - %s",
			    STMF_DATA_GROUP, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
		/* reset return value */
		ret = STMF_PS_SUCCESS;
	}

	/* find version property */
	/*
	 * Get the version property
	 */
	if (scf_pg_get_property(pg, STMF_VERSION_NAME, prop) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			ret = STMF_PS_ERROR_NOT_FOUND;
		} else {
			syslog(LOG_ERR, "get property %s/%s failed - %s",
			    STMF_DATA_GROUP, STMF_VERSION_NAME,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
	}

	/* no version property found */
	if (ret == STMF_PS_ERROR_NOT_FOUND) {
		/*
		 * If we have no version property, go ahead
		 * and create it. We're obviously making an assumption
		 * here that someone did not delete the existing property
		 * and that this is the initial set and the initial call
		 * to iPsInit.
		 * If they did delete it, this will simply plant this
		 * library's version on this service. That may or may not be
		 * correct and we have no way of determining that.
		 */
		/*
		 * Begin the transaction
		 */
		if (scf_transaction_start(tran, pg) == -1) {
			syslog(LOG_ERR, "start transaction for %s failed - %s",
			    STMF_DATA_GROUP, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		if (scf_transaction_property_new(tran, entry,
		    STMF_VERSION_NAME, SCF_TYPE_COUNT) == -1) {
			syslog(LOG_ERR,
			    "transaction property new %s/%s failed - %s",
			    STMF_DATA_GROUP, STMF_VERSION_NAME,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		/*
		 * set the version number
		 */
		scf_value_set_count(value, *version);

		/*
		 * add the value to the transaction
		 */
		if (scf_entry_add_value(entry, value) == -1) {
			syslog(LOG_ERR, "add value %s/%s failed - %s",
			    STMF_DATA_GROUP, STMF_VERSION_NAME,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
		if ((commitRet = scf_transaction_commit(tran)) != 1) {
			syslog(LOG_ERR, "transaction commit for %s failed - %s",
			    STMF_DATA_GROUP, scf_strerror(scf_error()));
			if (commitRet == 0) {
				ret = STMF_PS_ERROR_BUSY;
			} else {
				ret = STMF_PS_ERROR;
			}
			goto out;
		}
		/* reset return value */
		ret = STMF_PS_SUCCESS;
	} else {
		/* get the version property */
		if (scf_pg_get_property(pg, STMF_VERSION_NAME, prop) == -1) {
			syslog(LOG_ERR, "get property %s/%s failed - %s",
			    STMF_DATA_GROUP, STMF_VERSION_NAME,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		if (scf_property_get_value(prop, value) == -1) {
			syslog(LOG_ERR, "get property value %s/%s failed - %s",
			    STMF_DATA_GROUP, STMF_VERSION_NAME,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		/*
		 * Get the actual value of the view entry count property
		 */
		if (scf_value_get_count(value, version) == -1) {
			syslog(LOG_ERR, "get count value %s/%s failed - %s",
			    STMF_DATA_GROUP, STMF_VERSION_NAME,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
	}

out:
	/*
	 * Free resources.
	 * handle and svc should not be free'd here. They're
	 * free'd elsewhere
	 */
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}
	if (prop != NULL) {
		scf_property_destroy(prop);
	}
	if (entry != NULL) {
		scf_entry_destroy(entry);
	}
	if (tran != NULL) {
		scf_transaction_destroy(tran);
	}
	if (value != NULL) {
		scf_value_destroy(value);
	}
	return (ret);
}



/*
 * iPsGetActualGroupName
 *
 * pgName - Property group name
 * groupName - requested group name
 * actualName - actual group name to reference (len must be >= MAXNAMELEN)
 *
 * returns:
 *  STMF_PS_SUCCESS on success
 *  STMF_PS_ERROR_* on failure
 */
static int
iPsGetActualGroupName(char *pgName, char *groupName, char *actualName)
{
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;
	scf_propertygroup_t	*pg = NULL;
	scf_property_t	*prop = NULL;
	scf_iter_t	*propIter = NULL;
	scf_value_t	*value = NULL;
	char buf[MAXNAMELEN];
	int ret;

	ret = iPsInit(&handle, &svc);
	if (ret != STMF_PS_SUCCESS) {
		goto out;
	}

	/*
	 * Allocate scf resources
	 */
	if (((pg = scf_pg_create(handle)) == NULL) ||
	    ((prop = scf_property_create(handle)) == NULL) ||
	    ((propIter = scf_iter_create(handle)) == NULL) ||
	    ((value = scf_value_create(handle)) == NULL)) {
		syslog(LOG_ERR, "scf alloc resource failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * get group list property group
	 */
	if (scf_service_get_pg(svc, pgName, pg) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			ret = STMF_PS_ERROR_GROUP_NOT_FOUND;
		} else {
			syslog(LOG_ERR, "get pg %s failed - %s",
			    pgName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
		}
		goto out;
	}

	/*
	 * propIter is the iterator handle
	 */
	if (scf_iter_pg_properties(propIter, pg) == -1) {
		syslog(LOG_ERR, "iter properties for %s failed - %s",
		    pgName, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * Iterate through group properties searching for the requested
	 * group name. When we find it, we need to get the property name
	 * since it refers to the actual group name.
	 */

	/* initialize to not found */
	ret = STMF_PS_ERROR_GROUP_NOT_FOUND;
	while (scf_iter_next_property(propIter, prop) == 1) {
		if (scf_property_get_name(prop, actualName, MAXNAMELEN) == -1) {
			syslog(LOG_ERR, "get name from %s iter failed - %s",
			    pgName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}
		/*
		 * Skip over non-member list properties
		 */
		if (strstr(actualName, STMF_MEMBER_LIST_SUFFIX)) {
			continue;
		}
		if (scf_property_get_value(prop, value) == -1) {
			syslog(LOG_ERR, "get property value %s/%s failed - %s",
			    pgName, actualName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}
		if (scf_value_get_ustring(value, buf, sizeof (buf)) == -1) {
			syslog(LOG_ERR, "get ustring %s/%s failed - %s",
			    pgName, actualName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}

		/*
		 * When we find a match, set success and break
		 */
		if ((strlen(buf) == strlen(groupName)) &&
		    bcmp(buf, groupName, strlen(buf)) == 0) {
			ret = STMF_PS_SUCCESS;
			break;
		}
	}

	/*
	 * if we didn't find it, ret is set to STMF_PS_ERROR_GROUP_NOT_FOUND
	 */

out:
	/*
	 * Free resources
	 */
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}
	if (propIter != NULL) {
		scf_iter_destroy(propIter);
	}
	if (prop != NULL) {
		scf_property_destroy(prop);
	}
	if (value != NULL) {
		scf_value_destroy(value);
	}

	return (ret);
}

/*
 * psAddHostGroupMember
 *
 * Add a host group member to a host group,
 *
 * Input: groupName - name of group to which the member is added
 *        memberName - name of group member to add
 */
int
psAddHostGroupMember(char *groupName, char *memberName)
{
	int ret;
	char groupPropListName[MAXNAMELEN];
	char groupPropName[MAXNAMELEN];

	ret = iPsGetActualGroupName(STMF_HOST_GROUPS, groupName,
	    groupPropName);
	if (ret != STMF_PS_SUCCESS) {
		return (ret);
	}

	if (snprintf(groupPropListName, sizeof (groupPropListName),
	    "%s-%s", groupPropName, STMF_MEMBER_LIST_SUFFIX) >
	    sizeof (groupPropListName)) {
		syslog(LOG_ERR, "buffer overflow on property name %s",
		    groupPropName);
		return (STMF_PS_ERROR);
	}

	return (iPsAddRemoveGroupMember(STMF_HOST_GROUPS, groupPropListName,
	    memberName, ADD));
}

/*
 * psAddTargetGroupMember
 *
 * Add a target port group member to a target group
 *
 * Input: groupName - name of group to which the member is added
 *        memberName - name of group member to add. Must be nul terminated.
 */
int
psAddTargetGroupMember(char *groupName, char *memberName)
{
	int ret;
	char groupPropListName[MAXNAMELEN];
	char groupPropName[MAXNAMELEN];

	ret = iPsGetActualGroupName(STMF_TARGET_GROUPS, groupName,
	    groupPropName);
	if (ret != STMF_PS_SUCCESS) {
		return (ret);
	}

	if (snprintf(groupPropListName, sizeof (groupPropListName),
	    "%s-%s", groupPropName, STMF_MEMBER_LIST_SUFFIX) >
	    sizeof (groupPropListName)) {
		syslog(LOG_ERR, "buffer overflow on property name %s",
		    groupPropName);
		return (STMF_PS_ERROR);
	}

	return (iPsAddRemoveGroupMember(STMF_TARGET_GROUPS, groupPropListName,
	    memberName, ADD));
}


/*
 * psAddViewEntry
 *
 * luGuid - logical unit identifier
 * viewEntry - pointer to viewEntry allocated by the caller that contains
 *             the values to set for this view entry
 *
 * returns:
 *  STMF_PS_SUCCESS on success
 *  STMF_PS_ERROR_* on failure
 */
int
psAddViewEntry(stmfGuid *lu, stmfViewEntry *viewEntry)
{
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;
	scf_propertygroup_t	*pg = NULL;
	char guidAsciiBuf[33]; /* size of ascii hex 16 byte guid with NULL */
	char viewEntryPgName[VIEW_ENTRY_PG_SIZE];
	char scfLuPgName[LOGICAL_UNIT_PG_SIZE];
	int ret = STMF_PS_SUCCESS;
	sigset_t sigmaskRestore;

	/* grab the signal hold lock */
	(void) pthread_mutex_lock(&sigSetLock);

	/*
	 * hold signals until we're done
	 */
	if (holdSignal(&sigmaskRestore) != 0) {
		(void) pthread_mutex_unlock(&sigSetLock);
		return (STMF_PS_ERROR);
	}

	ret = iPsInit(&handle, &svc);
	if (ret != STMF_PS_SUCCESS) {
		goto out;
	}

	pg = scf_pg_create(handle);
	if (pg == NULL) {
		syslog(LOG_ERR, "scf pg alloc failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/* Convert to ASCII uppercase hexadecimal string */
	(void) snprintf(guidAsciiBuf, sizeof (guidAsciiBuf),
	    "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
	    lu->guid[0], lu->guid[1], lu->guid[2], lu->guid[3], lu->guid[4],
	    lu->guid[5], lu->guid[6], lu->guid[7], lu->guid[8], lu->guid[9],
	    lu->guid[10], lu->guid[11], lu->guid[12], lu->guid[13],
	    lu->guid[14], lu->guid[15]);

	(void) snprintf(scfLuPgName, sizeof (scfLuPgName), "%s-%s",
	    STMF_LU_PREFIX, guidAsciiBuf);

	bzero(viewEntryPgName, sizeof (viewEntryPgName));
	/*
	 * Format of view entry property group name:
	 *	VE-<view_entry_name>-<lu_name>
	 */
	(void) snprintf(viewEntryPgName, sizeof (viewEntryPgName),
	    "%s-%d-%s", STMF_VE_PREFIX, viewEntry->veIndex, guidAsciiBuf);

	ret = iPsAddViewEntry(scfLuPgName, viewEntryPgName, viewEntry);

out:
	/*
	 * Okay, we're done. Release the signals
	 */
	if (releaseSignal(&sigmaskRestore) != 0) {
		/*
		 * Don't set this as an STMF_PS_ERROR_*. We succeeded
		 * the requested operation. But we do need to log it.
		 */
		syslog(LOG_ERR, "Unable to release one or more signals - %s",
		    strerror(errno));
	}

	/*
	 * Free resources
	 */
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}

	/* release the signal hold lock */
	(void) pthread_mutex_unlock(&sigSetLock);

	return (ret);
}

/*
 * psCheckService
 *
 * Purpose: Checks whether service exists
 *
 */
int
psCheckService()
{
	int ret;
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;

	ret = iPsInit(&handle, &svc);

	/*
	 * Free resources
	 */
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}

	return (ret);
}

/*
 * psCreateHostGroup
 *
 * groupName - name of group to create
 *
 * returns:
 *  STMF_PS_SUCCESS on success
 *  STMF_PS_ERROR_* on failure
 */
int
psCreateHostGroup(char *groupName)
{
	return (iPsCreateDeleteGroup(STMF_HOST_GROUPS, groupName, ADD));
}

/*
 * psCreateTargetGroup
 *
 * groupName - name of group to create
 *
 * returns:
 *  STMF_PS_SUCCESS on success
 *  STMF_PS_ERROR_* on failure
 */
int
psCreateTargetGroup(char *groupName)
{
	return (iPsCreateDeleteGroup(STMF_TARGET_GROUPS, groupName, ADD));
}

/*
 * psDeleteHostGroup
 *
 * groupName - name of group to delete
 *
 * returns:
 *  STMF_PS_SUCCESS on success
 *  STMF_PS_ERROR_* on failure
 */
int
psDeleteHostGroup(char *groupName)
{
	return (iPsCreateDeleteGroup(STMF_HOST_GROUPS, groupName, REMOVE));
}

/*
 * psDeleteTargetGroup
 *
 * groupName - name of group to delete
 *
 * returns:
 *  STMF_PS_SUCCESS on success
 *  STMF_PS_ERROR_* on failure
 */
int
psDeleteTargetGroup(char *groupName)
{
	return (iPsCreateDeleteGroup(STMF_TARGET_GROUPS, groupName,
	    REMOVE));
}

/*
 * psGetHostGroupList
 *
 * groupList - pointer to pointer to stmfGroupList. Contains the list
 *             of host groups on successful return.
 *
 * returns:
 *  STMF_PS_SUCCESS on success
 *  STMF_PS_ERROR_* on failure
 */
int
psGetHostGroupList(stmfGroupList **groupList)
{
	return (iPsGetGroupList(STMF_HOST_GROUPS, groupList));
}

/*
 * psGetLogicalUnitList
 *
 *
 */
int
psGetLogicalUnitList(stmfGuidList **guidList)
{
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;
	scf_propertygroup_t	*pg = NULL;
	scf_iter_t	*pgIter = NULL;
	char buf[MAXNAMELEN];
	int guidCnt = 0;
	int i = 0, j;
	int ret = STMF_PS_SUCCESS;
	unsigned int guid[sizeof (stmfGuid)];
	stmfGuid outGuid;

	assert(guidList != NULL);

	ret = iPsInit(&handle, &svc);
	if (ret != STMF_PS_SUCCESS) {
		goto out;
	}

	/*
	 * Allocate scf resources
	 */
	if (((pg = scf_pg_create(handle)) == NULL) ||
	    ((pgIter = scf_iter_create(handle)) == NULL)) {
		syslog(LOG_ERR, "scf alloc resource failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * pgIter is the iterator handle
	 */
	if (scf_iter_service_pgs(pgIter, svc) == -1) {
		syslog(LOG_ERR, "iter property groups failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	while (scf_iter_next_pg(pgIter, pg) == 1) {
		if (scf_pg_get_name(pg, buf, sizeof (buf)) == -1) {
			syslog(LOG_ERR, "get pg name failed - %s",
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}
		/*
		 * Only count LU property groups
		 */
		if (strncmp(buf, STMF_LU_PREFIX, strlen(STMF_LU_PREFIX)) == 0) {
			guidCnt++;
		}
	}

	/*
	 * pgIter is the iterator handle
	 */
	if (scf_iter_service_pgs(pgIter, svc) == -1) {
		syslog(LOG_ERR, "iter property groups failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	*guidList = (stmfGuidList *)calloc(1, sizeof (stmfGuidList) +
	    guidCnt * sizeof (stmfGuid));
	if (*guidList == NULL) {
		ret = STMF_PS_ERROR_NOMEM;
		goto out;
	}

	/*
	 * it's possible for entries to be added/removed while we're retrieving
	 * the property groups. Just make sure we don't write beyond our
	 * allocated buffer by checking to ensure i < guidCnt.
	 */
	while ((scf_iter_next_pg(pgIter, pg) == 1) && (i < guidCnt)) {
		if (scf_pg_get_name(pg, buf, sizeof (buf)) == -1) {
			syslog(LOG_ERR, "get pg name failed - %s",
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}
		/*
		 * Only use LU property groups
		 */
		if (strncmp(buf, STMF_LU_PREFIX, strlen(STMF_LU_PREFIX)) != 0) {
			continue;
		}

		j = strlen(STMF_LU_PREFIX) + strlen("-");

		(void) sscanf(buf + j,
		    "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
		    &guid[0], &guid[1], &guid[2], &guid[3], &guid[4], &guid[5],
		    &guid[6], &guid[7], &guid[8], &guid[9], &guid[10],
		    &guid[11], &guid[12], &guid[13], &guid[14], &guid[15]);

		for (j = 0; j < sizeof (stmfGuid); j++) {
			outGuid.guid[j] = guid[j];
		}

		bcopy(&outGuid, (*guidList)->guid[i++].guid, sizeof (stmfGuid));
		(*guidList)->cnt++;
	}

	if (ret != STMF_PS_SUCCESS) {
		free(*guidList);
		goto out;
	}

out:
	/*
	 * Free resources
	 */
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}
	if (pgIter != NULL) {
		scf_iter_destroy(pgIter);
	}

	return (ret);
}

/*
 * psGetTargetGroupList
 *
 * groupList - pointer to pointer to stmfGroupList. Contains the list
 *             of target groups on successful return.
 *
 * returns:
 *  STMF_PS_SUCCESS on success
 *  STMF_PS_ERROR_* on failure
 */
int
psGetTargetGroupList(stmfGroupList **groupList)
{
	return (iPsGetGroupList(STMF_TARGET_GROUPS, groupList));
}

/*
 * psGetHostGroupMemberList
 *
 * groupName - group name for which to retrieve a member list
 * groupMemberList - pointer to pointer to stmfGroupProperties list
 *
 * returns:
 *  STMF_PS_SUCCESS on success
 *  STMF_PS_ERROR_* on failure
 */
int
psGetHostGroupMemberList(char *groupName, stmfGroupProperties **groupMemberList)
{
	int ret;
	char groupPropListName[MAXNAMELEN];
	char groupPropName[MAXNAMELEN];

	ret = iPsGetActualGroupName(STMF_HOST_GROUPS, groupName,
	    groupPropName);
	if (ret != STMF_PS_SUCCESS) {
		return (ret);
	}

	if (snprintf(groupPropListName, sizeof (groupPropListName),
	    "%s-%s", groupPropName, STMF_MEMBER_LIST_SUFFIX) >
	    sizeof (groupPropListName)) {
		syslog(LOG_ERR, "buffer overflow on property name %s",
		    groupPropName);
		return (STMF_PS_ERROR);
	}

	return (iPsGetGroupMemberList(STMF_HOST_GROUPS, groupPropListName,
	    groupMemberList));
}

/*
 * psGetTargetGroupMemberList
 *
 * groupName - group name for which to retrieve a member list
 * groupMemberList - pointer to pointer to stmfGroupProperties list
 *
 * returns:
 *  STMF_PS_SUCCESS on success
 *  STMF_PS_ERROR_* on failure
 */
int
psGetTargetGroupMemberList(char *groupName,
    stmfGroupProperties **groupMemberList)
{
	int ret;
	char groupPropListName[MAXNAMELEN];
	char groupPropName[MAXNAMELEN];

	ret = iPsGetActualGroupName(STMF_TARGET_GROUPS, groupName,
	    groupPropName);
	if (ret != STMF_PS_SUCCESS) {
		return (ret);
	}

	if (snprintf(groupPropListName, sizeof (groupPropListName),
	    "%s-%s", groupPropName, STMF_MEMBER_LIST_SUFFIX) >
	    sizeof (groupPropListName)) {
		syslog(LOG_ERR, "buffer overflow on property name %s",
		    groupPropName);
		return (STMF_PS_ERROR);
	}

	return (iPsGetGroupMemberList(STMF_TARGET_GROUPS,
	    groupPropListName, groupMemberList));
}

/*
 * qsort function
 * sort on veIndex
 */
static int
viewEntryCompare(const void *p1, const void *p2)
{

	stmfViewEntry *v1 = (stmfViewEntry *)p1, *v2 = (stmfViewEntry *)p2;
	if (v1->veIndex > v2->veIndex)
		return (1);
	if (v1->veIndex < v2->veIndex)
		return (-1);
	return (0);
}

/*
 * psGetViewEntryList
 *
 * luGuid - identifier of logical unit for which to retrieve a view entry list
 * viewEntryList - pointer to pointer to stmfViewEntryList. It will be allocated
 *                 on successful return.
 *
 * returns:
 *  STMF_PS_SUCCESS on success
 *  STMF_PS_ERROR_* on failure
 */
int
psGetViewEntryList(stmfGuid *lu, stmfViewEntryList **viewEntryList)
{
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;
	scf_propertygroup_t	*pg = NULL;
	scf_property_t	*prop = NULL;
	scf_value_t *value = NULL;
	scf_iter_t  *propIter = NULL;
	char guidAsciiBuf[33]; /* size of ascii hex 16 byte guid with NULL */
	char viewEntryPgName[VIEW_ENTRY_PG_SIZE];
	char luPgName[LOGICAL_UNIT_PG_SIZE];
	int ret = STMF_PS_SUCCESS;
	uint64_t i = 0;
	uint64_t veCnt;


	ret = iPsInit(&handle, &svc);
	if (ret != STMF_PS_SUCCESS) {
		goto out;
	}

	/*
	 * Allocate scf resources
	 */
	if (((pg = scf_pg_create(handle)) == NULL) ||
	    ((prop = scf_property_create(handle)) == NULL) ||
	    ((propIter = scf_iter_create(handle)) == NULL) ||
	    ((value = scf_value_create(handle)) == NULL)) {
		syslog(LOG_ERR, "scf alloc resource failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/* Convert to ASCII uppercase hexadecimal string */
	(void) snprintf(guidAsciiBuf, sizeof (guidAsciiBuf),
	    "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
	    lu->guid[0], lu->guid[1], lu->guid[2], lu->guid[3], lu->guid[4],
	    lu->guid[5], lu->guid[6], lu->guid[7], lu->guid[8], lu->guid[9],
	    lu->guid[10], lu->guid[11], lu->guid[12], lu->guid[13],
	    lu->guid[14], lu->guid[15]);

	/* form the LU property group name (LU-<guid>) */
	(void) snprintf(luPgName, sizeof (luPgName), "%s-%s",
	    STMF_LU_PREFIX, guidAsciiBuf);

	/* get the property group associated with this LU */
	if (scf_service_get_pg(svc, luPgName, pg) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			ret = STMF_PS_ERROR_NOT_FOUND;
		} else {
			syslog(LOG_ERR, "get pg %s failed - %s",
			    luPgName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
		}
		goto out;
	}

	/* get the view entry count property */
	if (scf_pg_get_property(pg, STMF_VE_CNT, prop) == -1) {
		syslog(LOG_ERR, "get property %s/%s failed - %s",
		    luPgName, STMF_VE_CNT, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	if (scf_property_get_value(prop, value) == -1) {
		syslog(LOG_ERR, "get property value %s/%s failed - %s",
		    luPgName, STMF_VE_CNT, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * Get the actual value of the view entry count property
	 */
	if (scf_value_get_count(value, &veCnt) == -1) {
		syslog(LOG_ERR, "get integer value %s/%s failed - %s",
		    luPgName, STMF_VE_CNT, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * propIter is the iterator handle
	 */
	if (scf_iter_pg_properties(propIter, pg) == -1) {
		syslog(LOG_ERR, "iter properties for %s failed - %s",
		    luPgName, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * alloc the list based on the view entry count
	 */
	*viewEntryList = (stmfViewEntryList *)calloc(1,
	    sizeof (stmfViewEntryList) + veCnt * sizeof (stmfViewEntry));
	if (*viewEntryList == NULL) {
		ret = STMF_PS_ERROR_NOMEM;
		goto out;
	}

	i = 0;
	/*
	 * iterate through the view entry properties to find the
	 * view entries
	 */
	while (scf_iter_next_property(propIter, prop) == 1) {
		/* find match for view entry property */
		if (scf_property_get_name(prop, viewEntryPgName,
		    sizeof (viewEntryPgName)) != -1) {
			if (strncmp(viewEntryPgName, STMF_VE_PREFIX,
			    strlen(STMF_VE_PREFIX)) != 0) {
				continue;
			}
			/*
			 * We've exceeded our alloc limit
			 * break with error
			 */
			if (i == veCnt) {
				ret = STMF_PS_ERROR;
				break;
			}

			if ((ret = iPsGetViewEntry(viewEntryPgName,
			    &((*viewEntryList)->ve[i]))) != STMF_PS_SUCCESS) {
				break;
			}

			i++;

			/* set the list count */
			(*viewEntryList)->cnt++;
		} else {
			syslog(LOG_ERR, "scf iter %s properties failed - %s",
			    luPgName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}

	}

	if (ret != STMF_PS_SUCCESS) {
		free(*viewEntryList);
		goto out;
	}

	/*
	 * We're sorting the final list here based on the veIndex
	 * If we don't, the caller is going to have to do it to reap
	 * some intelligent output.
	 */
	qsort((void *)&((*viewEntryList)->ve[0]), (*viewEntryList)->cnt,
	    sizeof (stmfViewEntry), viewEntryCompare);

out:
	/*
	 * Free resources
	 */
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}
	if (prop != NULL) {
		scf_property_destroy(prop);
	}
	if (value != NULL) {
		scf_value_destroy(value);
	}
	if (propIter != NULL) {
		scf_iter_destroy(propIter);
	}

	return (ret);
}

/*
 * iPsGetViewEntry
 *
 * viewEntryPgName - view entry property group name to retrieve
 * viewEntry - pointer to stmfViewEntry structure allocated by the caller
 *
 * returns:
 *  STMF_PS_SUCCESS on success
 *  STMF_PS_ERROR_* on failure
 */
static int
iPsGetViewEntry(char *viewEntryPgName, stmfViewEntry *viewEntry)
{
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;
	scf_propertygroup_t	*pg = NULL;
	scf_property_t	*prop = NULL;
	scf_value_t *value = NULL;
	uint8_t scfBool;
	char *indexPtr;
	char groupName[sizeof (stmfGroupName)];
	int ret = STMF_PS_SUCCESS;


	ret = iPsInit(&handle, &svc);
	if (ret != STMF_PS_SUCCESS) {
		goto out;
	}

	/*
	 * Allocate scf resources
	 */
	if (((pg = scf_pg_create(handle)) == NULL) ||
	    ((prop = scf_property_create(handle)) == NULL) ||
	    ((value = scf_value_create(handle)) == NULL)) {
		syslog(LOG_ERR, "scf alloc resource failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	bzero(viewEntry, sizeof (stmfViewEntry));

	/*
	 * get the service property group view entry handle
	 */
	if (scf_service_get_pg(svc, viewEntryPgName, pg) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			ret = STMF_PS_ERROR_NOT_FOUND;
		} else {
			syslog(LOG_ERR, "get pg %s failed - %s",
			    viewEntryPgName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
		}
		goto out;
	}


	/*
	 * get index
	 * format is: VE-<veIndex>-GUID
	 */
	indexPtr = strchr(viewEntryPgName, '-');
	if (!indexPtr) {
		ret = STMF_PS_ERROR;
		goto out;
	}

	/* Set the index */
	viewEntry->veIndex = atoi(strtok(++indexPtr, "-"));

	viewEntry->veIndexValid = B_TRUE;

	/* get allHosts property */
	if (scf_pg_get_property(pg, STMF_VE_ALLHOSTS,
	    prop) == -1) {
		syslog(LOG_ERR, "get property %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_ALLHOSTS,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	if (scf_property_get_value(prop, value) == -1) {
		syslog(LOG_ERR, "get property %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_ALLHOSTS,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/* set allHosts */
	if (scf_value_get_boolean(value, (uint8_t *)&scfBool) == -1) {
		syslog(LOG_ERR, "get property %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_ALLHOSTS,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}
	viewEntry->allHosts = scfBool;

	/* get hostGroup property */
	if (scf_pg_get_property(pg, STMF_VE_HOSTGROUP,
	    prop) == -1) {
		syslog(LOG_ERR, "get property %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_HOSTGROUP,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	if (scf_property_get_value(prop, value) == -1) {
		syslog(LOG_ERR, "get property %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_HOSTGROUP,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	if (scf_value_get_ustring(value, groupName,
	    sizeof (groupName)) == -1) {
		syslog(LOG_ERR, "get value %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_HOSTGROUP,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}
	/* set hostGroup */
	bcopy(groupName, viewEntry->hostGroup, strlen(groupName));

	/* get allTargets property */
	if (scf_pg_get_property(pg, STMF_VE_ALLTARGETS,
	    prop) == -1) {
		syslog(LOG_ERR, "get property %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_ALLTARGETS,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	if (scf_property_get_value(prop, value) == -1) {
		syslog(LOG_ERR, "get property value %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_ALLTARGETS,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/* set allTargets */
	if (scf_value_get_boolean(value, (uint8_t *)&scfBool) == -1) {
		syslog(LOG_ERR, "get value %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_ALLTARGETS,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}
	viewEntry->allTargets = scfBool;

	/* get targetGroup property */
	if (scf_pg_get_property(pg, STMF_VE_TARGETGROUP, prop) == -1) {
		syslog(LOG_ERR, "get property %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_TARGETGROUP,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	if (scf_property_get_value(prop, value) == -1) {
		syslog(LOG_ERR, "get property value %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_TARGETGROUP,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	if (scf_value_get_ustring(value, groupName,
	    sizeof (groupName)) == -1) {
		syslog(LOG_ERR, "get value %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_TARGETGROUP,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}
	/* set targetGroup */
	bcopy(groupName, viewEntry->targetGroup, strlen(groupName));

	/* get luNbr property */
	if (scf_pg_get_property(pg, STMF_VE_LUNBR,
	    prop) == -1) {
		syslog(LOG_ERR, "get property %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_LUNBR,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	if (scf_property_get_value(prop, value) == -1) {
		syslog(LOG_ERR, "get property value %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_LUNBR,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/* set luNbr */
	if (scf_value_get_opaque(value, (char *)viewEntry->luNbr,
	    sizeof (viewEntry->luNbr)) == -1) {
		syslog(LOG_ERR, "get opaque value %s/%s failed - %s",
		    viewEntryPgName, STMF_VE_LUNBR,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}
	/* set luNbrValid to true since we just got it */
	viewEntry->luNbrValid = B_TRUE;

out:
	/*
	 * Free resources
	 */
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}
	if (value != NULL) {
		scf_value_destroy(value);
	}
	if (prop != NULL) {
		scf_property_destroy(prop);
	}

	return (ret);
}


/*
 * psRemoveHostGroupMember
 *
 * Remove a host group member from a host group,
 *
 * groupName - name of group from which the member is removed
 * memberName - name of group member to remove
 *
 * returns:
 *  STMF_PS_SUCCESS on success
 *  STMF_PS_ERROR_* on failure
 */
int
psRemoveHostGroupMember(char *groupName, char *memberName)
{
	int ret;
	char groupPropListName[MAXNAMELEN];
	char groupPropName[MAXNAMELEN];

	ret = iPsGetActualGroupName(STMF_HOST_GROUPS, groupName,
	    groupPropName);
	if (ret != STMF_PS_SUCCESS) {
		return (ret);
	}

	if (snprintf(groupPropListName, sizeof (groupPropListName),
	    "%s-%s", groupPropName, STMF_MEMBER_LIST_SUFFIX) >
	    sizeof (groupPropListName)) {
		syslog(LOG_ERR, "buffer overflow on property name %s",
		    groupPropName);
		return (STMF_PS_ERROR);
	}

	return (iPsAddRemoveGroupMember(STMF_HOST_GROUPS, groupPropListName,
	    memberName, REMOVE));
}

/*
 * psRemoveTargetGroupMember
 *
 * Remove a target port group member from an target port group,
 *
 * groupName - name of group from which the member is removed
 * memberName - name of group member to remove
 *
 * returns:
 *  STMF_PS_SUCCESS on success
 *  STMF_PS_ERROR_* on failure
 */
int
psRemoveTargetGroupMember(char *groupName, char *memberName)
{
	int ret;
	char groupPropListName[MAXNAMELEN];
	char groupPropName[MAXNAMELEN];

	ret = iPsGetActualGroupName(STMF_TARGET_GROUPS, groupName,
	    groupPropName);
	if (ret != STMF_PS_SUCCESS) {
		return (ret);
	}

	if (snprintf(groupPropListName, sizeof (groupPropListName),
	    "%s-%s", groupPropName, STMF_MEMBER_LIST_SUFFIX) >
	    sizeof (groupPropListName)) {
		syslog(LOG_ERR, "buffer overflow on property name %s",
		    groupPropName);
		return (STMF_PS_ERROR);
	}

	return (iPsAddRemoveGroupMember(STMF_TARGET_GROUPS, groupPropListName,
	    memberName, REMOVE));
}

/*
 * psGetProviderData
 *
 * Retrieves an nvlist on a per provider basis
 *
 * providerName - property group name to use
 * nvl - nvlist to retrieve
 *
 */
int
psGetProviderData(char *providerName, nvlist_t **nvl, int providerType,
    uint64_t *setToken)
{
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;
	scf_propertygroup_t	*pg = NULL;
	scf_property_t	*prop = NULL;
	scf_value_t	*value = NULL;
	uint64_t blockCnt = 0;
	ssize_t blockOffset = 0;
	ssize_t actualBlockSize = 0;
	char pgName[MAXPATHLEN];
	char dataPropertyName[STMF_PROVIDER_DATA_PROP_NAME_SIZE];
	char *nvlistEncoded = NULL;
	ssize_t nvlistEncodedSize = 0;
	boolean_t foundSetCnt = B_TRUE;
	int i;
	int ret = STMF_PS_SUCCESS;

	if (providerName == NULL || (providerType != STMF_LU_PROVIDER_TYPE &&
	    providerType != STMF_PORT_PROVIDER_TYPE)) {
		ret = STMF_PS_ERROR_INVALID_ARG;
		goto out;
	}

	ret = iPsInit(&handle, &svc);
	if (ret != STMF_PS_SUCCESS) {
		goto out;
	}

	/*
	 * create the property group name
	 */
	(void) snprintf(pgName, sizeof (pgName), "%s%s",
	    STMF_PROVIDER_DATA_PREFIX, providerName);

	/*
	 * Allocate scf resources
	 */
	if (((pg = scf_pg_create(handle)) == NULL) ||
	    ((value = scf_value_create(handle)) == NULL) ||
	    ((prop = scf_property_create(handle)) == NULL)) {
		syslog(LOG_ERR, "scf alloc resource failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * Retrieve the existing property group.
	 */
	if (scf_service_get_pg(svc, pgName, pg) == -1) {
		if (scf_error() != SCF_ERROR_NOT_FOUND) {
			syslog(LOG_ERR, "get pg %s failed - %s", pgName,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		} else {
			ret = STMF_PS_ERROR_NOT_FOUND;
			goto out;
		}
	}

	/*
	 * Get the STMF_PROVIDER_DATA_PROP_COUNT property
	 */
	if (scf_pg_get_property(pg, STMF_PROVIDER_DATA_PROP_COUNT,
	    prop) == -1) {
		syslog(LOG_ERR, "get property %s/%s failed - %s",
		    pgName, STMF_PROVIDER_DATA_PROP_COUNT,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * Get the STMF_PROVIDER_DATA_PROP_COUNT value
	 */
	if (scf_property_get_value(prop, value) == -1) {
		syslog(LOG_ERR, "get property value %s/%s failed - %s",
		    pgName, STMF_PROVIDER_DATA_PROP_COUNT,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * Now get the actual value from the value handle
	 */
	if (scf_value_get_count(value, &blockCnt) == -1) {
		syslog(LOG_ERR, "get integer value %s/%s failed - %s",
		    pgName, STMF_PROVIDER_DATA_PROP_COUNT,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/* Has the caller requested the token to be set? */
	if (setToken) {
		/*
		 * Get the STMF_PROVIDER_DATA_PROP_SET_COUNT property
		 * If it doesn't exist, we assume it to be zero.
		 */
		*setToken = 0;
		if (scf_pg_get_property(pg, STMF_PROVIDER_DATA_PROP_SET_COUNT,
		    prop) == -1) {
			if (scf_error() == SCF_ERROR_NOT_FOUND) {
				foundSetCnt = B_FALSE;
			} else {
				syslog(LOG_ERR, "get property %s/%s "
				    "failed - %s", pgName,
				    STMF_PROVIDER_DATA_PROP_SET_COUNT,
				    scf_strerror(scf_error()));
				ret = STMF_PS_ERROR;
				goto out;
			}
		}

		if (foundSetCnt) {
			/*
			 * Get the STMF_PROVIDER_DATA_PROP_SET_COUNT value
			 */
			if (scf_property_get_value(prop, value) == -1) {
				syslog(LOG_ERR,
				    "get property value %s/%s failed - %s",
				    pgName, STMF_PROVIDER_DATA_PROP_SET_COUNT,
				    scf_strerror(scf_error()));
				ret = STMF_PS_ERROR;
				goto out;
			}

			/*
			 * Now get the actual value from the value handle
			 * and set the caller's token
			 */
			if (scf_value_get_count(value, setToken) == -1) {
				syslog(LOG_ERR,
				    "get integer value %s/%s failed - %s",
				    pgName, STMF_PROVIDER_DATA_PROP_SET_COUNT,
				    scf_strerror(scf_error()));
				ret = STMF_PS_ERROR;
				goto out;
			}
		}
	}

	nvlistEncoded = (char *)calloc(1,
	    blockCnt * STMF_PROVIDER_DATA_PROP_SIZE);
	if (nvlistEncoded == NULL) {
		syslog(LOG_ERR, "nvlistEncoded alloc failed");
		ret = STMF_PS_ERROR_NOMEM;
		goto out;
	}

	for (i = 0; i < blockCnt; i++) {
		bzero(dataPropertyName, sizeof (dataPropertyName));
		/*
		 * create the name to use for the property
		 */
		(void) snprintf(dataPropertyName, sizeof (dataPropertyName),
		    "%s-%d", STMF_PROVIDER_DATA_PROP_PREFIX, i);

		if (scf_pg_get_property(pg, dataPropertyName, prop) == -1) {
			syslog(LOG_ERR, "get property %s/%s failed - %s",
			    pgName, dataPropertyName,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		if (scf_property_get_value(prop, value) == -1) {
			syslog(LOG_ERR, "get property value %s/%s failed - %s",
			    pgName, dataPropertyName,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		/*
		 * Set the data block offset
		 */
		blockOffset = STMF_PROVIDER_DATA_PROP_SIZE * i;
		actualBlockSize = scf_value_get_opaque(value,
		    &nvlistEncoded[blockOffset], STMF_PROVIDER_DATA_PROP_SIZE);
		if (actualBlockSize == -1) {
			syslog(LOG_ERR, "get opaque property value %s/%s "
			    "failed - %s", pgName, dataPropertyName,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
		nvlistEncodedSize += actualBlockSize;
	}

	if (nvlist_unpack(nvlistEncoded, nvlistEncodedSize, nvl, 0) != 0) {
		syslog(LOG_ERR, "unable to unpack nvlist");
		ret = STMF_PS_ERROR;
		goto out;
	}


out:
	/*
	 * Free resources
	 */
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}
	if (prop != NULL) {
		scf_property_destroy(prop);
	}
	if (value != NULL) {
		scf_value_destroy(value);
	}
	if (nvlistEncoded != NULL) {
		free(nvlistEncoded);
	}

	return (ret);

}
/*
 * psGetProviderDataList
 *
 * Retrieves the list of providers that currently store persistent data
 *
 * providerList - pointer to a pointer to an stmfProviderList structure
 *                On success, this will contain the list of providers
 *                currently storing persistent data.
 */
int
psGetProviderDataList(stmfProviderList **providerList)
{
	scf_handle_t *handle = NULL;
	scf_service_t *svc = NULL;
	scf_propertygroup_t *pg = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *value = NULL;
	scf_iter_t *pgIter = NULL;
	char buf[MAXNAMELEN];
	int providerCnt = 0;
	int64_t providerType;
	int i = 0, j;
	int ret = STMF_PS_SUCCESS;

	ret = iPsInit(&handle, &svc);
	if (ret != STMF_PS_SUCCESS) {
		goto out;
	}

	*providerList = NULL;

	/*
	 * Allocate scf resources
	 */
	if (((pg = scf_pg_create(handle)) == NULL) ||
	    ((value = scf_value_create(handle)) == NULL) ||
	    ((prop = scf_property_create(handle)) == NULL) ||
	    ((pgIter = scf_iter_create(handle)) == NULL)) {
		syslog(LOG_ERR, "scf alloc resource failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * pgIter is the iterator handle
	 */
	if (scf_iter_service_pgs(pgIter, svc) == -1) {
		syslog(LOG_ERR, "iter property groups failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	while (scf_iter_next_pg(pgIter, pg) == 1) {
		if (scf_pg_get_name(pg, buf, sizeof (buf)) == -1) {
			syslog(LOG_ERR, "get name failed - %s",
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}
		/*
		 * Only count LU property groups
		 */
		if (strncmp(buf, STMF_PROVIDER_DATA_PREFIX,
		    strlen(STMF_PROVIDER_DATA_PREFIX)) == 0) {
			providerCnt++;
		}
	}

	/*
	 * pgIter is the iterator handle
	 */
	if (scf_iter_service_pgs(pgIter, svc) == -1) {
		syslog(LOG_ERR, "iter property groups failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	*providerList = (stmfProviderList *)calloc(1,
	    sizeof (stmfProviderList) + providerCnt * sizeof (stmfProvider));
	if (*providerList == NULL) {
		ret = STMF_PS_ERROR_NOMEM;
		goto out;
	}

	/*
	 * it's possible for entries to be added/removed while we're retrieving
	 * the property groups. Just make sure we don't write beyond our
	 * allocated buffer by checking to ensure i < providerCnt.
	 */
	while ((scf_iter_next_pg(pgIter, pg) == 1) && (i < providerCnt)) {
		if (scf_pg_get_name(pg, buf, sizeof (buf)) == -1) {
			syslog(LOG_ERR, "get name failed - %s",
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}
		/*
		 * Only use provider data property groups
		 */
		if (strncmp(buf, STMF_PROVIDER_DATA_PREFIX,
		    strlen(STMF_PROVIDER_DATA_PREFIX)) != 0) {
			continue;
		}

		/*
		 * Get the STMF_PROVIDER_DATA_PROP_TYPE property
		 */
		if (scf_pg_get_property(pg, STMF_PROVIDER_DATA_PROP_TYPE,
		    prop) == -1) {
			syslog(LOG_ERR, "get property %s/%s failed - %s",
			    buf, STMF_PROVIDER_DATA_PROP_TYPE,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}

		/*
		 * Get the STMF_PROVIDER_DATA_PROP_TYPE value
		 */
		if (scf_property_get_value(prop, value) == -1) {
			syslog(LOG_ERR, "get property value %s/%s failed - %s",
			    buf, STMF_PROVIDER_DATA_PROP_TYPE,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}

		/*
		 * Now get the actual value from the value handle
		 */
		if (scf_value_get_integer(value, &providerType) == -1) {
			syslog(LOG_ERR, "get integer value %s/%s failed - %s",
			    buf, STMF_PROVIDER_DATA_PROP_TYPE,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			break;
		}

		(*providerList)->provider[i].providerType = providerType;

		/* determine offset for copy of provider name */
		j = strlen(STMF_PROVIDER_DATA_PREFIX);

		/* copy provider name to caller's list */
		(void) strncpy((*providerList)->provider[i].name, buf + j,
		    sizeof ((*providerList)->provider[i].name));
		i++;
		(*providerList)->cnt++;
	}

	if (ret != STMF_PS_SUCCESS) {
		free(*providerList);
		goto out;
	}

out:
	/*
	 * Free resources
	 */
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}
	if (value != NULL) {
		scf_value_destroy(value);
	}
	if (prop != NULL) {
		scf_property_destroy(prop);
	}
	if (pgIter != NULL) {
		scf_iter_destroy(pgIter);
	}

	return (ret);
}


/*
 * psSetProviderData
 *
 * Stores a packed nvlist on a per provider basis
 *
 * providerName - property group name to use
 * nvl - nvlist to store
 * providerType - type of provider (logical unit or port)
 *
 */
int
psSetProviderData(char *providerName, nvlist_t *nvl, int providerType,
    uint64_t *setToken)
{
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;
	scf_propertygroup_t	*pg = NULL;
	scf_property_t	*prop = NULL;
	scf_transaction_t *tran = NULL;
	/* represents arrays of entry and value pointers for scf */
	scf_transaction_entry_t	**addEntry = NULL;
	scf_transaction_entry_t	**deleteEntry = NULL;
	scf_value_t **addValue = NULL;

	/*
	 * These declarations are for known entry and value set/get
	 * operations
	 */
	scf_transaction_entry_t *entry1 = NULL;
	scf_transaction_entry_t *entry2 = NULL;
	scf_transaction_entry_t *entry3 = NULL;
	scf_transaction_entry_t *entry5 = NULL;
	scf_value_t *value1 = NULL;
	scf_value_t *value2 = NULL;
	scf_value_t *value3 = NULL;
	scf_value_t *value4 = NULL;
	scf_value_t *value5 = NULL;

	boolean_t newPg = B_FALSE;
	char pgName[MAXPATHLEN];
	char dataPropertyName[STMF_PROVIDER_DATA_PROP_NAME_SIZE];
	char *nvlistEncoded = NULL;
	size_t nvlistEncodedSize;
	size_t blockSize;
	int i, j = 0;
	int addEntryAlloc = 0, deleteEntryAlloc = 0, addValueAlloc = 0;
	int blockOffset;
	uint64_t oldBlockCnt = 0;
	uint64_t blockCnt = 0;
	uint64_t setCnt = 0;
	boolean_t foundSetCnt = B_TRUE;
	int ret = STMF_PS_SUCCESS;
	int commitRet;

	if (providerName == NULL || (providerType != STMF_LU_PROVIDER_TYPE &&
	    providerType != STMF_PORT_PROVIDER_TYPE)) {
		ret = STMF_PS_ERROR_INVALID_ARG;
		goto out;
	}

	ret = iPsInit(&handle, &svc);
	if (ret != STMF_PS_SUCCESS) {
		goto out;
	}

	bzero(pgName, sizeof (pgName));
	/*
	 * create the property group name
	 */
	(void) snprintf(pgName, sizeof (pgName), "%s%s",
	    STMF_PROVIDER_DATA_PREFIX, providerName);

	/*
	 * Allocate scf resources
	 */
	if (((pg = scf_pg_create(handle)) == NULL) ||
	    ((entry1 = scf_entry_create(handle)) == NULL) ||
	    ((entry2 = scf_entry_create(handle)) == NULL) ||
	    ((entry3 = scf_entry_create(handle)) == NULL) ||
	    ((entry5 = scf_entry_create(handle)) == NULL) ||
	    ((value1 = scf_value_create(handle)) == NULL) ||
	    ((value2 = scf_value_create(handle)) == NULL) ||
	    ((value3 = scf_value_create(handle)) == NULL) ||
	    ((value4 = scf_value_create(handle)) == NULL) ||
	    ((value5 = scf_value_create(handle)) == NULL) ||
	    ((prop = scf_property_create(handle)) == NULL) ||
	    ((tran = scf_transaction_create(handle)) == NULL)) {
		syslog(LOG_ERR, "scf alloc resource failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/*
	 * Get the existing property group
	 */
	if (scf_service_get_pg(svc, pgName, pg) == -1) {
		if (scf_error() != SCF_ERROR_NOT_FOUND) {
			syslog(LOG_ERR, "get pg %s failed - %s",
			    pgName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		} else {
			/*
			 * create the property group.
			 */
			if (scf_service_add_pg(svc, pgName,
			    SCF_GROUP_APPLICATION, 0, pg) == -1) {
				syslog(LOG_ERR, "add pg %s failed - %s",
				    pgName, scf_strerror(scf_error()));
				ret = STMF_PS_ERROR;
				goto out;
			}
			newPg = B_TRUE;
		}
	}

	/*
	 * Begin the transaction
	 */
	if (scf_transaction_start(tran, pg) == -1) {
		syslog(LOG_ERR, "start transaction for %s failed - %s",
		    pgName, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	if (!newPg) {
		/*
		 * Get the STMF_PROVIDER_DATA_PROP_COUNT property
		 */
		if (scf_pg_get_property(pg, STMF_PROVIDER_DATA_PROP_COUNT,
		    prop) == -1) {
			syslog(LOG_ERR, "get property %s/%s failed - %s",
			    pgName, STMF_PROVIDER_DATA_PROP_COUNT,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		/*
		 * Get the STMF_PROVIDER_DATA_PROP_COUNT value
		 */
		if (scf_property_get_value(prop, value4) == -1) {
			syslog(LOG_ERR, "get property value %s/%s failed - %s",
			    pgName, STMF_PROVIDER_DATA_PROP_COUNT,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		/*
		 * Now get the actual value from the value handle
		 */
		if (scf_value_get_count(value4, &oldBlockCnt) == -1) {
			syslog(LOG_ERR, "get integer value %s/%s failed - %s",
			    pgName, STMF_PROVIDER_DATA_PROP_COUNT,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
	}

	/*
	 * Get the STMF_PROVIDER_DATA_PROP_SET_COUNT property
	 * If it doesn't exist, we'll create it later after successfully
	 * setting the data.
	 */
	if (scf_pg_get_property(pg, STMF_PROVIDER_DATA_PROP_SET_COUNT,
	    prop) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			foundSetCnt = B_FALSE;
		} else {
			syslog(LOG_ERR, "get property %s/%s failed - %s",
			    pgName, STMF_PROVIDER_DATA_PROP_SET_COUNT,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
	}

	if (foundSetCnt) {
		/*
		 * Get the STMF_PROVIDER_DATA_PROP_SET_COUNT value
		 */
		if (scf_property_get_value(prop, value5) == -1) {
			syslog(LOG_ERR, "get property value %s/%s failed - %s",
			    pgName, STMF_PROVIDER_DATA_PROP_SET_COUNT,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		/*
		 * Now get the actual value from the value handle
		 */
		if (scf_value_get_count(value5, &setCnt) == -1) {
			syslog(LOG_ERR, "get integer value %s/%s failed - %s",
			    pgName, STMF_PROVIDER_DATA_PROP_SET_COUNT,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		/*
		 * Compare the setCnt prop to the caller's.
		 */
		if (setToken && (*setToken != setCnt)) {
			ret = STMF_PS_ERROR_PROV_DATA_STALE;
			goto out;
		}
	}

	setCnt++;

	/*
	 * prepare the list for writing
	 */
	if (nvlist_pack(nvl, &nvlistEncoded, &nvlistEncodedSize,
	    NV_ENCODE_XDR, 0) != 0) {
		syslog(LOG_ERR, "nvlist_pack for %s failed",
		    pgName);
		ret = STMF_PS_ERROR_NOMEM;
		goto out;
	}

	/* Determine how many chunks we need to write */
	blockCnt = nvlistEncodedSize/STMF_PROVIDER_DATA_PROP_SIZE;
	if (nvlistEncodedSize % STMF_PROVIDER_DATA_PROP_SIZE)
		blockCnt++;

	/* allocate entry and value resources for writing those chunks */
	addEntry = (scf_transaction_entry_t **)calloc(1, sizeof (*addEntry)
	    * blockCnt);
	if (addEntry == NULL) {
		syslog(LOG_ERR, "addEntry alloc for %s failed", pgName);
		ret = STMF_PS_ERROR_NOMEM;
		goto out;
	}

	addValue = (scf_value_t **)calloc(1, sizeof (*addValue)
	    * blockCnt);
	if (addValue == NULL) {
		syslog(LOG_ERR, "value alloc for %s failed", pgName);
		ret = STMF_PS_ERROR_NOMEM;
		goto out;
	}

	/*
	 * allocate entry delete resources for deleting anything existing
	 * that is more than the new block count. We could leave them around
	 * without suffering any ill effects but it will be cleaner to look at
	 * in smf tools if they are deleted.
	 */
	if (oldBlockCnt > blockCnt) {
		deleteEntry = (scf_transaction_entry_t **)calloc(1,
		    sizeof (*deleteEntry) * (oldBlockCnt - blockCnt));
		if (deleteEntry == NULL) {
			syslog(LOG_ERR, "deleteEntry alloc for %s failed",
			    pgName);
			ret = STMF_PS_ERROR_NOMEM;
			goto out;
		}
		deleteEntryAlloc = oldBlockCnt - blockCnt;
	}


	for (i = 0; i < blockCnt; i++) {
		/*
		 * Create the entry resource for the prop
		 */
		addEntry[i] = scf_entry_create(handle);
		if (addEntry[i] == NULL) {
			syslog(LOG_ERR, "scf value alloc for %s failed - %s",
			    pgName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		/* bump alloc count for addEntry allocation */
		addEntryAlloc++;

		/*
		 * create the name to use for the property
		 */
		(void) snprintf(dataPropertyName, sizeof (dataPropertyName),
		    "%s-%d", STMF_PROVIDER_DATA_PROP_PREFIX, i);

		/*
		 * Create the new property
		 */
		if (scf_transaction_property_new(tran, addEntry[i],
		    dataPropertyName, SCF_TYPE_OPAQUE) == -1) {
			if (scf_error() == SCF_ERROR_EXISTS) {
				if (scf_transaction_property_change(tran,
				    addEntry[i], dataPropertyName,
				    SCF_TYPE_OPAQUE) == -1) {
					syslog(LOG_ERR, "transaction property "
					    "change %s/%s failed - %s",
					    pgName, dataPropertyName,
					    scf_strerror(scf_error()));
					ret = STMF_PS_ERROR;
					goto out;
				}
			} else {
				syslog(LOG_ERR,
				    "transaction property new %s/%s "
				    "failed - %s", pgName, dataPropertyName,
				    scf_strerror(scf_error()));
				ret = STMF_PS_ERROR;
				goto out;
			}
		}
		/*
		 * Create the value resource for the prop
		 */
		addValue[i] = scf_value_create(handle);
		if (addValue[i] == NULL) {
			syslog(LOG_ERR, "scf value alloc for %s failed - %s",
			    pgName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		/* bump alloc count for addValue allocation */
		addValueAlloc++;

		/*
		 * Set the data block offset and size
		 */
		if ((STMF_PROVIDER_DATA_PROP_SIZE * (i + 1))
		    > nvlistEncodedSize) {
			blockSize = nvlistEncodedSize
			    - STMF_PROVIDER_DATA_PROP_SIZE * i;
		} else {
			blockSize = STMF_PROVIDER_DATA_PROP_SIZE;
		}

		blockOffset = STMF_PROVIDER_DATA_PROP_SIZE * i;
		if (scf_value_set_opaque(addValue[i],
		    &nvlistEncoded[blockOffset], blockSize) == -1) {
			syslog(LOG_ERR, "set value for %s failed - %s",
			    pgName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		/*
		 * Add the data block to the transaction entry
		 */
		if (scf_entry_add_value(addEntry[i], addValue[i]) == -1) {
			syslog(LOG_ERR, "add value for %s failed - %s",
			    pgName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
	}

	/*
	 * Now we need to delete any chunks (properties) that are no longer
	 * needed. Iterate through the rest of the chunks deleting each.
	 */
	for (i = blockCnt; i < oldBlockCnt; i++) {
		/*
		 * Create the entry resource for the prop
		 */
		deleteEntry[j] = scf_entry_create(handle);
		if (deleteEntry[j] == NULL) {
			syslog(LOG_ERR, "scf value alloc for %s failed - %s",
			    pgName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		/*
		 * create the name to use for the property
		 */
		(void) snprintf(dataPropertyName, sizeof (dataPropertyName),
		    "%s-%d", STMF_PROVIDER_DATA_PROP_PREFIX, i);

		/*
		 * Delete the existing property
		 */
		if (scf_transaction_property_delete(tran, deleteEntry[j++],
		    dataPropertyName) == -1) {
			syslog(LOG_ERR, "delete property %s/%s failed - %s",
			    pgName, dataPropertyName,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
	}

	if (newPg) {
		/*
		 * Ensure the read_authorization property is set
		 * for the group
		 */
		if (scf_transaction_property_new(tran, entry1,
		    "read_authorization", SCF_TYPE_ASTRING) == -1) {
			syslog(LOG_ERR, "transaction property %s/%s new "
			    "failed - %s", pgName, "read_authorization",
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		if (scf_value_set_astring(value1, STMF_SMF_READ_ATTR) == -1) {
			syslog(LOG_ERR, "set value %s/%s failed - %s",
			    pgName, "read_authorization",
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}

		if (scf_entry_add_value(entry1, value1) == -1) {
			syslog(LOG_ERR, "add value %s/%s failed - %s",
			    pgName, "read_authorization",
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
	}

	/* create or change the count property */
	if (scf_transaction_property_new(tran, entry2,
	    STMF_PROVIDER_DATA_PROP_COUNT, SCF_TYPE_COUNT) == -1) {
		if (scf_error() == SCF_ERROR_EXISTS) {
			if (scf_transaction_property_change(tran, entry2,
			    STMF_PROVIDER_DATA_PROP_COUNT,
			    SCF_TYPE_COUNT) == -1) {
				syslog(LOG_ERR, "transaction property change "
				    "%s/%s failed - %s", pgName,
				    STMF_PROVIDER_DATA_PROP_COUNT,
				    scf_strerror(scf_error()));
				ret = STMF_PS_ERROR;
				goto out;
			}
		} else {
			syslog(LOG_ERR, "transaction property %s/%s new "
			    "failed - %s", pgName,
			    STMF_PROVIDER_DATA_PROP_COUNT,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
	}

	scf_value_set_count(value2, blockCnt);

	if (scf_entry_add_value(entry2, value2) == -1) {
		syslog(LOG_ERR, "add value %s/%s failed - %s",
		    pgName, STMF_PROVIDER_DATA_PROP_COUNT,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/* create or change the set count property */
	if (scf_transaction_property_new(tran, entry5,
	    STMF_PROVIDER_DATA_PROP_SET_COUNT, SCF_TYPE_COUNT) == -1) {
		if (scf_error() == SCF_ERROR_EXISTS) {
			if (scf_transaction_property_change(tran, entry5,
			    STMF_PROVIDER_DATA_PROP_SET_COUNT,
			    SCF_TYPE_COUNT) == -1) {
				syslog(LOG_ERR,
				    "transaction property change %s/%s "
				    "failed - %s", pgName,
				    STMF_PROVIDER_DATA_PROP_SET_COUNT,
				    scf_strerror(scf_error()));
				ret = STMF_PS_ERROR;
				goto out;
			}
		} else {
			syslog(LOG_ERR, "transaction property new %s/%s "
			    "failed - %s", pgName,
			    STMF_PROVIDER_DATA_PROP_SET_COUNT,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
	}



	scf_value_set_count(value5, setCnt);

	if (scf_entry_add_value(entry5, value5) == -1) {
		syslog(LOG_ERR, "add value %s/%s failed - %s",
		    pgName, STMF_PROVIDER_DATA_PROP_SET_COUNT,
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/* create or change the provider type property */
	if (scf_transaction_property_new(tran, entry3,
	    STMF_PROVIDER_DATA_PROP_TYPE, SCF_TYPE_INTEGER) == -1) {
		if (scf_error() == SCF_ERROR_EXISTS) {
			if (scf_transaction_property_change(tran, entry3,
			    STMF_PROVIDER_DATA_PROP_TYPE,
			    SCF_TYPE_INTEGER) == -1) {
				syslog(LOG_ERR,
				    "transaction property change %s/%s "
				    "failed - %s", pgName,
				    STMF_PROVIDER_DATA_PROP_TYPE,
				    scf_strerror(scf_error()));
				ret = STMF_PS_ERROR;
				goto out;
			}
		} else {
			syslog(LOG_ERR, "transaction property new %s/%s "
			    "failed - %s", pgName, STMF_PROVIDER_DATA_PROP_TYPE,
			    scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
			goto out;
		}
	}

	switch (providerType) {
		case STMF_PORT_PROVIDER_TYPE:
		case STMF_LU_PROVIDER_TYPE:
			scf_value_set_integer(value3, providerType);
			break;
		default:
			ret = STMF_PS_ERROR;
			goto out;
	}

	if (scf_entry_add_value(entry3, value3) == -1) {
		syslog(LOG_ERR, "add value %s/%s failed - %s", pgName,
		    STMF_PROVIDER_DATA_PROP_TYPE, scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}


	if ((commitRet = scf_transaction_commit(tran)) != 1) {
		syslog(LOG_ERR, "transaction commit for %s failed - %s",
		    pgName, scf_strerror(scf_error()));
		if (commitRet == 0) {
			ret = STMF_PS_ERROR_BUSY;
		} else {
			ret = STMF_PS_ERROR;
		}
		goto out;
	}

	/* pass the new token back to the caller if requested */
	if (ret == STMF_PS_SUCCESS && setToken) {
		*setToken = setCnt;
	}

out:
	/*
	 * Free resources
	 */
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}
	if (prop != NULL) {
		scf_property_destroy(prop);
	}
	if (tran != NULL) {
		scf_transaction_destroy(tran);
	}
	for (i = 0; i < addEntryAlloc; i++) {
		scf_entry_destroy(addEntry[i]);
	}
	for (i = 0; i < addValueAlloc; i++) {
		scf_value_destroy(addValue[i]);
	}
	free(addValue);
	free(addEntry);
	for (i = 0; i < deleteEntryAlloc; i++) {
		scf_entry_destroy(deleteEntry[i]);
	}
	free(deleteEntry);
	if (entry1 != NULL) {
		scf_entry_destroy(entry1);
	}
	if (entry2 != NULL) {
		scf_entry_destroy(entry2);
	}
	if (entry3 != NULL) {
		scf_entry_destroy(entry3);
	}
	if (entry5 != NULL) {
		scf_entry_destroy(entry5);
	}
	if (value1 != NULL) {
		scf_value_destroy(value1);
	}
	if (value2 != NULL) {
		scf_value_destroy(value2);
	}
	if (value3 != NULL) {
		scf_value_destroy(value3);
	}
	if (value4 != NULL) {
		scf_value_destroy(value4);
	}
	if (value5 != NULL) {
		scf_value_destroy(value5);
	}
	if (nvlistEncoded != NULL) {
		free(nvlistEncoded);
	}

	return (ret);
}

/*
 * psGetViewEntry
 *
 * Purpose: Get a single view entry based on the logical unit identifier and
 *          view entry index
 *
 * lu - logical unit identifier
 * viewEntryIndex - index of view entry
 * ve - caller allocated stmfViewEntry structure. On success, this will
 *      contain the retrieved view entry
 */
int
psGetViewEntry(stmfGuid *lu, uint32_t viewEntryIndex, stmfViewEntry *ve)
{
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;
	scf_propertygroup_t	*pg = NULL;
	char guidAsciiBuf[33]; /* size of ascii hex 16 byte guid with NULL */
	char viewEntryPgName[VIEW_ENTRY_PG_SIZE];
	char luPgName[LOGICAL_UNIT_PG_SIZE];
	int ret = STMF_PS_SUCCESS;

	ret = iPsInit(&handle, &svc);
	if (ret != STMF_PS_SUCCESS) {
		goto out;
	}

	pg = scf_pg_create(handle);
	if (pg == NULL) {
		syslog(LOG_ERR, "scf pg alloc failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/* Convert to ASCII uppercase hexadecimal string */
	(void) snprintf(guidAsciiBuf, sizeof (guidAsciiBuf),
	    "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
	    lu->guid[0], lu->guid[1], lu->guid[2], lu->guid[3], lu->guid[4],
	    lu->guid[5], lu->guid[6], lu->guid[7], lu->guid[8], lu->guid[9],
	    lu->guid[10], lu->guid[11], lu->guid[12], lu->guid[13],
	    lu->guid[14], lu->guid[15]);

	(void) snprintf(luPgName, sizeof (luPgName), "%s-%s",
	    STMF_LU_PREFIX, guidAsciiBuf);

	/*
	 * Format of view entry property group name:
	 *	VE-<view_entry_index>-<lu_name>
	 */
	(void) snprintf(viewEntryPgName, sizeof (viewEntryPgName),
	    "%s-%d-%s", STMF_VE_PREFIX, viewEntryIndex, guidAsciiBuf);

	if (scf_service_get_pg(svc, viewEntryPgName, pg) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			ret = STMF_PS_ERROR_NOT_FOUND;
		} else {
			syslog(LOG_ERR, "get pg %s failed - %s",
			    viewEntryPgName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
		}
		goto out;
	}


	if ((ret = iPsGetViewEntry(viewEntryPgName, ve)) != STMF_PS_SUCCESS) {
		ret = STMF_PS_ERROR;
		goto out;
	}

out:
	/*
	 * Free resources
	 */
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}

	return (ret);
}

/*
 * psRemoveViewEntry
 *
 * Remove a view entry
 *
 * luGuid - identifier of logical unit from which to remove view entry
 * viewEntryIndex - view entry name to remove
 *
 * returns:
 *  STMF_PS_SUCCESS on success
 *  STMF_PS_ERROR_* on failure
 */
int
psRemoveViewEntry(stmfGuid *lu, uint32_t viewEntryIndex)
{
	scf_handle_t	*handle = NULL;
	scf_service_t	*svc = NULL;
	scf_propertygroup_t	*pg = NULL;
	char guidAsciiBuf[33]; /* size of ascii hex 16 byte guid with NULL */
	char viewEntryPgName[VIEW_ENTRY_PG_SIZE];
	char luPgName[LOGICAL_UNIT_PG_SIZE];
	int ret = STMF_PS_SUCCESS;
	sigset_t sigmaskRestore;

	/* grab the signal hold lock */
	(void) pthread_mutex_lock(&sigSetLock);

	/*
	 * hold signals until we're done
	 */
	if (holdSignal(&sigmaskRestore) != 0) {
		(void) pthread_mutex_unlock(&sigSetLock);
		return (STMF_PS_ERROR);
	}

	ret = iPsInit(&handle, &svc);
	if (ret != STMF_PS_SUCCESS) {
		goto out;
	}

	pg = scf_pg_create(handle);
	if (pg == NULL) {
		syslog(LOG_ERR, "scf pg alloc failed - %s",
		    scf_strerror(scf_error()));
		ret = STMF_PS_ERROR;
		goto out;
	}

	/* Convert to ASCII uppercase hexadecimal string */
	(void) snprintf(guidAsciiBuf, sizeof (guidAsciiBuf),
	    "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
	    lu->guid[0], lu->guid[1], lu->guid[2], lu->guid[3], lu->guid[4],
	    lu->guid[5], lu->guid[6], lu->guid[7], lu->guid[8], lu->guid[9],
	    lu->guid[10], lu->guid[11], lu->guid[12], lu->guid[13],
	    lu->guid[14], lu->guid[15]);

	(void) snprintf(luPgName, sizeof (luPgName), "%s-%s",
	    STMF_LU_PREFIX, guidAsciiBuf);

	/*
	 * Format of view entry property group name:
	 *	VE-<view_entry_index>-<lu_name>
	 */
	(void) snprintf(viewEntryPgName, sizeof (viewEntryPgName),
	    "%s-%d-%s", STMF_VE_PREFIX, viewEntryIndex, guidAsciiBuf);

	if (scf_service_get_pg(svc, viewEntryPgName, pg) == -1) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			ret = STMF_PS_ERROR_NOT_FOUND;
		} else {
			syslog(LOG_ERR, "get pg %s failed - %s",
			    viewEntryPgName, scf_strerror(scf_error()));
			ret = STMF_PS_ERROR;
		}
		goto out;
	}

	/*
	 * update the logical unit property group to remove
	 * the view entry and update the view entry count
	 * If it fails, we won't delete the property group so that
	 * we maintain consistency.
	 */
	if ((ret = iPsAddRemoveLuViewEntry(luPgName, viewEntryPgName,
	    REMOVE)) != STMF_PS_SUCCESS) {
		goto out;
	}

	/*
	 * Delete the view entry. If this fails, we should try to add
	 * the logical unit view entry property group back otherwise
	 * we're inconsistent.
	 */
	if (scf_pg_delete(pg) == -1) {
		syslog(LOG_ERR, "delete pg %s failed - %s", viewEntryPgName,
		    scf_strerror(scf_error()));
		if ((ret = iPsAddRemoveLuViewEntry(luPgName, viewEntryPgName,
		    ADD)) != STMF_PS_SUCCESS) {
			syslog(LOG_ERR, "add of view entry %s failed, possible"
			    "inconsistency - %s", viewEntryPgName,
			    scf_strerror(scf_error()));
		}
		ret = STMF_PS_ERROR;
		goto out;
	}

out:
	/*
	 * Okay, we're done. Release the signals
	 */
	if (releaseSignal(&sigmaskRestore) != 0) {
		/*
		 * Don't set this as an STMF_PS_ERROR_*. We succeeded
		 * the requested operation. But we do need to log it.
		 */
		syslog(LOG_ERR, "Unable to release one or more signals - %s",
		    strerror(errno));
	}

	/*
	 * Free resources
	 */
	if (handle != NULL) {
		scf_handle_destroy(handle);
	}
	if (svc != NULL) {
		scf_service_destroy(svc);
	}
	if (pg != NULL) {
		scf_pg_destroy(pg);
	}

	/* release the signal hold lock */
	(void) pthread_mutex_unlock(&sigSetLock);

	return (ret);
}



/*
 * holdSignal
 *
 * Hold SIGINT, SIGTERM, SIGQUIT until further notice.
 *
 * Saves old signal mask on a per thread basis
 * and saves action for the process.
 *
 * Installs action for above signals.
 *
 * locks held: sigSetLock
 *
 * returns:
 *  0 on success
 *  non-zero otherwise
 */
static int
holdSignal(sigset_t *sigmaskRestore)
{
	struct sigaction act;
	sigset_t sigmask;

	/*
	 * Return existing signal mask for this thread
	 */
	if (pthread_sigmask(0, NULL, sigmaskRestore) != 0) {
		return (1);
	}

	(void) sigemptyset(&act.sa_mask);
	act.sa_handler = sigHandler;
	act.sa_flags = 0;

	/*
	 * Have we set the actions for the signals we want to catch?
	 */
	if (!actionSet) {
		if (sigaction(SIGQUIT, &act, &currentActionQuit) != 0) {
			return (1);
		}

		if (sigaction(SIGINT, &act, &currentActionInt) != 0) {
			return (1);
		}

		if (sigaction(SIGTERM, &act, &currentActionTerm) != 0) {
			return (1);
		}

		actionSet = B_TRUE;
	}

	/*
	 * We still need to change the mask for the current thread
	 */
	if (sigfillset(&sigmask) != 0) {
		return (1);
	}

	(void) sigdelset(&sigmask, SIGQUIT);

	(void) sigdelset(&sigmask, SIGINT);

	(void) sigdelset(&sigmask, SIGTERM);

	if (pthread_sigmask(SIG_SETMASK, &sigmask, NULL) != 0) {
		return (1);
	}

	return (0);
}

/*
 * releaseSignal
 *
 * Re-install the original signal mask and signal actions
 *
 * Also, raise any signals that were caught during the hold period and clear
 * the signal from the caught set (signalsCaught).
 *
 * locks held: sigSetLock
 *
 * Returns
 *  0 on success
 *  non-zero otherwise
 */
static int
releaseSignal(sigset_t *sigmaskRestore)
{
	int ret = 0;

	if (sigaction(SIGQUIT, &currentActionQuit, NULL) != 0) {
		ret = 1;
	}

	if (sigaction(SIGINT, &currentActionInt, NULL) != 0) {
		ret = 1;
	}

	if (sigaction(SIGTERM, &currentActionTerm, NULL) != 0) {
		ret = 1;
	}

	actionSet = B_FALSE;

	/*
	 * Restore previous signal mask for this thread
	 */
	if (pthread_sigmask(SIG_SETMASK, sigmaskRestore, NULL) != 0) {
		syslog(LOG_ERR, "Unable to restore sigmask");
	}

	/*
	 * Now raise signals that were raised while we were held
	 */
	if (sigismember(&signalsCaught, SIGTERM)) {
		(void) sigdelset(&signalsCaught, SIGTERM);
		(void) raise(SIGTERM);
	}

	if (sigismember(&signalsCaught, SIGINT)) {
		(void) sigdelset(&signalsCaught, SIGINT);
		(void) raise(SIGINT);
	}

	if (sigismember(&signalsCaught, SIGQUIT)) {
		(void) sigdelset(&signalsCaught, SIGQUIT);
		(void) raise(SIGQUIT);
	}

	return (ret);
}
