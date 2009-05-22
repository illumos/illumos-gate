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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains functions to initialize the gssapi library and
 * load mechanism libraries.
 *
 * It also contain functions requiring direct access to the mechanism's
 * list (gss_inidicate_mechs and gss_release_oid) as well as support
 * functions which translate the mechanism strings to oids and vise versa.
 *
 * The mechanism libraries are loaded on demand.  This is triggered
 * through the get_mechanism function call.
 *
 * Updates to the mechList are performed with the following restrictions:
 *	- once a library is loaded, none of the fields are updated
 *	- existing entiries for non-loaded mechs, will have the
 *		library and kernel module names updated only
 *		(i.e. the mech oid and mech name will not be updated)
 */

#include <mechglueP.h>
#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <ctype.h>
#include <errno.h>
#include <synch.h>
#include <dlfcn.h>
#include <libintl.h>


#ifndef TEXT_DOMAIN
#error TEXT_DOMAIN not defined
#endif

#define	MECH_CONF "/etc/gss/mech"

#define	MECH_LIB_PREFIX1	"/usr/lib/"

/*
 * This #ifdef mess figures out if we are to be compiled into
 * a sparcv9/lp64 binary for the purposes of figuring the absolute location
 * of gss-api mechanism modules.
 */
#ifdef	_LP64

#ifdef	__sparc

#define	MECH_LIB_PREFIX2	"sparcv9/"

#elif defined(__amd64)

#define	MECH_LIB_PREFIX2	"amd64/"

#else	/* __sparc */

you need to define where under /usr the LP64 libraries live for this platform

#endif	/* __sparc */

#else	/* _LP64 */

#define	MECH_LIB_PREFIX2	""

#endif	/* _LP64 */

#define	MECH_LIB_DIR		"gss/"

#define	MECH_LIB_PREFIX	MECH_LIB_PREFIX1 MECH_LIB_PREFIX2 MECH_LIB_DIR


#ifndef	MECH_SYM
#define	MECH_SYM "gss_mech_initialize"
#endif

#define	M_DEFAULT	"default"

/* Local functions */
static gss_mech_info searchMechList(const gss_OID);
static void loadConfigFile(const char *);
static void updateMechList(void);


/*
 * list of mechanism libraries and their entry points.
 * the list also maintains state of the mech libraries (loaded or not).
 */
static gss_mech_info g_mechList = NULL;
static gss_mech_info g_mechListTail = NULL;
static mutex_t g_mechListLock;
static time_t g_confFileModTime = (time_t)0;

/*
 * function used to reclaim the memory used by a gss_OID structure.
 * This routine requires direct access to the mechList.
 */
OM_uint32
gss_release_oid(minor_status, oid)
OM_uint32 *minor_status;
gss_OID *oid;
{
	OM_uint32 major;
	gss_mech_info aMech = g_mechList;

	if (minor_status == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*minor_status = 0;

	while (aMech != NULL) {

		/*
		 * look through the loaded mechanism libraries for
		 * gss_internal_release_oid until one returns success.
		 * gss_internal_release_oid will only return success when
		 * the OID was recognized as an internal mechanism OID. if no
		 * mechanisms recognize the OID, then call the generic version.
		 */

		/*
		 * we can walk the mechanism list without a mutex, because we
		 * are only looking at fields which once read will never change.
		 * Mechanism entries are always added to the end, and as
		 * complete entries.
		 */
		if (aMech->mech && aMech->mech->gss_internal_release_oid) {
			major = aMech->mech->gss_internal_release_oid(
					aMech->mech->context,
					minor_status, oid);
			if (major == GSS_S_COMPLETE)
				return (GSS_S_COMPLETE);
		}
		aMech = aMech->next;
	} /* while */

	return (generic_gss_release_oid(minor_status, oid));
} /* gss_release_oid */


/*
 * this function will return an oid set indicating available mechanisms.
 * The set returned is based on configuration file entries and
 * NOT on the loaded mechanisms.  This function does not check if any
 * of these can actually be loaded.
 * This routine needs direct access to the mechanism list.
 * To avoid reading the configuration file each call, we will save a
 * a mech oid set, and only update it once the file has changed.
 */
static time_t g_mechSetTime = (time_t)0;
static gss_OID_set_desc g_mechSet = { 0, NULL };
static mutex_t g_mechSetLock;


OM_uint32
gss_indicate_mechs(minorStatus, mechSet)
OM_uint32 *minorStatus;
gss_OID_set *mechSet;
{
	gss_mech_info mList;
	char *fileName;
	struct stat fileInfo;
	int count, i, j;
	gss_OID curItem;

	/* Initialize outputs. */

	if (minorStatus != NULL)
		*minorStatus = 0;

	if (mechSet != NULL)
		*mechSet = GSS_C_NO_OID_SET;

	/* Validate arguments. */
	if (minorStatus == NULL || mechSet == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	fileName = MECH_CONF;

	/*
	 * If we have already computed the mechanisms supported and if it
	 * is still valid; make a copy and return to caller,
	 * otherwise build it first.
	 */
	if ((stat(fileName, &fileInfo) == 0 &&
		fileInfo.st_mtime > g_mechSetTime)) {
		/*
		 * lock the mutex since we will be updating
		 * the mechList structure
		 * we need to keep the lock while we build the mechanism list
		 * since we are accessing parts of the mechList which could be
		 * modified.
		 */
		(void) mutex_lock(&g_mechListLock);

		/*
		 * this checks for the case when we need to re-construct the
		 * g_mechSet structure, but the mechanism list is upto date
		 * (because it has been read by someone calling
		 * __gss_get_mechanism)
		 */
		if (fileInfo.st_mtime > g_confFileModTime)
		{
			g_confFileModTime = fileInfo.st_mtime;
			loadConfigFile(fileName);
		}

		/*
		 * we need to lock the mech set so that no one else will
		 * try to read it as we are re-creating it
		 */
		(void) mutex_lock(&g_mechSetLock);

		/* if the oid list already exists we must free it first */
		if (g_mechSet.count != 0) {
			for (i = 0; i < g_mechSet.count; i++)
				free(g_mechSet.elements[i].elements);
			free(g_mechSet.elements);
			g_mechSet.elements = NULL;
			g_mechSet.count = 0;
		}

		/* determine how many elements to have in the list */
		mList = g_mechList;
		count = 0;
		while (mList != NULL) {
			count++;
			mList = mList->next;
		}

		/* this should always be true, but.... */
		if (count > 0) {
			g_mechSet.elements =
				(gss_OID) calloc(count, sizeof (gss_OID_desc));
			if (g_mechSet.elements == NULL) {
				(void) mutex_unlock(&g_mechSetLock);
				(void) mutex_unlock(&g_mechListLock);
				return (GSS_S_FAILURE);
			}

			(void) memset(g_mechSet.elements, 0,
				count * sizeof (gss_OID_desc));

			/* now copy each oid element */
			g_mechSet.count = count;
			count = 0;
			mList = g_mechList;
			while (mList != NULL) {
				curItem = &(g_mechSet.elements[count]);
				curItem->elements = (void*)
					malloc(mList->mech_type->length);
				if (curItem->elements == NULL) {
					/*
					 * this is nasty - we must delete the
					 * part of the array already copied
					 */
					for (i = 0; i < count; i++) {
						free(g_mechSet.elements[i].
							elements);
					}
					free(g_mechSet.elements);
					g_mechSet.count = 0;
					g_mechSet.elements = NULL;
					(void) mutex_unlock(&g_mechSetLock);
					(void) mutex_unlock(&g_mechListLock);
					return (GSS_S_FAILURE);
				}
				g_OID_copy(curItem, mList->mech_type);
				count++;
				mList = mList->next;
			}
		}

		g_mechSetTime = fileInfo.st_mtime;
		(void) mutex_unlock(&g_mechSetLock);
		(void) mutex_unlock(&g_mechListLock);
	} /* if g_mechSet is out of date or not initialized */

	/*
	 * the mech set is created and it is up to date
	 * so just copy it to caller
	 */
	if ((*mechSet =
		(gss_OID_set) malloc(sizeof (gss_OID_set_desc))) == NULL)
	{
		return (GSS_S_FAILURE);
	}

	/*
	 * need to lock the g_mechSet in case someone tries to update it while
	 * I'm copying it.
	 */
	(void) mutex_lock(&g_mechSetLock);

	/* allocate space for the oid structures */
	if (((*mechSet)->elements =
		(void*) calloc(g_mechSet.count, sizeof (gss_OID_desc)))
		== NULL)
	{
		(void) mutex_unlock(&g_mechSetLock);
		free(*mechSet);
		*mechSet = NULL;
		return (GSS_S_FAILURE);
	}

	/* now copy the oid structures */
	(void) memcpy((*mechSet)->elements, g_mechSet.elements,
		g_mechSet.count * sizeof (gss_OID_desc));

	(*mechSet)->count = g_mechSet.count;

	/* still need to copy each of the oid elements arrays */
	for (i = 0; i < (*mechSet)->count; i++) {
		curItem = &((*mechSet)->elements[i]);
		curItem->elements =
			(void *) malloc(g_mechSet.elements[i].length);
		if (curItem->elements == NULL) {
			(void) mutex_unlock(&g_mechSetLock);
			/*
			 * must still free the allocated elements for
			 * each allocated gss_OID_desc
			 */
			for (j = 0; j < i; j++) {
				free((*mechSet)->elements[j].elements);
			}
			free((*mechSet)->elements);
			free(mechSet);
			*mechSet = NULL;
			return (GSS_S_FAILURE);
		}
		g_OID_copy(curItem, &g_mechSet.elements[i]);
	}
	(void) mutex_unlock(&g_mechSetLock);
	return (GSS_S_COMPLETE);
} /* gss_indicate_mechs */

/*
 * this function has been added for use by modules that need to
 * know what (if any) optional parameters are supplied in the
 * config file (MECH_CONF).
 * It will return the option string for a specified mechanism.
 * caller is responsible for freeing the memory
 */
char *
__gss_get_modOptions(oid)
const gss_OID oid;
{
	gss_mech_info aMech;
	char *modOptions = NULL;

	/* make sure we have fresh data */
	(void) mutex_lock(&g_mechListLock);
	updateMechList();
	(void) mutex_unlock(&g_mechListLock);

	/* searching the list does not require a lock */
	if ((aMech = searchMechList(oid)) == NULL ||
		aMech->optionStr == NULL) {
		return (NULL);
	}

	/*
	 * need to obtain a lock on this structure in case someone else
	 * will try to update it during the copy
	 */
	(void) mutex_lock(&g_mechListLock);
	if (aMech->optionStr)
		modOptions = strdup(aMech->optionStr);
	(void) mutex_unlock(&g_mechListLock);

	return (modOptions);
} /* __gss_get_modOptions */

/*
 * this function has been added for use by gssd.
 * It will return the kernel module name for a specified mechanism.
 * caller is responsible for freeing the memory
 */
char *
__gss_get_kmodName(oid)
const gss_OID oid;
{
	gss_mech_info aMech;
	char *kmodName = NULL;

	/* make sure we have fresh data */
	(void) mutex_lock(&g_mechListLock);
	updateMechList();
	(void) mutex_unlock(&g_mechListLock);

	/* searching the list does not require a lock */
	if ((aMech = searchMechList(oid)) == NULL || aMech->kmodName == NULL) {
		return (NULL);
	}

	/*
	 * need to obtain a lock on this structure in case someone else
	 * will try to update it during the copy
	 */
	(void) mutex_lock(&g_mechListLock);
	if (aMech->kmodName)
		kmodName = strdup(aMech->kmodName);
	(void) mutex_unlock(&g_mechListLock);

	return (kmodName);
} /* __gss_get_kmodName */


/*
 * given a mechanism string return the mechanism oid
 */
OM_uint32
__gss_mech_to_oid(const char *mechStr, gss_OID* oid)
{
	gss_mech_info aMech;

	if (oid == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	*oid = GSS_C_NULL_OID;

	if ((mechStr == NULL) || (strlen(mechStr) == 0) ||
		(strcasecmp(mechStr, M_DEFAULT) == 0))
		return (GSS_S_COMPLETE);

	/* ensure we have fresh data */
	(void) mutex_lock(&g_mechListLock);
	updateMechList();
	(void) mutex_unlock(&g_mechListLock);

	aMech = g_mechList;

	/* no lock required - only looking at fields that are not updated */
	while (aMech != NULL) {
		if ((aMech->mechNameStr) &&
			strcmp(aMech->mechNameStr, mechStr) == 0) {
			*oid = aMech->mech_type;
			return (GSS_S_COMPLETE);
		}
		aMech = aMech->next;
	}
	return (GSS_S_FAILURE);
} /* __gss_mech_to_oid */


/*
 * Given the mechanism oid, return the readable mechanism name
 * associated with that oid from the mech config file
 * (/etc/gss/mech).
 */
const char *
__gss_oid_to_mech(const gss_OID oid)
{
	gss_mech_info aMech;

	if (oid == GSS_C_NULL_OID)
		return (M_DEFAULT);

	/* ensure we have fresh data */
	(void) mutex_lock(&g_mechListLock);
	updateMechList();
	(void) mutex_unlock(&g_mechListLock);

	if ((aMech = searchMechList(oid)) == NULL)
		return (NULL);

	return (aMech->mechNameStr);
} /* __gss_oid_to_mech */


/*
 * return a list of mechanism strings supported
 * upon return the array is terminated with a NULL entry
 */
OM_uint32
__gss_get_mechanisms(char *mechArray[], int arrayLen)
{
	gss_mech_info aMech;
	int i;

	if (mechArray == NULL || arrayLen < 1)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	/* ensure we have fresh data */
	(void) mutex_lock(&g_mechListLock);
	updateMechList();
	(void) mutex_unlock(&g_mechListLock);

	aMech = g_mechList;

	/* no lock required - only looking at fields that are not updated */
	for (i = 1; i < arrayLen; i++) {
		if (aMech != NULL) {
			*mechArray = aMech->mechNameStr;
			mechArray++;
			aMech = aMech->next;
		} else
			break;
	}
	*mechArray = NULL;
	return (GSS_S_COMPLETE);
} /* gss_get_mechanisms */


/*
 * determines if the mechList needs to be updated from file
 * and performs the update.
 * this functions must be called with a lock of g_mechListLock
 */
static void
updateMechList(void)
{
	char *fileName;
	struct stat fileInfo;

	fileName = MECH_CONF;

	/* check if mechList needs updating */
	if (stat(fileName, &fileInfo) == 0 &&
		(fileInfo.st_mtime > g_confFileModTime)) {
		loadConfigFile(fileName);
		g_confFileModTime = fileInfo.st_mtime;
	}
} /* updateMechList */


/*
 * given the mechanism type, return the mechanism structure
 * containing the mechanism library entry points.
 * will return NULL if mech type is not found
 * This function will also trigger the loading of the mechanism
 * module if it has not been already loaded.
 */
gss_mechanism
__gss_get_mechanism(oid)
const gss_OID oid;
{
	gss_mech_info aMech;
	gss_mechanism (*sym)(const gss_OID);
	void *dl;

	/* check if the mechanism is already loaded */
	if ((aMech = searchMechList(oid)) != NULL && aMech->mech) {
		return (aMech->mech);
	}

	/*
	 * might need to re-read the configuration file before loading
	 * the mechanism to ensure we have the latest info.
	 */
	(void) mutex_lock(&g_mechListLock);
	updateMechList();

	aMech = searchMechList(oid);

	/* is the mechanism present in the list ? */
	if (aMech == NULL) {
		(void) mutex_unlock(&g_mechListLock);
		return ((gss_mechanism)NULL);
	}

	/* has another thread loaded the mech */
	if (aMech->mech) {
		(void) mutex_unlock(&g_mechListLock);
		return (aMech->mech);
	}

	/* we found the mechanism, but it is not loaded */
	if ((dl = dlopen(aMech->uLibName, RTLD_NOW)) == NULL) {
		(void) syslog(LOG_INFO, "libgss dlopen(%s): %s\n",
				aMech->uLibName, dlerror());
		(void) mutex_unlock(&g_mechListLock);
		return ((gss_mechanism)NULL);
	}

	if ((sym = (gss_mechanism (*)(const gss_OID))dlsym(dl, MECH_SYM))
			== NULL) {
		(void) dlclose(dl);
		(void) syslog(LOG_INFO, "unable to initialize mechanism"
				" library [%s]\n", aMech->uLibName);
		(void) mutex_unlock(&g_mechListLock);
		return ((gss_mechanism)NULL);
	}

	/* Call the symbol to get the mechanism table */
	aMech->mech = (*sym)(aMech->mech_type);

	if (aMech->mech == NULL) {
		(void) dlclose(dl);
		(void) syslog(LOG_INFO, "unable to initialize mechanism"
				" library [%s]\n", aMech->uLibName);
		(void) mutex_unlock(&g_mechListLock);
		return ((gss_mechanism)NULL);
	}

	aMech->dl_handle = dl;

	(void) mutex_unlock(&g_mechListLock);
	return (aMech->mech);
} /* __gss_get_mechanism */

gss_mechanism_ext
__gss_get_mechanism_ext(oid)
const gss_OID oid;
{
	gss_mech_info aMech;
	gss_mechanism_ext mech_ext;

	/* check if the mechanism is already loaded */
	if ((aMech = searchMechList(oid)) != NULL && aMech->mech_ext != NULL)
		return (aMech->mech_ext);

	if (__gss_get_mechanism(oid) == NULL)
		return (NULL);

	if (aMech->dl_handle == NULL)
		return (NULL);

	/* Load the gss_config_ext struct for this mech */

	mech_ext = (gss_mechanism_ext)malloc(sizeof (struct gss_config_ext));

	if (mech_ext == NULL)
		return (NULL);

	/*
	 * dlsym() the mech's 'method' functions for the extended APIs
	 *
	 * NOTE:  Until the void *context argument is removed from the
	 * SPI method functions' signatures it will be necessary to have
	 * different function pointer typedefs and function names for
	 * the SPI methods than for the API.  When this argument is
	 * removed it will be possible to rename gss_*_sfct to gss_*_fct
	 * and and gssspi_* to gss_*.
	 */
	mech_ext->gss_acquire_cred_with_password =
		(gss_acquire_cred_with_password_sfct)dlsym(aMech->dl_handle,
			"gssspi_acquire_cred_with_password");

	/* Set aMech->mech_ext */
	(void) mutex_lock(&g_mechListLock);

	if (aMech->mech_ext == NULL)
		aMech->mech_ext = mech_ext;
	else
		free(mech_ext);	/* we raced and lost; don't leak */

	(void) mutex_unlock(&g_mechListLock);

	return (aMech->mech_ext);

} /* __gss_get_mechanism_ext */


/*
 * this routine is used for searching the list of mechanism data.
 * it needs not be mutex protected because we only add new structures
 * from the end and they are fully initialized before being added.
 */
static gss_mech_info searchMechList(oid)
const gss_OID oid;
{
	gss_mech_info aMech = g_mechList;

	/* if oid is null -> then get default which is the first in the list */
	if (oid == GSS_C_NULL_OID)
		return (aMech);

	while (aMech != NULL) {
		if (g_OID_equal(aMech->mech_type, oid))
			return (aMech);
		aMech = aMech->next;
	}

	/* none found */
	return ((gss_mech_info) NULL);
} /* searchMechList */


/*
 * loads the configuration file
 * this is called while having a mutex lock on the mechanism list
 * entries for libraries that have been loaded can't be modified
 * mechNameStr and mech_type fields are not updated during updates
 */
static void loadConfigFile(fileName)
const char *fileName;
{
	char buffer[BUFSIZ], *oidStr, *oid, *sharedLib, *kernMod, *endp;
	char *modOptions;
	char sharedPath[sizeof (MECH_LIB_PREFIX) + BUFSIZ];
	char *tmpStr;
	FILE *confFile;
	gss_OID mechOid;
	gss_mech_info aMech, tmp;
	OM_uint32 minor;
	gss_buffer_desc oidBuf;

	if ((confFile = fopen(fileName, "rF")) == NULL) {
		return;
	}

	(void) memset(buffer, 0, sizeof (buffer));
	while (fgets(buffer, BUFSIZ, confFile) != NULL) {

		/* ignore lines beginning with # */
		if (*buffer == '#')
			continue;

		/*
		 * find the first white-space character after
		 * the mechanism name
		 */
		oidStr = buffer;
		for (oid = buffer; *oid && !isspace(*oid); oid++);

		/* Now find the first non-white-space character */
		if (*oid) {
			*oid = '\0';
			oid++;
			while (*oid && isspace(*oid))
				oid++;
		}

		/*
		 * If that's all, then this is a corrupt entry. Skip it.
		 */
		if (! *oid)
			continue;

		/* Find the end of the oid and make sure it is NULL-ended */
		for (endp = oid; *endp && !isspace(*endp); endp++)
			;

		if (*endp) {
			*endp = '\0';
		}

		/*
		 * check if an entry for this oid already exists
		 * if it does, and the library is already loaded then
		 * we can't modify it, so skip it
		 */
		oidBuf.value = (void *)oid;
		oidBuf.length = strlen(oid);
		if (generic_gss_str_to_oid(&minor, &oidBuf, &mechOid)
			!= GSS_S_COMPLETE) {
			(void) syslog(LOG_INFO, "invalid mechanism oid"
					" [%s] in configuration file", oid);
			continue;
		}

		aMech = searchMechList(mechOid);
		if (aMech && aMech->mech) {
			free(mechOid->elements);
			free(mechOid);
			continue;
		}

		/* Find the start of the shared lib name */
		for (sharedLib = endp+1; *sharedLib && isspace(*sharedLib);
			sharedLib++)
			;

		/*
		 * If that's all, then this is a corrupt entry. Skip it.
		 */
		if (! *sharedLib) {
			free(mechOid->elements);
			free(mechOid);
			continue;
		}

		/*
		 * Find the end of the shared lib name and make sure it is
		 *  NULL-terminated.
		 */
		for (endp = sharedLib; *endp && !isspace(*endp); endp++)
			;

		if (*endp) {
			*endp = '\0';
		}

		/* Find the start of the optional kernel module lib name */
		for (kernMod = endp+1; *kernMod && isspace(*kernMod);
			kernMod++)
			;

		/*
		 * If this item starts with a bracket "[", then
		 * it is not a kernel module, but is a list of
		 * options for the user module to parse later.
		 */
		if (*kernMod && *kernMod != '[') {
			/*
			 * Find the end of the shared lib name and make sure
			 * it is NULL-terminated.
			 */
			for (endp = kernMod; *endp && !isspace(*endp); endp++)
				;

			if (*endp) {
				*endp = '\0';
			}
		} else
			kernMod = NULL;

		/* Find the start of the optional module options list */
		for (modOptions = endp+1; *modOptions && isspace(*modOptions);
			modOptions++);

		if (*modOptions == '[')  {
			/* move past the opening bracket */
			for (modOptions = modOptions+1;
			    *modOptions && isspace(*modOptions);
			    modOptions++);

			/* Find the closing bracket */
			for (endp = modOptions;
				*endp && *endp != ']'; endp++);

			if (endp)
				*endp = '\0';

		} else {
			modOptions = NULL;
		}

		(void) strcpy(sharedPath, MECH_LIB_PREFIX);
		(void) strcat(sharedPath, sharedLib);

		/*
		 * are we creating a new mechanism entry or
		 * just modifying existing (non loaded) mechanism entry
		 */
		if (aMech) {
			/*
			 * delete any old values and set new
			 * mechNameStr and mech_type are not modified
			 */
			if (aMech->kmodName) {
				free(aMech->kmodName);
				aMech->kmodName = NULL;
			}

			if (aMech->optionStr) {
				free(aMech->optionStr);
				aMech->optionStr = NULL;
			}

			if ((tmpStr = strdup(sharedPath)) != NULL) {
				if (aMech->uLibName)
					free(aMech->uLibName);
				aMech->uLibName = tmpStr;
			}

			if (kernMod) /* this is an optional parameter */
				aMech->kmodName = strdup(kernMod);

			if (modOptions) /* optional module options */
				aMech->optionStr = strdup(modOptions);

			/* the oid is already set */
			free(mechOid->elements);
			free(mechOid);
			continue;
		}

		/* adding a new entry */
		aMech = malloc(sizeof (struct gss_mech_config));
		if (aMech == NULL) {
			free(mechOid->elements);
			free(mechOid);
			continue;
		}
		(void) memset(aMech, 0, sizeof (struct gss_mech_config));
		aMech->mech_type = mechOid;
		aMech->uLibName = strdup(sharedPath);
		aMech->mechNameStr = strdup(oidStr);

		/* check if any memory allocations failed - bad news */
		if (aMech->uLibName == NULL || aMech->mechNameStr == NULL) {
			if (aMech->uLibName)
				free(aMech->uLibName);
			if (aMech->mechNameStr)
				free(aMech->mechNameStr);
			free(mechOid->elements);
			free(mechOid);
			free(aMech);
			continue;
		}
		if (kernMod)	/* this is an optional parameter */
			aMech->kmodName = strdup(kernMod);

		if (modOptions)
			aMech->optionStr = strdup(modOptions);
		/*
		 * add the new entry to the end of the list - make sure
		 * that only complete entries are added because other
		 * threads might currently be searching the list.
		 */
		tmp = g_mechListTail;
		g_mechListTail = aMech;

		if (tmp != NULL)
			tmp->next = aMech;

		if (g_mechList == NULL)
			g_mechList = aMech;
	} /* while */
	(void) fclose(confFile);
} /* loadConfigFile */
