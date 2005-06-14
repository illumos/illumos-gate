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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <pthread.h>

#include "util.h"

static void setLastError(CIMErrorReason, const cimchar *, const cimchar *, \
	int *);
static void cleanupThreadExceptions(void *pParam);


pthread_key_t	gWbemDiskLastErrorKey;

#pragma init(errorInit)
#pragma fini(errorFinalize)

/*
 * The infastructure will call this when
 * an error occurs, it should return a
 * CCIMException which describes the error.
 * Caller is responsable for freeing
 * memory assocaited with the returned CCIMException
 */

CCIMException   *
cp_getLastError()
{
	CCIMException   *lastError = NULL;

	lastError =
	    (CCIMException *)pthread_getspecific(gWbemDiskLastErrorKey);
	(void) pthread_setspecific(gWbemDiskLastErrorKey, NULL);
	return (lastError);
}

/*
 * Handle the errors that come in from the providers. This involves writing to
 * the CIM log and setting the last error on the stack for the CIMOM exception
 * handling.
 */

void
util_handleError(char *funcName, CIMErrorReason reason, char *reasonString,
    CCIMException *ex, int *errp)
{


	/*
	 * Create a copy of the exception, if it exists. The caller of
	 * this function should free the exception passed in.
	 */
	if (ex != NULL) {
	    if (reasonString == NULL) {
		setLastError(ex->mReason, ex->mErrorString, funcName, errp);
	    } else {
		setLastError(ex->mReason, reasonString, funcName, errp);
	    }
	    cim_freeCIMException(ex);
	} else {
	    setLastError(reason, reasonString, funcName, errp);
	}
}

void *
util_getKeyValue(CCIMPropertyList *propList, CIMType propType,
	char *key, int *error) {

	CCIMProperty		*pProp;
	CCIMPropertyList 	*pList = propList;

	*error = 0;

	do {
	    pProp = pList->mDataObject;
	    if (strcasecmp(pProp->mName, key) == 0) {
		break;
	    }
	    pList = pList->mNext;
	} while (pList);

	if (pList == NULL) {
	    *error = CIM_ERR_INVALID_PARAMETER;
	    return ((CCIMProperty *)NULL);
	}

	/*
	 * If reference property, then return object path. In all other cases.
	 * the value is a string.
	 */

	if (propType == reference) {
	    return (pProp->mObjPathValue);
	} else {
	    return (pProp->mValue);
	}
}
void
util_doProperty(cimchar *name, CIMType type, cimchar *value, CIMBool is_key,
    CCIMInstance *inst, int *error)
{

	CCIMProperty *prop;

	*error = 0;

	prop = cim_createProperty(name, type, value, NULL, is_key);
	if (prop == NULL) {
	    *error = CIM_ERR_FAILED;
	    return;
	}
	if ((cim_addProperty(inst, prop)) == cim_false) {
	    cim_freeProperty(prop);
	    *error = CIM_ERR_FAILED;
	    return;
	}
}

void
util_doReferenceProperty(cimchar *role, CCIMObjectPath *obj, CIMBool isKey,
	CCIMInstance *inst, int *error)
{

	CCIMProperty	*prop;

	*error = 0;
	prop = cim_createReferenceProperty(role, obj, isKey);
	if (prop == NULL) {
	    *error = CIM_ERR_INVALID_PARAMETER;
	    return;
	}
	if (cim_addProperty(inst, prop) == cim_false) {
	    cim_freeProperty(prop);
	    *error = CIM_ERR_FAILED;
	    return;
	}
}

/*
 * Function:	openFile
 *
 * Parameters:  fileName - char pointer to the name of the file to open.
 *		fMode - char pointer to the mode used to open the file.
 *
 * Returns:	On successful completion returns the FILE pointer for
 *		the open file.
 *		On failure returns a NULL FILE pointer.
 *
 * Description:	'fopen's file and checks for errors.
 */
FILE *
util_openFile(char *fileName, char *fMode)
{
	FILE		*pTmpFile;
	int		error;

	/* Open the temporary file based on fMode */
	pTmpFile = fopen(fileName, fMode);
	if (pTmpFile == NULL) {
	    util_handleError(UTIL_OPENFILE, CIM_ERR_FAILED,
		UTIL_FILEOPEN_FAILURE, NULL, &error);
	    return ((FILE *)NULL);
	}
	return (pTmpFile);
}

/*
 * Function:	util_closeFile
 *
 * Parameters:  file - FILE pointer to an open file.
 *
 * Returns:	On successful completion returns 1.
 *		On failure returns 0.
 *
 * Description:	'fclose's file and handles errors.
 */

/* ARGSUSED */
int
util_closeFile(FILE *file, char *fName)
{
	int	error;

	if (fclose(file) != 0) {
	    util_handleError(UTIL_CLOSEFILE, CIM_ERR_FAILED,
		UTIL_FILECLOSE_FAILURE, NULL, &error);
	    return (0);
	}
	return (1);
}

/*
 * Function:	util_removeFile
 *
 * Parameters:	tFName - char pointer to the filename
 *
 * Returns:	NULL
 *
 * Description:	Removes file and releases the memory used for
 *		the filename.
 */
void
util_removeFile(char *tFName)
{
	int	error;

	if (remove(tFName) != 0) {
	    util_handleError(UTIL_REMOVEFILE, CIM_ERR_FAILED,
		UTIL_FILEREMOVE_FAILURE, NULL, &error);
	}

	free(tFName);
}

char *
util_routineFailureMessage(char *routine)
{
	static char	msgBuf[MAXFAILSTRINGLEN];

	/*
	 * TRANSLATION_NOTE
	 *
	 * "%s Failed." indicates an error returned by the function
	 * whose name is specified by the string used to replace %s.
	 */
	(void) snprintf(msgBuf, MAXFAILSTRINGLEN,
	    dgettext(TEXT_DOMAIN, "%s Failed."), routine);

	return (msgBuf);
}

/*
 * Function:	util_routineStartDaemonMessage
 *
 * Parameters:	dname - the name of the daemon we we're attempting to start
 *
 * Returns:	the generated string
 *
 * Description:	creates a localized sring for eror messages.
 */
char *
util_routineStartDaemonMessage(char *dname)
{
	static char msgBuf[MAXFAILSTRINGLEN];

	/*
	 * TRANSLATION_NOTE
	 *
	 * "%s failed to start and must be started manually. " indicates
	 * an error stsrting the daemon specified by the string used to
	 * replace %s.
	 */
	(void) snprintf(msgBuf, MAXFAILSTRINGLEN,
	    dgettext(TEXT_DOMAIN,
	    "%s failed to start and must be started manually. "),
	    dname);

	return (msgBuf);
}

static void
cleanupThreadExceptions(void *pParam)
{
	CCIMException	*e = pParam;
	cim_freeCIMException(e);
}

static void errorInit()
{
	/* Create the TSD key */
	(void) pthread_key_create(&gWbemDiskLastErrorKey,
	    cleanupThreadExceptions);
	if (gethostname(hostName, MAXHOSTNAMELEN) < 0) {
	    hostName[0] = '\0';
	}
}

static void
errorFinalize()
{
	(void) pthread_key_delete(gWbemDiskLastErrorKey);
}

static void
setLastError(CIMErrorReason pRsn,
    const cimchar* pErrString, const cimchar* pCallingFunc, int *errp)
{
	char 		*msgp = "(null)";
	CCIMException	*lastError = NULL;

	lastError =
	    (CCIMException *)pthread_getspecific(gWbemDiskLastErrorKey);

	if (lastError != NULL) {
	    cim_freeCIMException(lastError);
	}

	if (pErrString != NULL) {
	    msgp = (char *)pErrString;
	}

	lastError = cim_createException(pRsn, msgp, pCallingFunc);
	(void) pthread_setspecific(gWbemDiskLastErrorKey, lastError);
	*errp = 1;
}
