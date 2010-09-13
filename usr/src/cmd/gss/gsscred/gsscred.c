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
 * Copyright 1997-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  gsscred utility
 *  Manages mapping between a security principal name and unix uid
 */

#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <unistd.h>
#include <string.h>
#include <gssapi/gssapi_ext.h>
#include "gsscred.h"

#define	MAX_STR_LEN	1024


/*
 * Internal Functions
 */
static void usage(void);
static void addUser(const char *name, const char *oid, const char *userUid,
		const char *userComment, const char *userMech);
static int file_listUsers(const gss_OID mechOid, const char *userUid,
		char **errDetails);
static int listUsers(const char *name, const char *nameTypeOid,
		const char *uid, const char *mechOid);
static int file_removeUsers(const gss_OID mechOid, const char *userUid,
		char **errDetails);
static int removeUsers(const char *name, const char *nameTypeOid,
		const char *uid, const char *mechOid);

/*
 * Global variables
 */
static int tableSource;
static char *PROG_NAME = NULL;

int
main(int argc, char *args[])
{
	char *userName = NULL, *nameTypeOID = NULL,
		*uid = NULL, *comment = NULL, *mech = NULL,
		operation = '0';
	int c, errflag = 0;
	extern char *optarg;

	PROG_NAME = *args;

	/* set locale and domain for internationalization */
	setlocale(LC_ALL, "");
	textdomain(TEXT_DOMAIN);

	if (argc < 2)
		usage();

	/* Process the input arguments */
	while ((c = getopt(argc, args, "arln:o:u:m:c:")) != EOF) {

		switch (c) {
		case 'n':
			userName = optarg;
			break;

		case 'o':
			nameTypeOID = optarg;
			break;

		case 'u':
			uid = optarg;
			break;

		case 'm':
			mech = optarg;
			break;

		case 'c':
			comment = optarg;
			break;

		case 'a':
		case 'r':
		case 'l':
			operation = c;
			errflag++;
			if (errflag > 1)
				usage();
			break;

		default:
			usage();
		}
	}

	/* determine which back-end to use as the gsscred store */
	tableSource = gsscred_read_config_file();

	/* perform the requested operation */
	switch (operation) {
		case 'a':
			addUser(userName, nameTypeOID, uid, comment, mech);
			break;

		case 'r':
			removeUsers(userName, nameTypeOID, uid, mech);
			break;

		case 'l':
			listUsers(userName, nameTypeOID, uid, mech);
			break;

		default:
			usage();
	}
	fprintf(stdout, "\n");
	return (0);
}  /* main */

/*
 * Handles the addition of users to the gsscred table.
 */
static void
addUser(const char *name, const char *nameOidStr,
	    const char *userUid, const char *userComment,
	    const char *mechOidStr)
{
	gss_OID mechOid;
	gss_buffer_desc fullName = GSS_C_EMPTY_BUFFER,
		hexBufDesc = GSS_C_EMPTY_BUFFER,
		hexMechOid = GSS_C_EMPTY_BUFFER;
	char comment[MAX_STR_LEN+1], hexBuf[MAX_STR_LEN+MAX_STR_LEN+1],
		hexMechOidBuf[MAX_STR_LEN+1], *commentPtr = NULL,
		*errDetail = NULL, uidStr[256], *uidPtr;
	struct passwd *aUser;
	OM_uint32 minor;
	int count = 0, retCode;

	hexMechOid.length = MAX_STR_LEN;
	hexMechOid.value = (void*)hexMechOidBuf;

	/* addition of users can only be performed by super users */
	if (getuid()) {
		fprintf(stderr,
			gettext("\nUser addition requires"
				" root privileges."));
		return;
	}

	/* the mechanism OID is required */
	if (mechOidStr == NULL) {
		fprintf(stderr, gettext("\nUnspecified mechanism."));
		usage();
	}

	/* Convert from string mechanism Oid to ASN.1 oid and then hex */
	if (__gss_mech_to_oid(mechOidStr, &mechOid) != GSS_S_COMPLETE) {
		fprintf(stderr,
			gettext("\nInvalid mechanism specified [%s]."),
			mechOidStr);
		return;
	}

	hexBufDesc.length = mechOid->length;
	hexBufDesc.value = mechOid->elements;

	if (!gsscred_AsHex(&hexBufDesc, &hexMechOid)) {
		fprintf(stderr,
			gettext("\nInternal error.  "
				"Conversion to hex failed."));
		return;
	}

	/*
	 * if the name is specified, then do single addition.
	 * Might have to look up the uid.
	 */
	if (name != NULL) {
		hexBufDesc.length = sizeof (hexBuf);
		hexBufDesc.value = hexBuf;

		/* build the name as needed */
		if (!gsscred_MakeName(mechOid, name, nameOidStr, &fullName)) {
			fprintf(stderr,
				gettext("\nError adding user [%s]."), name);
			return;
		}

		/* convert it to hex */
		if (!gsscred_AsHex(&fullName, &hexBufDesc)) {
			gss_release_buffer(&minor, &fullName);
			fprintf(stderr,
				gettext("\nInternal error.  "
					"Conversion to hex failed."));
			return;
		}

		/* might require the lookup of the uid if one not specified */
		if (userUid == NULL) {

			if ((aUser = getpwnam(name)) == NULL) {
				fprintf(stderr,
					gettext("\nUnable to obtain password"
						" information for [%s]."),
					name);
				gss_release_buffer(&minor, &fullName);
				return;
			}
			sprintf(uidStr, "%ld", aUser->pw_uid);
			uidPtr = uidStr;
		}
		else
			uidPtr = (char *)userUid;

		if (userComment == NULL) {
			sprintf(comment, "%s, %s", name, mechOidStr);
			commentPtr = comment;
		} else
			commentPtr = (char *)userComment;

		if (tableSource == GSSCRED_FLAT_FILE)
			retCode = file_addGssCredEntry(&hexBufDesc,
					uidPtr, commentPtr, &errDetail);
		else
			/* other backends (ldap, dss) coming soon */
			retCode	= 0;

		if (!retCode) {
			fprintf(stderr, gettext("\nError adding user [%s]."),
				commentPtr);

			if (errDetail) {
				fprintf(stderr, "\n%s\n", errDetail);
				free(errDetail);
				errDetail = NULL;
			}
		}

		gss_release_buffer(&minor, &fullName);
		return;
	}

	/*
	 * since no name specified, then we will load everyone from
	 * password table.  This means that -u and -o options are invalid.
	 * We just ignore it, but we could flag it as error.
	 */
	setpwent();

	while ((aUser = getpwent()) != NULL) {
		hexBufDesc.length = sizeof (hexBuf);
		hexBufDesc.value = hexBuf;

		if (!gsscred_MakeName(mechOid, aUser->pw_name,
			nameOidStr, &fullName)) {
			fprintf(stderr,
				gettext("\nError adding user [%s]."),
				aUser->pw_name);
			continue;
		}

		if (!gsscred_AsHex(&fullName, &hexBufDesc)) {
			gss_release_buffer(&minor, &fullName);
			fprintf(stderr,
				gettext("\nInternal error.  "
					"Conversion to hex failed."));
			continue;
		}

		sprintf(uidStr, "%ld", aUser->pw_uid);
		sprintf(comment, "%s, %s", aUser->pw_name, mechOidStr);
		if (tableSource == GSSCRED_FLAT_FILE)
			retCode = file_addGssCredEntry(&hexBufDesc,
					uidStr, comment, &errDetail);
		else
			retCode	= 0;

		if (!retCode) {
			fprintf(stderr,
				gettext("\nError adding user [%s]."),
				comment);

			if (errDetail) {
				fprintf(stderr, "\n%s\n", errDetail);
				free(errDetail);
				errDetail = NULL;
			}
		} else {
			count++;
			if ((count % 50) == 0)
				fprintf(stdout,
					gettext("\n[%d] users added..."),
					count);
		}
		gss_release_buffer(&minor, &fullName);
	}
	endpwent();
}  /* addUser */


/*
 *  Handles the searching of the gsscred table.
 */
static int listUsers(const char *name, const char *nameOidStr,
		const char *uidStr, const char *mechOidStr)
{
	GssCredEntry *entryPtr, *entryTmpPtr;
	char hexMech[256],
		hexName[(MAX_STR_LEN *2) + 1];
	gss_OID anOid = NULL, userMechOid = NULL;
	gss_OID_set mechSet = NULL;
	gss_buffer_desc inBufDesc = GSS_C_EMPTY_BUFFER,
		outBufDesc = GSS_C_EMPTY_BUFFER,
		searchName = GSS_C_EMPTY_BUFFER;
	int status = 1, numOfMechs, i;
	OM_uint32 minor;
	char *errDetails = NULL;

	/* Do we need to convert the mechanism oid? */
	if (mechOidStr != NULL) {

		if (__gss_mech_to_oid(mechOidStr, &userMechOid) !=
			GSS_S_COMPLETE) {
			fprintf(stderr,
				gettext("\nInvalid mechanism specified [%s]."),
				mechOidStr);
			return (0);
		}
		inBufDesc.length = userMechOid->length;
		inBufDesc.value = userMechOid->elements;
		outBufDesc.length = sizeof (hexMech);
		outBufDesc.value = hexMech;

		if (!gsscred_AsHex(&inBufDesc, &outBufDesc)) {
			fprintf(stderr,
				gettext("\nInternal error.  "
					"Conversion to hex failed."));
			status = 0;
			goto cleanup;
		}

	}	/* mechOidStr != NULL */

	/* are we retrieving everyone ? or searching by mech ? */
	if ((name == NULL && uidStr == NULL && mechOidStr == NULL) ||
	    (name == NULL && uidStr == NULL)) {

		if (tableSource == GSSCRED_FLAT_FILE) {
			file_listUsers(userMechOid, NULL, &errDetails);

			if (errDetails) {
				fprintf(stderr,
					gettext("\nError searching gsscred"
						" table [%s]."),
					errDetails);
				free(errDetails);
				errDetails = NULL;
				return (0);
			}
			return (1);
		}

	}

	/* Are we searching by uid or uid and mech? */
	if (name == NULL && uidStr != NULL) {

		if (tableSource == GSSCRED_FLAT_FILE)
			file_listUsers(userMechOid, uidStr, &errDetails);
		else {
			entryPtr = NULL;
			while (entryPtr != NULL) {
				fprintf(stdout, "\n%s\t%d\t%s",
					entryPtr->principal_name,
					entryPtr->unix_uid, entryPtr->comment);
				free(entryPtr->principal_name);
				free(entryPtr->comment);
				entryTmpPtr = entryPtr->next;
				free(entryPtr);
				entryPtr = entryTmpPtr;
			}
		}

		/* check for any errors */
		if (errDetails) {
			fprintf(stderr,
				gettext("\nError searching gsscred table "
					"[%s]."),
				errDetails);
			free(errDetails);
			errDetails = NULL;
			status = 0;
		}

		goto cleanup;
	}

	/*
	 * We are searching by name;
	 * how many mechs must we check?
	 */
	if (mechOidStr == NULL) {

		if (gss_indicate_mechs(&minor, &mechSet) != GSS_S_COMPLETE) {
			fprintf(stderr,
				gettext("\nInternal error.  "
					"GSS-API call failed."));
			return (0);
		}
		numOfMechs = mechSet->count;
	}
	else
		numOfMechs = 1;

	/* now look through all the mechs searching */
	for (i = 0; i < numOfMechs; i++) {

		if (mechOidStr == NULL) {
			anOid = &mechSet->elements[i];
			inBufDesc.length = anOid->length;
			inBufDesc.value = anOid->elements;
			outBufDesc.length = sizeof (hexMech);
			outBufDesc.value = hexMech;

			if (!gsscred_AsHex(&inBufDesc, &outBufDesc))
				continue;
		} else
			anOid = userMechOid;

		/* create a gss name */
		if (!gsscred_MakeName(anOid, name, nameOidStr, &outBufDesc))
			continue;

		/* now convert it to hex, and find it */
		searchName.value = hexName;
		searchName.length = sizeof (hexName);
		status = gsscred_AsHex(&outBufDesc, &searchName);
		free(outBufDesc.value);

		if (!status)
			continue;

		if (tableSource == GSSCRED_FLAT_FILE)
			file_getGssCredEntry(&searchName, uidStr, &errDetails);
		else {
			entryPtr = NULL;  /* other backends coming soon */
			while (entryPtr != NULL) {
				fprintf(stdout, "\n%s\t%d\t%s",
					entryPtr->principal_name,
					entryPtr->unix_uid, entryPtr->comment);
				free(entryPtr->principal_name);
				free(entryPtr->comment);
				entryTmpPtr = entryPtr->next;
				free(entryPtr);
				entryPtr = entryTmpPtr;
			}
		}

		/* any errors to display */
		if (errDetails) {
			fprintf(stderr,
				gettext("\nError searching gsscred table "
					"[%s]."),
				errDetails);
			free(errDetails);
			errDetails = NULL;
			status = 0;
		}
	}	/* for */

cleanup:
	if (mechSet != NULL)
		gss_release_oid_set(&minor, &mechSet);

	return (status);
}  /* listUsers */

/*
 * Performs additional handling while searching for users
 * stored in the flat file table.
 */
int
file_listUsers(const gss_OID mechOid, const char *unixUid,
		char **errDetails)
{
	gss_buffer_desc mechBufDesc = GSS_C_EMPTY_BUFFER,
		mechHexBufDesc = GSS_C_EMPTY_BUFFER;
	char mechBuf[128], mechHexBuf[256];

	if (mechOid != NULL) {
		/* must make the name header whic contains mech oid */
		mechBufDesc.value = (void *) mechBuf;
		mechBufDesc.length = sizeof (mechBuf);
		mechHexBufDesc.value = (void*) mechHexBuf;
		mechHexBufDesc.length = sizeof (mechHexBuf);

		if ((!gsscred_MakeNameHeader(mechOid, &mechBufDesc)) ||
			(!gsscred_AsHex(&mechBufDesc, &mechHexBufDesc))) {
			(*errDetails) = strdup(
					gettext("\nInternal error. "
					" Conversion to hex failed."));
			return (0);
		}

		return (file_getGssCredEntry(&mechHexBufDesc,
				unixUid, errDetails));
	}

	return (file_getGssCredEntry(NULL, unixUid, errDetails));
}  /* file_listUsers */


/*
 *  Handles the deletion of users.
 */
static int removeUsers(const char *name, const char *nameOidStr,
		const char *uidStr, const char *mechOidStr)
{
	char hexMech[256],
		hexName[(MAX_STR_LEN *2) + 1],
		*errDetails = NULL;
	gss_OID anOid = NULL, userMechOid = NULL;
	gss_OID_set mechSet = NULL;
	gss_buffer_desc inBufDesc = GSS_C_EMPTY_BUFFER,
		outBufDesc = GSS_C_EMPTY_BUFFER,
		searchName = GSS_C_EMPTY_BUFFER;
	int status = 0, numOfMechs, i;
	OM_uint32 minor;


	/* user deletion can only be performed by super user */
	if (getuid()) {

		fprintf(stderr,
			gettext("\nUser deletion requires"
				" root privileges."));
		return (0);
	}

	/* do we need to convert the mechanism oid? */
	if (mechOidStr != NULL) {
		if (__gss_mech_to_oid(mechOidStr, &userMechOid) !=
		GSS_S_COMPLETE) {
			fprintf(stderr,
				gettext("\nInvalid mechanism specified [%s]."),
				mechOidStr);
			return (0);
		}

		inBufDesc.length = userMechOid->length;
		inBufDesc.value = userMechOid->elements;
		outBufDesc.length = sizeof (hexMech);
		outBufDesc.value = hexMech;

		if (!gsscred_AsHex(&inBufDesc, &outBufDesc)) {
			fprintf(stderr,
				gettext("\nInternal error."
					"  Conversion to hex failed."));
			status = 0;
			goto cleanup;
		}

	}	 /* mechOidStr != NULL */

	/* are we deleting the entire table or an entire mech ? */
	if (name == NULL && uidStr == NULL) {

		if (tableSource == GSSCRED_FLAT_FILE)
			status = file_removeUsers(userMechOid,
					NULL, &errDetails);
		else
			status = 0;

		/* display any errors */
		if (errDetails) {
			fprintf(stderr,
				gettext("\nError deleting gsscred entry "
					"[%s]."),
				errDetails);
			free(errDetails);
			errDetails = NULL;
		}
		goto cleanup;
	}

	/* are we deleting by uid or uid and mech? */
	if (name == NULL && uidStr != NULL) {

		if (tableSource == GSSCRED_FLAT_FILE)
			status = file_removeUsers(userMechOid, uidStr,
						&errDetails);
		else
			status = 0;

		/* check for any errors */
		if (errDetails) {
			fprintf(stderr,
				gettext("\nError deleting gsscred entry "
					"[%s]."),
				errDetails);
			free(errDetails);
			errDetails = NULL;
		}
		goto cleanup;
	}

	/*
	 * We are deleting by name;
	 * how many mechs must we check?
	 */
	if (mechOidStr == NULL) {

		if (gss_indicate_mechs(&minor, &mechSet) != GSS_S_COMPLETE) {
			fprintf(stderr,
				gettext("\nInternal error.  "
					"GSS-API call failed."));
			status = 0;
			goto cleanup;
		}
		numOfMechs = mechSet->count;
	}
	else
		numOfMechs = 1;

	/* now look through all the mechs, deleting */
	for (i = 0; i < numOfMechs; i++) {

		if (mechOidStr == NULL) {
			anOid = &mechSet->elements[i];
			inBufDesc.length = anOid->length;
			inBufDesc.value = anOid->elements;
			outBufDesc.length = sizeof (hexMech);
			outBufDesc.value = hexMech;
			if (!gsscred_AsHex(&inBufDesc, &outBufDesc))
				continue;
		} else
			anOid = userMechOid;

		/* create a gss name */
		if (!gsscred_MakeName(anOid, name, nameOidStr, &outBufDesc))
			continue;

		/* now convert it to hex, and delete it */
		searchName.value = hexName;
		searchName.length = sizeof (hexName);
		status = gsscred_AsHex(&outBufDesc, &searchName);
		free(outBufDesc.value);

		if (!status)
			continue;

		if (tableSource == GSSCRED_FLAT_FILE)
			status = file_deleteGssCredEntry(&searchName,
					uidStr, &errDetails);
		else
			status = 0;

		/* check for any errors */
		if (errDetails) {
			fprintf(stderr,
				gettext("\nError deleting gsscred entry"
					" [%s]."),
				errDetails);
			free(errDetails);
			errDetails = NULL;
		}
	}	 /* for */

cleanup:
	if (mechSet != NULL)
		gss_release_oid_set(&minor, &mechSet);

	return (status);
}  /* removeUsers */


/*
 * Performs additional handling while deleting users
 * stored in the flat file table.
 */
int file_removeUsers(const gss_OID mechOid, const char *unixUid,
		char **errDetails)
{
	gss_buffer_desc mechBufDesc = GSS_C_EMPTY_BUFFER,
		mechHexBufDesc = GSS_C_EMPTY_BUFFER;
	char mechBuf[128], mechHexBuf[256];

	if (mechOid != NULL) {
		/*
		 * need to create the buffer header which contains
		 * the mechanism oid.
		 */
		mechBufDesc.value = (void*) mechBuf;
		mechBufDesc.length = sizeof (mechBuf);
		mechHexBufDesc.value = (void *) mechHexBuf;
		mechHexBufDesc.length = sizeof (mechHexBuf);

		if ((!gsscred_MakeNameHeader(mechOid, &mechBufDesc)) ||
		    (!gsscred_AsHex(&mechBufDesc, &mechHexBufDesc))) {
			(*errDetails) = strdup(
				gettext("\nInternal error."
					"  Conversion to hex failed."));
			return (0);
		}

		return (file_deleteGssCredEntry(&mechHexBufDesc, unixUid,
						errDetails));
	}

	return (file_deleteGssCredEntry(NULL, unixUid, errDetails));
}  /* file_removeUsers */


/*
 * Prints the usage string, and terminates.
 */
static void usage(void)
{

	fprintf(stderr,
		gettext("\nUsage:\t %s [-n user [-o oid] [-u uid]]"
			" [-c comment] -m mech -a"
			"\n\t %s [-n user [-o oid]] [-u uid] [-m mech] -r"
			"\n\t %s [-n user [-o oid]] [-u uid] [-m mech] -l\n"),
		PROG_NAME, PROG_NAME, PROG_NAME);
	exit(1);
}  /* usage */
