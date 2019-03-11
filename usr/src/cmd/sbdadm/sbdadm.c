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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright (c) 2018, Joyent, Inc.
 */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libintl.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <strings.h>
#include <ctype.h>
#include <libnvpair.h>
#include <locale.h>

#include <cmdparse.h>
#include <sys/stmf_defines.h>
#include <libstmf.h>
#include <sys/stmf_sbd_ioctl.h>

#define	MAX_LU_LIST	8192
#define	LU_LIST_MAX_RETRIES 3
#define	GUID_INPUT  32

#define	VERSION_STRING_MAJOR	    "1"
#define	VERSION_STRING_MINOR	    "0"
#define	VERSION_STRING_MAX_LEN	    10


char *cmdName;

static char *getExecBasename(char *);
int delete_lu(int argc, char *argv[], cmdOptions_t *options,
    void *callData);
int create_lu(int argc, char *argv[], cmdOptions_t *options, void *callData);
int list_lus(int argc, char *argv[], cmdOptions_t *options, void *callData);
int modify_lu(int argc, char *argv[], cmdOptions_t *options, void *callData);
int import_lu(int argc, char *argv[], cmdOptions_t *options, void *callData);
static int callModify(char *, stmfGuid *, uint32_t, const char *, const char *);
int print_lu_attr(stmfGuid *);
void print_guid(uint8_t *g, FILE *f);
void print_attr_header();

optionTbl_t options[] = {
	{ "disk-size", required_argument, 's',
			"Size with <none>/k/m/g/t/p/e modifier" },
	{ "keep-views", no_arg, 'k',
			"Dont delete view entries related to the LU" },
	{ NULL, 0, 0 }
};

subCommandProps_t subCommands[] = {
	{ "create-lu", create_lu, "s", NULL, NULL,
		OPERAND_MANDATORY_SINGLE,
		"Full path of the file to initialize" },
	{ "delete-lu", delete_lu, "k", NULL, NULL,
		OPERAND_MANDATORY_SINGLE, "GUID of the LU to deregister" },
	{ "import-lu", import_lu, NULL, NULL, NULL,
		OPERAND_MANDATORY_SINGLE, "filename of the LU to import" },
	{ "list-lu", list_lus, NULL, NULL, NULL,
		OPERAND_NONE, "List all the exported LUs" },
	{ "modify-lu", modify_lu, "s", "s", NULL,
		OPERAND_MANDATORY_SINGLE,
		"Full path of the LU or GUID of a registered LU" },
	{ NULL, 0, 0, NULL, 0, NULL}
};

/*ARGSUSED*/
int
create_lu(int argc, char *operands[], cmdOptions_t *options, void *callData)
{
	luResource hdl = NULL;
	int ret = 0;
	stmfGuid createdGuid;

	ret = stmfCreateLuResource(STMF_DISK, &hdl);

	if (ret != STMF_STATUS_SUCCESS) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("Failure to create lu resource\n"));
		return (1);
	}

	for (; options->optval; options++) {
		switch (options->optval) {
			case 's':
				ret = stmfSetLuProp(hdl, STMF_LU_PROP_SIZE,
				    options->optarg);
				if (ret != STMF_STATUS_SUCCESS) {
					(void) fprintf(stderr, "%s: %c: %s\n",
					    cmdName, options->optval,
					    gettext("size param invalid"));
					(void) stmfFreeLuResource(hdl);
					return (1);
				}
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, options->optval,
				    gettext("unknown option"));
				return (1);
		}
	}

	ret = stmfSetLuProp(hdl, STMF_LU_PROP_FILENAME, operands[0]);

	if (ret != STMF_STATUS_SUCCESS) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, gettext("could not set filename"));
		return (1);
	}

	ret = stmfCreateLu(hdl, &createdGuid);
	switch (ret) {
		case STMF_STATUS_SUCCESS:
			break;
		case STMF_ERROR_BUSY:
		case STMF_ERROR_LU_BUSY:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("resource busy"));
			ret++;
			break;
		case STMF_ERROR_PERM:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("permission denied"));
			ret++;
			break;
		case STMF_ERROR_FILE_IN_USE:
			(void) fprintf(stderr, "%s: filename %s: %s\n", cmdName,
			    operands[0], gettext("in use"));
			ret++;
			break;
		case STMF_ERROR_INVALID_BLKSIZE:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("invalid block size"));
			ret++;
			break;
		case STMF_ERROR_GUID_IN_USE:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("guid in use"));
			ret++;
			break;
		case STMF_ERROR_META_FILE_NAME:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("meta file error"));
			ret++;
			break;
		case STMF_ERROR_DATA_FILE_NAME:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("data file error"));
			ret++;
			break;
		case STMF_ERROR_SIZE_OUT_OF_RANGE:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("invalid size"));
			ret++;
			break;
		case STMF_ERROR_META_CREATION:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("could not create meta file"));
			ret++;
			break;
		default:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("unknown error"));
			ret++;
			break;
	}

	if (ret != STMF_STATUS_SUCCESS) {
		goto done;
	}

	(void) printf("Created the following LU:\n");
	print_attr_header();
	ret = print_lu_attr(&createdGuid);

done:
	(void) stmfFreeLuResource(hdl);
	return (ret);
}

/*ARGSUSED*/
int
import_lu(int argc, char *operands[], cmdOptions_t *options, void *callData)
{
	int ret = 0;
	stmfGuid createdGuid;

	ret = stmfImportLu(STMF_DISK, operands[0], &createdGuid);
	switch (ret) {
		case STMF_STATUS_SUCCESS:
			break;
		case STMF_ERROR_BUSY:
		case STMF_ERROR_LU_BUSY:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("resource busy"));
			ret++;
			break;
		case STMF_ERROR_PERM:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("permission denied"));
			ret++;
			break;
		case STMF_ERROR_FILE_IN_USE:
			(void) fprintf(stderr, "%s: filename %s: %s\n", cmdName,
			    operands[0], gettext("in use"));
			ret++;
			break;
		case STMF_ERROR_GUID_IN_USE:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("guid in use"));
			ret++;
			break;
		case STMF_ERROR_META_FILE_NAME:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("meta file error"));
			ret++;
			break;
		case STMF_ERROR_DATA_FILE_NAME:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("data file error"));
			ret++;
			break;
		case STMF_ERROR_SIZE_OUT_OF_RANGE:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("invalid size"));
			ret++;
			break;
		case STMF_ERROR_META_CREATION:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("could not create meta file"));
			ret++;
			break;
		default:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("unknown error"));
			ret++;
			break;
	}

	if (ret != STMF_STATUS_SUCCESS) {
		goto done;
	}

	(void) printf("Imported the following LU:\n");
	print_attr_header();
	ret = print_lu_attr(&createdGuid);

done:
	return (ret);
}

/*ARGSUSED*/
int
delete_lu(int operandLen, char *operands[], cmdOptions_t *options,
    void *callData)
{
	int i, j;
	int ret = 0;
	int stmfRet;
	unsigned int inGuid[sizeof (stmfGuid)];
	stmfGuid delGuid;
	boolean_t keepViews = B_FALSE;
	boolean_t viewEntriesRemoved = B_FALSE;
	boolean_t noLunFound = B_FALSE;
	boolean_t views = B_FALSE;
	boolean_t notValidHexNumber = B_FALSE;
	char sGuid[GUID_INPUT + 1];
	stmfViewEntryList *viewEntryList = NULL;

	for (; options->optval; options++) {
		switch (options->optval) {
			/* Keep views for logical unit */
			case 'k':
				keepViews = B_TRUE;
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, options->optval,
				    gettext("unknown option"));
				return (1);
		}
	}


	for (i = 0; i < operandLen; i++) {
		for (j = 0; j < GUID_INPUT; j++) {
			if (!isxdigit(operands[i][j])) {
				notValidHexNumber = B_TRUE;
				break;
			}
			sGuid[j] = tolower(operands[i][j]);
		}
		if ((notValidHexNumber == B_TRUE) ||
		    (strlen(operands[i]) != GUID_INPUT)) {
			(void) fprintf(stderr, "%s: %s: %s%d%s\n",
			    cmdName, operands[i], gettext("must be "),
			    GUID_INPUT,
			    gettext(" hexadecimal digits long"));
			notValidHexNumber = B_FALSE;
			ret++;
			continue;
		}

		sGuid[j] = 0;

		(void) sscanf(sGuid,
		    "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
		    &inGuid[0], &inGuid[1], &inGuid[2], &inGuid[3],
		    &inGuid[4], &inGuid[5], &inGuid[6], &inGuid[7],
		    &inGuid[8], &inGuid[9], &inGuid[10], &inGuid[11],
		    &inGuid[12], &inGuid[13], &inGuid[14], &inGuid[15]);

		for (j = 0; j < sizeof (stmfGuid); j++) {
			delGuid.guid[j] = inGuid[j];
		}

		stmfRet = stmfDeleteLu(&delGuid);
		switch (stmfRet) {
			case STMF_STATUS_SUCCESS:
				break;
			case STMF_ERROR_NOT_FOUND:
				noLunFound = B_TRUE;
				break;
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("resource busy"));
				ret++;
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				ret++;
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("unknown error"));
				ret++;
				break;
		}

		if (!keepViews) {
			stmfRet = stmfGetViewEntryList(&delGuid,
			    &viewEntryList);
			if (stmfRet == STMF_STATUS_SUCCESS) {
				for (j = 0; j < viewEntryList->cnt; j++) {
					(void) stmfRemoveViewEntry(&delGuid,
					    viewEntryList->ve[j].veIndex);
				}
				/* check if viewEntryList is empty */
				if (viewEntryList->cnt != 0)
					viewEntriesRemoved = B_TRUE;
				stmfFreeMemory(viewEntryList);
			} else {
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("unable to remove view entries\n"));
				ret++;
			}
		}
		if (keepViews) {
			stmfRet = stmfGetViewEntryList(&delGuid,
			    &viewEntryList);
			if (stmfRet == STMF_STATUS_SUCCESS) {
				views = B_TRUE;
				stmfFreeMemory(viewEntryList);
			}
		}

		if ((!viewEntriesRemoved && noLunFound && !views) ||
		    (!views && keepViews && noLunFound)) {
			(void) fprintf(stderr, "%s: %s: %s\n",
			    cmdName, sGuid,
			    gettext("not found"));
			ret++;
		}
		noLunFound = viewEntriesRemoved = views = B_FALSE;
	}
	return (ret);
}

/*ARGSUSED*/
int
modify_lu(int operandLen, char *operands[], cmdOptions_t *options,
    void *callData)
{
	stmfGuid inGuid;
	unsigned int guid[sizeof (stmfGuid)];
	int ret = 0;
	int i;
	char *fname = NULL;
	char sGuid[GUID_INPUT + 1];
	boolean_t fnameUsed = B_FALSE;

	if (operands[0][0] == '/') {
		fnameUsed = B_TRUE;
		fname = operands[0];
	}

	/* check input length */
	if (!fnameUsed && strlen(operands[0]) != GUID_INPUT) {
		(void) fprintf(stderr, "%s: %s: %s%d%s\n", cmdName, operands[0],
		    gettext("must be "), GUID_INPUT,
		    gettext(" hexadecimal digits"));
		return (1);
	}

	if (!fnameUsed) {
		/* convert to lower case for scan */
		for (i = 0; i < 32; i++)
			sGuid[i] = tolower(operands[0][i]);
		sGuid[i] = 0;
		(void) sscanf(sGuid,
		    "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
		    &guid[0], &guid[1], &guid[2], &guid[3], &guid[4], &guid[5],
		    &guid[6], &guid[7], &guid[8], &guid[9], &guid[10],
		    &guid[11], &guid[12], &guid[13], &guid[14], &guid[15]);

		for (i = 0; i < sizeof (stmfGuid); i++) {
			inGuid.guid[i] = guid[i];
		}
	}

	for (; options->optval; options++) {
		switch (options->optval) {
			case 's':
				if (callModify(fname, &inGuid,
				    STMF_LU_PROP_SIZE, options->optarg,
				    "size") != 0) {
					return (1);
				}
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, options->optval,
				    gettext("unknown option"));
				return (1);
		}
	}
	return (ret);
}

static int
callModify(char *fname, stmfGuid *luGuid, uint32_t prop, const char *propVal,
    const char *propString)
{
	int ret = 0;
	int stmfRet = 0;

	if (!fname) {
		stmfRet = stmfModifyLu(luGuid, prop, propVal);
	} else {
		stmfRet = stmfModifyLuByFname(STMF_DISK, fname, prop,
		    propVal);
	}
	switch (stmfRet) {
		case STMF_STATUS_SUCCESS:
			break;
		case STMF_ERROR_BUSY:
		case STMF_ERROR_LU_BUSY:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("resource busy"));
			ret++;
			break;
		case STMF_ERROR_PERM:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("permission denied"));
			ret++;
			break;
		case STMF_ERROR_INVALID_BLKSIZE:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("invalid block size"));
			ret++;
			break;
		case STMF_ERROR_GUID_IN_USE:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("guid in use"));
			ret++;
			break;
		case STMF_ERROR_META_FILE_NAME:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("meta file error"));
			ret++;
			break;
		case STMF_ERROR_DATA_FILE_NAME:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("data file error"));
			ret++;
			break;
		case STMF_ERROR_FILE_SIZE_INVALID:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("file size invalid"));
			ret++;
			break;
		case STMF_ERROR_SIZE_OUT_OF_RANGE:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("invalid size"));
			ret++;
			break;
		case STMF_ERROR_META_CREATION:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("could not create meta file"));
			ret++;
			break;
		default:
			(void) fprintf(stderr, "%s: %s: %s: %d\n", cmdName,
			    gettext("could not set property"), propString,
			    stmfRet);
			ret++;
			break;
	}

	return (ret);
}


/*ARGSUSED*/
int
list_lus(int argc, char *argv[], cmdOptions_t *options, void *callData)
{
	int stmfRet;
	stmfGuidList *luList;
	stmfLogicalUnitProperties luProps;
	int sbdLuCnt = 0;
	int i;

	if ((stmfRet = stmfGetLogicalUnitList(&luList))
	    != STMF_STATUS_SUCCESS) {
		switch (stmfRet) {
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				break;
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("resource busy"));
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("list failed"));
				break;
		}
		return (1);
	}

	for (i = 0; i < luList->cnt; i++) {
		stmfRet = stmfGetLogicalUnitProperties(&luList->guid[i],
		    &luProps);
		if (stmfRet != STMF_STATUS_SUCCESS) {
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("list failed"));
			return (1);
		}
		if (strcmp(luProps.providerName, "sbd") == 0) {
			sbdLuCnt++;
		}
	}


	if (sbdLuCnt == 0)
		return (0);

	(void) printf("\nFound %d LU(s)\n", sbdLuCnt);
	print_attr_header();

	for (i = 0; i < luList->cnt; i++) {
		stmfRet = stmfGetLogicalUnitProperties(&luList->guid[i],
		    &luProps);
		if (stmfRet != STMF_STATUS_SUCCESS) {
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("list failed"));
			return (1);
		}
		if (strcmp(luProps.providerName, "sbd") == 0) {
			(void) print_lu_attr(&luList->guid[i]);
		}
	}
	return (0);
}

void
print_attr_header()
{
	(void) printf("\n");
	(void) printf("	      GUID                    DATA SIZE      "
	    "     SOURCE\n");
	(void) printf("--------------------------------  -------------------"
	    "  ----------------\n");
}

void
print_guid(uint8_t *g, FILE *f)
{
	int i;

	for (i = 0; i < 16; i++) {
		(void) fprintf(f, "%02x", g[i]);
	}
}

int
print_lu_attr(stmfGuid *guid)
{
	luResource hdl = NULL;
	int stmfRet = 0;
	int ret = 0;
	char propVal[MAXPATHLEN];
	size_t propValSize = sizeof (propVal);

	if ((stmfRet = stmfGetLuResource(guid, &hdl)) != STMF_STATUS_SUCCESS) {
		switch (stmfRet) {
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("resource busy"));
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			case STMF_ERROR_NOT_FOUND:
				/* No error here */
				return (0);
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("get extended properties failed"));
				break;
		}
		return (1);
	}

	print_guid((uint8_t *)guid, stdout);

	stmfRet = stmfGetLuProp(hdl, STMF_LU_PROP_SIZE, propVal,
	    &propValSize);
	if (stmfRet == STMF_STATUS_SUCCESS) {
		(void) printf("  %-19s  ", propVal);
	} else if (stmfRet == STMF_ERROR_NO_PROP) {
		(void) printf("not set\n");
	} else {
		(void) printf("<error retrieving property>\n");
		ret++;
	}

	stmfRet = stmfGetLuProp(hdl, STMF_LU_PROP_FILENAME, propVal,
	    &propValSize);
	if (stmfRet == STMF_STATUS_SUCCESS) {
		(void) printf("%s\n", propVal);
	} else if (stmfRet == STMF_ERROR_NO_PROP) {
		(void) printf("not set\n");
	} else {
		(void) printf("<error retrieving property>\n");
		ret++;
	}


	(void) stmfFreeLuResource(hdl);
	return (ret);
}

/*
 * input:
 *  execFullName - exec name of program (argv[0])
 *
 *  copied from usr/src/cmd/zoneadm/zoneadm.c in OS/Net
 *  (changed name to lowerCamelCase to keep consistent with this file)
 *
 * Returns:
 *  command name portion of execFullName
 */
static char *
getExecBasename(char *execFullname)
{
	char *lastSlash, *execBasename;

	/* guard against '/' at end of command invocation */
	for (;;) {
		lastSlash = strrchr(execFullname, '/');
		if (lastSlash == NULL) {
			execBasename = execFullname;
			break;
		} else {
			execBasename = lastSlash + 1;
			if (*execBasename == '\0') {
				*lastSlash = '\0';
				continue;
			}
			break;
		}
	}
	return (execBasename);
}
int
main(int argc, char *argv[])
{
	synTables_t synTables;
	char versionString[VERSION_STRING_MAX_LEN];
	int ret;
	int funcRet;
	void *subcommandArgs = NULL;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);
	/* set global command name */
	cmdName = getExecBasename(argv[0]);

	(void) snprintf(versionString, VERSION_STRING_MAX_LEN, "%s.%s",
	    VERSION_STRING_MAJOR, VERSION_STRING_MINOR);
	synTables.versionString = versionString;
	synTables.longOptionTbl = options;
	synTables.subCommandPropsTbl = subCommands;

	ret = cmdParse(argc, argv, synTables, subcommandArgs, &funcRet);
	if (ret != 0) {
		return (ret);
	}

	return (funcRet);
} /* end main */
