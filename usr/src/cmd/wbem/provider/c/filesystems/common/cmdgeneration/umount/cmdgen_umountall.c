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

#include "cmdgen_include.h"

/*
 * Public data type declaration
 */
#define	UMNTALL_CMD "/usr/sbin/umountall"
#define	FSTYPE_FLAG "-F"
#define	HOST_FLAG "-h"
#define	KILL_FLAG "-k"
#define	LOCAL_FLAG "-l"
#define	NO_PARALLEL_FLAG "-s"
#define	REMOTE_FLAG "-r"
#define	SPACE " "


/*
 * Public methods
 */
/*
 * Method: cmdgen_umountall
 *
 * Description: Forms the umountall command with the options given.
 *
 * Parameters:
 *	- CCIMPropertyList *paramList - The parameter list containing the
 *	options for the umountall command.
 *	- int *errp - The error indicator.  Upon error, this will get set to a
 *	value != 0.
 *
 * Returns:
 *	- char * - The formed umounall command.
 *	- NULL if an error occurred.
 */
char *
cmdgen_umountall(CCIMPropertyList *paramList, int *errp) {
	CCIMPropertyList	*currentParam;
	CCIMProperty		*fstypeProp = NULL;
	CCIMProperty		*hostProp = NULL;
	CCIMProperty		*onlyLocalProp = NULL;
	CCIMProperty		*onlyRemoteProp = NULL;
	CCIMProperty		*killProcessesProp = NULL;
	CCIMProperty		*inParallelProp = NULL;
	char			*cmd = NULL;
	int			cmdLen;

	cmd = strdup(UMNTALL_CMD);
	if (cmd == NULL) {
		*errp = errno;
		return (NULL);
	}

	/*
	 * In parameters in the paramList are as follows:
	 * 1. String fstype,
	 * 2. String host,
	 * 3. Boolean onlyLocalFileSystems,
	 * 4. Boolean onlyRemoteFileSystems,
	 * 5. Boolean killProcesses,
	 * 6. Boolean umountInParallel
	 *
	 * They are expected to always be in this order in the property list.
	 */
	/*
	 * Check if a file system type was passed in.  If one was we will
	 * use this in forming the command.
	 */
	currentParam = paramList;
	fstypeProp = currentParam->mDataObject;
	if (fstypeProp != NULL && fstypeProp->mValue != NULL &&
		strlen(fstypeProp->mValue) != 0) {

		cim_logDebug("cmdgen_umountall", "Adding the -F flag");
		/*
		 * Add -F <fstype> to the command
		 */
		cmdLen = strlen(cmd) + strlen(SPACE) + strlen(FSTYPE_FLAG) +
			strlen(SPACE) + strlen(fstypeProp->mValue) + 1;
		cmd = realloc(cmd, (size_t)(cmdLen * sizeof (char)));
		if (cmd == NULL) {
			*errp = errno;
			return (NULL);
		}
		(void) snprintf(cmd, cmdLen, "%s%s%s%s%s", cmd, SPACE,
		    FSTYPE_FLAG, SPACE, fstypeProp->mValue);
	}

	/*
	 * Check if a host was passed in.
	 */
	currentParam = currentParam->mNext;
	hostProp = currentParam->mDataObject;
	if (hostProp != NULL && hostProp->mValue != NULL &&
		strlen(hostProp->mValue) != 0) {

		cim_logDebug("cmdgen_umountall", "Adding the -h flag");
		/*
		 * Add -h <host> to the command.
		 */
		cmdLen = strlen(cmd) + strlen(SPACE) + strlen(HOST_FLAG) +
			strlen(SPACE) + strlen(hostProp->mValue) + 1;
		cmd = realloc(cmd, (size_t)(cmdLen * sizeof (char)));
		if (cmd == NULL) {
			*errp = errno;
			return (NULL);
		}
		(void) snprintf(cmd, cmdLen, "%s%s%s%s%s", cmd, SPACE,
		    HOST_FLAG, SPACE, hostProp->mValue);
	}

	currentParam = currentParam->mNext;
	onlyLocalProp = currentParam->mDataObject;
	if (onlyLocalProp != NULL && onlyLocalProp->mValue != NULL) {
		if (strcmp(onlyLocalProp->mValue, "1") == 0 ||
			strcasecmp(onlyLocalProp->mValue, "true") == 0) {

			cim_logDebug("cmdgen_umountall",
				"Adding the -l flag");
			/*
			 * Add the -l flag to the command.
			 */
			cmdLen = strlen(cmd) + strlen(SPACE) +
				strlen(LOCAL_FLAG) + 1;

			cmd = realloc(cmd, (size_t)(cmdLen * sizeof (char)));
			if (cmd == NULL) {
				*errp = errno;
				return (NULL);
			}
			(void) snprintf(cmd, cmdLen, "%s%s%s", cmd, SPACE,
				LOCAL_FLAG);
		}
	}

	currentParam = currentParam->mNext;
	onlyRemoteProp = currentParam->mDataObject;
	if (onlyRemoteProp != NULL && onlyRemoteProp->mValue != NULL) {
		if (strcmp(onlyRemoteProp->mValue, "1") == 0 ||
			strcasecmp(onlyRemoteProp->mValue, "true") == 0) {

			/*
			 * Add the -r flag to the command.
			 */
			cim_logDebug("cmdgen_umountall",
				"Adding the -r flag");

			cmdLen = strlen(cmd) + strlen(SPACE) +
				strlen(REMOTE_FLAG) + 1;
			cmd = realloc(cmd, (size_t)(cmdLen * sizeof (char)));
			if (cmd == NULL) {
				*errp = errno;
				return (NULL);
			}
			(void) snprintf(cmd, cmdLen, "%s%s%s", cmd, SPACE,
				REMOTE_FLAG);
		}
	}

	currentParam = currentParam->mNext;
	killProcessesProp = currentParam->mDataObject;
	if (killProcessesProp != NULL && killProcessesProp->mValue != NULL) {
		if (strcmp(killProcessesProp->mValue, "1") == 0 ||
			strcasecmp(killProcessesProp->mValue, "true") == 0) {

			/*
			 * Add the -k flag to the command.
			 */
			cim_logDebug("cmdgen_umountall",
				"Adding the -k flag");
			cmdLen = strlen(cmd) + strlen(SPACE) +
				strlen(KILL_FLAG) + 1;
			cmd = realloc(cmd, (size_t)(cmdLen * sizeof (char)));
			if (cmd == NULL) {
				*errp = errno;
				return (NULL);
			}
			(void) snprintf(cmd, cmdLen, "%s%s%s", cmd, SPACE,
			    KILL_FLAG);
		}
	}

	currentParam = currentParam->mNext;
	inParallelProp = currentParam->mDataObject;
	if (inParallelProp != NULL && inParallelProp->mValue != NULL) {
		if (strcmp(inParallelProp->mValue, "0") == 0 ||
			strcasecmp(inParallelProp->mValue, "false") == 0) {

			/*
			 * Add the -s flag (do not perform umount operation in
			 * parallel) to the command.
			 */
			cim_logDebug("cmdgen_umountall",
				"Adding the -s flag");
			cmdLen = strlen(cmd) + strlen(SPACE) +
				strlen(NO_PARALLEL_FLAG) + 1;
			cmd = realloc(cmd, (size_t)(cmdLen * sizeof (char)));
			if (cmd == NULL) {
				*errp = errno;
				return (NULL);
			}
			(void) snprintf(cmd, cmdLen, "%s%s%s", cmd, SPACE,
				NO_PARALLEL_FLAG);
		}
	}

	/*
	 * The caller must free the memory allocated to the return value
	 * using free().
	 */
	cim_logDebug("cmdgen_umountall", "Returning command: %s", cmd);
	*errp = 0;
	return (cmd);
} /* cmdgen_umountall */
