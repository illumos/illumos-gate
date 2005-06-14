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

#define	MNTALL_CMD "/usr/sbin/mountall"
#define	FSTYPE_FLAG "-F"
#define	LOCAL_FLAG "-l"
#define	REMOTE_FLAG "-r"
#define	SPACE " "

/*
 * Public methods
 */
/*
 * The -g flag is a project-private interface for pxfs and is not documented in
 * the mountall man page.  Therefore, we will not support it with this public
 * interface.
 */
/*
 * Method: cmdgen_mountall
 *
 * Description: Forms the mountall command with the options given.
 *
 * Parameters:
 *	- CCIMPropertyList *paramList - The property list containing the
 *	options to form the mountall command.
 *	- int *errp - The error indicator.  Upon error, this will be set to a
 *	value != 0.
 *
 * Returns:
 *	- char * - The mountall command.
 *	- NULL if an error occurred.
 */
char *
cmdgen_mountall(CCIMPropertyList *paramList, int *errp) {
	CCIMPropertyList	*currentParam;
	CCIMProperty		*fstypeProp = NULL;
	CCIMProperty		*onlyLocalProp = NULL;
	CCIMProperty		*onlyRemoteProp = NULL;
	CCIMProperty		*fileProp = NULL;
	char			*cmd = NULL;
	int			cmdLen;

	*errp = 0;
	cmd = strdup(MNTALL_CMD);
	if (cmd == NULL) {
		*errp = errno;
		return (NULL);
	}

	cim_logDebug("cmdgen_mountall", "Set command to: %s", cmd);
	/*
	 * In parameters are as follows:
	 * 1. String fstype,
	 * 2. Boolean onlyLocalFileSystems,
	 * 3. Boolean onlyRemoteFileSystems,
	 * 4. String fstable
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

		cim_logDebug("cmdgen_mountall", "Adding the -F flag");
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

	currentParam = currentParam->mNext;
	onlyLocalProp = currentParam->mDataObject;

	if (onlyLocalProp != NULL && onlyLocalProp->mValue != NULL) {
		if (strcmp(onlyLocalProp->mValue, "1") == 0 ||
			strcasecmp(onlyLocalProp->mValue, "true") == 0) {

			cim_logDebug("cmdgen_mountall", "Adding the -l flag");
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
			(void) snprintf(cmd, cmdLen, "%s%s%s", cmd,
			    SPACE, LOCAL_FLAG);
		}
	}

	currentParam = currentParam->mNext;
	onlyRemoteProp = currentParam->mDataObject;

	cim_logDebug("cmdgen_mountall", "Checking onlyRemoteProp");
	if (onlyRemoteProp != NULL && onlyRemoteProp->mValue != NULL) {
		if (strcmp(onlyRemoteProp->mValue, "1") == 0 ||
			strcasecmp(onlyRemoteProp->mValue, "true") == 0) {

			cim_logDebug("cmdgen_mountall", "Adding the -r flag");

			/*
			 * Add the -r flag to the command.
			 */
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
	fileProp = currentParam->mDataObject;

	if (fileProp != NULL && fileProp->mValue != NULL &&
		strlen(fileProp->mValue) != 0) {

		cim_logDebug("cmdgen_mountall", "Adding the fstable");
		/*
		 * Add the file to the command.
		 */
		cmdLen = strlen(cmd) + strlen(SPACE) +
			strlen(fileProp->mValue) + 1;
		cmd = realloc(cmd, (size_t)(cmdLen * sizeof (char)));
		if (cmd == NULL) {
			*errp = errno;
			return (NULL);
		}
		(void) snprintf(cmd, cmdLen, "%s%s%s", cmd, SPACE,
			fileProp->mValue);
	}

	/*
	 * The caller must free the memory allocated to the return value
	 * using free().
	 */
	cim_logDebug("cmdgen_mountall", "The return command is: %s", cmd);
	return (cmd);
} /* cmdgen_mountall */
