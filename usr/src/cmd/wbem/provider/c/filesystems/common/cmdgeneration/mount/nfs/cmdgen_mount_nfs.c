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
#include "nfs_keys.h"
#include "util.h"
#include "messageStrings.h"
#include "Solaris_NFSMount.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

/*
 * Private variables
 */
#define	NFS_MNT_CMD	"mount -F nfs\0"
#define	SPACE		" "
#define	SPEC_OPT_FLAG	"-o"

/*
 * Private method declarations
 */
char	*add_property_to_optstring(char *opt_string, CCIMProperty *prop,
		int element, int *errp);
char	*add_to_mntopts(char *mntopt_string, char *attribute, char *value,
			int *errp);
char	*create_command(char *resource, char *mntpnt, boolean_t mflag,
			boolean_t Oflag, boolean_t spec_option_flag,
			char *mntopt, int *errp);
char	*create_option_string(CCIMInstance *inst, int *errp);

/*
 * Public methods
 */
/*
 * Method: cmdgen_mount_nfs
 *
 * Description: Creates the nfs mount command with the options from the
 * CCIMInstance passed in.
 *
 * Parameters:
 *	- CCIMInstance *inst - The instance containing the properties of the
 *	mount.
 *	- CCIMObjectPath *objPath - The object path containing properties of
 *	the mount.
 *	- int *errp - The error indicator.  Upon error, a value != 0 will be
 *	set.
 *
 * Returns:
 *	- char * - The nfs mount command generated.
 *	- NULL if an error occurred.
 */
/* ARGSUSED */
char *
cmdgen_mount_nfs(CCIMInstance *inst, CCIMObjectPath *objPath, int *errp) {
	boolean_t mflag; /* NoMnttabEntry flag */
	boolean_t Oflag; /* Overlay flag */
	boolean_t spec_option_flag; /* "-o" */
	char *cmd;
	char *resource;
	char *mntpnt;
	char *mntopt;
	CCIMProperty *mnt_prop;

	*errp = 0;
	if (inst == NULL) {
		*errp = EINVAL;
		return (NULL);
	}

	/*
	 * First, get the resource and mount point from the Dependent
	 * and Antecedent properties, respectively.
	 */
	mnt_prop = cim_getProperty(inst, nfsMountProps[ANT].name);
	if (mnt_prop == NULL) {
		*errp = EINVAL;
		return (NULL);
	} else {
		CCIMPropertyList *ant_proplist;
		char *tmp;

		ant_proplist = mnt_prop->mObjPathValue->mKeyProperties;

		tmp = util_getKeyValue(ant_proplist, string,
			NAME, errp);
		if (tmp == NULL || *errp != 0) {
			return (NULL);
		}

		mntpnt = strdup(tmp);
		if (mntpnt == NULL) {
			*errp = ENOMEM;
			return (NULL);
		}
		cim_freeProperty(mnt_prop);
	}

	mnt_prop = cim_getProperty(inst, nfsMountProps[DEP].name);
	if (mnt_prop == NULL) {
		*errp = EINVAL;
		return (NULL);
	} else {
		CCIMPropertyList *dep_proplist;
		char *tmp;

		dep_proplist = mnt_prop->mObjPathValue->mKeyProperties;
		/*
		 * We expect the resource to be in the
		 * form of "resource\=<resource>" or
		 * just "<resource>".  Determine which
		 * format we have.
		 */
		tmp = util_getKeyValue(dep_proplist, string, NAME, errp);
		if (tmp == NULL || *errp != 0) {
			return (NULL);
		}

		resource = strdup(tmp);
		if (resource == NULL) {
			*errp = ENOMEM;
			free(mntpnt);
			return (NULL);
		}

		cim_freeProperty(mnt_prop);
	}

	/*
	 * Next get the mount attributes which are set with flags.
	 * For NFS those are:
	 * -r (read only) ** We don't check for this one since it
	 * can be added w/ the "ro" option.
	 * -m:(no mnttab entry)
	 * -O:(overlay)
	 */
	mflag = B_FALSE;
	mnt_prop = cim_getProperty(inst, nfsMountProps[NOMNTTABENT].name);
	if (mnt_prop != NULL && mnt_prop->mValue != NULL) {
		if ((strcmp(mnt_prop->mValue, "1") == 0))
			mflag = B_TRUE;

		cim_freeProperty(mnt_prop);
	}

	Oflag = B_FALSE;
	mnt_prop = cim_getProperty(inst, nfsMountProps[OVERLAY].name);
	if (mnt_prop != NULL && mnt_prop->mValue != NULL) {
		/*
		 * Determine the value of the property.
		 */
		cim_logDebug("cmdgen_mount_nfs", "nfsMountProps[OVERLAY] = %s",
			mnt_prop->mValue);
		if ((strcmp(mnt_prop->mValue, "1") == 0))
			Oflag = B_TRUE;

		cim_freeProperty(mnt_prop);
	}

	/*
	 * Now check if the MountOptions property is populated.
	 * If yes, create the mount with the options defined in that
	 * string.  No other property values will need to be checked.
	 */

	mnt_prop = cim_getProperty(inst, nfsMountProps[MNTOPTS].name);
	if (mnt_prop != NULL && (strlen(mnt_prop->mValue) != 0)) {
		cim_logDebug("cmdgen_mount_nfs",
			"MountOptions =%s", mnt_prop->mValue);
		spec_option_flag = B_TRUE;
		cmd = create_command(resource, mntpnt, mflag, Oflag,
			spec_option_flag, mnt_prop->mValue, errp);
		free(resource);
		free(mntpnt);
		if (cmd == NULL) {
			return (NULL);
		}
		cim_freeProperty(mnt_prop);

	} else {
		mntopt = create_option_string(inst, errp);
		/*
		 * If mntopt is NULL we either don't have any options,
		 * or we ran into an error.
		 */
		if (mntopt == NULL) {
			if (*errp != 0) {
				free(resource);
				free(mntpnt);
				return (NULL);
			}
			spec_option_flag = B_FALSE;
		} else {
			spec_option_flag = B_TRUE;
		}
		cmd = create_command(resource, mntpnt, mflag, Oflag,
				    spec_option_flag, mntopt, errp);
		free(resource);
		free(mntpnt);
		free(mntopt);
		if (cmd == NULL) {
			return (NULL);
		}
	}

	return (cmd);
} /* cmdgen_mount_nfs */

/*
 * Private methods
 */

char *
add_property_to_optstring(char *opt_string, CCIMProperty *prop, int element,
	int *errp) {

	char	*ret_val = NULL;

	*errp = 0;
	if (prop->mType == boolean) {
		if (strcmp(prop->mValue, "1") == 0) {
			if (nfsMountProps[element].true_opt_value != NULL) {
				ret_val = add_to_mntopts(opt_string,
					nfsMountProps[element].true_opt_value,
					NULL, errp);
				if (ret_val == NULL && *errp != 0) {
					return (NULL);
				}
			}
		} else {
			if (nfsMountProps[element].false_opt_value != NULL) {
				ret_val = add_to_mntopts(opt_string,
					nfsMountProps[element].false_opt_value,
					NULL, errp);
				if (ret_val == NULL && *errp != 0) {
					return (NULL);
				}
			}
		}
	} else {
		if ((nfsMountProps[element].string_opt_value != NULL) &&
			(strlen(prop->mValue) != 0)) {
			ret_val = add_to_mntopts(opt_string,
				nfsMountProps[element].string_opt_value,
				prop->mValue, errp);
			if (ret_val == NULL && *errp != 0) {
				return (NULL);
			}
		}
	}

	return (ret_val);
} /* add_property_to_optstring */

/*
 * Method: add_to_mntopts
 *
 * Description: Adds the passed in mount option to the option list.
 *
 * Parameters:
 *	- char *mntopt_string - The option string to add the mount option to.
 *	A NULL value may be passed in if the option is the first one in the
 *	mount option string.
 *	- char *attribute - The mount option being added to the option string.
 *	- char *value - The value of the mount option.  This only applies to
 *	mount options having an '=' character.  Example: acdirmax=
 *	A NULL value will be passed in if the option does not require a value.
 *	- int *errp - The error indicator.  If an error occurred the value will
 *	be != 0 upon return.
 *
 * Returns: The mount option string, as passed in with mntopt_string,
 * concatenated with the passed in attribute, and value, if one exists.
 *
 * NOTE: The caller will have to free the space allocated for the returned
 * string.
 */
char *
add_to_mntopts(char *mntopt_string, char *attribute, char *value, int *errp) {
	int len;
	char *ret_val;
	char *tmp = NULL;

	/*
	 * Check if value is not NULL.  If it isn't we need to
	 * concatenate attribute with value.
	 */
	if (value != NULL) {
		tmp = (char *)calloc((size_t)(strlen(attribute) +
			strlen(value) + 1), (size_t)sizeof (char));
		if (tmp == NULL) {
			*errp = ENOMEM;
			return (NULL);
		}
		(void) snprintf(tmp, (size_t)(strlen(attribute) +
			strlen(value) + 1), "%s%s", attribute, value);
	} else {
		tmp = strdup(attribute);
		if (tmp == NULL) {
			*errp = ENOMEM;
			return (NULL);
		}
	}

	/*
	 * If mntopt_string is NULL, this is the very first attribute in the
	 * mount option list.
	 */
	if (mntopt_string == NULL) {
		ret_val = strdup(tmp);
		if (ret_val == NULL) {
			free(tmp);
			*errp = ENOMEM;
			return (NULL);
		}

	} else {
		len = (strlen(mntopt_string) + strlen(tmp) + 2);
		ret_val = (char *)calloc((size_t)len, (size_t)sizeof (char));
		if (ret_val == NULL)
		{
			free(tmp);
			*errp = ENOMEM;
			return (NULL);
		}
		(void) snprintf(ret_val, (size_t)len, "%s%s%s",
		    mntopt_string, ",", tmp);
	}
	free(tmp);
	*errp = 0;
	return (ret_val);
} /* add_to_mntopts */

/*
 * Method: create_command
 *
 * Description: Creates the nfs mount command out of the properties passed in.
 *
 * Parameters:
 *	- char *resource - The resource to be mounted.
 *	- char *mntpnt - The mount point.
 *	- boolean_t mflag - Whether or not to add the '-m' flag.
 *	- boolean_t Oflag - Whether or not to add the '-O' flag.
 *	- boolean_t spec_option_flag - Whether or not to add the '-o' flag.
 *	- char *mntopts - The mount option string.
 *	- int *errp - The error indicator.  Upon error, this will be set to a
 *	value != 0.
 *
 * Returns:
 *	- char * - The command generated.
 *	- NULL if an error occurred.
 */
char *
create_command(char *resource, char *mntpnt, boolean_t mflag, boolean_t Oflag,
	boolean_t spec_option_flag, char *mntopts, int *errp) {

	char	*cmd = NULL;
	int	cmdMaxLen;

	*errp = 0;
	cmdMaxLen = strlen(NFS_MNT_CMD) + strlen(resource) + strlen(mntpnt) +
		MAXSIZE;

	if (mntopts != NULL) {
		cmdMaxLen = cmdMaxLen + strlen(mntopts);
	}

	/*
	 * Allocate a space we know will be big enough for the command.
	 */
	cmd = calloc((size_t)cmdMaxLen, (size_t)sizeof (char));
	if (cmd == NULL) {
		*errp = errno;
		return (NULL);
	}

	(void) snprintf(cmd, cmdMaxLen, "%s", NFS_MNT_CMD);

	if (mflag == B_TRUE)
		(void) snprintf(cmd, cmdMaxLen, "%s%s%s", cmd, SPACE,
			NFS_NOMNTTABENT_TRUE);

	if (Oflag == B_TRUE)
		(void) snprintf(cmd, cmdMaxLen, "%s%s%s", cmd, SPACE,
		    NFS_OVERLAY);

	if (spec_option_flag == B_TRUE)
		(void) snprintf(cmd, cmdMaxLen, "%s%s%s%s%s", cmd, SPACE,
			SPEC_OPT_FLAG, SPACE, mntopts);

	(void) snprintf(cmd, cmdMaxLen, "%s%s%s%s%s", cmd, SPACE,
	    resource, SPACE, mntpnt);

	return (cmd);
} /* create_command */

/*
 * Method: create_option_string
 *
 * Description: Creates the mount command understandable option string from the
 * passed in Solaris_NFSMount instance.
 *
 * Parameters:
 *	- CCIMInstance *inst - The Solaris_NFSMount instance containing all of
 *	the properties of the mount to be created.
 *	- int *errp - The error indicator.  Upon error, this will be set to a
 *	value != 0.
 *
 * Returns:
 *	- char * - The mount option string.
 *	- NULL if an error occurred.
 */
char *
create_option_string(CCIMInstance *inst, int *errp) {
	CCIMProperty	*mnt_prop;
	char		*mntopt_string = NULL;
	char		*tmp;
	int		currentElement;

	*errp = 0;
	for (currentElement = 0; currentElement < PROPCOUNT; currentElement++) {
		mnt_prop = cim_getProperty(inst,
			nfsMountProps[currentElement].name);
		if (mnt_prop == NULL) {
			*errp = EINVAL;
			free(mntopt_string);
			return (NULL);
		}

		/*
		 * Handle special "vers=highest" case.
		 */
		if ((strcmp(mnt_prop->mName, "Version") == 0) &&
			(strcasecmp(mnt_prop->mValue, "highest") == 0)) {
			cim_freeProperty(mnt_prop);
			continue;
		}

		tmp = add_property_to_optstring(mntopt_string, mnt_prop,
			currentElement, errp);
		if (tmp == NULL) {
			if (*errp != 0) {
				free(mntopt_string);
				return (NULL);
			}
		} else {

			free(mntopt_string);
			mntopt_string = strdup(tmp);
			if (mntopt_string == NULL) {
				*errp = errno;
				free(tmp);
				return (NULL);
			}

			free(tmp);
		}
		cim_freeProperty(mnt_prop);
	}

	return (mntopt_string);
} /* create_option_string */
