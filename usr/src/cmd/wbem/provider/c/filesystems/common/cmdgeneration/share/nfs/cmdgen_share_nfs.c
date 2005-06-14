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

#include <errno.h>
#include "cmdgen_include.h"
#include "nfs_share_attr.h"
#include "nfs_sharesecurity_attr.h"
#include "Solaris_NFSShare.h"


/*
 * Private data type declaration
 */
#define	NFS_SHARE_CMD	"share -F nfs"
#define	SPEC_OPT_FLAG	"-o"

/*
 * Private method declarations
 */
static char *create_shareopt_string(CCIMInstance *, int *);
static char *add_option_string(char *, char *, int *);
static char *create_sharesec_optstring(CCIMInstance *, int *);

/*
 * Public methods
 */
/*
 * generates the share command string
 * memory returned must be freed by the caller.
 */
/* ARGSUSED */
char *
cmdgen_share_nfs(CCIMInstance *inst, CCIMObjectPath *objPath, int *error)
{

	CCIMProperty *share_Prop;
	char *share_desc;
	char *cmd;
	char *shareopts;
	char *sharesecopts;
	size_t len;

	cim_logDebug("cmdgen_share_nfs", "Just entering...");
	if (inst != NULL) {
		/*
		 * Create the share command using the properties
		 * passed in from inst.
		 */

		/*
		 * Get the share description attribute if the "-d"
		 * flag is set.
		 */

		share_Prop = cim_getProperty(inst,
		    nfsShareProps[DESCRIPTION].name);
		if (share_Prop != NULL && strcmp(share_Prop->mValue, "") != 0) {
			len = strlen(share_Prop->mValue) + 4;
			share_desc = (char *)calloc(len, sizeof (char));
			(void) snprintf(share_desc, len, "-d %s",
			    share_Prop->mValue);
		} else {
			share_desc = strdup("");
		}

		share_Prop =
		    cim_getProperty(inst, nfsShareProps[SHAREDNAME].name);
		if (share_Prop == NULL) {
			free(share_desc);
			*error = EINVAL;
			return ((char *)NULL);
		}
		shareopts = create_shareopt_string(inst, error);
		sharesecopts = create_sharesec_optstring(inst, error);

		shareopts = add_option_string(shareopts, sharesecopts, error);
		free(sharesecopts);

		if (shareopts == NULL) {
			len = strlen(NFS_SHARE_CMD) +
			    strlen(SPEC_OPT_FLAG) + strlen(share_desc) +
			    strlen(share_Prop->mValue) + 3;
			cmd = (char *)calloc(len, sizeof (char));
			(void) snprintf(cmd, len, "%s %s %s", NFS_SHARE_CMD,
			    share_desc, share_Prop->mValue);
		} else {
			len = strlen(NFS_SHARE_CMD) + strlen(SPEC_OPT_FLAG) +
			    strlen(shareopts) + strlen(share_desc) +
			    strlen(share_Prop->mValue) + 5;
			cmd = (char *)calloc(len, sizeof (char));
			(void) snprintf(cmd, len, "%s %s %s %s %s",
			    NFS_SHARE_CMD, SPEC_OPT_FLAG, shareopts, share_desc,
			    share_Prop->mValue);
		}
		cim_freeProperty(share_Prop);
		free(share_desc);
		if (shareopts != NULL) {
			free(shareopts);
		}
		cim_logDebug("cmdgen_share_nfs", "Returning command: %s",
		    cmd);
		return (cmd);
	} else {
		cmd = NULL;
		return ((char *)cmd);
	}
	/*
	 * Not reached
	 */
}

/*
 * Private methods
 */

/*
 * creates and returns the options string by gathering the vaious share
 * options from the instance attributes.
 */
static char *
create_shareopt_string(CCIMInstance *inst, int *error)
{
	CCIMProperty *share_Prop;
	char *shareopts = NULL;

	shareopts = NULL;

	cim_logDebug("create_shareopt_string", "Just entering...");
	/*
	 * Check AllowAccessControll
	 */
	share_Prop =
	    cim_getProperty(inst, nfsShareProps[ALLOWACCESSCONTROL].name);
	if (share_Prop != NULL) {
		if (strcmp(share_Prop->mValue, "0") != 0 &&
		    strcmp(share_Prop->mValue, "") != 0) {
			/*
			 * add the "aclok" attribute to the shareopt string.
			 */
			shareopts = add_option_string(shareopts,
			    ALLOWACCESSCONTROL_TRUE, error);
			if (shareopts == NULL)
				return (NULL);
		}
		cim_freeProperty(share_Prop);
	}
	/*
	 * Check EffectiveUID
	 */
	share_Prop = cim_getProperty(inst, nfsShareProps[EFFECTIVEUID].name);
	if (share_Prop != NULL) {
		if (strcmp(share_Prop->mValue, "0") != 0 &&
		    strcmp(share_Prop->mValue, "") != 0) {
			char *tmp;
			size_t len;

			len = strlen(share_Prop->mValue) + 7;
			tmp = (char *)calloc(len, sizeof (char));
			(void) snprintf(tmp, len, "%s%s", EFFECTIVEUID_SET,
			    share_Prop->mValue);
			/*
			 * add "anon=" attribute and value to shareopt sting.
			 */
			shareopts = add_option_string(shareopts, tmp, error);
			free(tmp);
			if (shareopts == NULL)
				return (NULL);
		}
		cim_freeProperty(share_Prop);
	}

	/*
	 * Check IgnoreSetID
	 */
	share_Prop = cim_getProperty(inst, nfsShareProps[IGNORESETID].name);
	if (share_Prop != NULL) {
		if (strcmp(share_Prop->mValue, "0") != 0 &&
		    strcmp(share_Prop->mValue, "") != 0) {
			/*
			 * add "nosuid" attribute to shareopt sting.
			 */
			shareopts = add_option_string(shareopts,
			    IGNORESETID_TRUE, error);
			if (shareopts == NULL)
				return (NULL);
		}
		cim_freeProperty(share_Prop);
	}

	/*
	 * Check LogFileTag
	 */
	share_Prop = cim_getProperty(inst, nfsShareProps[LOGFILETAG].name);
	if (share_Prop != NULL) {
		if (strcmp(share_Prop->mValue, "") != 0) {
			char *tmp;
			size_t len;

			len = strlen(share_Prop->mValue) + 5;
			tmp = (char *)calloc(len, sizeof (char));
			(void) snprintf(tmp, len, "%s%s", LOGFILETAG_SET,
			    share_Prop->mValue);
			/*
			 * add "log=" attribute and value to shareopt sting.
			 */
			shareopts = add_option_string(shareopts, tmp, error);
			free(tmp);
			if (shareopts == NULL)
				return (NULL);
		}
		cim_freeProperty(share_Prop);
	}

	/*
	 * Check PreventSubdirMount
	 */
	share_Prop =
	    cim_getProperty(inst, nfsShareProps[PREVENTSUBDIRMOUNT].name);
	if (share_Prop != NULL) {
		if (strcmp(share_Prop->mValue, "0") != 0 &&
		    strcmp(share_Prop->mValue, "") != 0) {
			/*
			 * add "nosub" attribute to shareopt sting.
			 */
			shareopts = add_option_string(shareopts,
			    PREVENTSUBDIRMOUNT_TRUE, error);
			if (shareopts == NULL)
				return (NULL);
		}
		cim_freeProperty(share_Prop);
	}

	/*
	 * Check Public
	 */
	share_Prop = cim_getProperty(inst, nfsShareProps[PUBLIC].name);
	if (share_Prop != NULL) {
		if (strcmp(share_Prop->mValue, "0") != 0 &&
		    strcmp(share_Prop->mValue, "") != 0) {
			/*
			 * add "public" attribute to shareopt sting.
			 */
			shareopts = add_option_string(shareopts, PUBLIC_TRUE,
			    error);
			if (shareopts == NULL)
				return (NULL);
		}
		cim_freeProperty(share_Prop);
	}

	if (shareopts != NULL) {
		cim_logDebug("create_shareopt_string",
		    "The share opts string is: %s", shareopts);
	} else {
		cim_logDebug("create_shareopt_string",
		    "The share opts string is NULL");
	}
	return (shareopts);
}

/*
 * Adds the option to the existing option string. The existing option
 * string may be reallocated. In either case, the new pointer to
 * the complete string is returned.
 */
static char *
add_option_string(char *str, char *opt, int *error)
{
	char *ret_val;
	size_t len;

	if (opt == NULL)
		ret_val = str;
	else if (str == NULL) {
		ret_val = strdup(opt);
		if (ret_val == NULL)
			*error = ENOMEM;
	} else {
		len = strlen(str) + strlen(opt) + 2;
		ret_val = realloc(str, len);
		if (ret_val == NULL) {
			free(str);
			*error = ENOMEM;
		} else
			(void) snprintf(ret_val, len, "%s,%s", str, opt);
	}

	return (ret_val);
}

/*
 * creates and returns the security options string
 */
static char *
create_sharesec_optstring(CCIMInstance *inst, int *err)
{
	CCIMProperty	*shareProp;
	char 		**securityStrings;
	char		*optstring;
	int		number_of_strings;
	optstring = NULL;

	shareProp = cim_getProperty(inst, SECOPTS);
	if (shareProp == NULL || strcmp(shareProp->mValue, "") == 0) {
		/*
		 * No security options specified.
		 */
		return (NULL);
	}
	securityStrings =
	    cim_decodeStringArray(shareProp->mValue, &number_of_strings);
	if (securityStrings != NULL) {
		int i;

		for (i = 0; i < number_of_strings; i++) {
			optstring = add_option_string(optstring,
			    securityStrings[i], err);
			if (optstring == NULL)
				return (NULL);
		}
		cim_freeStringArray(securityStrings);
	}
	if (optstring != NULL) {
		cim_logDebug("create_sharesec_optstring",
		    "The share security opts string is: %s", optstring);
	} else {
		cim_logDebug("create_sharesec_optstring",
		    "The share security opts string is NULL");
	}
	return (optstring);
}
