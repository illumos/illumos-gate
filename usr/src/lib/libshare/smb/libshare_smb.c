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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * SMB specific functions
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <zone.h>
#include <errno.h>
#include <locale.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include "libshare.h"
#include "libshare_impl.h"
#include <pwd.h>
#include <limits.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <strings.h>
#include "libshare_smb.h"
#include <rpcsvc/daemon_utils.h>
#include <smbsrv/smb_share.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/libsmb.h>
#include <libdlpi.h>

#define	SMB_CSC_BUFSZ		64

#define	SMB_VALID_SUB_CHRS	"UDhMLmIiSPu"	/* substitution characters */

/* internal functions */
static int smb_share_init(void);
static void smb_share_fini(void);
static int smb_enable_share(sa_share_t);
static int smb_share_changed(sa_share_t);
static int smb_resource_changed(sa_resource_t);
static int smb_rename_resource(sa_handle_t, sa_resource_t, char *);
static int smb_disable_share(sa_share_t share, char *);
static int smb_validate_property(sa_handle_t, sa_property_t, sa_optionset_t);
static int smb_set_proto_prop(sa_property_t);
static sa_protocol_properties_t smb_get_proto_set(void);
static char *smb_get_status(void);
static int smb_parse_optstring(sa_group_t, char *);
static char *smb_format_options(sa_group_t, int);

static int smb_enable_service(void);

static int range_check_validator(int, char *);
static int range_check_validator_zero_ok(int, char *);
static int string_length_check_validator(int, char *);
static int print_enable_validator(int, char *);
static int true_false_validator(int, char *);
static int ipv4_validator(int, char *);
static int hostname_validator(int, char *);
static int path_validator(int, char *);
static int cmd_validator(int, char *);
static int disposition_validator(int, char *);

static int smb_enable_resource(sa_resource_t);
static int smb_disable_resource(sa_resource_t);
static uint64_t smb_share_features(void);
static int smb_list_transient(sa_handle_t);

static int smb_build_shareinfo(sa_share_t, sa_resource_t, smb_share_t *);
static void smb_csc_option(const char *, smb_share_t *);
static char *smb_csc_name(const smb_share_t *);
static sa_group_t smb_get_defaultgrp(sa_handle_t);
static int interface_validator(int, char *);
static int smb_update_optionset_props(sa_handle_t, sa_resource_t, nvlist_t *);

static boolean_t smb_saprop_getbool(sa_optionset_t, char *);
static boolean_t smb_saprop_getstr(sa_optionset_t, char *, char *, size_t);

static struct {
	char *value;
	uint32_t flag;
} cscopt[] = {
	{ "disabled",	SMB_SHRF_CSC_DISABLED },
	{ "manual",	SMB_SHRF_CSC_MANUAL },
	{ "auto",	SMB_SHRF_CSC_AUTO },
	{ "vdo",	SMB_SHRF_CSC_VDO }
};

/* size of basic format allocation */
#define	OPT_CHUNK	1024

/* size of string for types - big enough to hold "dependency" */
#define	SCFTYPE_LEN	32

/*
 * Indexes of entries in smb_proto_options table.
 * Changes to smb_proto_options table may require
 * an update to these values.
 */
#define	PROTO_OPT_WINS1			6
#define	PROTO_OPT_WINS_EXCLUDE		8

typedef struct smb_hostifs_walker {
	const char	*hiw_ifname;
	boolean_t	hiw_matchfound;
} smb_hostifs_walker_t;


/*
 * ops vector that provides the protocol specific info and operations
 * for share management.
 */

struct sa_plugin_ops sa_plugin_ops = {
	SA_PLUGIN_VERSION,
	SMB_PROTOCOL_NAME,
	smb_share_init,
	smb_share_fini,
	smb_enable_share,
	smb_disable_share,
	smb_validate_property,
	NULL,	/* valid_space */
	NULL,	/* security_prop */
	smb_parse_optstring,
	smb_format_options,
	smb_set_proto_prop,
	smb_get_proto_set,
	smb_get_status,
	NULL,	/* space_alias */
	NULL,	/* update_legacy */
	NULL,	/* delete_legacy */
	smb_share_changed,
	smb_enable_resource,
	smb_disable_resource,
	smb_share_features,
	smb_list_transient,
	smb_resource_changed,
	smb_rename_resource,
	NULL,	/* run_command */
	NULL,	/* command_help */
	NULL	/* delete_proto_section */
};

struct option_defs optdefs[] = {
	{ SHOPT_AD_CONTAINER,	OPT_TYPE_STRING },
	{ SHOPT_ABE,		OPT_TYPE_BOOLEAN },
	{ SHOPT_NAME,		OPT_TYPE_NAME },
	{ SHOPT_RO,		OPT_TYPE_ACCLIST },
	{ SHOPT_RW,		OPT_TYPE_ACCLIST },
	{ SHOPT_NONE,		OPT_TYPE_ACCLIST },
	{ SHOPT_CATIA,		OPT_TYPE_BOOLEAN },
	{ SHOPT_CSC,		OPT_TYPE_CSC },
	{ SHOPT_GUEST,		OPT_TYPE_BOOLEAN },
	{ SHOPT_DFSROOT,	OPT_TYPE_BOOLEAN },
	{ SHOPT_DESCRIPTION,	OPT_TYPE_STRING },
	{ NULL, NULL }
};

/*
 * findopt(name)
 *
 * Lookup option "name" in the option table and return the table
 * index.
 */
static int
findopt(char *name)
{
	int i;
	if (name != NULL) {
		for (i = 0; optdefs[i].tag != NULL; i++) {
			if (strcmp(optdefs[i].tag, name) == 0)
				return (i);
		}
	}
	return (-1);
}

/*
 * is_a_number(number)
 *
 * is the string a number in one of the forms we want to use?
 */
static boolean_t
is_a_number(char *number)
{
	boolean_t isnum = B_TRUE;
	boolean_t ishex = B_FALSE;

	if (number == NULL || *number == '\0')
		return (B_FALSE);

	if (strncasecmp(number, "0x", 2) == 0) {
		number += 2;
		ishex = B_TRUE;
	} else if (*number == '-') {
		number++;
	}

	while (isnum && (*number != '\0')) {
		isnum = (ishex) ? isxdigit(*number) : isdigit(*number);
		number++;
	}

	return (isnum);
}

/*
 * check ro vs rw values.  Over time this may get beefed up.
 * for now it just does simple checks.
 */

static int
check_rorw(char *v1, char *v2)
{
	int ret = SA_OK;
	if (strcmp(v1, v2) == 0)
		ret = SA_VALUE_CONFLICT;
	return (ret);
}

/*
 * validresource(name)
 *
 * Check that name only has valid characters in it. The current valid
 * set are the printable characters but not including:
 *	" / \ [ ] : | < > + ; , ? * = \t
 * Note that space is included and there is a maximum length.
 */
static boolean_t
validresource(const char *name)
{
	const char *cp;
	size_t len;

	if (name == NULL)
		return (B_FALSE);

	len = strlen(name);
	if (len == 0 || len > SA_MAX_RESOURCE_NAME)
		return (B_FALSE);

	if (strpbrk(name, "\"/\\[]:|<>+;,?*=\t") != NULL) {
		return (B_FALSE);
	}

	for (cp = name; *cp != '\0'; cp++)
		if (iscntrl(*cp))
			return (B_FALSE);

	return (B_TRUE);
}

/*
 * Check that the client-side caching (CSC) option value is valid.
 */
static boolean_t
validcsc(const char *value)
{
	int i;

	for (i = 0; i < (sizeof (cscopt) / sizeof (cscopt[0])); ++i) {
		if (strcasecmp(value, cscopt[i].value) == 0)
			return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * smb_isonline()
 *
 * Determine if the SMF service instance is in the online state or
 * not. A number of operations depend on this state.
 */
static boolean_t
smb_isonline(void)
{
	char *str;
	boolean_t ret = B_FALSE;

	if ((str = smf_get_state(SMBD_DEFAULT_INSTANCE_FMRI)) != NULL) {
		ret = (strcmp(str, SCF_STATE_STRING_ONLINE) == 0);
		free(str);
	}
	return (ret);
}

/*
 * smb_isdisabled()
 *
 * Determine if the SMF service instance is in the disabled state or
 * not. A number of operations depend on this state.
 */
static boolean_t
smb_isdisabled(void)
{
	char *str;
	boolean_t ret = B_FALSE;

	if ((str = smf_get_state(SMBD_DEFAULT_INSTANCE_FMRI)) != NULL) {
		ret = (strcmp(str, SCF_STATE_STRING_DISABLED) == 0);
		free(str);
	}
	return (ret);
}

/*
 * smb_isautoenable()
 *
 * Determine if the SMF service instance auto_enabled set or not. A
 * number of operations depend on this state.  The property not being
 * set or being set to true means autoenable.  Only being set to false
 * is not autoenabled.
 */
static boolean_t
smb_isautoenable(void)
{
	boolean_t ret = B_TRUE;
	scf_simple_prop_t *prop;
	uint8_t *retstr;

	prop = scf_simple_prop_get(NULL, SMBD_DEFAULT_INSTANCE_FMRI,
	    "application", "auto_enable");
	if (prop != NULL) {
		retstr = scf_simple_prop_next_boolean(prop);
		ret = *retstr != 0;
		scf_simple_prop_free(prop);
	}
	return (ret);
}

/*
 * smb_ismaint()
 *
 * Determine if the SMF service instance is in the disabled state or
 * not. A number of operations depend on this state.
 */
static boolean_t
smb_ismaint(void)
{
	char *str;
	boolean_t ret = B_FALSE;

	if ((str = smf_get_state(SMBD_DEFAULT_INSTANCE_FMRI)) != NULL) {
		ret = (strcmp(str, SCF_STATE_STRING_MAINT) == 0);
		free(str);
	}
	return (ret);
}

/*
 * smb_enable_share tells the implementation that it is to enable the share.
 * This entails converting the path and options into the appropriate ioctl
 * calls. It is assumed that all error checking of paths, etc. were
 * done earlier.
 */
static int
smb_enable_share(sa_share_t share)
{
	char *path;
	smb_share_t si;
	sa_resource_t resource;
	boolean_t iszfs;
	boolean_t privileged;
	int err = SA_OK;
	priv_set_t *priv_effective;
	boolean_t online;

	/*
	 * Don't support Trusted Extensions.
	 */
	if (is_system_labeled()) {
		(void) printf(dgettext(TEXT_DOMAIN,
		    "SMB: service not supported with Trusted Extensions\n"));
		return (SA_NOT_SUPPORTED);
	}

	priv_effective = priv_allocset();
	(void) getppriv(PRIV_EFFECTIVE, priv_effective);
	privileged = (priv_isfullset(priv_effective) == B_TRUE);
	priv_freeset(priv_effective);

	/* get the path since it is important in several places */
	path = sa_get_share_attr(share, "path");
	if (path == NULL)
		return (SA_NO_SUCH_PATH);

	/*
	 * If administratively disabled, don't try to start anything.
	 */
	online = smb_isonline();
	if (!online && !smb_isautoenable() && smb_isdisabled())
		goto done;

	iszfs = sa_path_is_zfs(path);

	if (iszfs) {

		if (privileged == B_FALSE && !online) {

			if (!online) {
				(void) printf(dgettext(TEXT_DOMAIN,
				    "SMB: Cannot share remove "
				    "file system: %s\n"), path);
				(void) printf(dgettext(TEXT_DOMAIN,
				    "SMB: Service needs to be enabled "
				    "by a privileged user\n"));
				err = SA_NO_PERMISSION;
				errno = EPERM;
			}
			if (err) {
				sa_free_attr_string(path);
				return (err);
			}

		}
	}

	if (privileged == B_TRUE && !online) {
		err = smb_enable_service();
		if (err != SA_OK) {
			(void) printf(dgettext(TEXT_DOMAIN,
			    "SMB: Unable to enable service\n"));
		} else {
			online = B_TRUE;
		}
	}

	/*
	 * Don't bother trying to start shares if the service isn't
	 * running.
	 */
	if (!online)
		goto done;

	/* Each share can have multiple resources */
	for (resource = sa_get_share_resource(share, NULL);
	    resource != NULL;
	    resource = sa_get_next_resource(resource)) {
		err = smb_build_shareinfo(share, resource, &si);
		if (err != SA_OK) {
			sa_free_attr_string(path);
			return (err);
		}

		if (!iszfs) {
			err = smb_share_create(&si);
		} else {
			share_t sh;

			(void) sa_sharetab_fill_zfs(share, &sh, "smb");
			err = sa_share_zfs(share, resource, (char *)path, &sh,
			    &si, ZFS_SHARE_SMB);
			if (err != SA_OK) {
				errno = err;
				err = -1;
			}
			sa_emptyshare(&sh);
		}
	}
	if (!iszfs)
		(void) sa_update_sharetab(share, "smb");
done:
	sa_free_attr_string(path);

	return (err == NERR_DuplicateShare ? 0 : err);
}

/*
 * This is the share for CIFS all shares have resource names.
 * Enable tells the smb server to update its hash. If it fails
 * because smb server is down, we just ignore as smb server loads
 * the resources from sharemanager at startup.
 */

static int
smb_enable_resource(sa_resource_t resource)
{
	sa_share_t share;
	smb_share_t si;
	int ret = SA_OK;
	int err;
	boolean_t isonline;

	share = sa_get_resource_parent(resource);
	if (share == NULL)
		return (SA_NO_SUCH_PATH);

	/*
	 * If administratively disabled, don't try to start anything.
	 */
	isonline = smb_isonline();
	if (!isonline && !smb_isautoenable() && smb_isdisabled())
		return (SA_OK);

	if (!isonline) {
		(void) smb_enable_service();

		if (!smb_isonline())
			return (SA_OK);
	}

	if ((ret = smb_build_shareinfo(share, resource, &si)) != SA_OK)
		return (ret);

	/*
	 * Attempt to add the share. Any error that occurs if it was
	 * online is an error but don't count NERR_DuplicateName if
	 * smb/server had to be brought online since bringing the
	 * service up will enable the share that was just added prior
	 * to the attempt to enable.
	 */
	err = smb_share_create(&si);
	if (err == NERR_Success || !(!isonline && err == NERR_DuplicateName))
		(void) sa_update_sharetab(share, "smb");
	else
		return (SA_NOT_SHARED);

	return (SA_OK);
}

/*
 * Remove it from smb server hash.
 */
static int
smb_disable_resource(sa_resource_t resource)
{
	char *rname;
	uint32_t res;
	sa_share_t share;

	rname = sa_get_resource_attr(resource, "name");
	if (rname == NULL)
		return (SA_NO_SUCH_RESOURCE);

	if (smb_isonline()) {
		res = smb_share_delete(rname);
		if (res != NERR_Success &&
		    res != NERR_NetNameNotFound) {
			sa_free_attr_string(rname);
			return (SA_CONFIG_ERR);
		}
	}

	sa_free_attr_string(rname);

	share = sa_get_resource_parent(resource);
	if (share != NULL) {
		rname = sa_get_share_attr(share, "path");
		if (rname != NULL) {
			sa_handle_t handle;

			handle = sa_find_group_handle((sa_group_t)resource);
			(void) sa_delete_sharetab(handle, rname, "smb");
			sa_free_attr_string(rname);
		}
	}
	/*
	 * Always return OK as smb/server may be down and
	 * Shares will be picked up when loaded.
	 */
	return (SA_OK);
}

/*
 * smb_share_changed(sa_share_t share)
 *
 * The specified share has changed.
 */
static int
smb_share_changed(sa_share_t share)
{
	char *path;
	sa_resource_t resource;

	if (!smb_isonline())
		return (SA_OK);

	/* get the path since it is important in several places */
	path = sa_get_share_attr(share, "path");
	if (path == NULL)
		return (SA_NO_SUCH_PATH);

	for (resource = sa_get_share_resource(share, NULL);
	    resource != NULL;
	    resource = sa_get_next_resource(resource))
		(void) smb_resource_changed(resource);

	sa_free_attr_string(path);

	return (SA_OK);
}

/*
 * smb_resource_changed(sa_resource_t resource)
 *
 * The specified resource has changed.
 */
static int
smb_resource_changed(sa_resource_t resource)
{
	uint32_t res;
	sa_share_t share;
	smb_share_t si;

	if (!smb_isonline())
		return (SA_OK);

	if ((share = sa_get_resource_parent(resource)) == NULL)
		return (SA_CONFIG_ERR);

	if ((res = smb_build_shareinfo(share, resource, &si)) != SA_OK)
		return (res);

	res = smb_share_modify(&si);

	if (res != NERR_Success)
		return (SA_CONFIG_ERR);

	return (smb_enable_service());
}

/*
 * smb_disable_share(sa_share_t share, char *path)
 *
 * Unshare the specified share. Note that "path" is the same
 * path as what is in the "share" object. It is passed in to avoid an
 * additional lookup. A missing "path" value makes this a no-op
 * function.
 */
static int
smb_disable_share(sa_share_t share, char *path)
{
	char *rname;
	sa_resource_t resource;
	sa_group_t parent;
	boolean_t iszfs;
	int err = SA_OK;
	int ret = SA_OK;
	sa_handle_t handle;
	boolean_t first = B_TRUE; /* work around sharetab issue */

	if (path == NULL)
		return (ret);

	/*
	 * If the share is in a ZFS group we need to handle it
	 * differently.  Just being on a ZFS file system isn't
	 * enough since we may be in a legacy share case.
	 */
	parent = sa_get_parent_group(share);
	iszfs = sa_group_is_zfs(parent);

	if (!smb_isonline())
		goto done;

	for (resource = sa_get_share_resource(share, NULL);
	    resource != NULL;
	    resource = sa_get_next_resource(resource)) {
		rname = sa_get_resource_attr(resource, "name");
		if (rname == NULL) {
			continue;
		}
		if (!iszfs) {
			err = smb_share_delete(rname);
			switch (err) {
			case NERR_NetNameNotFound:
			case NERR_Success:
				err = SA_OK;
				break;
			default:
				err = SA_CONFIG_ERR;
				break;
			}
		} else {
			share_t sh;

			(void) sa_sharetab_fill_zfs(share, &sh, "smb");
			err = sa_share_zfs(share, resource, (char *)path, &sh,
			    rname, ZFS_UNSHARE_SMB);
			if (err != SA_OK) {
				switch (err) {
				case EINVAL:
				case ENOENT:
					err = SA_OK;
					break;
				default:
					/*
					 * If we are no longer the first case,
					 * we don't care about the sa_share_zfs
					 * err if it is -1. This works around
					 * a problem in sharefs and should be
					 * removed when sharefs supports
					 * multiple entries per path.
					 */
					if (!first)
						err = SA_OK;
					else
						err = SA_SYSTEM_ERR;
					break;
				}
			}

			first = B_FALSE;

			sa_emptyshare(&sh);
		}

		if (err != SA_OK)
			ret = err;
		sa_free_attr_string(rname);
	}
done:
	if (!iszfs) {
		handle = sa_find_group_handle((sa_group_t)share);
		if (handle != NULL)
			(void) sa_delete_sharetab(handle, path, "smb");
		else
			ret = SA_SYSTEM_ERR;
	}
	return (ret);
}

/*
 * smb_validate_property(handle, property, parent)
 *
 * Check that the property has a legitimate value for its type.
 * Handle isn't currently used but may need to be in the future.
 */

/*ARGSUSED*/
static int
smb_validate_property(sa_handle_t handle, sa_property_t property,
    sa_optionset_t parent)
{
	int ret = SA_OK;
	char *propname;
	int optindex;
	sa_group_t parent_group;
	char *value;
	char *other;

	propname = sa_get_property_attr(property, "type");

	if ((optindex = findopt(propname)) < 0)
		ret = SA_NO_SUCH_PROP;

	/* need to validate value range here as well */
	if (ret == SA_OK) {
		parent_group = sa_get_parent_group((sa_share_t)parent);
		if (optdefs[optindex].share && !sa_is_share(parent_group))
			ret = SA_PROP_SHARE_ONLY;
	}
	if (ret != SA_OK) {
		if (propname != NULL)
			sa_free_attr_string(propname);
		return (ret);
	}

	value = sa_get_property_attr(property, "value");
	if (value != NULL) {
		/* first basic type checking */
		switch (optdefs[optindex].type) {
		case OPT_TYPE_NUMBER:
			/* check that the value is all digits */
			if (!is_a_number(value))
				ret = SA_BAD_VALUE;
			break;
		case OPT_TYPE_BOOLEAN:
			ret = true_false_validator(0, value);
			break;
		case OPT_TYPE_NAME:
			/*
			 * Make sure no invalid characters
			 */
			if (!validresource(value))
				ret = SA_BAD_VALUE;
			break;
		case OPT_TYPE_STRING:
			/* whatever is here should be ok */
			break;
		case OPT_TYPE_CSC:
			if (!validcsc(value))
				ret = SA_BAD_VALUE;
			break;
		case OPT_TYPE_ACCLIST: {
			sa_property_t oprop;
			char *ovalue;
			/*
			 * access list handling. Should eventually
			 * validate that all the values make sense.
			 * Also, ro and rw may have cross value
			 * conflicts.
			 */
			if (parent == NULL)
				break;
			if (strcmp(propname, SHOPT_RO) == 0)
				other = SHOPT_RW;
			else if (strcmp(propname, SHOPT_RW) == 0)
				other = SHOPT_RO;
			else
				other = NULL;
			if (other == NULL)
				break;

			/* compare rw(ro) with ro(rw) */
			oprop = sa_get_property(parent, other);
			if (oprop == NULL)
				break;
			/*
			 * only potential
			 * confusion if other
			 * exists
			 */
			ovalue = sa_get_property_attr(oprop, "value");
			if (ovalue != NULL) {
				ret = check_rorw(value, ovalue);
				sa_free_attr_string(ovalue);
			}
			break;
		}
		default:
			break;
		}
	}

	if (value != NULL)
		sa_free_attr_string(value);
	if (ret == SA_OK && optdefs[optindex].check != NULL)
		/* do the property specific check */
		ret = optdefs[optindex].check(property);

	if (propname != NULL)
		sa_free_attr_string(propname);
	return (ret);
}

/*
 * Protocol management functions
 *
 * properties defined in the default files are defined in
 * proto_option_defs for parsing and validation.
 */

struct smb_proto_option_defs {
	int smb_index;
	int32_t minval;
	int32_t maxval; /* In case of length of string this should be max */
	int (*validator)(int, char *);
	int32_t	refresh;
} smb_proto_options[] = {
	{ SMB_CI_SYS_CMNT, 0, MAX_VALUE_BUFLEN,
	    string_length_check_validator, SMB_REFRESH_REFRESH },
	{ SMB_CI_MAX_WORKERS, 64, 1024, range_check_validator,
	    SMB_REFRESH_REFRESH },
	{ SMB_CI_NBSCOPE, 0, MAX_VALUE_BUFLEN,
	    string_length_check_validator, 0 },
	{ SMB_CI_LM_LEVEL, 2, 5, range_check_validator, 0 },
	{ SMB_CI_KEEPALIVE, 20, 5400, range_check_validator_zero_ok,
	    SMB_REFRESH_REFRESH },
	{ SMB_CI_WINS_SRV1, 0, MAX_VALUE_BUFLEN,
	    ipv4_validator, SMB_REFRESH_REFRESH },
	{ SMB_CI_WINS_SRV2, 0, MAX_VALUE_BUFLEN,
	    ipv4_validator, SMB_REFRESH_REFRESH },
	{ SMB_CI_WINS_EXCL, 0, MAX_VALUE_BUFLEN,
	    interface_validator, SMB_REFRESH_REFRESH },
	{ SMB_CI_SIGNING_ENABLE, 0, 0, true_false_validator,
	    SMB_REFRESH_REFRESH },
	{ SMB_CI_SIGNING_REQD, 0, 0, true_false_validator,
	    SMB_REFRESH_REFRESH },
	{ SMB_CI_RESTRICT_ANON, 0, 0, true_false_validator,
	    SMB_REFRESH_REFRESH },
	{ SMB_CI_DOMAIN_SRV, 0, MAX_VALUE_BUFLEN,
	    hostname_validator, SMB_REFRESH_REFRESH },
	{ SMB_CI_ADS_SITE, 0, MAX_VALUE_BUFLEN,
	    string_length_check_validator, SMB_REFRESH_REFRESH },
	{ SMB_CI_DYNDNS_ENABLE, 0, 0, true_false_validator, 0 },
	{ SMB_CI_AUTOHOME_MAP, 0, MAX_VALUE_BUFLEN, path_validator, 0 },
	{ SMB_CI_IPV6_ENABLE, 0, 0, true_false_validator,
	    SMB_REFRESH_REFRESH },
	{ SMB_CI_PRINT_ENABLE, 0, 0, print_enable_validator,
	    SMB_REFRESH_REFRESH },
	{ SMB_CI_TRAVERSE_MOUNTS, 0, 0, true_false_validator,
	    SMB_REFRESH_REFRESH },
	{ SMB_CI_MAP, 0, MAX_VALUE_BUFLEN, cmd_validator, SMB_REFRESH_REFRESH },
	{ SMB_CI_UNMAP, 0, MAX_VALUE_BUFLEN, cmd_validator,
	    SMB_REFRESH_REFRESH },
	{ SMB_CI_DISPOSITION, 0, MAX_VALUE_BUFLEN,
	    disposition_validator, SMB_REFRESH_REFRESH },
};

#define	SMB_OPT_NUM \
	(sizeof (smb_proto_options) / sizeof (smb_proto_options[0]))

/*
 * Check the range of value as int range.
 */
static int
range_check_validator(int index, char *value)
{
	int ret = SA_OK;

	if (!is_a_number(value)) {
		ret = SA_BAD_VALUE;
	} else {
		int val;
		val = strtoul(value, NULL, 0);
		if (val < smb_proto_options[index].minval ||
		    val > smb_proto_options[index].maxval)
			ret = SA_BAD_VALUE;
	}
	return (ret);
}

/*
 * Check the range of value as int range.
 */
static int
range_check_validator_zero_ok(int index, char *value)
{
	int ret = SA_OK;

	if (!is_a_number(value)) {
		ret = SA_BAD_VALUE;
	} else {
		int val;
		val = strtoul(value, NULL, 0);
		if (val == 0)
			ret = SA_OK;
		else {
			if (val < smb_proto_options[index].minval ||
			    val > smb_proto_options[index].maxval)
			ret = SA_BAD_VALUE;
		}
	}
	return (ret);
}

/*
 * Check the length of the string
 */
static int
string_length_check_validator(int index, char *value)
{
	int ret = SA_OK;

	if (value == NULL)
		return (SA_BAD_VALUE);
	if (strlen(value) > smb_proto_options[index].maxval)
		ret = SA_BAD_VALUE;
	return (ret);
}

/*
 * Check yes/no
 */
/*ARGSUSED*/
static int
true_false_validator(int index, char *value)
{
	if (value == NULL)
		return (SA_BAD_VALUE);
	if ((strcasecmp(value, "true") == 0) ||
	    (strcasecmp(value, "false") == 0))
		return (SA_OK);
	return (SA_BAD_VALUE);
}

/*
 * If printing support is compiled in, this is the same as:
 * true_false_validator.  Otherwise, only allow false.
 */
/*ARGSUSED*/
static int
print_enable_validator(int index, char *value)
{
	if (value == NULL)
		return (SA_BAD_VALUE);

#ifdef	HAVE_CUPS
	if (strcasecmp(value, "true") == 0)
		return (SA_OK);
#endif
	if (strcasecmp(value, "false") == 0)
		return (SA_OK);

	return (SA_BAD_VALUE);
}

/*
 * Check IP v4 address.
 */
/*ARGSUSED*/
static int
ipv4_validator(int index, char *value)
{
	char sbytes[16];

	if (value == NULL)
		return (SA_OK);

	if (strlen(value) == 0)
		return (SA_OK);

	if (inet_pton(AF_INET, value, (void *)sbytes) != 1)
		return (SA_BAD_VALUE);

	return (SA_OK);
}

/*
 * Check that the specified name is an IP address (v4 or v6) or a hostname.
 * Per RFC 1035 and 1123, names may contain alphanumeric characters, hyphens
 * and dots.  The first and last character of a label must be alphanumeric.
 * Interior characters may be alphanumeric or hypens.
 *
 * Domain names should not contain underscores but we allow them because
 * Windows names are often in non-compliance with this rule.
 */
/*ARGSUSED*/
static int
hostname_validator(int index, char *value)
{
	char		sbytes[INET6_ADDRSTRLEN];
	boolean_t	new_label = B_TRUE;
	char		*p;
	char		label_terminator;
	int		len;

	if (value == NULL)
		return (SA_OK);

	if ((len = strlen(value)) == 0)
		return (SA_OK);

	if (inet_pton(AF_INET, value, (void *)sbytes) == 1)
		return (SA_OK);

	if (inet_pton(AF_INET6, value, (void *)sbytes) == 1)
		return (SA_OK);

	if (len >= MAXHOSTNAMELEN)
		return (SA_BAD_VALUE);

	if (strspn(value, "0123456789.") == len)
		return (SA_BAD_VALUE);

	label_terminator = *value;

	for (p = value; *p != '\0'; ++p) {
		if (new_label) {
			if (!isalnum(*p))
				return (SA_BAD_VALUE);
			new_label = B_FALSE;
			label_terminator = *p;
			continue;
		}

		if (*p == '.') {
			if (!isalnum(label_terminator))
				return (SA_BAD_VALUE);
			new_label = B_TRUE;
			label_terminator = *p;
			continue;
		}

		label_terminator = *p;

		if (isalnum(*p) || *p == '-' || *p == '_')
			continue;

		return (SA_BAD_VALUE);
	}

	if (!isalnum(label_terminator))
		return (SA_BAD_VALUE);

	return (SA_OK);
}

/*
 * Call back function for dlpi_walk.
 * Returns TRUE if interface name exists on the host.
 */
static boolean_t
smb_get_interface(const char *ifname, void *arg)
{
	smb_hostifs_walker_t *iterp = arg;

	iterp->hiw_matchfound = (strcmp(ifname, iterp->hiw_ifname) == 0);

	return (iterp->hiw_matchfound);
}

/*
 * Checks to see if the input interface exists on the host.
 * Returns B_TRUE if the match is found, B_FALSE otherwise.
 */
static boolean_t
smb_validate_interface(const char *ifname)
{
	smb_hostifs_walker_t	iter;

	if ((ifname == NULL) || (*ifname == '\0'))
		return (B_FALSE);

	iter.hiw_ifname = ifname;
	iter.hiw_matchfound = B_FALSE;
	dlpi_walk(smb_get_interface, &iter, 0);

	return (iter.hiw_matchfound);
}

/*
 * Check valid interfaces. Interface names value can be NULL or empty.
 * Returns SA_BAD_VALUE if interface cannot be found on the host.
 */
/*ARGSUSED*/
static int
interface_validator(int index, char *value)
{
	char buf[16];
	int ret = SA_OK;
	char *ifname, *tmp, *p;

	if (value == NULL || *value == '\0')
		return (ret);

	if (strlen(value) > MAX_VALUE_BUFLEN)
		return (SA_BAD_VALUE);

	if ((p = strdup(value)) == NULL)
		return (SA_NO_MEMORY);

	tmp = p;
	while ((ifname = strsep(&tmp, ",")) != NULL) {
		if (*ifname == '\0') {
			ret = SA_BAD_VALUE;
			break;
		}

		if (!smb_validate_interface(ifname)) {
			if (inet_pton(AF_INET, ifname, (void *)buf) == 0) {
				ret = SA_BAD_VALUE;
				break;
			}
		}
	}

	free(p);
	return (ret);
}

/*
 * Check path
 */
/*ARGSUSED*/
static int
path_validator(int index, char *path)
{
	struct stat buffer;
	int fd, status;

	if (path == NULL)
		return (SA_BAD_VALUE);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return (SA_BAD_VALUE);

	status = fstat(fd, &buffer);
	(void) close(fd);

	if (status < 0)
		return (SA_BAD_VALUE);

	if (buffer.st_mode & S_IFDIR)
		return (SA_OK);
	return (SA_BAD_VALUE);
}

/*
 * the protoset holds the defined options so we don't have to read
 * them multiple times
 */
static sa_protocol_properties_t protoset;

static int
findprotoopt(char *name)
{
	int i;
	char *sc_name;

	for (i = 0; i < SMB_OPT_NUM; i++) {
		sc_name = smb_config_getname(smb_proto_options[i].smb_index);
		if (strcasecmp(sc_name, name) == 0)
			return (i);
	}

	return (-1);
}

/*
 * smb_load_proto_properties()
 *
 * read the smb config values from SMF.
 */

static int
smb_load_proto_properties()
{
	sa_property_t prop;
	char value[MAX_VALUE_BUFLEN];
	char *name;
	int index;
	int ret = SA_OK;
	int rc;

	protoset = sa_create_protocol_properties(SMB_PROTOCOL_NAME);
	if (protoset == NULL)
		return (SA_NO_MEMORY);

	for (index = 0; index < SMB_OPT_NUM && ret == SA_OK; index++) {
		rc = smb_config_get(smb_proto_options[index].smb_index,
		    value, sizeof (value));
		if (rc != SMBD_SMF_OK)
			continue;
		name = smb_config_getname(smb_proto_options[index].smb_index);
		prop = sa_create_property(name, value);
		if (prop != NULL)
			ret = sa_add_protocol_property(protoset, prop);
		else
			ret = SA_NO_MEMORY;
	}
	return (ret);
}

/*
 * smb_share_init()
 *
 * Initialize the smb plugin.
 */

static int
smb_share_init(void)
{
	if (sa_plugin_ops.sa_init != smb_share_init)
		return (SA_SYSTEM_ERR);

	smb_share_door_clnt_init();
	return (smb_load_proto_properties());
}

/*
 * smb_share_fini()
 *
 */
static void
smb_share_fini(void)
{
	xmlFreeNode(protoset);
	protoset = NULL;

	smb_share_door_clnt_fini();
}

/*
 * smb_get_proto_set()
 *
 * Return an optionset with all the protocol specific properties in
 * it.
 */
static sa_protocol_properties_t
smb_get_proto_set(void)
{
	return (protoset);
}

/*
 * smb_enable_dependencies()
 *
 * SMBD_DEFAULT_INSTANCE_FMRI may have some dependencies that aren't
 * enabled. This will attempt to enable all of them.
 */
static void
smb_enable_dependencies(const char *fmri)
{
	scf_handle_t *handle;
	scf_service_t *service;
	scf_instance_t *inst = NULL;
	scf_iter_t *iter;
	scf_property_t *prop;
	scf_value_t *value;
	scf_propertygroup_t *pg;
	scf_scope_t *scope;
	char type[SCFTYPE_LEN];
	char *dependency;
	char *servname;
	int maxlen;

	/*
	 * Get all required handles and storage.
	 */
	handle = scf_handle_create(SCF_VERSION);
	if (handle == NULL)
		return;

	if (scf_handle_bind(handle) != 0) {
		scf_handle_destroy(handle);
		return;
	}

	maxlen = scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH);
	if (maxlen == (ssize_t)-1)
		maxlen = MAXPATHLEN;

	dependency = malloc(maxlen);

	service = scf_service_create(handle);

	iter = scf_iter_create(handle);

	pg = scf_pg_create(handle);

	prop = scf_property_create(handle);

	value = scf_value_create(handle);

	scope = scf_scope_create(handle);

	if (service == NULL || iter == NULL || pg == NULL || prop == NULL ||
	    value == NULL || scope == NULL || dependency == NULL)
		goto done;

	/*
	 *  We passed in the FMRI for the default instance but for
	 *  some things we need the simple form so construct it. Since
	 *  we reuse the storage that dependency points to, we need to
	 *  use the servname early.
	 */
	(void) snprintf(dependency, maxlen, "%s", fmri + sizeof ("svc:"));
	servname = strrchr(dependency, ':');
	if (servname == NULL)
		goto done;
	*servname = '\0';
	servname = dependency;

	/*
	 * Setup to iterate over the service property groups, only
	 * looking at those that are "dependency" types. The "entity"
	 * property will have the FMRI of the service we are dependent
	 * on.
	 */
	if (scf_handle_get_scope(handle, SCF_SCOPE_LOCAL, scope) != 0)
		goto done;

	if (scf_scope_get_service(scope, servname, service) != 0)
		goto done;

	if (scf_iter_service_pgs(iter, service) != 0)
		goto done;

	while (scf_iter_next_pg(iter, pg) > 0) {
		char *services[2];
		/*
		 * Have a property group for the service. See if it is
		 * a dependency pg and only do operations on those.
		 */
		if (scf_pg_get_type(pg, type, SCFTYPE_LEN) <= 0)
			continue;

		if (strncmp(type, SCF_GROUP_DEPENDENCY, SCFTYPE_LEN) != 0)
			continue;
		/*
		 * Have a dependency.  Attempt to enable it.
		 */
		if (scf_pg_get_property(pg, SCF_PROPERTY_ENTITIES, prop) != 0)
			continue;

		if (scf_property_get_value(prop, value) != 0)
			continue;

		services[1] = NULL;

		if (scf_value_get_as_string(value, dependency, maxlen) > 0) {
			services[0] = dependency;
			_check_services(services);
		}
	}

done:
	if (dependency != NULL)
		free(dependency);
	if (value != NULL)
		scf_value_destroy(value);
	if (prop != NULL)
		scf_property_destroy(prop);
	if (pg != NULL)
		scf_pg_destroy(pg);
	if (iter != NULL)
		scf_iter_destroy(iter);
	if (scope != NULL)
		scf_scope_destroy(scope);
	if (inst != NULL)
		scf_instance_destroy(inst);
	if (service != NULL)
		scf_service_destroy(service);

	(void) scf_handle_unbind(handle);
	scf_handle_destroy(handle);
}

/*
 * How long to wait for service to come online
 */
#define	WAIT_FOR_SERVICE	15

/*
 * smb_enable_service()
 *
 */
static int
smb_enable_service(void)
{
	int i;
	int ret = SA_OK;
	char *service[] = { SMBD_DEFAULT_INSTANCE_FMRI, NULL };

	if (!smb_isonline()) {
		/*
		 * Attempt to start the idmap, and other dependent
		 * services, first.  If it fails, the SMB service will
		 * ultimately fail so we use that as the error.  If we
		 * don't try to enable idmap, smb won't start the
		 * first time unless the admin has done it
		 * manually. The service could be administratively
		 * disabled so we won't always get started.
		 */
		smb_enable_dependencies(SMBD_DEFAULT_INSTANCE_FMRI);
		_check_services(service);

		/* Wait for service to come online */
		for (i = 0; i < WAIT_FOR_SERVICE; i++) {
			if (smb_isonline()) {
				ret =  SA_OK;
				break;
			} else if (smb_ismaint()) {
				/* maintenance requires help */
				ret = SA_SYSTEM_ERR;
				break;
			} else {
				/* try another time */
				ret = SA_BUSY;
				(void) sleep(1);
			}
		}
	}
	return (ret);
}

/*
 * smb_validate_proto_prop(index, name, value)
 *
 * Verify that the property specified by name can take the new
 * value. This is a sanity check to prevent bad values getting into
 * the default files.
 */
static int
smb_validate_proto_prop(int index, char *name, char *value)
{
	if ((name == NULL) || (index < 0))
		return (SA_BAD_VALUE);

	if (smb_proto_options[index].validator == NULL)
		return (SA_OK);

	if (smb_proto_options[index].validator(index, value) == SA_OK)
		return (SA_OK);
	return (SA_BAD_VALUE);
}

/*
 * smb_set_proto_prop(prop)
 *
 * check that prop is valid.
 */
/*ARGSUSED*/
static int
smb_set_proto_prop(sa_property_t prop)
{
	int ret = SA_OK;
	char *name;
	char *value;
	int index = -1;
	struct smb_proto_option_defs *opt;

	name = sa_get_property_attr(prop, "type");
	value = sa_get_property_attr(prop, "value");
	if (name != NULL && value != NULL) {
		index = findprotoopt(name);
		if (index >= 0) {
			/* should test for valid value */
			ret = smb_validate_proto_prop(index, name, value);
			if (ret == SA_OK) {
				opt = &smb_proto_options[index];

				/* Save to SMF */
				(void) smb_config_set(opt->smb_index, value);
				/*
				 * Specialized refresh mechanisms can
				 * be flagged in the proto_options and
				 * processed here.
				 */
				if (opt->refresh & SMB_REFRESH_REFRESH)
					(void) smf_refresh_instance(
					    SMBD_DEFAULT_INSTANCE_FMRI);
				else if (opt->refresh & SMB_REFRESH_RESTART)
					(void) smf_restart_instance(
					    SMBD_DEFAULT_INSTANCE_FMRI);
			}
		}
	}

	if (name != NULL)
		sa_free_attr_string(name);
	if (value != NULL)
		sa_free_attr_string(value);

	return (ret);
}

/*
 * smb_get_status()
 *
 * What is the current status of the smbd? We use the SMF state here.
 * Caller must free the returned value.
 */

static char *
smb_get_status(void)
{
	return (smf_get_state(SMBD_DEFAULT_INSTANCE_FMRI));
}

/*
 * This protocol plugin require resource names
 */
static uint64_t
smb_share_features(void)
{
	return (SA_FEATURE_RESOURCE | SA_FEATURE_ALLOWSUBDIRS |
	    SA_FEATURE_ALLOWPARDIRS | SA_FEATURE_SERVER);
}

/*
 * This should be used to convert smb_share_t to sa_resource_t
 * Should only be needed to build transient shares/resources to be
 * supplied to sharemgr to display.
 */
static int
smb_add_transient(sa_handle_t handle, smb_share_t *si)
{
	int err;
	sa_share_t share;
	sa_group_t group;
	sa_resource_t resource;
	nvlist_t *nvl;
	char *opt;

	if (si == NULL)
		return (SA_INVALID_NAME);

	if ((share = sa_find_share(handle, si->shr_path)) == NULL) {
		if ((group = smb_get_defaultgrp(handle)) == NULL)
			return (SA_NO_SUCH_GROUP);

		share = sa_get_share(group, si->shr_path);
		if (share == NULL) {
			share = sa_add_share(group, si->shr_path,
			    SA_SHARE_TRANSIENT, &err);
			if (share == NULL)
				return (SA_NO_SUCH_PATH);
		}
	}

	/*
	 * Now handle the resource. Make sure that the resource is
	 * transient and added to the share.
	 */
	resource = sa_get_share_resource(share, si->shr_name);
	if (resource == NULL) {
		resource = sa_add_resource(share,
		    si->shr_name, SA_SHARE_TRANSIENT, &err);
		if (resource == NULL)
			return (SA_NO_SUCH_RESOURCE);
	}

	if (si->shr_cmnt[0] != '\0')
		(void) sa_set_resource_description(resource, si->shr_cmnt);

	if (si->shr_container[0] != '\0')
		(void) sa_set_resource_attr(resource, SHOPT_AD_CONTAINER,
		    si->shr_container);

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0)
		return (SA_NO_MEMORY);

	if ((opt = smb_csc_name(si)) != NULL)
		err |= nvlist_add_string(nvl, SHOPT_CSC, opt);

	opt = (si->shr_flags & SMB_SHRF_ABE) ? "true" : "false";
	err |= nvlist_add_string(nvl, SHOPT_ABE, opt);

	if ((si->shr_flags & SMB_SHRF_AUTOHOME) == 0) {
		opt = (si->shr_flags & SMB_SHRF_GUEST_OK) ? "true" : "false";
		err |= nvlist_add_string(nvl, SHOPT_GUEST, opt);
	}

	if (si->shr_access_ro[0] != '\0')
		err |= nvlist_add_string(nvl, SHOPT_RO, si->shr_access_ro);

	if (si->shr_access_rw[0] != '\0')
		err |= nvlist_add_string(nvl, SHOPT_RW, si->shr_access_rw);

	if (si->shr_access_none[0] != '\0')
		err |= nvlist_add_string(nvl, SHOPT_NONE, si->shr_access_none);

	if (err) {
		nvlist_free(nvl);
		return (SA_CONFIG_ERR);
	}

	err = smb_update_optionset_props(handle, resource, nvl);

	nvlist_free(nvl);
	return (err);
}

/*
 * Return smb transient shares.
 */
static int
smb_list_transient(sa_handle_t handle)
{
	int i, offset;
	smb_shrlist_t list;
	int res;

	if (smb_share_count() <= 0)
		return (SA_OK);

	offset = 0;
	while (smb_share_list(offset, &list) == NERR_Success) {
		if (list.sl_cnt == 0)
			break;

		for (i = 0; i < list.sl_cnt; i++) {
			res = smb_add_transient(handle, &(list.sl_shares[i]));
			if (res != SA_OK)
				return (res);
		}
		offset += list.sl_cnt;
	}

	return (SA_OK);
}

/*
 * fix_resource_name(share, name,  prefix)
 *
 * Construct a name where the ZFS dataset has the prefix replaced with "name".
 */
static char *
fix_resource_name(sa_share_t share, char *name, char *prefix)
{
	char buf[SA_MAX_RESOURCE_NAME + 1];
	char *dataset;
	size_t bufsz = SA_MAX_RESOURCE_NAME + 1;
	size_t prelen;

	if (prefix == NULL)
		return (strdup(name));

	dataset = sa_get_share_attr(share, "dataset");
	if (dataset == NULL)
		return (strdup(name));

	(void) strlcpy(buf, name, bufsz);
	prelen = strlen(prefix);

	if (strncmp(dataset, prefix, prelen) == 0)
		(void) strlcat(buf, dataset + prelen, bufsz);

	sa_free_attr_string(dataset);
	sa_fix_resource_name(buf);
	return (strdup(buf));
}

/*
 * smb_parse_optstring(group, options)
 *
 * parse a compact option string into individual options. This allows
 * ZFS sharesmb and sharemgr "share" command to work.  group can be a
 * group, a share or a resource.
 */
static int
smb_parse_optstring(sa_group_t group, char *options)
{
	char *dup;
	char *base;
	char *lasts;
	char *token;
	sa_optionset_t optionset;
	sa_group_t parent = NULL;
	sa_resource_t resource = NULL;
	int iszfs = 0;
	int persist = 0;
	int need_optionset = 0;
	int ret = SA_OK;
	sa_property_t prop;

	/*
	 * In order to not attempt to change ZFS properties unless
	 * absolutely necessary, we never do it in the legacy parsing
	 * so we need to keep track of this.
	 */
	if (sa_is_share(group)) {
		char *zfs;

		parent = sa_get_parent_group(group);
		if (parent != NULL) {
			zfs = sa_get_group_attr(parent, "zfs");
			if (zfs != NULL) {
				sa_free_attr_string(zfs);
				iszfs = 1;
			}
		}
	} else {
		iszfs = sa_group_is_zfs(group);
		/*
		 * If a ZFS group, then we need to see if a resource
		 * name is being set. If so, bail with
		 * SA_PROP_SHARE_ONLY, so we come back in with a share
		 * instead of a group.
		 */
		if (iszfs ||
		    strncmp(options, "name=", sizeof ("name=") - 1) == 0 ||
		    strstr(options, ",name=") != NULL) {
			return (SA_PROP_SHARE_ONLY);
		}
	}

	/* do we have an existing optionset? */
	optionset = sa_get_optionset(group, "smb");
	if (optionset == NULL) {
		/* didn't find existing optionset so create one */
		optionset = sa_create_optionset(group, "smb");
		if (optionset == NULL)
			return (SA_NO_MEMORY);
	} else {
		/*
		 * If an optionset already exists, we've come through
		 * twice so ignore the second time.
		 */
		return (ret);
	}

	/* We need a copy of options for the next part. */
	dup = strdup(options);
	if (dup == NULL)
		return (SA_NO_MEMORY);

	/*
	 * SMB properties are straightforward and are strings,
	 * integers or booleans.  Properties are separated by
	 * commas. It will be necessary to parse quotes due to some
	 * strings not having a restricted characters set.
	 *
	 * Note that names will create a resource. For now, if there
	 * is a set of properties "before" the first name="", those
	 * properties will be placed on the group.
	 */
	persist = sa_is_persistent(group);
	base = dup;
	token = dup;
	lasts = NULL;
	while (token != NULL && ret == SA_OK) {
		ret = SA_OK;
		token = strtok_r(base, ",", &lasts);
		base = NULL;
		if (token != NULL) {
			char *value;
			/*
			 * All SMB properties have values so there
			 * MUST be an '=' character.  If it doesn't,
			 * it is a syntax error.
			 */
			value = strchr(token, '=');
			if (value != NULL) {
				*value++ = '\0';
			} else {
				ret = SA_SYNTAX_ERR;
				break;
			}
			/*
			 * We may need to handle a "name" property
			 * that is a ZFS imposed resource name. Each
			 * name would trigger getting a new "resource"
			 * to put properties on. For now, assume no
			 * "name" property for special handling.
			 */

			if (strcmp(token, SHOPT_NAME) == 0) {
				char *prefix;
				char *name = NULL;
				/*
				 * We have a name, so now work on the
				 * resource level. We have a "share"
				 * in "group" due to the caller having
				 * added it. If we are called with a
				 * group, the check for group/share
				 * at the beginning of this function
				 * will bail out the parse if there is a
				 * "name" but no share.
				 */
				if (!iszfs) {
					ret = SA_SYNTAX_ERR;
					break;
				}
				/*
				 * Make sure the parent group has the
				 * "prefix" property since we will
				 * need to use this for constructing
				 * inherited name= values.
				 */
				prefix = sa_get_group_attr(parent, "prefix");
				if (prefix == NULL) {
					prefix = sa_get_group_attr(parent,
					    "name");
					if (prefix != NULL) {
						(void) sa_set_group_attr(parent,
						    "prefix", prefix);
					}
				}
				name = fix_resource_name((sa_share_t)group,
				    value, prefix);
				if (name != NULL) {
					resource = sa_add_resource(
					    (sa_share_t)group, name,
					    SA_SHARE_TRANSIENT, &ret);
					sa_free_attr_string(name);
				} else {
					ret = SA_NO_MEMORY;
				}
				if (prefix != NULL)
					sa_free_attr_string(prefix);

				/* A resource level optionset is needed */

				need_optionset = 1;
				if (resource == NULL) {
					ret = SA_NO_MEMORY;
					break;
				}
				continue;
			}

			if (iszfs && strcmp(token, SHOPT_DESCRIPTION) == 0) {
				if (resource == NULL)
					(void) sa_set_share_description(
					    (sa_share_t)group, value);
				else
					(void) sa_set_resource_description(
					    resource, value);
				continue;
			}

			if (need_optionset) {
				optionset = sa_create_optionset(resource,
				    "smb");
				need_optionset = 0;
			}

			prop = sa_create_property(token, value);
			if (prop == NULL)
				ret = SA_NO_MEMORY;
			else
				ret = sa_add_property(optionset, prop);
			if (ret != SA_OK)
				break;
			if (!iszfs)
				ret = sa_commit_properties(optionset, !persist);
		}
	}
	free(dup);
	return (ret);
}

/*
 * smb_sprint_option(rbuff, rbuffsize, incr, prop, sep)
 *
 * provides a mechanism to format SMB properties into legacy output
 * format. If the buffer would overflow, it is reallocated and grown
 * as appropriate. Special cases of converting internal form of values
 * to those used by "share" are done. this function does one property
 * at a time.
 */

static void
smb_sprint_option(char **rbuff, size_t *rbuffsize, size_t incr,
			sa_property_t prop, int sep)
{
	char *name;
	char *value;
	int curlen;
	char *buff = *rbuff;
	size_t buffsize = *rbuffsize;

	name = sa_get_property_attr(prop, "type");
	value = sa_get_property_attr(prop, "value");
	if (buff != NULL)
		curlen = strlen(buff);
	else
		curlen = 0;
	if (name != NULL) {
		int len;
		len = strlen(name) + sep;

		/*
		 * A future RFE would be to replace this with more
		 * generic code and to possibly handle more types.
		 *
		 * For now, everything else is treated as a string. If
		 * we get any properties that aren't exactly
		 * name/value pairs, we may need to
		 * interpret/transform.
		 */
		if (value != NULL)
			len += 1 + strlen(value);

		while (buffsize <= (curlen + len)) {
			/* need more room */
			buffsize += incr;
			buff = realloc(buff, buffsize);
			*rbuff = buff;
			*rbuffsize = buffsize;
			if (buff == NULL) {
				/* realloc failed so free everything */
				if (*rbuff != NULL)
					free(*rbuff);
				goto err;
			}
		}
		if (buff == NULL)
			goto err;
		(void) snprintf(buff + curlen, buffsize - curlen,
		    "%s%s=%s", sep ? "," : "",
		    name, value != NULL ? value : "\"\"");

	}
err:
	if (name != NULL)
		sa_free_attr_string(name);
	if (value != NULL)
		sa_free_attr_string(value);
}

/*
 * smb_format_resource_options(resource, hier)
 *
 * format all the options on the group into a flattened option
 * string. If hier is non-zero, walk up the tree to get inherited
 * options.
 */

static char *
smb_format_options(sa_group_t group, int hier)
{
	sa_optionset_t options = NULL;
	sa_property_t prop;
	int sep = 0;
	char *buff;
	size_t buffsize;


	buff = malloc(OPT_CHUNK);
	if (buff == NULL)
		return (NULL);

	buff[0] = '\0';
	buffsize = OPT_CHUNK;

	/*
	 * We may have a an optionset relative to this item. format
	 * these if we find them and then add any security definitions.
	 */

	options = sa_get_derived_optionset(group, "smb", hier);

	/*
	 * do the default set first but skip any option that is also
	 * in the protocol specific optionset.
	 */
	if (options != NULL) {
		for (prop = sa_get_property(options, NULL);
		    prop != NULL; prop = sa_get_next_property(prop)) {
			/*
			 * use this one since we skipped any
			 * of these that were also in
			 * optdefault
			 */
			smb_sprint_option(&buff, &buffsize, OPT_CHUNK,
			    prop, sep);
			if (buff == NULL) {
				/*
				 * buff could become NULL if there
				 * isn't enough memory for
				 * smb_sprint_option to realloc()
				 * as necessary. We can't really
				 * do anything about it at this
				 * point so we return NULL.  The
				 * caller should handle the
				 * failure.
				 */
				if (options != NULL)
					sa_free_derived_optionset(
					    options);
				return (buff);
			}
			sep = 1;
		}
	}

	if (options != NULL)
		sa_free_derived_optionset(options);
	return (buff);
}

/*
 * smb_rename_resource(resource, newname)
 *
 * Change the current exported name of the resource to newname.
 */
/*ARGSUSED*/
int
smb_rename_resource(sa_handle_t handle, sa_resource_t resource, char *newname)
{
	int ret = SA_OK;
	int err;
	char *oldname;

	if (!smb_isonline())
		return (SA_OK);

	oldname = sa_get_resource_attr(resource, "name");
	if (oldname == NULL)
		return (SA_NO_SUCH_RESOURCE);

	err = smb_share_rename(oldname, newname);

	sa_free_attr_string(oldname);

	/* improve error values somewhat */
	switch (err) {
	case NERR_Success:
		break;
	case NERR_InternalError:
		ret = SA_SYSTEM_ERR;
		break;
	case NERR_DuplicateShare:
		ret = SA_DUPLICATE_NAME;
		break;
	default:
		ret = SA_CONFIG_ERR;
		break;
	}

	return (ret);
}

static int
smb_build_shareinfo(sa_share_t share, sa_resource_t resource, smb_share_t *si)
{
	sa_optionset_t opts;
	char *path;
	char *rname;
	char *val = NULL;
	char csc_value[SMB_CSC_BUFSZ];

	bzero(si, sizeof (smb_share_t));

	if ((path = sa_get_share_attr(share, "path")) == NULL)
		return (SA_NO_SUCH_PATH);

	if ((rname = sa_get_resource_attr(resource, "name")) == NULL) {
		sa_free_attr_string(path);
		return (SA_NO_SUCH_RESOURCE);
	}

	(void) strlcpy(si->shr_path, path, sizeof (si->shr_path));
	(void) strlcpy(si->shr_name, rname, sizeof (si->shr_name));
	sa_free_attr_string(path);
	sa_free_attr_string(rname);

	val = sa_get_resource_description(resource);
	if (val == NULL)
		val = sa_get_share_description(share);

	if (val != NULL) {
		(void) strlcpy(si->shr_cmnt, val, sizeof (si->shr_cmnt));
		sa_free_share_description(val);
	}

	si->shr_flags = (sa_is_persistent(share))
	    ? SMB_SHRF_PERM : SMB_SHRF_TRANS;

	opts = sa_get_derived_optionset(resource, SMB_PROTOCOL_NAME, 1);
	if (opts == NULL)
		return (SA_OK);

	if (smb_saprop_getbool(opts, SHOPT_CATIA))
		si->shr_flags |= SMB_SHRF_CATIA;

	if (smb_saprop_getbool(opts, SHOPT_ABE))
		si->shr_flags |= SMB_SHRF_ABE;

	if (smb_saprop_getbool(opts, SHOPT_GUEST))
		si->shr_flags |= SMB_SHRF_GUEST_OK;

	if (smb_saprop_getbool(opts, SHOPT_DFSROOT))
		si->shr_flags |= SMB_SHRF_DFSROOT;

	(void) smb_saprop_getstr(opts, SHOPT_AD_CONTAINER, si->shr_container,
	    sizeof (si->shr_container));

	if (smb_saprop_getstr(opts, SHOPT_CSC, csc_value, sizeof (csc_value)))
		smb_csc_option(csc_value, si);

	if (smb_saprop_getstr(opts, SHOPT_RO, si->shr_access_ro,
	    sizeof (si->shr_access_ro)))
		si->shr_flags |= SMB_SHRF_ACC_RO;

	if (smb_saprop_getstr(opts, SHOPT_RW, si->shr_access_rw,
	    sizeof (si->shr_access_rw)))
		si->shr_flags |= SMB_SHRF_ACC_RW;

	if (smb_saprop_getstr(opts, SHOPT_NONE, si->shr_access_none,
	    sizeof (si->shr_access_none)))
		si->shr_flags |= SMB_SHRF_ACC_NONE;

	sa_free_derived_optionset(opts);
	return (SA_OK);
}

/*
 * Map a client-side caching (CSC) option to the appropriate share
 * flag.  Only one option is allowed; an error will be logged if
 * multiple options have been specified.  We don't need to do anything
 * about multiple values here because the SRVSVC will not recognize
 * a value containing multiple flags and will return the default value.
 *
 * If the option value is not recognized, it will be ignored: invalid
 * values will typically be caught and rejected by sharemgr.
 */
static void
smb_csc_option(const char *value, smb_share_t *si)
{
	char buf[SMB_CSC_BUFSZ];
	int i;

	for (i = 0; i < (sizeof (cscopt) / sizeof (cscopt[0])); ++i) {
		if (strcasecmp(value, cscopt[i].value) == 0) {
			si->shr_flags |= cscopt[i].flag;
			break;
		}
	}

	switch (si->shr_flags & SMB_SHRF_CSC_MASK) {
	case 0:
	case SMB_SHRF_CSC_DISABLED:
	case SMB_SHRF_CSC_MANUAL:
	case SMB_SHRF_CSC_AUTO:
	case SMB_SHRF_CSC_VDO:
		break;

	default:
		buf[0] = '\0';

		for (i = 0; i < (sizeof (cscopt) / sizeof (cscopt[0])); ++i) {
			if (si->shr_flags & cscopt[i].flag) {
				(void) strlcat(buf, " ", SMB_CSC_BUFSZ);
				(void) strlcat(buf, cscopt[i].value,
				    SMB_CSC_BUFSZ);
			}
		}

		syslog(LOG_ERR, "csc option conflict:%s", buf);
		break;
	}
}

/*
 * Return the option name for the first CSC flag (there should be only
 * one) encountered in the share flags.
 */
static char *
smb_csc_name(const smb_share_t *si)
{
	int i;

	for (i = 0; i < (sizeof (cscopt) / sizeof (cscopt[0])); ++i) {
		if (si->shr_flags & cscopt[i].flag)
			return (cscopt[i].value);
	}

	return (NULL);
}

/*
 * smb_get_defaultgrp
 *
 * If default group for CIFS shares (i.e. "smb") exists
 * then it will return the group handle, otherwise it will
 * create the group and return the handle.
 *
 * All the shares created by CIFS clients (this is only possible
 * via RPC) will be added to "smb" groups.
 */
static sa_group_t
smb_get_defaultgrp(sa_handle_t handle)
{
	sa_group_t group = NULL;
	int err;

	group = sa_get_group(handle, SMB_DEFAULT_SHARE_GROUP);
	if (group != NULL)
		return (group);

	group = sa_create_group(handle, SMB_DEFAULT_SHARE_GROUP, &err);
	if (group == NULL)
		return (NULL);

	if (sa_create_optionset(group, SMB_DEFAULT_SHARE_GROUP) == NULL) {
		(void) sa_remove_group(group);
		group = NULL;
	}

	return (group);
}

/*
 * Checks to see if the command args are the supported substitution specifier.
 * i.e. <cmd> %U %S
 */
static int
cmd_validator(int index, char *value)
{
	char cmd[MAXPATHLEN];
	char *ptr, *v;
	boolean_t skip_cmdname;

	if (string_length_check_validator(index, value) != SA_OK)
		return (SA_BAD_VALUE);

	if (*value == '\0')
		return (SA_OK);

	(void) strlcpy(cmd, value, sizeof (cmd));

	ptr = cmd;
	skip_cmdname = B_TRUE;
	do {
		if ((v = strsep(&ptr, " ")) == NULL)
			break;

		if (*v != '\0') {

			if (skip_cmdname) {
				skip_cmdname = B_FALSE;
				continue;
			}

			if ((strlen(v) != 2) || *v != '%')
				return (SA_BAD_VALUE);

			if (strpbrk(v, SMB_VALID_SUB_CHRS) == NULL)
				return (SA_BAD_VALUE);
		}

	} while (v != NULL);

	/*
	 * If skip_cmdname is still true then the string contains
	 * only spaces.  Don't allow such a string.
	 */
	if (skip_cmdname)
		return (SA_BAD_VALUE);

	return (SA_OK);
}

/*ARGSUSED*/
static int
disposition_validator(int index, char *value)
{
	if (value == NULL)
		return (SA_BAD_VALUE);

	if (*value == '\0')
		return (SA_OK);

	if ((strcasecmp(value, SMB_EXEC_DISP_CONTINUE) == 0) ||
	    (strcasecmp(value, SMB_EXEC_DISP_TERMINATE) == 0))
		return (SA_OK);

	return (SA_BAD_VALUE);
}

/*
 * Updates the optionset properties of the share resource.
 * The properties are given as a list of name-value pair.
 * The name argument should be the optionset property name and the value
 * should be a valid value for the specified property.
 *
 * When calling this function for permanent shares, the caller must also
 * call sa_commit_properties() to commit the changes to SMF.
 */
static int
smb_update_optionset_props(sa_handle_t handle, sa_resource_t resource,
    nvlist_t *nvl)
{
	sa_property_t prop;
	sa_optionset_t opts;
	int err = SA_OK;
	nvpair_t *cur;
	char *name, *val;

	if ((opts = sa_get_optionset(resource, SMB_PROTOCOL_NAME)) == NULL) {
		opts = sa_create_optionset(resource, SMB_PROTOCOL_NAME);
		if (opts == NULL)
			return (SA_CONFIG_ERR);
	}

	cur = nvlist_next_nvpair(nvl, NULL);
	while (cur != NULL) {
		name = nvpair_name(cur);
		err = nvpair_value_string(cur, &val);
		if ((err != 0) || (name == NULL) || (val == NULL)) {
			err = SA_CONFIG_ERR;
			break;
		}

		prop = NULL;
		if ((prop = sa_get_property(opts, name)) == NULL) {
			prop = sa_create_property(name, val);
			if (prop != NULL) {
				err = sa_valid_property(handle, opts,
				    SMB_PROTOCOL_NAME, prop);
				if (err != SA_OK) {
					(void) sa_remove_property(prop);
					break;
				}
			}
			err = sa_add_property(opts, prop);
			if (err != SA_OK)
				break;
		} else {
			err = sa_update_property(prop, val);
			if (err != SA_OK)
				break;
		}

		cur = nvlist_next_nvpair(nvl, cur);
	}

	return (err);
}

static boolean_t
smb_saprop_getbool(sa_optionset_t opts, char *propname)
{
	sa_property_t prop;
	char *val;
	boolean_t propval = B_FALSE;

	prop = sa_get_property(opts, propname);
	if ((val = sa_get_property_attr(prop, "value")) != NULL) {
		if ((strcasecmp(val, "true") == 0) || (strcmp(val, "1") == 0))
			propval = B_TRUE;
		free(val);
	}

	return (propval);
}

static boolean_t
smb_saprop_getstr(sa_optionset_t opts, char *propname, char *buf, size_t bufsz)
{
	sa_property_t prop;
	char *val;

	prop = sa_get_property(opts, propname);
	if ((val = sa_get_property_attr(prop, "value")) != NULL) {
		(void) strlcpy(buf, val, bufsz);
		free(val);
		return (B_TRUE);
	}

	return (B_FALSE);
}
