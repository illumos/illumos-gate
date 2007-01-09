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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Share control API
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "libshare.h"
#include "libshare_impl.h"
#include <libscf.h>
#include "scfutil.h"
#include <ctype.h>
#include <libintl.h>

#if _NOT_SMF
#define	CONFIG_FILE	"/var/tmp/share.cfg"
#define	CONFIG_FILE_TMP	"/var/tmp/share.cfg.tmp"
#endif
#define	TSTAMP(tm)	(uint64_t)(((uint64_t)tm.tv_sec << 32) | \
					(tm.tv_nsec & 0xffffffff))

/*
 * internal data structures
 */

static xmlNodePtr sa_config_tree;	/* the current config */
static xmlDocPtr  sa_config_doc = NULL;	/* current config document */
extern struct sa_proto_plugin *sap_proto_list;

/* current SMF/SVC repository handle */
static scfutilhandle_t *scf_handle = NULL;
extern void getlegacyconfig(char *, xmlNodePtr *);
extern int gettransients(xmlNodePtr *);
extern int sa_valid_property(void *, char *, sa_property_t);
extern char *sa_fstype(char *);
extern int sa_is_share(void *);
extern ssize_t scf_max_name_len; /* defined in scfutil during initialization */
extern int sa_group_is_zfs(sa_group_t);
extern int sa_path_is_zfs(char *);
extern int sa_zfs_set_sharenfs(sa_group_t, char *, int);
extern void update_legacy_config(void);
extern int issubdir(char *, char *);
extern void sa_zfs_init(void);
extern void sa_zfs_fini(void);

static int sa_initialized = 0;

/* helper functions */

char *
sa_errorstr(int err)
{
	static char errstr[32];
	char *ret = NULL;

	switch (err) {
	case SA_OK:
	    ret = gettext("ok");
	    break;
	case SA_NO_SUCH_PATH:
	    ret = gettext("path doesn't exist");
	    break;
	case SA_NO_MEMORY:
	    ret = gettext("no memory");
	    break;
	case SA_DUPLICATE_NAME:
	    ret = gettext("name in use");
	    break;
	case SA_BAD_PATH:
	    ret = gettext("bad path");
	    break;
	case SA_NO_SUCH_GROUP:
	    ret = gettext("no such group");
	    break;
	case SA_CONFIG_ERR:
	    ret = gettext("configuration error");
	    break;
	case SA_SYSTEM_ERR:
	    ret = gettext("system error");
	    break;
	case SA_SYNTAX_ERR:
	    ret = gettext("syntax error");
	    break;
	case SA_NO_PERMISSION:
	    ret = gettext("no permission");
	    break;
	case SA_BUSY:
	    ret = gettext("busy");
	    break;
	case SA_NO_SUCH_PROP:
	    ret = gettext("no such property");
	    break;
	case SA_INVALID_NAME:
	    ret = gettext("invalid name");
	    break;
	case SA_INVALID_PROTOCOL:
	    ret = gettext("invalid protocol");
	    break;
	case SA_NOT_ALLOWED:
	    ret = gettext("operation not allowed");
	    break;
	case SA_BAD_VALUE:
	    ret = gettext("bad property value");
	    break;
	case SA_INVALID_SECURITY:
	    ret = gettext("invalid security type");
	    break;
	case SA_NO_SUCH_SECURITY:
	    ret = gettext("security type not found");
	    break;
	case SA_VALUE_CONFLICT:
	    ret = gettext("property value conflict");
	    break;
	case SA_NOT_IMPLEMENTED:
	    ret = gettext("not implemented");
	    break;
	case SA_INVALID_PATH:
	    ret = gettext("invalid path");
	    break;
	case SA_NOT_SUPPORTED:
	    ret = gettext("operation not supported");
	    break;
	case SA_PROP_SHARE_ONLY:
	    ret = gettext("property not valid for group");
	    break;
	case SA_NOT_SHARED:
	    ret = gettext("not shared");
	    break;
	default:
	    (void) snprintf(errstr, sizeof (errstr),
				gettext("unknown %d"), err);
	    ret = errstr;
	}
	return (ret);
}

/*
 * get_legacy_timestamp(root, path)
 *	gets the timestamp of the last time sharemgr updated the legacy
 *	files. This is used to determine if someone has modified them by
 *	hand.
 */
static uint64_t
get_legacy_timestamp(xmlNodePtr root, char *path)
{
	uint64_t tval = 0;
	xmlNodePtr node;
	xmlChar *lpath = NULL;
	xmlChar *timestamp = NULL;

	for (node = root->xmlChildrenNode; node != NULL;
		node = node->next) {
	    if (xmlStrcmp(node->name, (xmlChar *)"legacy") == 0) {
		/* a possible legacy node for this path */
		lpath = xmlGetProp(node, (xmlChar *)"path");
		if (lpath != NULL && xmlStrcmp(lpath, (xmlChar *)path) == 0) {
		    /* now have the node, extract the data */
		    timestamp = xmlGetProp(node, (xmlChar *)"timestamp");
		    if (timestamp != NULL) {
			tval = strtoull((char *)timestamp, NULL, 0);
			break;
		    }
		}
		if (lpath != NULL) {
		    xmlFree(lpath);
		    lpath = NULL;
		}
	    }
	}
	if (lpath != NULL)
	    xmlFree(lpath);
	if (timestamp != NULL)
	    xmlFree(timestamp);
	return (tval);
}

/*
 * set_legacy_timestamp(root, path, timevalue)
 *
 * add the current timestamp value to the configuration for use in
 * determining when to update the legacy files.  For SMF, this
 * property is kept in default/operation/legacy_timestamp
 */

static void
set_legacy_timestamp(xmlNodePtr root, char *path, uint64_t tval)
{
	xmlNodePtr node;
	xmlChar *lpath = NULL;

	for (node = root->xmlChildrenNode; node != NULL;
		node = node->next) {
	    if (xmlStrcmp(node->name, (xmlChar *)"legacy") == 0) {
		/* a possible legacy node for this path */
		lpath = xmlGetProp(node, (xmlChar *)"path");
		if (lpath != NULL && xmlStrcmp(lpath, (xmlChar *)path) == 0) {
		    xmlFree(lpath);
		    break;
		}
		if (lpath != NULL)
		    xmlFree(lpath);
	    }
	}
	if (node == NULL) {
	    /* need to create the first legacy timestamp node */
	    node = xmlNewChild(root, NULL, (xmlChar *)"legacy", NULL);
	}
	if (node != NULL) {
	    char tstring[32];
	    int ret;

	    (void) snprintf(tstring, sizeof (tstring), "%lld", tval);
	    xmlSetProp(node, (xmlChar *)"timestamp", (xmlChar *)tstring);
	    xmlSetProp(node, (xmlChar *)"path", (xmlChar *)path);
	    /* now commit to SMF */
	    ret = sa_get_instance(scf_handle, "default");
	    if (ret == SA_OK) {
		ret = sa_start_transaction(scf_handle, "operation");
		if (ret == SA_OK) {
		    ret = sa_set_property(scf_handle, "legacy-timestamp",
					    tstring);
		    if (ret == SA_OK) {
			(void) sa_end_transaction(scf_handle);
		    } else {
			sa_abort_transaction(scf_handle);
		    }
		}
	    }
	}
}

/*
 * is_shared(share)
 *
 * determine if the specified share is currently shared or not.
 */
static int
is_shared(sa_share_t share)
{
	char *shared;
	int result = 0; /* assume not */

	shared = sa_get_share_attr(share, "shared");
	if (shared != NULL) {
	    if (strcmp(shared, "true") == 0)
		result = 1;
	    sa_free_attr_string(shared);
	}
	return (result);
}

/*
 * checksubdir(newpath, strictness)
 *
 * checksubdir determines if the specified path (newpath) is a
 * subdirectory of another share. It calls issubdir() from the old
 * share implementation to do the complicated work. The strictness
 * parameter determines how strict a check to make against the
 * path. The strictness values mean:
 * SA_CHECK_NORMAL == only check newpath against shares that are active
 * SA_CHECK_STRICT == check newpath against both active shares and those
 *		      stored in the repository
 */
static int
checksubdir(char *newpath, int strictness)
{
	sa_group_t group;
	sa_share_t share;
	int issub;
	char *path = NULL;

	for (issub = 0, group = sa_get_group(NULL);
		group != NULL && !issub;
		group = sa_get_next_group(group)) {
	    for (share = sa_get_share(group, NULL); share != NULL;
		    share = sa_get_next_share(share)) {
		/*
		 * The original behavior of share never checked
		 * against the permanent configuration
		 * (/etc/dfs/dfstab).  PIT has a number of cases where
		 * it depends on this older behavior even though it
		 * could be considered incorrect.  We may tighten this
		 * up in the future.
		 */
		if (strictness == SA_CHECK_NORMAL && !is_shared(share))
		    continue;

		path = sa_get_share_attr(share, "path");
		/*
		 * If path is NULL, then a share is in the process of
		 * construction or someone has modified the property
		 * group inappropriately. It should be ignored.
		 */
		if (path == NULL)
		    continue;
		if (newpath != NULL &&
		    (strcmp(path, newpath) == 0 || issubdir(newpath, path) ||
			issubdir(path, newpath))) {
		    sa_free_attr_string(path);
		    path = NULL;
		    issub = SA_INVALID_PATH;
		    break;
		}
		sa_free_attr_string(path);
		path = NULL;
	    }
	}
	if (path != NULL)
	    sa_free_attr_string(path);
	return (issub);
}

/*
 * validpath(path, strictness)
 * determine if the provided path is valid for a share. It shouldn't
 * be a sub-dir of an already shared path or the parent directory of a
 * share path.
 */
static int
validpath(char *path, int strictness)
{
	int error = SA_OK;
	struct stat st;
	sa_share_t share;
	char *fstype;

	if (*path != '/') {
	    return (SA_BAD_PATH);
	}
	if (stat(path, &st) < 0) {
	    error = SA_NO_SUCH_PATH;
	} else {
	    share = sa_find_share(path);
	    if (share != NULL) {
		error = SA_DUPLICATE_NAME;
	    }
	    if (error == SA_OK) {
		/*
		 * check for special case with file system that might
		 * have restrictions.  For now, ZFS is the only case
		 * since it has its own idea of how to configure
		 * shares. We do this before subdir checking since
		 * things like ZFS will do that for us. This should
		 * also be done via plugin interface.
		 */
		fstype = sa_fstype(path);
		if (fstype != NULL && strcmp(fstype, "zfs") == 0) {
		    if (sa_zfs_is_shared(path))
			error = SA_DUPLICATE_NAME;
		}
		if (fstype != NULL)
		    sa_free_fstype(fstype);
	    }
	    if (error == SA_OK) {
		error = checksubdir(path, strictness);
	    }
	}
	return (error);
}

/*
 * check to see if group/share is persistent.
 */
static int
is_persistent(sa_group_t group)
{
	char *type;
	int persist = 1;

	type = sa_get_group_attr(group, "type");
	if (type != NULL && strcmp(type, "transient") == 0)
	    persist = 0;
	if (type != NULL)
	    sa_free_attr_string(type);
	return (persist);
}

/*
 * sa_valid_group_name(name)
 *
 * check that the "name" contains only valid characters and otherwise
 * fits the required naming conventions. Valid names must start with
 * an alphabetic and the remainder may consist of only alphanumeric
 * plus the '-' and '_' characters. This name limitation comes from
 * inherent limitations in SMF.
 */

int
sa_valid_group_name(char *name)
{
	int ret = 1;
	ssize_t len;

	if (name != NULL && isalpha(*name)) {
	    char c;
	    len = strlen(name);
	    if (len < (scf_max_name_len - sizeof ("group:"))) {
		for (c = *name++; c != '\0' && ret != 0; c = *name++) {
		    if (!isalnum(c) && c != '-' && c != '_')
			ret = 0;
		}
	    } else {
		ret = 0;
	    }
	} else {
	    ret = 0;
	}
	return (ret);
}


/*
 * is_zfs_group(group)
 *	Determine if the specified group is a ZFS sharenfs group
 */
static int
is_zfs_group(sa_group_t group)
{
	int ret = 0;
	xmlNodePtr parent;
	xmlChar *zfs;

	if (strcmp((char *)((xmlNodePtr)group)->name, "share") == 0) {
	    parent = (xmlNodePtr)sa_get_parent_group(group);
	} else {
	    parent = (xmlNodePtr)group;
	}
	zfs = xmlGetProp(parent, (xmlChar *)"zfs");
	if (zfs != NULL) {
	    xmlFree(zfs);
	    ret = 1;
	}
	return (ret);
}

/*
 * sa_optionset_name(optionset, oname, len, id)
 *	return the SMF name for the optionset. If id is not NULL, it
 *	will have the GUID value for a share and should be used
 *	instead of the keyword "optionset" which is used for
 *	groups. If the optionset doesn't have a protocol type
 *	associated with it, "default" is used. This shouldn't happen
 *	at this point but may be desirable in the future if there are
 *	protocol independent properties added. The name is returned in
 *	oname.
 */

static int
sa_optionset_name(sa_optionset_t optionset, char *oname, size_t len, char *id)
{
	char *proto;

	if (id == NULL)
	    id = "optionset";

	proto = sa_get_optionset_attr(optionset, "type");
	len = snprintf(oname, len, "%s_%s", id, proto ? proto : "default");

	if (proto != NULL)
	    sa_free_attr_string(proto);
	return (len);
}

/*
 * sa_security_name(optionset, oname, len, id)
 *
 * return the SMF name for the security. If id is not NULL, it will
 * have the GUID value for a share and should be used instead of the
 * keyword "optionset" which is used for groups. If the optionset
 * doesn't have a protocol type associated with it, "default" is
 * used. This shouldn't happen at this point but may be desirable in
 * the future if there are protocol independent properties added. The
 * name is returned in oname. The security type is also encoded into
 * the name. In the future, this wil *be handled a bit differently.
 */

static int
sa_security_name(sa_security_t security, char *oname, size_t len, char *id)
{
	char *proto;
	char *sectype;

	if (id == NULL)
	    id = "optionset";

	proto = sa_get_security_attr(security, "type");
	sectype = sa_get_security_attr(security, "sectype");
	len = snprintf(oname, len, "%s_%s_%s", id,
			    proto ? proto : "default",
			    sectype ? sectype : "default");
	if (proto != NULL)
	    sa_free_attr_string(proto);
	if (sectype != NULL)
	    sa_free_attr_string(sectype);
	return (len);
}

/*
 * sa_init(init_service)
 *	Initialize the API
 *	find all the shared objects
 *	init the tables with all objects
 *	read in the current configuration
 */

void
sa_init(int init_service)
{
	struct stat st;
	int legacy = 0;
	uint64_t tval = 0;

	if (!sa_initialized) {
	    /* get protocol specific structures */
	    (void) proto_plugin_init();
	    if (init_service & SA_INIT_SHARE_API) {
		/*
		 * initialize access into libzfs. We use this when
		 * collecting info about ZFS datasets and shares.
		 */
		sa_zfs_init();
		/*
		 * since we want to use SMF, initialize an svc handle
		 * and find out what is there.
		 */
		scf_handle = sa_scf_init();
		if (scf_handle != NULL) {
		    (void) sa_get_config(scf_handle, &sa_config_tree,
				    &sa_config_doc);
		    tval = get_legacy_timestamp(sa_config_tree,
						SA_LEGACY_DFSTAB);
		    if (tval == 0) {
			/* first time so make sure default is setup */
			sa_group_t defgrp;
			sa_optionset_t opt;
			defgrp = sa_get_group("default");
			if (defgrp != NULL) {
			    opt = sa_get_optionset(defgrp, NULL);
			    if (opt == NULL)
				/* NFS is the default for default */
				opt = sa_create_optionset(defgrp, "nfs");
			}
		    }
		    if (stat(SA_LEGACY_DFSTAB, &st) >= 0 &&
			tval != TSTAMP(st.st_ctim)) {
			getlegacyconfig(SA_LEGACY_DFSTAB, &sa_config_tree);
			if (stat(SA_LEGACY_DFSTAB, &st) >= 0)
			    set_legacy_timestamp(sa_config_tree,
						SA_LEGACY_DFSTAB,
						TSTAMP(st.st_ctim));
		    }
		    legacy |= sa_get_zfs_shares("zfs");
		    legacy |= gettransients(&sa_config_tree);
		}
	    }
	}
}

/*
 * sa_fini()
 *	Uninitialize the API structures including the configuration
 *	data structures and ZFS related data.
 */

void
sa_fini()
{
	if (sa_initialized) {
		/* free the config trees */
		sa_initialized = 0;
		if (sa_config_doc != NULL)
			xmlFreeDoc(sa_config_doc);
		sa_config_tree = NULL;
		sa_config_doc = NULL;
		sa_scf_fini(scf_handle);
		sa_zfs_fini();
		(void) proto_plugin_init();
	}
}

/*
 * sa_get_protocols(char **protocol)
 *	Get array of protocols that are supported
 *	Returns pointer to an allocated and NULL terminated
 *	array of strings.  Caller must free.
 *	This really should be determined dynamically.
 *	If there aren't any defined, return -1.
 *	Use free() to return memory.
 */

int
sa_get_protocols(char ***protocols)
{
	int numproto = -1;

	if (protocols != NULL) {
	    struct sa_proto_plugin *plug;
	    for (numproto = 0, plug = sap_proto_list; plug != NULL;
		plug = plug->plugin_next) {
		numproto++;
	    }

	    *protocols = calloc(numproto + 1,  sizeof (char *));
	    if (*protocols != NULL) {
		int ret = 0;
		for (plug = sap_proto_list; plug != NULL;
		    plug = plug->plugin_next) {
		    /* faking for now */
		    (*protocols)[ret++] = plug->plugin_ops->sa_protocol;
		}
	    } else {
		numproto = -1;
	    }
	}
	return (numproto);
}

/*
 * find_group_by_name(node, group)
 *
 * search the XML document subtree specified by node to find the group
 * specified by group. Searching subtree allows subgroups to be
 * searched for.
 */

static xmlNodePtr
find_group_by_name(xmlNodePtr node, xmlChar *group)
{
	xmlChar *name = NULL;

	for (node = node->xmlChildrenNode; node != NULL;
	    node = node->next) {
	    if (xmlStrcmp(node->name, (xmlChar *)"group") == 0) {
		/* if no groupname, return the first found */
		if (group == NULL)
		    break;
		name = xmlGetProp(node, (xmlChar *)"name");
		if (name != NULL &&
		    xmlStrcmp(name, group) == 0) {
		    break;
		}
		if (name != NULL) {
		    xmlFree(name);
		    name = NULL;
		}
	    }
	}
	if (name != NULL)
	    xmlFree(name);
	return (node);
}

/*
 * sa_get_group(groupname)
 *	Return the "group" specified.  If groupname is NULL,
 *	return the first group of the list of groups.
 */
sa_group_t
sa_get_group(char *groupname)
{
	xmlNodePtr node = NULL;
	char *subgroup = NULL;
	char *group = NULL;

	if (sa_config_tree != NULL) {
	    if (groupname != NULL) {
		group = strdup(groupname);
		subgroup = strchr(group, '/');
		if (subgroup != NULL)
		    *subgroup++ = '\0';
	    }
	    node = find_group_by_name(sa_config_tree, (xmlChar *)group);
	    /* if a subgroup, find it before returning */
	    if (subgroup != NULL && node != NULL) {
		node = find_group_by_name(node, (xmlChar *)subgroup);
	    }
	}
	if (node != NULL && (char *)group != NULL)
	    (void) sa_get_instance(scf_handle, (char *)group);
	if (group != NULL)
	    free(group);
	return ((sa_group_t)(node));
}

/*
 * sa_get_next_group(group)
 *	Return the "next" group after the specified group from
 *	the internal group list.  NULL if there are no more.
 */
sa_group_t
sa_get_next_group(sa_group_t group)
{
	xmlNodePtr ngroup = NULL;
	if (group != NULL) {
	    for (ngroup = ((xmlNodePtr)group)->next; ngroup != NULL;
		    ngroup = ngroup->next) {
		if (xmlStrcmp(ngroup->name, (xmlChar *)"group") == 0)
		    break;
	    }
	}
	return ((sa_group_t)ngroup);
}

/*
 * sa_get_share(group, sharepath)
 *	Return the share object for the share specified. The share
 *	must be in the specified group.  Return NULL if not found.
 */
sa_share_t
sa_get_share(sa_group_t group, char *sharepath)
{
	xmlNodePtr node = NULL;
	xmlChar *path;

	/*
	 * For future scalability, this should end up building a cache
	 * since it will get called regularly by the mountd and info
	 * services.
	 */
	if (group != NULL) {
	    for (node = ((xmlNodePtr)group)->children; node != NULL;
		    node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"share") == 0) {
			if (sharepath == NULL) {
				break;
			} else {
				/* is it the correct share? */
			    path = xmlGetProp(node, (xmlChar *)"path");
			    if (path != NULL &&
				xmlStrcmp(path, (xmlChar *)sharepath) == 0) {
				xmlFree(path);
				break;
			    }
			    xmlFree(path);
			}
		}
	    }
	}
	return ((sa_share_t)node);
}

/*
 * sa_get_next_share(share)
 *	Return the next share following the specified share
 *	from the internal list of shares. Returns NULL if there
 *	are no more shares.  The list is relative to the same
 *	group.
 */
sa_share_t
sa_get_next_share(sa_share_t share)
{
	xmlNodePtr node = NULL;

	if (share != NULL) {
	    for (node = ((xmlNodePtr)share)->next; node != NULL;
		    node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"share") == 0) {
			break;
		}
	    }
	}
	return ((sa_share_t)node);
}

/*
 * _sa_get_child_node(node, type)
 *
 * find the child node of the specified node that has "type". This is
 * used to implement several internal functions.
 */

static xmlNodePtr
_sa_get_child_node(xmlNodePtr node, xmlChar *type)
{
	xmlNodePtr child;
	for (child = node->xmlChildrenNode; child != NULL;
	    child = child->next)
	    if (xmlStrcmp(child->name, type) == 0)
		return (child);
	return ((xmlNodePtr)NULL);
}

/*
 *  find_share(group, path)
 *
 * Search all the shares in the specified group for one that has the
 * specified path.
 */

static sa_share_t
find_share(sa_group_t group, char *sharepath)
{
	sa_share_t share;
	char *path;

	for (share = sa_get_share(group, NULL); share != NULL;
	    share = sa_get_next_share(share)) {
	    path = sa_get_share_attr(share, "path");
	    if (path != NULL && strcmp(path, sharepath) == 0) {
		sa_free_attr_string(path);
		break;
	    }
	    if (path != NULL)
		sa_free_attr_string(path);
	}
	return (share);
}

/*
 * sa_get_sub_group(group)
 *
 * Get the first sub-group of group. The sa_get_next_group() function
 * can be used to get the rest. This is currently only used for ZFS
 * sub-groups but could be used to implement a more general mechanism.
 */

sa_group_t
sa_get_sub_group(sa_group_t group)
{
	return ((sa_group_t)_sa_get_child_node((xmlNodePtr)group,
					    (xmlChar *)"group"));
}

/*
 * sa_find_share(sharepath)
 *	Finds a share regardless of group.  In the future, this
 *	function should utilize a cache and hash table of some kind.
 *	The current assumption is that a path will only be shared
 *	once.  In the future, this may change as implementation of
 *	resource names comes into being.
 */
sa_share_t
sa_find_share(char *sharepath)
{
	sa_group_t group;
	sa_group_t zgroup;
	sa_share_t share = NULL;
	int done = 0;

	for (group = sa_get_group(NULL); group != NULL && !done;
		group = sa_get_next_group(group)) {
	    if (is_zfs_group(group)) {
		for (zgroup = (sa_group_t)_sa_get_child_node((xmlNodePtr)group,
							(xmlChar *)"group");
		    zgroup != NULL; zgroup = sa_get_next_group(zgroup)) {
		    share = find_share(zgroup, sharepath);
		    if (share != NULL)
			break;
		}
	    } else {
		share = find_share(group, sharepath);
	    }
	    if (share != NULL)
		break;
	}
	return (share);
}

/*
 *  sa_check_path(group, path, strictness)
 *
 * check that path is a valid path relative to the group.  Currently,
 * we are ignoring the group and checking only the NFS rules. Later,
 * we may want to use the group to then check against the protocols
 * enabled on the group. The strictness values mean:
 * SA_CHECK_NORMAL == only check newpath against shares that are active
 * SA_CHECK_STRICT == check newpath against both active shares and those
 *		      stored in the repository
 */

int
sa_check_path(sa_group_t group, char *path, int strictness)
{
#ifdef lint
	group = group;
#endif
	return (validpath(path, strictness));
}

/*
 * _sa_add_share(group, sharepath, persist, *error)
 *
 * common code for all types of add_share. sa_add_share() is the
 * public API, we also need to be able to do this when parsing legacy
 * files and construction of the internal configuration while
 * extracting config info from SMF.
 */

sa_share_t
_sa_add_share(sa_group_t group, char *sharepath, int persist, int *error)
{
	xmlNodePtr node = NULL;
	int err;

	err  = SA_OK; /* assume success */

	node = xmlNewChild((xmlNodePtr)group, NULL,
				(xmlChar *)"share", NULL);
	if (node != NULL) {
	    xmlSetProp(node, (xmlChar *)"path", (xmlChar *)sharepath);
	    xmlSetProp(node, (xmlChar *)"type", persist ?
			(xmlChar *)"persist" : (xmlChar *)"transient");
	    if (persist != SA_SHARE_TRANSIENT) {
		/*
		 * persistent shares come in two flavors: SMF and
		 * ZFS. Sort this one out based on target group and
		 * path type. Currently, only NFS is supported in the
		 * ZFS group and it is always on.
		 */
		if (sa_group_is_zfs(group) && sa_path_is_zfs(sharepath)) {
		    err = sa_zfs_set_sharenfs(group, sharepath, 1);
		} else {
		    err = sa_commit_share(scf_handle, group,
						(sa_share_t)node);
		}
	    }
	    if (err == SA_NO_PERMISSION && persist & SA_SHARE_PARSER) {
		/* called by the dfstab parser so could be a show */
		err = SA_OK;
	    }
	    if (err != SA_OK) {
		/*
		 * we couldn't commit to the repository so undo
		 * our internal state to reflect reality.
		 */
		xmlUnlinkNode(node);
		xmlFreeNode(node);
		node = NULL;
	    }
	} else {
	    err = SA_NO_MEMORY;
	}
	if (error != NULL)
	    *error = err;
	return (node);
}

/*
 * sa_add_share(group, sharepath, persist, *error)
 *
 *	Add a new share object to the specified group.  The share will
 *	have the specified sharepath and will only be constructed if
 *	it is a valid path to be shared.  NULL is returned on error
 *	and a detailed error value will be returned via the error
 *	pointer.
 */
sa_share_t
sa_add_share(sa_group_t group, char *sharepath, int persist, int *error)
{
	xmlNodePtr node = NULL;
	sa_share_t dup;
	int strictness = SA_CHECK_NORMAL;

	/*
	 * If the share is to be permanent, use strict checking so a
	 * bad config doesn't get created. Transient shares only need
	 * to check against the currently active
	 * shares. SA_SHARE_PARSER is a modifier used internally to
	 * indicate that we are being called by the dfstab parser and
	 * that we need strict checking in all cases. Normally persist
	 * is in integer value but SA_SHARE_PARSER may be or'd into
	 * it as an override.
	 */
	if (persist & SA_SHARE_PARSER || persist == SA_SHARE_PERMANENT)
	    strictness = SA_CHECK_STRICT;

	if ((dup = sa_find_share(sharepath)) == NULL &&
		(*error = sa_check_path(group, sharepath, strictness)) ==
			SA_OK) {
	    node = _sa_add_share(group, sharepath, persist, error);
	}
	if (dup != NULL)
	    *error = SA_DUPLICATE_NAME;

	return ((sa_share_t)node);
}

/*
 * sa_enable_share(share, protocol)
 *	Enable the specified share to the specified protocol.
 *	If protocol is NULL, then all protocols.
 */
int
sa_enable_share(sa_share_t share, char *protocol)
{
	char *sharepath;
	struct stat st;
	int err = 0;

	sharepath = sa_get_share_attr(share, "path");
	if (stat(sharepath, &st) < 0) {
	    err = SA_NO_SUCH_PATH;
	} else {
	    /* tell the server about the share */
	    if (protocol != NULL) {
		/* lookup protocol specific handler */
		err = sa_proto_share(protocol, share);
		if (err == SA_OK)
		    (void) sa_set_share_attr(share, "shared", "true");
	    } else {
		/* tell all protocols */
		err = sa_proto_share("nfs", share); /* only NFS for now */
		(void) sa_set_share_attr(share, "shared", "true");
	    }
	}
	if (sharepath != NULL)
	    sa_free_attr_string(sharepath);
	return (err);
}

/*
 * sa_disable_share(share, protocol)
 *	Disable the specified share to the specified protocol.
 *	If protocol is NULL, then all protocols.
 */
int
sa_disable_share(sa_share_t share, char *protocol)
{
	char *path;
	char *shared;
	int ret = SA_OK;

	path = sa_get_share_attr(share, "path");
	shared = sa_get_share_attr(share, "shared");

	if (protocol != NULL) {
	    ret = sa_proto_unshare(protocol, path);
	} else {
	    /* need to do all protocols */
	    ret = sa_proto_unshare("nfs", path);
	}
	if (ret == SA_OK)
		(void) sa_set_share_attr(share, "shared", NULL);
	if (path != NULL)
	    sa_free_attr_string(path);
	if (shared != NULL)
	    sa_free_attr_string(shared);
	return (ret);
}

/*
 * sa_remove_share(share)
 *
 * remove the specified share from its containing group.
 * Remove from the SMF or ZFS configuration space.
 */

int
sa_remove_share(sa_share_t share)
{
	sa_group_t group;
	int ret = SA_OK;
	char *type;
	int transient = 0;
	char *groupname;
	char *zfs;

	type = sa_get_share_attr(share, "type");
	group = sa_get_parent_group(share);
	zfs = sa_get_group_attr(group, "zfs");
	groupname = sa_get_group_attr(group, "name");
	if (type != NULL && strcmp(type, "persist") != 0)
	    transient = 1;
	if (type != NULL)
	    sa_free_attr_string(type);

	/* remove the node from its group then free the memory */

	/*
	 * need to test if "busy"
	 */
	/* only do SMF action if permanent */
	if (!transient || zfs != NULL) {
	    /* remove from legacy dfstab as well as possible SMF */
	    ret = sa_delete_legacy(share);
	    if (ret == SA_OK) {
		if (!sa_group_is_zfs(group)) {
		    ret = sa_delete_share(scf_handle, group, share);
		} else {
		    char *sharepath = sa_get_share_attr(share, "path");
		    if (sharepath != NULL) {
			ret = sa_zfs_set_sharenfs(group, sharepath, 0);
			sa_free_attr_string(sharepath);
		    }
		}
	    }
	}
	if (groupname != NULL)
	    sa_free_attr_string(groupname);
	if (zfs != NULL)
	    sa_free_attr_string(zfs);

	xmlUnlinkNode((xmlNodePtr)share);
	xmlFreeNode((xmlNodePtr)share);
	return (ret);
}

/*
 * sa_move_share(group, share)
 *
 * move the specified share to the specified group.  Update SMF
 * appropriately.
 */

int
sa_move_share(sa_group_t group, sa_share_t share)
{
	sa_group_t oldgroup;
	int ret = SA_OK;

	/* remove the node from its group then free the memory */

	oldgroup = sa_get_parent_group(share);
	if (oldgroup != group) {
	    xmlUnlinkNode((xmlNodePtr)share);
	    /* now that the share isn't in its old group, add to the new one */
	    xmlAddChild((xmlNodePtr)group, (xmlNodePtr)share);
	    /* need to deal with SMF */
	    if (ret == SA_OK) {
		/*
		 * need to remove from old group first and then add to
		 * new group. Ideally, we would do the other order but
		 * need to avoid having the share in two groups at the
		 * same time.
		 */
		ret = sa_delete_share(scf_handle, oldgroup, share);
	    }
	    ret = sa_commit_share(scf_handle, group, share);
	}
	return (ret);
}

/*
 * sa_get_parent_group(share)
 *
 * Return the containg group for the share. If a group was actually
 * passed in, we don't want a parent so return NULL.
 */

sa_group_t
sa_get_parent_group(sa_share_t share)
{
	xmlNodePtr node = NULL;
	if (share != NULL) {
	    node = ((xmlNodePtr)share)->parent;
		/*
		 * make sure parent is a group and not sharecfg since
		 * we may be cheating and passing in a group.
		 * Eventually, groups of groups might come into being.
		 */
	    if (node == NULL ||
		xmlStrcmp(node->name, (xmlChar *)"sharecfg") == 0)
		node = NULL;
	}
	return ((sa_group_t)node);
}

/*
 * _sa_create_group(groupname)
 *
 * Create a group in the document. The caller will need to deal with
 * configuration store and activation.
 */

sa_group_t
_sa_create_group(char *groupname)
{
	xmlNodePtr node = NULL;

	if (sa_valid_group_name(groupname)) {
	    node = xmlNewChild(sa_config_tree, NULL,
				(xmlChar *)"group", NULL);
	    if (node != NULL) {
		xmlSetProp(node, (xmlChar *)"name", (xmlChar *)groupname);
		xmlSetProp(node, (xmlChar *)"state", (xmlChar *)"enabled");
	    }
	}
	return ((sa_group_t)node);
}

/*
 * _sa_create_zfs_group(group, groupname)
 *
 * Create a ZFS subgroup under the specified group. This may
 * eventually form the basis of general sub-groups, but is currently
 * restricted to ZFS.
 */
sa_group_t
_sa_create_zfs_group(sa_group_t group, char *groupname)
{
	xmlNodePtr node = NULL;

	node = xmlNewChild((xmlNodePtr)group, NULL,
				(xmlChar *)"group", NULL);
	if (node != NULL) {
		xmlSetProp(node, (xmlChar *)"name", (xmlChar *)groupname);
		xmlSetProp(node, (xmlChar *)"state", (xmlChar *)"enabled");
	}

	return ((sa_group_t)node);
}

/*
 * sa_create_group(groupname, *error)
 *
 * Create a new group with groupname.  Need to validate that it is a
 * legal name for SMF and the construct the SMF service instance of
 * svc:/network/shares/group to implement the group. All necessary
 * operational properties must be added to the group at this point
 * (via the SMF transaction model).
 */
sa_group_t
sa_create_group(char *groupname, int *error)
{
	xmlNodePtr node = NULL;
	sa_group_t group;
	int ret;
	char rbacstr[256];

	ret = SA_OK;

	if (scf_handle == NULL) {
	    ret = SA_SYSTEM_ERR;
	    goto err;
	}

	group = sa_get_group(groupname);
	if (group != NULL) {
	    ret = SA_DUPLICATE_NAME;
	} else {
	    if (sa_valid_group_name(groupname)) {
		node = xmlNewChild(sa_config_tree, NULL,
				    (xmlChar *)"group", NULL);
		if (node != NULL) {
		    xmlSetProp(node, (xmlChar *)"name", (xmlChar *)groupname);
		    /* default to the group being enabled */
		    xmlSetProp(node, (xmlChar *)"state", (xmlChar *)"enabled");
		    ret = sa_create_instance(scf_handle, groupname);
		    if (ret == SA_OK) {
			ret = sa_start_transaction(scf_handle, "operation");
		    }
		    if (ret == SA_OK) {
			ret = sa_set_property(scf_handle, "state", "enabled");
			if (ret == SA_OK) {
			    ret = sa_end_transaction(scf_handle);
			} else {
			    sa_abort_transaction(scf_handle);
			}
		    }
		    if (ret == SA_OK) {
			/* initialize the RBAC strings */
			ret = sa_start_transaction(scf_handle, "general");
			if (ret == SA_OK) {
			    (void) snprintf(rbacstr, sizeof (rbacstr), "%s.%s",
					SA_RBAC_MANAGE, groupname);
			    ret = sa_set_property(scf_handle,
						    "action_authorization",
						    rbacstr);
			}
			if (ret == SA_OK) {
			    (void) snprintf(rbacstr, sizeof (rbacstr), "%s.%s",
					SA_RBAC_VALUE, groupname);
			    ret = sa_set_property(scf_handle,
						    "value_authorization",
						    rbacstr);
			}
			if (ret == SA_OK) {
			    ret = sa_end_transaction(scf_handle);
			} else {
			    sa_abort_transaction(scf_handle);
			}
		    }
		    if (ret != SA_OK) {
			/*
			 * Couldn't commit the group so we need to
			 * undo internally.
			 */
			xmlUnlinkNode(node);
			xmlFreeNode(node);
			node = NULL;
		    }
		} else {
		    ret = SA_NO_MEMORY;
		}
	    } else {
		ret = SA_INVALID_NAME;
	    }
	}
err:
	if (error != NULL)
	    *error = ret;
	return ((sa_group_t)node);
}

/*
 * sa_remove_group(group)
 *
 * Remove the specified group. This deletes from the SMF repository.
 * All property groups and properties are removed.
 */

int
sa_remove_group(sa_group_t group)
{
	char *name;
	int ret = SA_OK;

	name = sa_get_group_attr(group, "name");
	if (name != NULL) {
	    ret = sa_delete_instance(scf_handle, name);
	    sa_free_attr_string(name);
	}
	xmlUnlinkNode((xmlNodePtr)group); /* make sure unlinked */
	xmlFreeNode((xmlNodePtr)group);   /* now it is gone */
	return (ret);
}

/*
 * sa_update_config()
 *
 * Used to update legacy files that need to be updated in bulk
 * Currently, this is a placeholder and will go away in a future
 * release.
 */

int
sa_update_config()
{
	/*
	 * do legacy files first so we can tell when they change.
	 * This will go away when we start updating individual records
	 * rather than the whole file.
	 */
	update_legacy_config();
	return (SA_OK);
}

/*
 * get_node_attr(node, tag)
 *
 * Get the speficied tag(attribute) if it exists on the node.  This is
 * used internally by a number of attribute oriented functions.
 */

static char *
get_node_attr(void *nodehdl, char *tag)
{
	xmlNodePtr node = (xmlNodePtr)nodehdl;
	xmlChar *name = NULL;

	if (node != NULL) {
		name = xmlGetProp(node, (xmlChar *)tag);
	}
	return ((char *)name);
}

/*
 * get_node_attr(node, tag)
 *
 * Set the speficied tag(attribute) to the specified value This is
 * used internally by a number of attribute oriented functions. It
 * doesn't update the repository, only the internal document state.
 */

void
set_node_attr(void *nodehdl, char *tag, char *value)
{
	xmlNodePtr node = (xmlNodePtr)nodehdl;
	if (node != NULL && tag != NULL) {
		if (value != NULL) {
			xmlSetProp(node, (xmlChar *)tag, (xmlChar *)value);
		} else {
			xmlUnsetProp(node, (xmlChar *)tag);
		}
	}
}

/*
 * sa_get_group_attr(group, tag)
 *
 * Get the specied attribute, if defined, for the group.
 */

char *
sa_get_group_attr(sa_group_t group, char *tag)
{
	return (get_node_attr((void *)group, tag));
}

/*
 * sa_set_group_attr(group, tag, value)
 *
 * set the specified tag/attribute on the group using value as its
 * value.
 *
 * This will result in setting the property in the SMF repository as
 * well as in the internal document.
 */

int
sa_set_group_attr(sa_group_t group, char *tag, char *value)
{
	int ret;
	char *groupname;

	groupname = sa_get_group_attr(group, "name");
	ret = sa_get_instance(scf_handle, groupname);
	if (ret == SA_OK) {
	    set_node_attr((void *)group, tag, value);
	    ret = sa_start_transaction(scf_handle, "operation");
	    if (ret == SA_OK) {
		ret = sa_set_property(scf_handle, tag, value);
		if (ret == SA_OK)
		    (void) sa_end_transaction(scf_handle);
		else {
		    sa_abort_transaction(scf_handle);
		}
	    }
	}
	if (groupname != NULL)
	    sa_free_attr_string(groupname);
	return (ret);
}

/*
 * sa_get_share_attr(share, tag)
 *
 * Return the value of the tag/attribute set on the specified
 * share. Returns NULL if the tag doesn't exist.
 */

char *
sa_get_share_attr(sa_share_t share, char *tag)
{
	return (get_node_attr((void *)share, tag));
}

/*
 * sa_get_resource(group, resource)
 *
 * Search all the shares in the speified group for a share with a
 * resource name matching the one specified.
 *
 * In the future, it may be advantageous to allow group to be NULL and
 * search all groups but that isn't needed at present.
 */

sa_share_t
sa_get_resource(sa_group_t group, char *resource)
{
	sa_share_t share = NULL;
	char *name = NULL;

	if (resource != NULL) {
	    for (share = sa_get_share(group, NULL); share != NULL;
		share = sa_get_next_share(share)) {
		name = sa_get_share_attr(share, "resource");
		if (name != NULL) {
		    if (strcmp(name, resource) == 0)
			break;
		    sa_free_attr_string(name);
		    name = NULL;
		}
	    }
	    if (name != NULL)
		sa_free_attr_string(name);
	}
	return ((sa_share_t)share);
}

/*
 * _sa_set_share_description(share, description)
 *
 * Add a description tag with text contents to the specified share.
 * A separate XML tag is used rather than a property.
 */

xmlNodePtr
_sa_set_share_description(sa_share_t share, char *content)
{
	xmlNodePtr node;
	node = xmlNewChild((xmlNodePtr)share,
			    NULL, (xmlChar *)"description", NULL);
	xmlNodeSetContent(node, (xmlChar *)content);
	return (node);
}

/*
 * sa_set_share_attr(share, tag, value)
 *
 * Set the share attribute specified by tag to the specified value. In
 * the case of "resource", enforce a no duplicates in a group rule. If
 * the share is not transient, commit the changes to the repository
 * else just update the share internally.
 */

int
sa_set_share_attr(sa_share_t share, char *tag, char *value)
{
	sa_group_t group;
	sa_share_t resource;
	int ret = SA_OK;

	group = sa_get_parent_group(share);

	/*
	 * There are some attributes that may have specific
	 * restrictions on them. Initially, only "resource" has
	 * special meaning that needs to be checked. Only one instance
	 * of a resource name may exist within a group.
	 */

	if (strcmp(tag, "resource") == 0) {
	    resource = sa_get_resource(group, value);
	    if (resource != share && resource != NULL)
		ret = SA_DUPLICATE_NAME;
	}
	if (ret == SA_OK) {
	    set_node_attr((void *)share, tag, value);
	    if (group != NULL) {
		char *type;
		/* we can probably optimize this some */
		type = sa_get_share_attr(share, "type");
		if (type == NULL || strcmp(type, "transient") != 0)
		    ret = sa_commit_share(scf_handle, group, share);
		if (type != NULL)
		    sa_free_attr_string(type);
	    }
	}
	return (ret);
}

/*
 * sa_get_property_attr(prop, tag)
 *
 * Get the value of the specified property attribute. Standard
 * attributes are "type" and "value".
 */

char *
sa_get_property_attr(sa_property_t prop, char *tag)
{
	return (get_node_attr((void *)prop, tag));
}

/*
 * sa_get_optionset_attr(prop, tag)
 *
 * Get the value of the specified property attribute. Standard
 * attribute is "type".
 */

char *
sa_get_optionset_attr(sa_property_t optionset, char *tag)
{
	return (get_node_attr((void *)optionset, tag));

}

/*
 * sa_set_optionset_attr(optionset, tag, value)
 *
 * Set the specified attribute(tag) to the specified value on the
 * optionset.
 */

void
sa_set_optionset_attr(sa_group_t optionset, char *tag, char *value)
{
	set_node_attr((void *)optionset, tag, value);
}

/*
 * sa_free_attr_string(string)
 *
 * Free the string that was returned in one of the sa_get_*_attr()
 * functions.
 */

void
sa_free_attr_string(char *string)
{
	xmlFree((xmlChar *)string);
}

/*
 * sa_get_optionset(group, proto)
 *
 * Return the optionset, if it exists, that is associated with the
 * specified protocol.
 */

sa_optionset_t
sa_get_optionset(void *group, char *proto)
{
	xmlNodePtr node;
	xmlChar *value = NULL;

	for (node = ((xmlNodePtr)group)->children; node != NULL;
		node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"optionset") == 0) {
		    value = xmlGetProp(node, (xmlChar *)"type");
		    if (proto != NULL) {
			if (value != NULL &&
			    xmlStrcmp(value, (xmlChar *)proto) == 0) {
			    break;
			}
			if (value != NULL) {
			    xmlFree(value);
			    value = NULL;
			}
		    } else {
			break;
		    }
		}
	}
	if (value != NULL)
	    xmlFree(value);
	return ((sa_optionset_t)node);
}

/*
 * sa_get_next_optionset(optionset)
 *
 * Return the next optionset in the group. NULL if this was the last.
 */

sa_optionset_t
sa_get_next_optionset(sa_optionset_t optionset)
{
	xmlNodePtr node;

	for (node = ((xmlNodePtr)optionset)->next; node != NULL;
		node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"optionset") == 0) {
			break;
		}
	}
	return ((sa_optionset_t)node);
}

/*
 * sa_get_security(group, sectype, proto)
 *
 * Return the security optionset. The internal name is a hold over
 * from the implementation and will be changed before the API is
 * finalized. This is really a named optionset that can be negotiated
 * as a group of properties (like NFS security options).
 */

sa_security_t
sa_get_security(sa_group_t group, char *sectype, char *proto)
{
	xmlNodePtr node;
	xmlChar *value = NULL;

	for (node = ((xmlNodePtr)group)->children; node != NULL;
		node = node->next) {
	    if (xmlStrcmp(node->name, (xmlChar *)"security") == 0) {
		if (proto != NULL) {
		    value = xmlGetProp(node, (xmlChar *)"type");
		    if (value == NULL ||
			(value != NULL &&
			xmlStrcmp(value, (xmlChar *)proto) != 0)) {
			/* it doesn't match so continue */
			xmlFree(value);
			value = NULL;
			continue;
		    }
		}
		if (value != NULL) {
		    xmlFree(value);
		    value = NULL;
		}
		/* potential match */
		if (sectype != NULL) {
		    value = xmlGetProp(node, (xmlChar *)"sectype");
		    if (value != NULL &&
			xmlStrcmp(value, (xmlChar *)sectype) == 0) {
			break;
		    }
		} else {
		    break;
		}
	    }
	    if (value != NULL) {
		xmlFree(value);
		value = NULL;
	    }
	}
	if (value != NULL)
	    xmlFree(value);
	return ((sa_security_t)node);
}

/*
 * sa_get_next_security(security)
 *
 * Get the next security optionset if one exists.
 */

sa_security_t
sa_get_next_security(sa_security_t security)
{
	xmlNodePtr node;

	for (node = ((xmlNodePtr)security)->next; node != NULL;
		node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"security") == 0) {
			break;
		}
	}
	return ((sa_security_t)node);
}

/*
 * sa_get_property(optionset, prop)
 *
 * Get the property object with the name specified in prop from the
 * optionset.
 */

sa_property_t
sa_get_property(sa_optionset_t optionset, char *prop)
{
	xmlNodePtr node = (xmlNodePtr)optionset;
	xmlChar *value = NULL;

	if (optionset == NULL)
	    return (NULL);

	for (node = node->children; node != NULL;
		node = node->next) {
	    if (xmlStrcmp(node->name, (xmlChar *)"option") == 0) {
		if (prop == NULL)
		    break;
		value = xmlGetProp(node, (xmlChar *)"type");
		if (value != NULL && xmlStrcmp(value, (xmlChar *)prop) == 0) {
		    break;
		}
		if (value != NULL) {
		    xmlFree(value);
		    value = NULL;
		}
	    }
	}
	if (value != NULL)
		xmlFree(value);
	if (node != NULL && xmlStrcmp(node->name, (xmlChar *)"option") != 0) {
	    /* avoid a non option node -- it is possible to be a text node */
	    node = NULL;
	}
	return ((sa_property_t)node);
}

/*
 * sa_get_next_property(property)
 *
 * Get the next property following the specified property. NULL if
 * this was the last.
 */

sa_property_t
sa_get_next_property(sa_property_t property)
{
	xmlNodePtr node;

	for (node = ((xmlNodePtr)property)->next; node != NULL;
		node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"option") == 0) {
			break;
		}
	}
	return ((sa_property_t)node);
}

/*
 * sa_set_share_description(share, content)
 *
 * Set the description of share to content.
 */

int
sa_set_share_description(sa_share_t share, char *content)
{
	xmlNodePtr node;
	sa_group_t group;
	int ret = SA_OK;

	for (node = ((xmlNodePtr)share)->children; node != NULL;
		node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"description") == 0) {
			break;
		}
	}
	group = sa_get_parent_group(share);
	/* no existing description but want to add */
	if (node == NULL && content != NULL) {
		/* add a description */
	    node = _sa_set_share_description(share, content);
	} else if (node != NULL && content != NULL) {
		/* update a description */
		xmlNodeSetContent(node, (xmlChar *)content);
	} else if (node != NULL && content == NULL) {
		/* remove an existing description */
		xmlUnlinkNode(node);
		xmlFreeNode(node);
	}
	if (group != NULL && is_persistent((sa_group_t)share))
	    ret = sa_commit_share(scf_handle, group, share);
	return (ret);
}

/*
 * fixproblemchars(string)
 *
 * don't want any newline or tab characters in the text since these
 * could break display of data and legacy file formats.
 */
static void
fixproblemchars(char *str)
{
	int c;
	for (c = *str; c != '\0'; c = *++str) {
	    if (c == '\t' || c == '\n')
		*str = ' ';
	    else if (c == '"')
		*str = '\'';
	}
}

/*
 * sa_get_share_description(share)
 *
 * Return the description text for the specified share if it
 * exists. NULL if no description exists.
 */

char *
sa_get_share_description(sa_share_t share)
{
	xmlChar *description = NULL;
	xmlNodePtr node;

	for (node = ((xmlNodePtr)share)->children; node != NULL;
		node = node->next) {
	    if (xmlStrcmp(node->name, (xmlChar *)"description") == 0) {
		break;
	    }
	}
	if (node != NULL) {
	    description = xmlNodeGetContent((xmlNodePtr)share);
	    fixproblemchars((char *)description);
	}
	return ((char *)description);
}

/*
 * sa_free(share_description(description)
 *
 * Free the description string.
 */

void
sa_free_share_description(char *description)
{
	xmlFree((xmlChar *)description);
}

/*
 * sa_create_optionset(group, proto)
 *
 * Create an optionset for the specified protocol in the specied
 * group. This is manifested as a property group within SMF.
 */

sa_optionset_t
sa_create_optionset(sa_group_t group, char *proto)
{
	sa_optionset_t optionset;
	sa_group_t parent = group;

	optionset = sa_get_optionset(group, proto);
	if (optionset != NULL) {
		/* can't have a duplicate protocol */
	    optionset = NULL;
	} else {
	    optionset = (sa_optionset_t)xmlNewChild((xmlNodePtr)group,
						    NULL,
						    (xmlChar *)"optionset",
						    NULL);
		/*
		 * only put to repository if on a group and we were
		 * able to create an optionset.
		 */
	    if (optionset != NULL) {
		char oname[256];
		char *groupname;
		char *id = NULL;

		if (sa_is_share(group))
		    parent = sa_get_parent_group((sa_share_t)group);

		sa_set_optionset_attr(optionset, "type", proto);

		if (sa_is_share(group)) {
			id = sa_get_share_attr((sa_share_t)group, "id");
		}
		(void) sa_optionset_name(optionset, oname,
					sizeof (oname), id);
		groupname = sa_get_group_attr(parent, "name");
		if (groupname != NULL && is_persistent(group)) {
			(void) sa_get_instance(scf_handle, groupname);
			sa_free_attr_string(groupname);
			(void) sa_create_pgroup(scf_handle, oname);
		}
		if (id != NULL)
		    sa_free_attr_string(id);
	    }
	}
	return (optionset);
}

/*
 * sa_get_property_parent(property)
 *
 * Given a property, return the object it is a property of. This will
 * be an optionset of some type.
 */

static sa_optionset_t
sa_get_property_parent(sa_property_t property)
{
	xmlNodePtr node = NULL;

	if (property != NULL) {
	    node = ((xmlNodePtr)property)->parent;
	}
	return ((sa_optionset_t)node);
}

/*
 * sa_get_optionset_parent(optionset)
 *
 * Return the parent of the specified optionset. This could be a group
 * or a share.
 */

static sa_group_t
sa_get_optionset_parent(sa_optionset_t optionset)
{
	xmlNodePtr node = NULL;

	if (optionset != NULL) {
	    node = ((xmlNodePtr)optionset)->parent;
	}
	return ((sa_group_t)node);
}

/*
 * zfs_needs_update(share)
 *
 * In order to avoid making multiple updates to a ZFS share when
 * setting properties, the share attribute "changed" will be set to
 * true when a property is added or modifed.  When done adding
 * properties, we can then detect that an update is needed.  We then
 * clear the state here to detect additional changes.
 */

static int
zfs_needs_update(sa_share_t share)
{
	char *attr;
	int result = 0;

	attr = sa_get_share_attr(share, "changed");
	if (attr != NULL) {
	    sa_free_attr_string(attr);
		result = 1;
	}
	set_node_attr((void *)share, "changed", NULL);
	return (result);
}

/*
 * zfs_set_update(share)
 *
 * Set the changed attribute of the share to true.
 */

static void
zfs_set_update(sa_share_t share)
{
	set_node_attr((void *)share, "changed", "true");
}

/*
 * sa_commit_properties(optionset, clear)
 *
 * Check if SMF or ZFS config and either update or abort the pending
 * changes.
 */

int
sa_commit_properties(sa_optionset_t optionset, int clear)
{
	sa_group_t group;
	sa_group_t parent;
	int zfs = 0;
	int needsupdate = 0;
	int ret = SA_OK;

	group = sa_get_optionset_parent(optionset);
	if (group != NULL && (sa_is_share(group) || is_zfs_group(group))) {
	    /* only update ZFS if on a share */
	    parent = sa_get_parent_group(group);
	    zfs++;
	    if (parent != NULL && is_zfs_group(parent)) {
		needsupdate = zfs_needs_update(group);
	    } else {
		zfs = 0;
	    }
	}
	if (zfs) {
	    if (!clear && needsupdate)
		ret = sa_zfs_update((sa_share_t)group);
	} else {
	    if (clear)
		(void) sa_abort_transaction(scf_handle);
	    else
		ret = sa_end_transaction(scf_handle);
	}
	return (ret);
}

/*
 * sa_destroy_optionset(optionset)
 *
 * Remove the optionset from its group. Update the repostory to
 * reflect this change.
 */

int
sa_destroy_optionset(sa_optionset_t optionset)
{
	char name[256];
	int len;
	int ret;
	char *id = NULL;
	sa_group_t group;
	int ispersist = 1;

	/* now delete the prop group */
	group = sa_get_optionset_parent(optionset);
	if (group != NULL && sa_is_share(group)) {
	    ispersist = is_persistent(group);
	    id = sa_get_share_attr((sa_share_t)group, "id");
	}
	if (ispersist) {
	    len = sa_optionset_name(optionset, name, sizeof (name), id);
	    if (len > 0) {
		ret = sa_delete_pgroup(scf_handle, name);
	    }
	}
	xmlUnlinkNode((xmlNodePtr)optionset);
	xmlFreeNode((xmlNodePtr)optionset);
	if (id != NULL)
	    sa_free_attr_string(id);
	return (ret);
}

/* private to the implementation */
int
_sa_remove_optionset(sa_optionset_t optionset)
{
	int ret = SA_OK;

	xmlUnlinkNode((xmlNodePtr)optionset);
	xmlFreeNode((xmlNodePtr)optionset);
	return (ret);
}

/*
 * sa_create_security(group, sectype, proto)
 *
 * Create a security optionset (one that has a type name and a
 * proto). Security is left over from a pure NFS implementation. The
 * naming will change in the future when the API is released.
 */
sa_security_t
sa_create_security(sa_group_t group, char *sectype, char *proto)
{
	sa_security_t security;
	char *id = NULL;
	sa_group_t parent;
	char *groupname = NULL;

	if (group != NULL && sa_is_share(group)) {
	    id = sa_get_share_attr((sa_share_t)group, "id");
	    parent = sa_get_parent_group(group);
	    if (parent != NULL)
		groupname = sa_get_group_attr(parent, "name");
	} else if (group != NULL) {
	    groupname = sa_get_group_attr(group, "name");
	}

	security = sa_get_security(group, sectype, proto);
	if (security != NULL) {
		/* can't have a duplicate security option */
		security = NULL;
	} else {
		security = (sa_security_t)xmlNewChild((xmlNodePtr)group,
							NULL,
							(xmlChar *)"security",
							NULL);
		if (security != NULL) {
			char oname[256];
			sa_set_security_attr(security, "type", proto);

			sa_set_security_attr(security, "sectype", sectype);
			(void) sa_security_name(security, oname,
						sizeof (oname), id);
			if (groupname != NULL && is_persistent(group)) {
			    (void) sa_get_instance(scf_handle, groupname);
			    (void) sa_create_pgroup(scf_handle, oname);
			}
		}
	}
	if (groupname != NULL)
	    sa_free_attr_string(groupname);
	return (security);
}

/*
 * sa_destroy_security(security)
 *
 * Remove the specified optionset from the document and the
 * configuration.
 */

int
sa_destroy_security(sa_security_t security)
{
	char name[256];
	int len;
	int ret = SA_OK;
	char *id = NULL;
	sa_group_t group;
	int iszfs = 0;
	int ispersist = 1;

	group = sa_get_optionset_parent(security);

	if (group != NULL)
	    iszfs = sa_group_is_zfs(group);

	if (group != NULL && !iszfs) {
	    if (sa_is_share(group))
		ispersist = is_persistent(group);
	    id = sa_get_share_attr((sa_share_t)group, "id");
	}
	if (ispersist) {
	    len = sa_security_name(security, name, sizeof (name), id);
	    if (!iszfs && len > 0) {
		ret = sa_delete_pgroup(scf_handle, name);
	    }
	}
	xmlUnlinkNode((xmlNodePtr)security);
	xmlFreeNode((xmlNodePtr)security);
	if (iszfs) {
	    ret = sa_zfs_update(group);
	}
	if (id != NULL)
	    sa_free_attr_string(id);
	return (ret);
}

/*
 * sa_get_security_attr(optionset, tag)
 *
 * Return the specified attribute value from the optionset.
 */

char *
sa_get_security_attr(sa_property_t optionset, char *tag)
{
	return (get_node_attr((void *)optionset, tag));

}

/*
 * sa_set_security_attr(optionset, tag, value)
 *
 * Set the optioset attribute specied by tag to the specified value.
 */

void
sa_set_security_attr(sa_group_t optionset, char *tag, char *value)
{
	set_node_attr((void *)optionset, tag, value);
}

/*
 * is_nodetype(node, type)
 *
 * Check to see if node is of the type specified.
 */

static int
is_nodetype(void *node, char *type)
{
	return (strcmp((char *)((xmlNodePtr)node)->name, type) == 0);
}

/*
 * sa_set_prop_by_prop(optionset, group, prop, type)
 *
 * Add/remove/update the specified property prop into the optionset or
 * share. If a share, sort out which property group based on GUID. In
 * all cases, the appropriate transaction is set (or ZFS share is
 * marked as needing an update)
 */

#define	SA_PROP_OP_REMOVE	1
#define	SA_PROP_OP_ADD		2
#define	SA_PROP_OP_UPDATE	3
static int
sa_set_prop_by_prop(sa_optionset_t optionset, sa_group_t group,
			sa_property_t prop, int type)
{
	char *name;
	char *valstr;
	int ret = SA_OK;
	scf_transaction_entry_t *entry;
	scf_value_t *value;
	int opttype; /* 1 == optionset, 0 == security */
	char *id = NULL;
	int iszfs = 0;
	int isshare = 0;
	sa_group_t parent = NULL;

	if (!is_persistent(group)) {
		/*
		 * if the group/share is not persistent we don't need
		 * to do anything here
		 */
	    return (SA_OK);
	}
	name = sa_get_property_attr(prop, "type");
	valstr = sa_get_property_attr(prop, "value");
	entry = scf_entry_create(scf_handle->handle);
	opttype = is_nodetype((void *)optionset, "optionset");

	if (valstr != NULL && entry != NULL) {
	    if (sa_is_share(group)) {
		isshare = 1;
		parent = sa_get_parent_group(group);
		if (parent != NULL) {
		    iszfs = is_zfs_group(parent);
		}
	    } else {
		iszfs = is_zfs_group(group);
	    }
	    if (!iszfs) {
		if (scf_handle->trans == NULL) {
		    char oname[256];
		    char *groupname = NULL;
		    if (isshare) {
			if (parent != NULL) {
			    groupname = sa_get_group_attr(parent, "name");
			}
			id = sa_get_share_attr((sa_share_t)group, "id");
		    } else {
			groupname = sa_get_group_attr(group, "name");
		    }
		    if (groupname != NULL) {
			ret = sa_get_instance(scf_handle, groupname);
			sa_free_attr_string(groupname);
		    }
		    if (opttype)
			(void) sa_optionset_name(optionset, oname,
							sizeof (oname), id);
		    else
			(void) sa_security_name(optionset, oname,
							sizeof (oname), id);
		    ret = sa_start_transaction(scf_handle, oname);
		}
		if (ret == SA_OK) {
		    switch (type) {
		    case SA_PROP_OP_REMOVE:
			ret = scf_transaction_property_delete(scf_handle->trans,
								entry,
								name);
			break;
		    case SA_PROP_OP_ADD:
		    case SA_PROP_OP_UPDATE:
			value = scf_value_create(scf_handle->handle);
			if (value != NULL) {
			    if (type == SA_PROP_OP_ADD)
				ret = scf_transaction_property_new(
							    scf_handle->trans,
							    entry,
							    name,
							    SCF_TYPE_ASTRING);
			    else
				ret = scf_transaction_property_change(
							    scf_handle->trans,
							    entry,
							    name,
							    SCF_TYPE_ASTRING);
			    if (ret == 0) {
				ret = scf_value_set_astring(value, valstr);
				if (ret == 0)
				    ret = scf_entry_add_value(entry, value);
				if (ret != 0) {
				    scf_value_destroy(value);
				    ret = SA_SYSTEM_ERR;
				}
			    } else {
				scf_entry_destroy(entry);
				ret = SA_SYSTEM_ERR;
			    }
			    break;
			}
		    }
		}
	    } else {
		/*
		 * ZFS update. The calling function would have updated
		 * the internal XML structure. Just need to flag it as
		 * changed for ZFS.
		 */
		zfs_set_update((sa_share_t)group);
	    }
	}

	if (name != NULL)
	    sa_free_attr_string(name);
	if (valstr != NULL)
	    sa_free_attr_string(valstr);
	else if (entry != NULL)
	    scf_entry_destroy(entry);

	if (ret == -1)
	    ret = SA_SYSTEM_ERR;

	return (ret);
}

/*
 * sa_create_property(name, value)
 *
 * Create a new property with the specified name and value.
 */

sa_property_t
sa_create_property(char *name, char *value)
{
	xmlNodePtr node;

	node = xmlNewNode(NULL, (xmlChar *)"option");
	if (node != NULL) {
		xmlSetProp(node, (xmlChar *)"type", (xmlChar *)name);
		xmlSetProp(node, (xmlChar *)"value", (xmlChar *)value);
	}
	return ((sa_property_t)node);
}

/*
 * sa_add_property(object, property)
 *
 * Add the specified property to the object. Issue the appropriate
 * transaction or mark a ZFS object as needing an update.
 */

int
sa_add_property(void *object, sa_property_t property)
{
	int ret = SA_OK;
	sa_group_t parent;
	sa_group_t group;
	char *proto;

	proto = sa_get_optionset_attr(object, "type");
	if (property != NULL) {
	    if ((ret = sa_valid_property(object, proto, property)) == SA_OK) {
		property = (sa_property_t)xmlAddChild((xmlNodePtr)object,
							(xmlNodePtr)property);
	    } else {
		if (proto != NULL)
		    sa_free_attr_string(proto);
		return (ret);
	    }
	}

	if (proto != NULL)
	    sa_free_attr_string(proto);

	parent = sa_get_parent_group(object);
	if (!is_persistent(parent)) {
	    return (ret);
	}

	if (sa_is_share(parent))
	    group = sa_get_parent_group(parent);
	else
	    group = parent;

	if (property == NULL)
	    ret = SA_NO_MEMORY;
	else {
	    char oname[256];

	    if (!is_zfs_group(group)) {
		char *id = NULL;
		if (sa_is_share((sa_group_t)parent)) {
		    id = sa_get_share_attr((sa_share_t)parent, "id");
		}
		if (scf_handle->trans == NULL) {
		    if (is_nodetype(object, "optionset"))
			(void) sa_optionset_name((sa_optionset_t)object,
					    oname, sizeof (oname), id);
		    else
			(void) sa_security_name((sa_optionset_t)object,
					    oname, sizeof (oname), id);
		    ret = sa_start_transaction(scf_handle, oname);
		}
		if (ret == SA_OK) {
		    char *name;
		    char *value;
		    name = sa_get_property_attr(property, "type");
		    value = sa_get_property_attr(property, "value");
		    if (name != NULL && value != NULL) {
			if (scf_handle->scf_state == SCH_STATE_INIT)
			    ret = sa_set_property(scf_handle, name, value);
		    } else
			ret = SA_CONFIG_ERR;
		    if (name != NULL)
			sa_free_attr_string(name);
		    if (value != NULL)
			sa_free_attr_string(value);
		}
		if (id != NULL)
		    sa_free_attr_string(id);
	    } else {
		/*
		 * ZFS is a special case. We do want to allow editing
		 * property/security lists since we can have a better
		 * syntax and we also want to keep things consistent
		 * when possible.
		 *
		 * Right now, we defer until the sa_commit_properties
		 * so we can get them all at once. We do need to mark
		 * the share as "changed"
		 */
		zfs_set_update((sa_share_t)parent);
	    }
	}
	return (ret);
}

/*
 * sa_remove_property(property)
 *
 * Remove the specied property from its containing object. Update the
 * repository as appropriate.
 */

int
sa_remove_property(sa_property_t property)
{
	int ret = SA_OK;

	if (property != NULL) {
		sa_optionset_t optionset;
		sa_group_t group;
		optionset = sa_get_property_parent(property);
		if (optionset != NULL) {
		    group = sa_get_optionset_parent(optionset);
		    if (group != NULL) {
			ret = sa_set_prop_by_prop(optionset, group, property,
					    SA_PROP_OP_REMOVE);
		    }
		}
		xmlUnlinkNode((xmlNodePtr)property);
		xmlFreeNode((xmlNodePtr)property);
	} else {
	    ret = SA_NO_SUCH_PROP;
	}
	return (ret);
}

/*
 * sa_update_property(property, value)
 *
 * Update the specified property to the new value.  If value is NULL,
 * we currently treat this as a remove.
 */

int
sa_update_property(sa_property_t property, char *value)
{
	int ret = SA_OK;
	if (value == NULL) {
		return (sa_remove_property(property));
	} else {
		sa_optionset_t optionset;
		sa_group_t group;
		set_node_attr((void *)property, "value", value);
		optionset = sa_get_property_parent(property);
		if (optionset != NULL) {
		    group = sa_get_optionset_parent(optionset);
		    if (group != NULL) {
			ret = sa_set_prop_by_prop(optionset, group, property,
					    SA_PROP_OP_UPDATE);
		    }
		} else {
		    ret = SA_NO_SUCH_PROP;
		}
	}
	return (ret);
}

/*
 *  _sa_get_next_error(node)
 *
 * Get the next (first if node==NULL) error node in the
 * document. "error" nodes are added if there were syntax errors
 * during parsing of the /etc/dfs/dfstab file. They are preserved in
 * comments and recreated in the doc on the next parse.
 */

xmlNodePtr
_sa_get_next_error(xmlNodePtr node)
{
	if (node == NULL) {
	    for (node = sa_config_tree->xmlChildrenNode;
		node != NULL; node = node->next)
		if (xmlStrcmp(node->name, (xmlChar *)"error") == 0)
		    return (node);
	} else {
	    for (node = node->next; node != NULL; node = node->next)
		if (xmlStrcmp(node->name, (xmlChar *)"error") == 0)
		    return (node);
	}
	return (node);
}

/*
 * sa_get_protocol_property(propset, prop)
 *
 * Get the specified protocol specific property. These are global to
 * the protocol and not specific to a group or share.
 */

sa_property_t
sa_get_protocol_property(sa_protocol_properties_t propset, char *prop)
{
	xmlNodePtr node = (xmlNodePtr)propset;
	xmlChar *value = NULL;

	for (node = node->children; node != NULL;
		node = node->next) {
	    if (xmlStrcmp(node->name, (xmlChar *)"option") == 0) {
		if (prop == NULL)
		    break;
		value = xmlGetProp(node, (xmlChar *)"type");
		if (value != NULL &&
		    xmlStrcasecmp(value, (xmlChar *)prop) == 0) {
		    break;
		}
		if (value != NULL) {
		    xmlFree(value);
		    value = NULL;
		}
	    }
	}
	if (value != NULL)
		xmlFree(value);
	if (node != NULL && xmlStrcmp(node->name, (xmlChar *)"option") != 0) {
	    /* avoid a non option node -- it is possible to be a text node */
	    node = NULL;
	}
	return ((sa_property_t)node);
}

/*
 * sa_get_next_protocol_property(prop)
 *
 * Get the next protocol specific property in the list.
 */

sa_property_t
sa_get_next_protocol_property(sa_property_t prop)
{
	xmlNodePtr node;

	for (node = ((xmlNodePtr)prop)->next; node != NULL;
		node = node->next) {
		if (xmlStrcmp(node->name, (xmlChar *)"option") == 0) {
			break;
		}
	}
	return ((sa_property_t)node);
}

/*
 * sa_set_protocol_property(prop, value)
 *
 * Set the specified property to have the new value.  The protocol
 * specific plugin will then be called to update the property.
 */

int
sa_set_protocol_property(sa_property_t prop, char *value)
{
	sa_protocol_properties_t propset;
	char *proto;
	int ret = SA_INVALID_PROTOCOL;

	propset = ((xmlNodePtr)prop)->parent;
	if (propset != NULL) {
	    proto = sa_get_optionset_attr(propset, "type");
	    if (proto != NULL) {
		set_node_attr((xmlNodePtr)prop, "value", value);
		ret = sa_proto_set_property(proto, prop);
		sa_free_attr_string(proto);
	    }
	}
	return (ret);
}

/*
 * sa_add_protocol_property(propset, prop)
 *
 * Add a new property to the protocol sepcific property set.
 */

int
sa_add_protocol_property(sa_protocol_properties_t propset, sa_property_t prop)
{
	xmlNodePtr node;

	/* should check for legitimacy */
	node = xmlAddChild((xmlNodePtr)propset, (xmlNodePtr)prop);
	if (node != NULL)
	    return (SA_OK);
	return (SA_NO_MEMORY);
}

/*
 * sa_create_protocol_properties(proto)
 *
 * Create a protocol specifity property set.
 */

sa_protocol_properties_t
sa_create_protocol_properties(char *proto)
{
	xmlNodePtr node;
	node = xmlNewNode(NULL, (xmlChar *)"propertyset");
	if (node != NULL) {
	    xmlSetProp(node, (xmlChar *)"type", (xmlChar *)proto);
	}
	return (node);
}
