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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <utmpx.h>
#include <pwd.h>
#include <auth_attr.h>
#include <secdb.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <errno.h>

#include <libshare.h>
#include "sharemgr.h"
#include <libscf.h>
#include <libxml/tree.h>
#include <libintl.h>

static char *sa_get_usage(sa_usage_t);

/*
 * Implementation of the common sub-commands supported by sharemgr.
 * A number of helper functions are also included.
 */

/*
 * has_protocol(group, proto)
 *	If the group has an optionset with the specified protocol,
 *	return true (1) otherwise false (0).
 */
static int
has_protocol(sa_group_t group, char *protocol)
{
	sa_optionset_t optionset;
	int result = 0;

	optionset = sa_get_optionset(group, protocol);
	if (optionset != NULL) {
		result++;
	}
	return (result);
}

/*
 * add_list(list, item)
 *	Adds a new list member that points to item to the list.
 *	If list is NULL, it starts a new list.  The function returns
 *	the first member of the list.
 */
struct list *
add_list(struct list *listp, void *item, void *data)
{
	struct list *new, *tmp;

	new = malloc(sizeof (struct list));
	if (new != NULL) {
		new->next = NULL;
		new->item = item;
		new->itemdata = data;
	} else {
		return (listp);
	}

	if (listp == NULL)
		return (new);

	for (tmp = listp; tmp->next != NULL; tmp = tmp->next) {
		/* get to end of list */
	}
	tmp->next = new;
	return (listp);
}

/*
 * free_list(list)
 *	Given a list, free all the members of the list;
 */
static void
free_list(struct list *listp)
{
	struct list *tmp;
	while (listp != NULL) {
		tmp = listp;
		listp = listp->next;
		free(tmp);
	}
}

/*
 * check_authorization(instname, which)
 *
 * Checks to see if the specific type of authorization in which is
 * enabled for the user in this SMF service instance.
 */

static int
check_authorization(char *instname, int which)
{
	scf_handle_t *handle = NULL;
	scf_simple_prop_t *prop = NULL;
	char svcstring[SA_MAX_NAME_LEN + sizeof (SA_SVC_FMRI_BASE) + 1];
	char *authstr = NULL;
	ssize_t numauths;
	int ret = B_TRUE;
	uid_t uid;
	struct passwd *pw = NULL;

	uid = getuid();
	pw = getpwuid(uid);
	if (pw == NULL) {
		ret = B_FALSE;
	} else {
		/*
		 * Since names are restricted to SA_MAX_NAME_LEN won't
		 * overflow.
		 */
		(void) snprintf(svcstring, sizeof (svcstring), "%s:%s",
		    SA_SVC_FMRI_BASE, instname);
		handle = scf_handle_create(SCF_VERSION);
		if (handle != NULL) {
			if (scf_handle_bind(handle) == 0) {
				switch (which) {
				case SVC_SET:
					prop = scf_simple_prop_get(handle,
					    svcstring, "general",
					    SVC_AUTH_VALUE);
					break;
				case SVC_ACTION:
					prop = scf_simple_prop_get(handle,
					    svcstring, "general",
					    SVC_AUTH_ACTION);
					break;
				}
			}
		}
	}
	/* make sure we have an authorization string property */
	if (prop != NULL) {
		int i;
		numauths = scf_simple_prop_numvalues(prop);
		for (ret = 0, i = 0; i < numauths; i++) {
			authstr = scf_simple_prop_next_astring(prop);
			if (authstr != NULL) {
				/* check if this user has one of the strings */
				if (chkauthattr(authstr, pw->pw_name)) {
					ret = 1;
					break;
				}
			}
		}
		endauthattr();
		scf_simple_prop_free(prop);
	} else {
		/* no authorization string defined */
		ret = 0;
	}
	if (handle != NULL)
		scf_handle_destroy(handle);
	return (ret);
}

/*
 * check_authorizations(instname, flags)
 *
 * check all the needed authorizations for the user in this service
 * instance. Return value of 1(true) or 0(false) indicates whether
 * there are authorizations for the user or not.
 */

static int
check_authorizations(char *instname, int flags)
{
	int ret1 = 0;
	int ret2 = 0;
	int ret;

	if (flags & SVC_SET)
		ret1 = check_authorization(instname, SVC_SET);
	if (flags & SVC_ACTION)
		ret2 = check_authorization(instname, SVC_ACTION);
	switch (flags) {
	case SVC_ACTION:
		ret = ret2;
		break;
	case SVC_SET:
		ret = ret1;
		break;
	case SVC_ACTION|SVC_SET:
		ret = ret1 & ret2;
		break;
	default:
		/* if not flags set, we assume we don't need authorizations */
		ret = 1;
	}
	return (ret);
}

/*
 * enable_group(group, updateproto)
 *
 * enable all the shares in the specified group. This is a helper for
 * enable_all_groups in order to simplify regular and subgroup (zfs)
 * disabling. Group has already been checked for non-NULL.
 */

static void
enable_group(sa_group_t group, char *updateproto)
{
	sa_share_t share;

	for (share = sa_get_share(group, NULL);
	    share != NULL;
	    share = sa_get_next_share(share)) {
		if (updateproto != NULL)
			(void) sa_update_legacy(share, updateproto);
		(void) sa_enable_share(share, NULL);
	}
}

/*
 * isenabled(group)
 *
 * Returns B_TRUE if the group is enabled or B_FALSE if it isn't.
 * Moved to separate function to reduce clutter in the code.
 */

static int
isenabled(sa_group_t group)
{
	char *state;
	int ret = B_FALSE;

	if (group != NULL) {
		state = sa_get_group_attr(group, "state");
		if (state != NULL) {
			if (strcmp(state, "enabled") == 0)
				ret = B_TRUE;
			sa_free_attr_string(state);
		}
	}
	return (ret);
}

/*
 * enable_all_groups(list, setstate, online, updateproto)
 *	Given a list of groups, enable each one found.  If updateproto
 *	is not NULL, then update all the shares for the protocol that
 *	was passed in.
 */
static int
enable_all_groups(sa_handle_t handle, struct list *work, int setstate,
	int online, char *updateproto)
{
	int ret;
	char instance[SA_MAX_NAME_LEN + sizeof (SA_SVC_FMRI_BASE) + 1];
	char *state;
	char *name;
	char *zfs = NULL;
	sa_group_t group;
	sa_group_t subgroup;

	for (ret = SA_OK; work != NULL;	work = work->next) {
		group = (sa_group_t)work->item;

		/*
		 * If setstate == TRUE, then make sure to set
		 * enabled. This needs to be done here in order for
		 * the isenabled check to succeed on a newly enabled
		 * group.
		 */
		if (setstate == B_TRUE) {
			ret = sa_set_group_attr(group, "state",	"enabled");
			if (ret != SA_OK)
				break;
		}

		/*
		 * Check to see if group is enabled. If it isn't, skip
		 * the rest.  We don't want shares starting if the
		 * group is disabled. The properties may have been
		 * updated, but there won't be a change until the
		 * group is enabled.
		 */
		if (!isenabled(group))
			continue;

		/* if itemdata != NULL then a single share */
		if (work->itemdata != NULL) {
			ret = sa_enable_share((sa_share_t)work->itemdata, NULL);
		}
		if (ret != SA_OK)
			break;

		/* if itemdata == NULL then the whole group */
		if (work->itemdata == NULL) {
			zfs = sa_get_group_attr(group, "zfs");
			/*
			 * if the share is managed by ZFS, don't
			 * update any of the protocols since ZFS is
			 * handling this.  updateproto will contain
			 * the name of the protocol that we want to
			 * update legacy files for.
			 */
			enable_group(group, zfs == NULL ? updateproto : NULL);
			for (subgroup = sa_get_sub_group(group);
			    subgroup != NULL;
			    subgroup = sa_get_next_group(subgroup)) {
				/* never update legacy for ZFS subgroups */
				enable_group(subgroup, NULL);
			}
		}
		if (online) {
			zfs = sa_get_group_attr(group, "zfs");
			name = sa_get_group_attr(group, "name");
			if (name != NULL) {
				if (zfs == NULL) {
					(void) snprintf(instance,
					    sizeof (instance), "%s:%s",
					    SA_SVC_FMRI_BASE, name);
					state = smf_get_state(instance);
					if (state == NULL ||
					    strcmp(state, "online") != 0) {
						(void) smf_enable_instance(
						    instance, 0);
						free(state);
					}
				} else {
					sa_free_attr_string(zfs);
					zfs = NULL;
				}
				if (name != NULL)
					sa_free_attr_string(name);
			}
		}
	}
	if (ret == SA_OK) {
		ret = sa_update_config(handle);
	}
	return (ret);
}

/*
 * chk_opt(optlistp, security, proto)
 *
 * Do a sanity check on the optlist provided for the protocol.  This
 * is a syntax check and verification that the property is either a
 * general or specific to a names optionset.
 */

static int
chk_opt(struct options *optlistp, int security, char *proto)
{
	struct options *optlist;
	char *sep = "";
	int notfirst = 0;
	int ret;

	for (optlist = optlistp; optlist != NULL; optlist = optlist->next) {
		char *optname;

		optname = optlist->optname;
		ret = OPT_ADD_OK;
		/* extract property/value pair */
		if (sa_is_security(optname, proto)) {
			if (!security)
				ret = OPT_ADD_SECURITY;
		} else {
			if (security)
				ret = OPT_ADD_PROPERTY;
		}
		if (ret != OPT_ADD_OK) {
			if (notfirst == 0)
				(void) printf(
				    gettext("Property syntax error: "));
			switch (ret) {
			case OPT_ADD_SYNTAX:
				(void) printf(gettext("%ssyntax error: %s"),
				    sep, optname);
				sep = ", ";
				break;
			case OPT_ADD_SECURITY:
				(void) printf(gettext("%s%s requires -S"),
				    optname, sep);
				sep = ", ";
				break;
			case OPT_ADD_PROPERTY:
				(void) printf(
				    gettext("%s%s not supported with -S"),
				    optname, sep);
				sep = ", ";
				break;
			}
			notfirst++;
		}
	}
	if (notfirst) {
		(void) printf("\n");
		ret = SA_SYNTAX_ERR;
	}
	return (ret);
}

/*
 * free_opt(optlist)
 *	Free the specified option list.
 */
static void
free_opt(struct options *optlist)
{
	struct options *nextopt;
	while (optlist != NULL) {
		nextopt = optlist->next;
		free(optlist);
		optlist = nextopt;
	}
}

/*
 * check property list for valid properties
 * A null value is a remove which is always valid.
 */
static int
valid_options(struct options *optlist, char *proto, void *object, char *sec)
{
	int ret = SA_OK;
	struct options *cur;
	sa_property_t prop;
	sa_optionset_t parent = NULL;

	if (object != NULL) {
		if (sec == NULL)
			parent = sa_get_optionset(object, proto);
		else
			parent = sa_get_security(object, sec, proto);
	}

	for (cur = optlist; cur != NULL; cur = cur->next) {
		if (cur->optvalue == NULL)
			continue;
		prop = sa_create_property(cur->optname, cur->optvalue);
		if (prop == NULL)
			ret = SA_NO_MEMORY;
		if (ret != SA_OK ||
		    (ret = sa_valid_property(parent, proto, prop)) != SA_OK) {
			(void) printf(
			    gettext("Could not add property %s: %s\n"),
			    cur->optname, sa_errorstr(ret));
		}
		(void) sa_remove_property(prop);
	}
	return (ret);
}

/*
 * add_optionset(group, optlist, protocol, *err)
 *	Add the options in optlist to an optionset and then add the optionset
 *	to the group.
 *
 *	The return value indicates if there was a "change" while errors are
 *	returned via the *err parameters.
 */
static int
add_optionset(sa_group_t group, struct options *optlist, char *proto, int *err)
{
	sa_optionset_t optionset;
	int ret = SA_OK;
	int result = 0;

	optionset = sa_get_optionset(group, proto);
	if (optionset == NULL) {
		optionset = sa_create_optionset(group, proto);
		result = 1; /* adding a protocol is a change */
	}
	if (optionset == NULL) {
		ret = SA_NO_MEMORY;
		goto out;
	}
	while (optlist != NULL) {
		sa_property_t prop;
		prop = sa_get_property(optionset, optlist->optname);
		if (prop == NULL) {
			/*
			 * add the property, but only if it is
			 * a non-NULL or non-zero length value
			 */
			if (optlist->optvalue != NULL) {
				prop = sa_create_property(optlist->optname,
				    optlist->optvalue);
				if (prop != NULL) {
					ret = sa_valid_property(optionset,
					    proto, prop);
					if (ret != SA_OK) {
						(void) sa_remove_property(prop);
						(void) printf(gettext("Could "
						    "not add property "
						    "%s: %s\n"),
						    optlist->optname,
						    sa_errorstr(ret));
					}
				}
				if (ret == SA_OK) {
					ret = sa_add_property(optionset, prop);
					if (ret != SA_OK) {
						(void) printf(gettext(
						    "Could not add property "
						    "%s: %s\n"),
						    optlist->optname,
						    sa_errorstr(ret));
					} else {
						/* there was a change */
						result = 1;
					}
				}
			}
		} else {
			ret = sa_update_property(prop, optlist->optvalue);
			/* should check to see if value changed */
			if (ret != SA_OK) {
				(void) printf(gettext("Could not update "
				    "property %s: %s\n"), optlist->optname,
				    sa_errorstr(ret));
			} else {
				result = 1;
			}
		}
		optlist = optlist->next;
	}
	ret = sa_commit_properties(optionset, 0);

out:
	if (err != NULL)
		*err = ret;
	return (result);
}

/*
 * sa_create(flags, argc, argv)
 *	create a new group
 *	this may or may not have a protocol associated with it.
 *	No protocol means "all" protocols in this case.
 */
static int
sa_create(sa_handle_t handle, int flags, int argc, char *argv[])
{
	char *groupname;

	sa_group_t group;
	int verbose = 0;
	int dryrun = 0;
	int c;
	char *protocol = NULL;
	int ret = SA_OK;
	struct options *optlist = NULL;
	int err = 0;
	int auth;

	while ((c = getopt(argc, argv, "?hvnP:p:")) != EOF) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		case 'n':
			dryrun++;
			break;
		case 'P':
			protocol = optarg;
			if (sa_valid_protocol(protocol))
				break;
			(void) printf(gettext(
			    "Invalid protocol specified: %s\n"), protocol);
			return (SA_INVALID_PROTOCOL);
			break;
		case 'p':
			ret = add_opt(&optlist, optarg, 0);
			switch (ret) {
			case OPT_ADD_SYNTAX:
				(void) printf(gettext(
				    "Property syntax error for property: %s\n"),
				    optarg);
				return (SA_SYNTAX_ERR);
			case OPT_ADD_SECURITY:
				(void) printf(gettext(
				    "Security properties need "
				    "to be set with set-security: %s\n"),
				    optarg);
				return (SA_SYNTAX_ERR);
			default:
				break;
			}
			break;
		default:
		case 'h':
		case '?':
			(void) printf(gettext("usage: %s\n"),
			    sa_get_usage(USAGE_CREATE));
			return (0);
		}
	}

	if (optind >= argc) {
		(void) printf(gettext("usage: %s\n"),
		    sa_get_usage(USAGE_CREATE));
		(void) printf(gettext("\tgroup must be specified.\n"));
		return (SA_BAD_PATH);
	}

	if ((optind + 1) < argc) {
		(void) printf(gettext("usage: %s\n"),
		    sa_get_usage(USAGE_CREATE));
		(void) printf(gettext("\textraneous group(s) at end\n"));
		return (SA_SYNTAX_ERR);
	}

	if (protocol == NULL && optlist != NULL) {
		/* lookup default protocol */
		(void) printf(gettext("usage: %s\n"),
		    sa_get_usage(USAGE_CREATE));
		(void) printf(gettext("\tprotocol must be specified "
		    "with properties\n"));
		return (SA_INVALID_PROTOCOL);
	}

	if (optlist != NULL)
		ret = chk_opt(optlist, 0, protocol);
	if (ret == OPT_ADD_SECURITY) {
		(void) printf(gettext("Security properties not "
		    "supported with create\n"));
		return (SA_SYNTAX_ERR);
	}

	/*
	 * If a group already exists, we can only add a new protocol
	 * to it and not create a new one or add the same protocol
	 * again.
	 */

	groupname = argv[optind];

	auth = check_authorizations(groupname, flags);

	group = sa_get_group(handle, groupname);
	if (group != NULL) {
		/* group exists so must be a protocol add */
		if (protocol != NULL) {
			if (has_protocol(group, protocol)) {
				(void) printf(gettext(
				    "Group \"%s\" already exists"
				    " with protocol %s\n"), groupname,
				    protocol);
				ret = SA_DUPLICATE_NAME;
			}
		} else {
			/* must add new protocol */
			(void) printf(gettext(
			    "Group already exists and no protocol "
			    "specified.\n"));
			ret = SA_DUPLICATE_NAME;
		}
	} else {
		/*
		 * is it a valid name? Must comply with SMF instance
		 * name restrictions.
		 */
		if (!sa_valid_group_name(groupname)) {
			ret = SA_INVALID_NAME;
			(void) printf(gettext("Invalid group name: %s\n"),
			    groupname);
		}
	}
	if (ret == SA_OK) {
		/* check protocol vs optlist */
		if (optlist != NULL) {
			/* check options, if any, for validity */
			ret = valid_options(optlist, protocol, group, NULL);
		}
	}
	if (ret == SA_OK && !dryrun) {
		if (group == NULL) {
			group = sa_create_group(handle, (char *)groupname,
			    &err);
		}
		if (group != NULL) {
			sa_optionset_t optionset;
			if (optlist != NULL) {
				(void) add_optionset(group, optlist, protocol,
				    &ret);
			} else if (protocol != NULL) {
				optionset = sa_create_optionset(group,
				    protocol);
				if (optionset == NULL)
					ret = SA_NO_MEMORY;
			} else if (protocol == NULL) {
				char **protolist;
				int numprotos, i;
				numprotos = sa_get_protocols(&protolist);
				for (i = 0; i < numprotos; i++) {
					optionset = sa_create_optionset(group,
					    protolist[i]);
				}
				if (protolist != NULL)
					free(protolist);
			}
			/*
			 * We have a group and legal additions
			 */
			if (ret == SA_OK) {
				/*
				 * Commit to configuration for protocols that
				 * need to do block updates. For NFS, this
				 * doesn't do anything but it will be run for
				 * all protocols that implement the
				 * appropriate plugin.
				 */
				ret = sa_update_config(handle);
			} else {
				if (group != NULL)
					(void) sa_remove_group(group);
			}
		} else {
			ret = err;
			(void) printf(gettext("Could not create group: %s\n"),
			    sa_errorstr(ret));
		}
	}
	if (dryrun && ret == SA_OK && !auth && verbose) {
		(void) printf(gettext("Command would fail: %s\n"),
		    sa_errorstr(SA_NO_PERMISSION));
		ret = SA_NO_PERMISSION;
	}
	free_opt(optlist);
	return (ret);
}

/*
 * group_status(group)
 *
 * return the current status (enabled/disabled) of the group.
 */

static char *
group_status(sa_group_t group)
{
	char *state;
	int enabled = 0;

	state = sa_get_group_attr(group, "state");
	if (state != NULL) {
		if (strcmp(state, "enabled") == 0) {
			enabled = 1;
		}
		sa_free_attr_string(state);
	}
	return (enabled ? "enabled" : "disabled");
}

/*
 * sa_delete(flags, argc, argv)
 *
 *	Delete a group.
 */

static int
sa_delete(sa_handle_t handle, int flags, int argc, char *argv[])
{
	char *groupname;
	sa_group_t group;
	sa_share_t share;
	int verbose = 0;
	int dryrun = 0;
	int force = 0;
	int c;
	char *protocol = NULL;
	char *sectype = NULL;
	int ret = SA_OK;
	int auth;

	while ((c = getopt(argc, argv, "?hvnP:fS:")) != EOF) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		case 'n':
			dryrun++;
			break;
		case 'P':
			protocol = optarg;
			if (!sa_valid_protocol(protocol)) {
				(void) printf(gettext("Invalid protocol "
				    "specified: %s\n"),   protocol);
				return (SA_INVALID_PROTOCOL);
			}
			break;
		case 'S':
			sectype = optarg;
			break;
		case 'f':
			force++;
			break;
		default:
		case 'h':
		case '?':
			(void) printf(gettext("usage: %s\n"),
			    sa_get_usage(USAGE_DELETE));
			return (0);
		}
	}

	if (optind >= argc) {
		(void) printf(gettext("usage: %s\n"),
		    sa_get_usage(USAGE_DELETE));
		(void) printf(gettext("\tgroup must be specified.\n"));
		return (SA_SYNTAX_ERR);
	}

	if ((optind + 1) < argc) {
		(void) printf(gettext("usage: %s\n"),
		    sa_get_usage(USAGE_DELETE));
		(void) printf(gettext("\textraneous group(s) at end\n"));
		return (SA_SYNTAX_ERR);
	}

	if (sectype != NULL && protocol == NULL) {
		(void) printf(gettext("usage: %s\n"),
		    sa_get_usage(USAGE_DELETE));
		(void) printf(gettext("\tsecurity requires protocol to be "
		    "specified.\n"));
		return (SA_SYNTAX_ERR);
	}

	/*
	 * Determine if the group already exists since it must in
	 * order to be removed.
	 *
	 * We can delete when:
	 *
	 *	- group is empty
	 *	- force flag is set
	 *	- if protocol specified, only delete the protocol
	 */

	groupname = argv[optind];
	group = sa_get_group(handle, groupname);
	if (group == NULL) {
		ret = SA_NO_SUCH_GROUP;
		goto done;
	}
	auth = check_authorizations(groupname, flags);
	if (protocol == NULL) {
		share = sa_get_share(group, NULL);
		if (share != NULL)
			ret = SA_BUSY;
		if (share == NULL || (share != NULL && force == 1)) {
			ret = SA_OK;
			if (!dryrun) {
				while (share != NULL) {
					sa_share_t next_share;
					next_share = sa_get_next_share(share);
					/*
					 * need to do the disable of
					 * each share, but don't
					 * actually do anything on a
					 * dryrun.
					 */
					ret = sa_disable_share(share, NULL);
					ret = sa_remove_share(share);
					share = next_share;
				}
				ret = sa_remove_group(group);
			}
		}
		/* Commit to configuration if not a dryrun */
		if (!dryrun && ret == SA_OK) {
			ret = sa_update_config(handle);
		}
	} else {
		/* a protocol delete */
		sa_optionset_t optionset;
		sa_security_t security;
			if (sectype != NULL) {
			/* only delete specified security */
			security = sa_get_security(group, sectype, protocol);
			if (security != NULL && !dryrun)
				ret = sa_destroy_security(security);
			else
				ret = SA_INVALID_PROTOCOL;
		} else {
			optionset = sa_get_optionset(group, protocol);
			if (optionset != NULL && !dryrun) {
				/*
				 * have an optionset with
				 * protocol to delete
				 */
				ret = sa_destroy_optionset(optionset);
				/*
				 * Now find all security sets
				 * for the protocol and remove
				 * them. Don't remove other
				 * protocols.
				 */
				for (security =
				    sa_get_security(group, NULL, NULL);
				    ret == SA_OK && security != NULL;
				    security = sa_get_next_security(security)) {
					char *secprot;
					secprot = sa_get_security_attr(security,
					    "type");
					if (secprot != NULL &&
					    strcmp(secprot, protocol) == 0)
						ret = sa_destroy_security(
						    security);
					if (secprot != NULL)
						sa_free_attr_string(secprot);
				}
			} else {
				if (!dryrun)
					ret = SA_INVALID_PROTOCOL;
			}
		}
	}

done:
	if (ret != SA_OK) {
		(void) printf(gettext("Could not delete group: %s\n"),
		    sa_errorstr(ret));
	} else if (dryrun && !auth && verbose) {
		(void) printf(gettext("Command would fail: %s\n"),
		    sa_errorstr(SA_NO_PERMISSION));
	}
	return (ret);
}

/*
 * strndupr(*buff, str, buffsize)
 *
 * used with small strings to duplicate and possibly increase the
 * buffer size of a string.
 */
static char *
strndupr(char *buff, char *str, int *buffsize)
{
	int limit;
	char *orig_buff = buff;

	if (buff == NULL) {
		buff = (char *)malloc(64);
		if (buff == NULL)
			return (NULL);
		*buffsize = 64;
		buff[0] = '\0';
	}
	limit = strlen(buff) + strlen(str) + 1;
	if (limit > *buffsize) {
		limit = *buffsize = *buffsize + ((limit / 64) + 64);
		buff = realloc(buff, limit);
	}
	if (buff != NULL) {
		(void) strcat(buff, str);
	} else {
		/* if it fails, fail it hard */
		if (orig_buff != NULL)
			free(orig_buff);
	}
	return (buff);
}

/*
 * group_proto(group)
 *
 * return a string of all the protocols (space separated) associated
 * with this group.
 */

static char *
group_proto(sa_group_t group)
{
	sa_optionset_t optionset;
	char *proto;
	char *buff = NULL;
	int buffsize = 0;
	int addspace = 0;
	/*
	 * get the protocol list by finding the optionsets on this
	 * group and extracting the type value. The initial call to
	 * strndupr() initailizes buff.
	 */
	buff = strndupr(buff, "", &buffsize);
	if (buff != NULL) {
		for (optionset = sa_get_optionset(group, NULL);
		    optionset != NULL && buff != NULL;
		    optionset = sa_get_next_optionset(optionset)) {
			/*
			 * extract out the protocol type from this optionset
			 * and append it to the buffer "buff". strndupr() will
			 * reallocate space as necessay.
			 */
			proto = sa_get_optionset_attr(optionset, "type");
			if (proto != NULL) {
				if (addspace++)
					buff = strndupr(buff, " ", &buffsize);
				buff = strndupr(buff, proto, &buffsize);
				sa_free_attr_string(proto);
			}
		}
	}
	return (buff);
}

/*
 * sa_list(flags, argc, argv)
 *
 * implements the "list" subcommand to list groups and optionally
 * their state and protocols.
 */

/*ARGSUSED*/
static int
sa_list(sa_handle_t handle, int flags, int argc, char *argv[])
{
	sa_group_t group;
	int verbose = 0;
	int c;
	char *protocol = NULL;

	while ((c = getopt(argc, argv, "?hvP:")) != EOF) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		case 'P':
			protocol = optarg;
			if (!sa_valid_protocol(protocol)) {
				(void) printf(gettext(
				    "Invalid protocol specified: %s\n"),
				    protocol);
				return (SA_INVALID_PROTOCOL);
			}
			break;
		default:
		case 'h':
		case '?':
			(void) printf(gettext("usage: %s\n"),
			    sa_get_usage(USAGE_LIST));
			return (0);
		}
	}

	for (group = sa_get_group(handle, NULL);
	    group != NULL;
	    group = sa_get_next_group(group)) {
		char *name;
		char *proto;
		if (protocol == NULL || has_protocol(group, protocol)) {
			name = sa_get_group_attr(group, "name");
			if (name != NULL && (verbose > 1 || name[0] != '#')) {
				(void) printf("%s", (char *)name);
				if (verbose) {
					/*
					 * Need the list of protocols
					 * and current status once
					 * available. We do want to
					 * translate the
					 * enabled/disabled text here.
					 */
					(void) printf("\t%s", isenabled(group) ?
					    gettext("enabled") :
					    gettext("disabled"));
					proto = group_proto(group);
					if (proto != NULL) {
						(void) printf("\t%s",
						    (char *)proto);
						free(proto);
					}
				}
				(void) printf("\n");
			}
			if (name != NULL)
				sa_free_attr_string(name);
		}
	}
	return (0);
}

/*
 * out_properties(optionset, proto, sec)
 *
 * Format the properties and encode the protocol and optional named
 * optionset into the string.
 *
 * format is protocol[:name]=(property-list)
 */

static void
out_properties(sa_optionset_t optionset, char *proto, char *sec)
{
	char *type;
	char *value;
	int spacer;
	sa_property_t prop;

	if (sec == NULL)
		(void) printf(" %s=(", proto ? proto : gettext("all"));
	else
		(void) printf(" %s:%s=(", proto ? proto : gettext("all"), sec);

	for (spacer = 0, prop = sa_get_property(optionset, NULL);
	    prop != NULL;
	    prop = sa_get_next_property(prop)) {

		/*
		 * extract the property name/value and output with
		 * appropriate spacing. I.e. no prefixed space the
		 * first time through but a space on subsequent
		 * properties.
		 */
		type = sa_get_property_attr(prop, "type");
		value = sa_get_property_attr(prop, "value");
		if (type != NULL) {
			(void) printf("%s%s=", spacer ? " " : "",	type);
			spacer = 1;
			if (value != NULL)
				(void) printf("\"%s\"", value);
			else
				(void) printf("\"\"");
		}
		if (type != NULL)
			sa_free_attr_string(type);
		if (value != NULL)
			sa_free_attr_string(value);
	}
	(void) printf(")");
}

/*
 * show_properties(group, protocol, prefix)
 *
 * print the properties for a group. If protocol is NULL, do all
 * protocols otherwise only the specified protocol. All security
 * (named groups specific to the protocol) are included.
 *
 * The "prefix" is always applied. The caller knows whether it wants
 * some type of prefix string (white space) or not.  Once the prefix
 * has been output, it is reduced to the zero length string for the
 * remainder of the property output.
 */

static void
show_properties(sa_group_t group, char *protocol, char *prefix)
{
	sa_optionset_t optionset;
	sa_security_t security;
	char *value;
	char *secvalue;

	if (protocol != NULL) {
		optionset = sa_get_optionset(group, protocol);
		if (optionset != NULL) {
			(void) printf("%s", prefix);
			prefix = "";
			out_properties(optionset, protocol, NULL);
		}
		security = sa_get_security(group, protocol, NULL);
		if (security != NULL) {
			(void) printf("%s", prefix);
			prefix = "";
			out_properties(security, protocol, NULL);
		}
	} else {
		for (optionset = sa_get_optionset(group, protocol);
		    optionset != NULL;
		    optionset = sa_get_next_optionset(optionset)) {

			value = sa_get_optionset_attr(optionset, "type");
			(void) printf("%s", prefix);
			prefix = "";
			out_properties(optionset, value, 0);
			if (value != NULL)
				sa_free_attr_string(value);
		}
		for (security = sa_get_security(group, NULL, protocol);
		    security != NULL;
		    security = sa_get_next_security(security)) {

			value = sa_get_security_attr(security, "type");
			secvalue = sa_get_security_attr(security, "sectype");
			(void) printf("%s", prefix);
			prefix = "";
			out_properties(security, value, secvalue);
			if (value != NULL)
				sa_free_attr_string(value);
			if (secvalue != NULL)
				sa_free_attr_string(secvalue);
		}
	}
}

/*
 * show_group(group, verbose, properties, proto, subgroup)
 *
 * helper function to show the contents of a group.
 */

static void
show_group(sa_group_t group, int verbose, int properties, char *proto,
		char *subgroup)
{
	sa_share_t share;
	char *groupname;
	char *sharepath;
	char *resource;
	char *description;
	char *type;
	char *zfs = NULL;
	int iszfs = 0;

	groupname = sa_get_group_attr(group, "name");
	if (groupname != NULL) {
		if (proto != NULL && !has_protocol(group, proto)) {
			sa_free_attr_string(groupname);
			return;
		}
		/*
		 * check to see if the group is managed by ZFS. If
		 * there is an attribute, then it is. A non-NULL zfs
		 * variable will trigger the different way to display
		 * and will remove the transient property indicator
		 * from the output.
		 */
		zfs = sa_get_group_attr(group, "zfs");
		if (zfs != NULL) {
			iszfs = 1;
			sa_free_attr_string(zfs);
		}
		share = sa_get_share(group, NULL);
		if (subgroup == NULL)
			(void) printf("%s", groupname);
		else
			(void) printf("    %s/%s", subgroup, groupname);
		if (properties)
			show_properties(group, proto, "");
		(void) printf("\n");
		if (strcmp(groupname, "zfs") == 0) {
			sa_group_t zgroup;

			for (zgroup = sa_get_sub_group(group);
			    zgroup != NULL;
			    zgroup = sa_get_next_group(zgroup)) {
				show_group(zgroup, verbose, properties, proto,
				    "zfs");
			}
			sa_free_attr_string(groupname);
			return;
		}
		/*
		 * Have a group, so list the contents. Resource and
		 * description are only listed if verbose is set.
		 */
		for (share = sa_get_share(group, NULL);
		    share != NULL;
		    share = sa_get_next_share(share)) {
			sharepath = sa_get_share_attr(share, "path");
			if (sharepath != NULL) {
				if (verbose) {
					resource = sa_get_share_attr(share,
					    "resource");
					description =
					    sa_get_share_description(share);
					type = sa_get_share_attr(share,
					    "type");
					if (type != NULL && !iszfs &&
					    strcmp(type, "transient") == 0)
						(void) printf("\t* ");
					else
						(void) printf("\t  ");
					if (resource != NULL &&
					    strlen(resource) > 0) {
						(void) printf("%s=%s",
						    resource, sharepath);
					} else {
						(void) printf("%s", sharepath);
					}
					if (resource != NULL)
						sa_free_attr_string(resource);
					if (properties)
						show_properties(share, NULL,
						    "\t");
					if (description != NULL) {
						if (strlen(description) > 0) {
							(void) printf(
							    "\t\"%s\"",
							    description);
						}
						sa_free_share_description(
						    description);
					}
					if (type != NULL)
						sa_free_attr_string(type);
				} else {
					(void) printf("\t%s", sharepath);
					if (properties)
						show_properties(share, NULL,
						    "\t");
				}
				(void) printf("\n");
				sa_free_attr_string(sharepath);
			}
		}
	}
	if (groupname != NULL) {
		sa_free_attr_string(groupname);
	}
}

/*
 * show_group_xml_init()
 *
 * Create an XML document that will be used to display config info via
 * XML format.
 */

xmlDocPtr
show_group_xml_init()
{
	xmlDocPtr doc;
	xmlNodePtr root;

	doc = xmlNewDoc((xmlChar *)"1.0");
	if (doc != NULL) {
		root = xmlNewNode(NULL, (xmlChar *)"sharecfg");
		if (root != NULL)
			xmlDocSetRootElement(doc, root);
	}
	return (doc);
}

/*
 * show_group_xml(doc, group)
 *
 * Copy the group info into the XML doc.
 */

static void
show_group_xml(xmlDocPtr doc, sa_group_t group)
{
	xmlNodePtr node;
	xmlNodePtr root;

	root = xmlDocGetRootElement(doc);
	node = xmlCopyNode((xmlNodePtr)group, 1);
	if (node != NULL && root != NULL) {
		xmlAddChild(root, node);
		/*
		 * In the future, we may have interally used tags that
		 * should not appear in the XML output. Remove
		 * anything we don't want to show here.
		 */
	}
}

/*
 * sa_show(flags, argc, argv)
 *
 * Implements the show subcommand.
 */

/*ARGSUSED*/
int
sa_show(sa_handle_t handle, int flags, int argc, char *argv[])
{
	sa_group_t group;
	int verbose = 0;
	int properties = 0;
	int c;
	int ret = SA_OK;
	char *protocol = NULL;
	int xml = 0;
	xmlDocPtr doc;

	while ((c = getopt(argc, argv, "?hvP:px")) !=	EOF) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		case 'p':
			properties++;
			break;
		case 'P':
			protocol = optarg;
			if (!sa_valid_protocol(protocol)) {
				(void) printf(gettext(
				    "Invalid protocol specified: %s\n"),
				    protocol);
				return (SA_INVALID_PROTOCOL);
			}
			break;
		case 'x':
			xml++;
			break;
		default:
		case 'h':
		case '?':
			(void) printf(gettext("usage: %s\n"),
			    sa_get_usage(USAGE_SHOW));
			return (0);
		}
	}

	if (xml) {
		doc = show_group_xml_init();
		if (doc == NULL)
			ret = SA_NO_MEMORY;
	}

	if (optind == argc) {
		/* No group specified so go through them all */
		for (group = sa_get_group(handle, NULL);
		    group != NULL;
		    group = sa_get_next_group(group)) {
			/*
			 * Have a group so check if one we want and then list
			 * contents with appropriate options.
			 */
			if (xml)
				show_group_xml(doc, group);
			else
				show_group(group, verbose, properties, protocol,
				    NULL);
		}
	} else {
		/* Have a specified list of groups */
		for (; optind < argc; optind++) {
			group = sa_get_group(handle, argv[optind]);
			if (group != NULL) {
				if (xml)
					show_group_xml(doc, group);
				else
					show_group(group, verbose, properties,
					    protocol, NULL);
			} else {
				(void) printf(gettext("%s: not found\n"),
				    argv[optind]);
				ret = SA_NO_SUCH_GROUP;
			}
		}
	}
	if (xml && ret == SA_OK) {
		xmlDocFormatDump(stdout, doc, 1);
		xmlFreeDoc(doc);
	}
	return (ret);

}

/*
 * enable_share(group, share, update_legacy)
 *
 * helper function to enable a share if the group is enabled.
 */

static int
enable_share(sa_handle_t handle, sa_group_t group, sa_share_t share,
		int update_legacy)
{
	char *value;
	int enabled;
	sa_optionset_t optionset;
	int ret = SA_OK;
	char *zfs = NULL;
	int iszfs = 0;

	/*
	 * need to enable this share if the group is enabled but not
	 * otherwise. The enable is also done on each protocol
	 * represented in the group.
	 */
	value = sa_get_group_attr(group, "state");
	enabled = value != NULL && strcmp(value, "enabled") == 0;
	if (value != NULL)
		sa_free_attr_string(value);
	/* remove legacy config if necessary */
	if (update_legacy)
		ret = sa_delete_legacy(share);
	zfs = sa_get_group_attr(group, "zfs");
	if (zfs != NULL) {
		iszfs++;
		sa_free_attr_string(zfs);
	}

	/*
	 * Step through each optionset at the group level and
	 * enable the share based on the protocol type. This
	 * works because protocols must be set on the group
	 * for the protocol to be enabled.
	 */
	for (optionset = sa_get_optionset(group, NULL);
	    optionset != NULL && ret == SA_OK;
	    optionset = sa_get_next_optionset(optionset)) {
		value = sa_get_optionset_attr(optionset, "type");
		if (value != NULL) {
			if (enabled)
				ret = sa_enable_share(share, value);
			if (update_legacy && !iszfs)
				(void) sa_update_legacy(share, value);
			sa_free_attr_string(value);
		}
	}
	if (ret == SA_OK)
		(void) sa_update_config(handle);
	return (ret);
}

/*
 * sa_addshare(flags, argc, argv)
 *
 * implements add-share subcommand.
 */

int
sa_addshare(sa_handle_t handle, int flags, int argc, char *argv[])
{
	int verbose = 0;
	int dryrun = 0;
	int c;
	int ret = SA_OK;
	sa_group_t group;
	sa_share_t share;
	char *sharepath = NULL;
	char *description = NULL;
	char *resource = NULL;
	int persist = SA_SHARE_PERMANENT; /* default to persist */
	int auth;
	char dir[MAXPATHLEN];

	while ((c = getopt(argc, argv, "?hvns:d:r:t")) != EOF) {
		switch (c) {
		case 'n':
			dryrun++;
			break;
		case 'v':
			verbose++;
			break;
		case 'd':
			description = optarg;
			break;
		case 'r':
			resource = optarg;
			break;
		case 's':
			/*
			 * Save share path into group. Currently limit
			 * to one share per command.
			 */
			if (sharepath != NULL) {
				(void) printf(gettext(
				    "Adding multiple shares not supported\n"));
				return (1);
			}
			sharepath = optarg;
			break;
		case 't':
			persist = SA_SHARE_TRANSIENT;
			break;
		default:
		case 'h':
		case '?':
			(void) printf(gettext("usage: %s\n"),
			    sa_get_usage(USAGE_ADD_SHARE));
			return (0);
		}
	}

	if (optind >= argc) {
		(void) printf(gettext("usage: %s\n"),
		    sa_get_usage(USAGE_ADD_SHARE));
		if (dryrun || sharepath != NULL || description != NULL ||
		    resource != NULL || verbose || persist) {
			(void) printf(gettext("\tgroup must be specified\n"));
			ret = SA_NO_SUCH_GROUP;
		} else {
			ret = SA_OK;
		}
	} else {
		if (sharepath == NULL) {
			(void) printf(gettext("usage: %s\n"),
			    sa_get_usage(USAGE_ADD_SHARE));
			(void) printf(gettext(
			    "\t-s sharepath must be specified\n"));
			return (SA_BAD_PATH);
		}
		if (realpath(sharepath, dir) == NULL) {
			(void) printf(gettext(
			    "Path is not valid: %s\n"), sharepath);
			return (SA_BAD_PATH);
		} else {
			sharepath = dir;
		}

		/* Check for valid syntax */
		if (resource != NULL && strpbrk(resource, " \t/") != NULL) {
			(void) printf(gettext("usage: %s\n"),
			    sa_get_usage(USAGE_ADD_SHARE));
			(void) printf(gettext(
			    "\tresource must not contain white"
			    "space or '/' characters\n"));
			return (SA_BAD_PATH);
		}
		group = sa_get_group(handle, argv[optind]);
		if (group == NULL) {
			(void) printf(gettext("Group \"%s\" not found\n"),
			    argv[optind]);
			return (SA_NO_SUCH_GROUP);
		}
		auth = check_authorizations(argv[optind],  flags);
		share = sa_find_share(handle, sharepath);
		if (share != NULL) {
			group = sa_get_parent_group(share);
			if (group != NULL) {
				char *groupname;
				groupname = sa_get_group_attr(
				    group, "name");
				if (groupname != NULL) {
					(void) printf(gettext(
					    "Share path already "
					    "shared in group "
					    "\"%s\": %s\n"),
					    groupname, sharepath);
					sa_free_attr_string(groupname);
				} else {
					(void) printf(gettext(
					    "Share path already"
					    "shared: %s\n"),
					    groupname, sharepath);
				}
			} else {
				(void) printf(gettext(
				    "Share path %s already shared\n"),
				    sharepath);
			}
			return (SA_DUPLICATE_NAME);
		} else {
			/*
			 * Need to check that resource name is
			 * unique at some point. Path checking
			 * should use the "normal" rules which
			 * don't check the repository.
			 */
			if (dryrun)
				ret = sa_check_path(group, sharepath,
				    SA_CHECK_NORMAL);
			else
				share = sa_add_share(group, sharepath,
				    persist, &ret);
			if (!dryrun && share == NULL) {
				(void) printf(gettext(
				    "Could not add share: %s\n"),
				    sa_errorstr(ret));
			} else {
				if (!dryrun && ret == SA_OK) {
					if (resource != NULL &&
					    strpbrk(resource, " \t/") == NULL) {
						ret = sa_set_share_attr(share,
						    "resource", resource);
					}
					if (ret == SA_OK &&
					    description != NULL) {
						ret = sa_set_share_description(
						    share, description);
					}
					if (ret == SA_OK) {
						/* Now enable the share(s) */
						ret = enable_share(handle,
						    group, share, 1);
						ret = sa_update_config(handle);
					}
					switch (ret) {
					case SA_DUPLICATE_NAME:
						(void) printf(gettext(
						    "Resource name in"
						    "use: %s\n"), resource);
						break;
					default:
						(void) printf(
						    gettext("Could not set "
						    "attribute: %s\n"),
						    sa_errorstr(ret));
						break;
					case SA_OK:
						break;
					}
				} else if (dryrun && ret == SA_OK && !auth &&
				    verbose) {
					(void) printf(gettext(
					    "Command would fail: %s\n"),
					    sa_errorstr(SA_NO_PERMISSION));
					ret = SA_NO_PERMISSION;
				}
			}
		}
	}
	return (ret);
}

/*
 * sa_moveshare(flags, argc, argv)
 *
 * implements move-share subcommand.
 */

int
sa_moveshare(sa_handle_t handle, int flags, int argc, char *argv[])
{
	int verbose = 0;
	int dryrun = 0;
	int c;
	int ret = SA_OK;
	sa_group_t group;
	sa_share_t share;
	char *sharepath = NULL;
	int authsrc = 0, authdst = 0;

	while ((c = getopt(argc, argv, "?hvns:")) != EOF) {
		switch (c) {
		case 'n':
			dryrun++;
			break;
		case 'v':
			verbose++;
			break;
		case 's':
			/*
			 * Remove share path from group. Currently limit
			 * to one share per command.
			 */
			if (sharepath != NULL) {
				(void) printf(gettext("Moving multiple shares"
				    "not supported\n"));
				return (SA_BAD_PATH);
			}
			sharepath = optarg;
			break;
		default:
		case 'h':
		case '?':
			(void) printf(gettext("usage: %s\n"),
			    sa_get_usage(USAGE_MOVE_SHARE));
			return (0);
		}
	}

	if (optind >= argc || sharepath == NULL) {
			(void) printf(gettext("usage: %s\n"),
			    sa_get_usage(USAGE_MOVE_SHARE));
			if (dryrun || verbose || sharepath != NULL) {
				(void) printf(gettext(
				    "\tgroup must be specified\n"));
				ret = SA_NO_SUCH_GROUP;
			} else {
				if (sharepath == NULL) {
					ret = SA_SYNTAX_ERR;
					(void) printf(gettext(
					    "\tsharepath must be specified\n"));
				} else {
					ret = SA_OK;
				}
			}
	} else {
		sa_group_t parent;
		char *zfsold;
		char *zfsnew;

		if (sharepath == NULL) {
			(void) printf(gettext(
			    "sharepath must be specified with the -s "
			    "option\n"));
			return (SA_BAD_PATH);
		}
		group = sa_get_group(handle, argv[optind]);
		if (group == NULL) {
			(void) printf(gettext("Group \"%s\" not found\n"),
			    argv[optind]);
			return (SA_NO_SUCH_GROUP);
		}
		share = sa_find_share(handle, sharepath);
		authdst = check_authorizations(argv[optind], flags);
		if (share == NULL) {
			(void) printf(gettext("Share not found: %s\n"),
			    sharepath);
			return (SA_NO_SUCH_PATH);
		}

		parent = sa_get_parent_group(share);
		if (parent != NULL) {
			char *pname;
			pname = sa_get_group_attr(parent, "name");
			if (pname != NULL) {
				authsrc = check_authorizations(pname, flags);
				sa_free_attr_string(pname);
			}
			zfsold = sa_get_group_attr(parent, "zfs");
			zfsnew = sa_get_group_attr(group, "zfs");
			if ((zfsold != NULL && zfsnew == NULL) ||
			    (zfsold == NULL && zfsnew != NULL)) {
				ret = SA_NOT_ALLOWED;
			}
			if (zfsold != NULL)
				sa_free_attr_string(zfsold);
			if (zfsnew != NULL)
				sa_free_attr_string(zfsnew);
		}
		if (!dryrun && ret == SA_OK)
			ret = sa_move_share(group, share);

		if (ret == SA_OK && parent != group && !dryrun) {
			char *oldstate;
			ret = sa_update_config(handle);
			/*
			 * Note that the share may need to be
			 * "unshared" if the new group is
			 * disabled and the old was enabled or
			 * it may need to be share to update
			 * if the new group is enabled.
			 */
			oldstate = sa_get_group_attr(parent, "state");

			/* enable_share determines what to do */
			if (strcmp(oldstate, "enabled") == 0) {
				(void) sa_disable_share(share, NULL);
			}
			(void) enable_share(handle, group, share, 1);
			if (oldstate != NULL)
				sa_free_attr_string(oldstate);
		}

		if (ret != SA_OK)
			(void) printf(gettext("Could not move share: %s\n"),
			    sa_errorstr(ret));

		if (dryrun && ret == SA_OK && !(authsrc & authdst) &&
		    verbose) {
			(void) printf(gettext("Command would fail: %s\n"),
			    sa_errorstr(SA_NO_PERMISSION));
		}
	}
	return (ret);
}

/*
 * sa_removeshare(flags, argc, argv)
 *
 * implements remove-share subcommand.
 */

int
sa_removeshare(sa_handle_t handle, int flags, int argc, char *argv[])
{
	int verbose = 0;
	int dryrun = 0;
	int force = 0;
	int c;
	int ret = SA_OK;
	sa_group_t group;
	sa_share_t share;
	char *sharepath = NULL;
	char dir[MAXPATHLEN];
	int auth;

	while ((c = getopt(argc, argv, "?hfns:v")) != EOF) {
		switch (c) {
		case 'n':
			dryrun++;
			break;
		case 'v':
			verbose++;
			break;
		case 'f':
			force++;
			break;
		case 's':
			/*
			 * Remove share path from group. Currently limit
			 * to one share per command.
			 */
			if (sharepath != NULL) {
				(void) printf(gettext(
				    "Removing multiple shares not "
				    "supported\n"));
				return (SA_SYNTAX_ERR);
			}
			sharepath = optarg;
			break;
		default:
		case 'h':
		case '?':
			(void) printf(gettext("usage: %s\n"),
			    sa_get_usage(USAGE_REMOVE_SHARE));
			return (0);
		}
	}

	if (optind >= argc || sharepath == NULL) {
		if (sharepath == NULL) {
			(void) printf(gettext("usage: %s\n"),
			    sa_get_usage(USAGE_REMOVE_SHARE));
			(void) printf(gettext(
			    "\t-s sharepath must be specified\n"));
			ret = SA_BAD_PATH;
		} else {
			ret = SA_OK;
		}
	}
	if (ret != SA_OK) {
		return (ret);
	}

	if (optind < argc) {
		if ((optind + 1) < argc) {
			(void) printf(gettext("Extraneous group(s) at end of "
			    "command\n"));
			ret = SA_SYNTAX_ERR;
		} else {
			group = sa_get_group(handle, argv[optind]);
			if (group == NULL) {
				(void) printf(gettext(
				    "Group \"%s\" not found\n"), argv[optind]);
				ret = SA_NO_SUCH_GROUP;
			}
		}
	} else {
		group = NULL;
	}

	/*
	 * Lookup the path in the internal configuration. Care
	 * must be taken to handle the case where the
	 * underlying path has been removed since we need to
	 * be able to deal with that as well.
	 */
	if (ret == SA_OK) {
		if (group != NULL)
			share = sa_get_share(group, sharepath);
		else
			share = sa_find_share(handle, sharepath);
		/*
		 * If we didn't find the share with the provided path,
		 * it may be a symlink so attempt to resolve it using
		 * realpath and try again. Realpath will resolve any
		 * symlinks and place them in "dir". Note that
		 * sharepath is only used for the lookup the first
		 * time and later for error messages. dir will be used
		 * on the second attempt. Once a share is found, all
		 * operations are based off of the share variable.
		 */
		if (share == NULL) {
			if (realpath(sharepath, dir) == NULL) {
				ret = SA_BAD_PATH;
				(void) printf(gettext(
				    "Path is not valid: %s\n"), sharepath);
			} else {
				if (group != NULL)
					share = sa_get_share(group, dir);
				else
					share = sa_find_share(handle, dir);
			}
		}
	}

	/*
	 * If there hasn't been an error, there was likely a
	 * path found. If not, give the appropriate error
	 * message and set the return error. If it was found,
	 * then disable the share and then remove it from the
	 * configuration.
	 */
	if (ret != SA_OK) {
		return (ret);
	}
	if (share == NULL) {
		if (group != NULL)
			(void) printf(gettext("Share not found in group %s:"
			    " %s\n"), argv[optind], sharepath);
		else
			(void) printf(gettext("Share not found: %s\n"),
			    sharepath);
			ret = SA_NO_SUCH_PATH;
	} else {
		if (group == NULL)
			group = sa_get_parent_group(share);
		if (!dryrun) {
			if (ret == SA_OK) {
				ret = sa_disable_share(share, NULL);
				/*
				 * We don't care if it fails since it
				 * could be disabled already. Some
				 * unexpected errors could occur that
				 * prevent removal, so also check for
				 * force being set.
				 */
				if (ret == SA_OK || ret == SA_NO_SUCH_PATH ||
				    ret == SA_NOT_SUPPORTED ||
				    ret == SA_SYSTEM_ERR || force) {
					ret = sa_remove_share(share);
				}
				if (ret == SA_OK)
					ret = sa_update_config(handle);
			}
			if (ret != SA_OK)
				(void) printf(gettext(
				    "Could not remove share: %s\n"),
				    sa_errorstr(ret));

		} else if (ret == SA_OK) {
			char *pname;
			pname = sa_get_group_attr(group, "name");
			if (pname != NULL) {
				auth = check_authorizations(pname, flags);
				sa_free_attr_string(pname);
			}
			if (!auth && verbose) {
				(void) printf(gettext(
				    "Command would fail: %s\n"),
				    sa_errorstr(SA_NO_PERMISSION));
			}
		}
	}
	return (ret);
}

/*
 * sa_set_share(flags, argc, argv)
 *
 * implements set-share subcommand.
 */

int
sa_set_share(sa_handle_t handle, int flags, int argc, char *argv[])
{
	int dryrun = 0;
	int c;
	int ret = SA_OK;
	sa_group_t group, sharegroup;
	sa_share_t share;
	char *sharepath = NULL;
	char *description = NULL;
	char *resource = NULL;
	int auth;
	int verbose = 0;
	char *groupname;

	while ((c = getopt(argc, argv, "?hnd:r:s:")) != EOF) {
		switch (c) {
		case 'n':
			dryrun++;
			break;
		case 'd':
			description = optarg;
			break;
		case 'r':
			resource = optarg;
			break;
		case 'v':
			verbose++;
			break;
		case 's':
			/*
			 * Save share path into group. Currently limit
			 * to one share per command.
			 */
			if (sharepath != NULL) {
				(void) printf(gettext(
				    "Updating multiple shares not "
				    "supported\n"));
				return (SA_BAD_PATH);
			}
			sharepath = optarg;
			break;
		default:
		case 'h':
		case '?':
			(void) printf(gettext("usage: %s\n"),
			    sa_get_usage(USAGE_SET_SHARE));
			return (SA_OK);
		}
	}

	if (optind >= argc || sharepath == NULL) {
		if (sharepath == NULL) {
			(void) printf(gettext("usage: %s\n"),
			    sa_get_usage(USAGE_SET_SHARE));
			(void) printf(gettext("\tgroup must be specified\n"));
			ret = SA_BAD_PATH;
		} else {
			ret = SA_OK;
		}
	}
	if ((optind + 1) < argc) {
		(void) printf(gettext("usage: %s\n"),
		    sa_get_usage(USAGE_SET_SHARE));
		(void) printf(gettext("\tExtraneous group(s) at end\n"));
		ret = SA_SYNTAX_ERR;
	}

	if (ret != SA_OK)
		return (ret);

	if (optind < argc) {
		groupname = argv[optind];
		group = sa_get_group(handle, groupname);
	} else {
		group = NULL;
		groupname = NULL;
	}
	share = sa_find_share(handle, sharepath);
	if (share == NULL) {
		(void) printf(gettext("Share path \"%s\" not found\n"),
		    sharepath);
		return (SA_NO_SUCH_PATH);
	}
	sharegroup = sa_get_parent_group(share);
	if (group != NULL && group != sharegroup) {
		(void) printf(gettext("Group \"%s\" does not contain "
		    "share %s\n"), argv[optind], sharepath);
		ret = SA_BAD_PATH;
	} else {
		int delgroupname = 0;
		if (groupname == NULL) {
			groupname = sa_get_group_attr(sharegroup, "name");
			delgroupname = 1;
		}
		if (groupname != NULL) {
			auth = check_authorizations(groupname, flags);
			if (delgroupname) {
				sa_free_attr_string(groupname);
				groupname = NULL;
			}
		} else {
			ret = SA_NO_MEMORY;
		}
		if (resource != NULL) {
			if (strpbrk(resource, " \t/") == NULL) {
				if (!dryrun) {
					ret = sa_set_share_attr(share,
					    "resource", resource);
				} else {
					sa_share_t resshare;
					resshare = sa_get_resource(sharegroup,
					    resource);
					if (resshare != NULL &&
					    resshare != share)
						ret = SA_DUPLICATE_NAME;
				}
			} else {
				ret = SA_BAD_PATH;
				(void) printf(gettext("Resource must not "
				    "contain white space or '/'\n"));
			}
		}
		if (ret == SA_OK && description != NULL)
			ret = sa_set_share_description(share, description);
	}
	if (!dryrun && ret == SA_OK)
		ret = sa_update_config(handle);

	switch (ret) {
	case SA_DUPLICATE_NAME:
		(void) printf(gettext("Resource name in use: %s\n"), resource);
		break;
	default:
		(void) printf(gettext("Could not set attribute: %s\n"),
		    sa_errorstr(ret));
		break;
	case SA_OK:
		if (dryrun && !auth && verbose)
			(void) printf(gettext("Command would fail: %s\n"),
			    sa_errorstr(SA_NO_PERMISSION));
		break;
	}

	return (ret);
}

/*
 * add_security(group, sectype, optlist, proto, *err)
 *
 * Helper function to add a security option (named optionset) to the
 * group.
 */

static int
add_security(sa_group_t group, char *sectype,
		struct options *optlist, char *proto, int *err)
{
	sa_security_t security;
	int ret = SA_OK;
	int result = 0;

	sectype = sa_proto_space_alias(proto, sectype);
	security = sa_get_security(group, sectype, proto);
	if (security == NULL)
		security = sa_create_security(group, sectype, proto);

	if (sectype != NULL)
		sa_free_attr_string(sectype);

	if (security == NULL)
		return (ret);

	while (optlist != NULL) {
		sa_property_t prop;
		prop = sa_get_property(security, optlist->optname);
		if (prop == NULL) {
			/*
			 * Add the property, but only if it is
			 * a non-NULL or non-zero length value
			 */
			if (optlist->optvalue != NULL) {
				prop = sa_create_property(optlist->optname,
				    optlist->optvalue);
				if (prop != NULL) {
					ret = sa_valid_property(security, proto,
					    prop);
					if (ret != SA_OK) {
						(void) sa_remove_property(prop);
						(void) printf(gettext(
						    "Could not add "
						    "property %s: %s\n"),
						    optlist->optname,
						    sa_errorstr(ret));
					}
					if (ret == SA_OK) {
						ret = sa_add_property(security,
						    prop);
						if (ret != SA_OK) {
							(void) printf(gettext(
							    "Could not add "
							    "property (%s=%s): "
							    "%s\n"),
							    optlist->optname,
							    optlist->optvalue,
							    sa_errorstr(ret));
						} else {
							result = 1;
						}
					}
				}
			}
		} else {
			ret = sa_update_property(prop, optlist->optvalue);
			result = 1; /* should check if really changed */
		}
		optlist = optlist->next;
	}
	/*
	 * When done, properties may have all been removed but
	 * we need to keep the security type itself until
	 * explicitly removed.
	 */
	if (result)
		ret = sa_commit_properties(security, 0);
	*err = ret;
	return (result);
}

/*
 * zfscheck(group, share)
 *
 * For the special case where a share was provided, make sure it is a
 * compatible path for a ZFS property change.  The only path
 * acceptable is the path that defines the zfs sub-group (dataset with
 * the sharenfs property set) and not one of the paths that inherited
 * the NFS properties. Returns SA_OK if it is usable and
 * SA_NOT_ALLOWED if it isn't.
 *
 * If group is not a ZFS group/subgroup, we assume OK since the check
 * on return will catch errors for those cases.  What we are looking
 * for here is that the group is ZFS and the share is not the defining
 * share.  All else is SA_OK.
 */

static int
zfscheck(sa_group_t group, sa_share_t share)
{
	int ret = SA_OK;
	char *attr;

	if (sa_group_is_zfs(group)) {
		/*
		 * The group is a ZFS group.  Does the share represent
		 * the dataset that defined the group? It is only OK
		 * if the attribute "subgroup" exists on the share and
		 * has a value of "true".
		 */

		ret = SA_NOT_ALLOWED;
		attr = sa_get_share_attr(share, "subgroup");
		if (attr != NULL) {
			if (strcmp(attr, "true") == 0)
				ret = SA_OK;
			sa_free_attr_string(attr);
		}
	}
	return (ret);
}

/*
 * basic_set(groupname, optlist, protocol, sharepath, dryrun)
 *
 * This function implements "set" when a name space (-S) is not
 * specified. It is a basic set. Options and other CLI parsing has
 * already been done.
 */

static int
basic_set(sa_handle_t handle, char *groupname, struct options *optlist,
		char *protocol,	char *sharepath, int dryrun)
{
	sa_group_t group;
	int ret = SA_OK;
	int change = 0;
	struct list *worklist = NULL;

	group = sa_get_group(handle, groupname);
	if (group != NULL) {
		sa_share_t share = NULL;
		if (sharepath != NULL) {
			share = sa_get_share(group, sharepath);
			if (share == NULL) {
				(void) printf(gettext(
				    "Share does not exist in group %s\n"),
				    groupname, sharepath);
				ret = SA_NO_SUCH_PATH;
			} else {
				/* if ZFS and OK, then only group */
				ret = zfscheck(group, share);
				if (ret == SA_OK &&
				    sa_group_is_zfs(group))
					share = NULL;
				if (ret == SA_NOT_ALLOWED)
					(void) printf(gettext(
					    "Properties on ZFS group shares "
					    "not supported: %s\n"), sharepath);
			}
		}
		if (ret == SA_OK) {
			/* group must exist */
			ret = valid_options(optlist, protocol,
			    share == NULL ? group : share, NULL);
			if (ret == SA_OK && !dryrun) {
				if (share != NULL)
					change |= add_optionset(share, optlist,
					    protocol, &ret);
				else
					change |= add_optionset(group, optlist,
					    protocol, &ret);
				if (ret == SA_OK && change)
					worklist = add_list(worklist, group,
					    share);
			}
		}
		free_opt(optlist);
	} else {
		(void) printf(gettext("Group \"%s\" not found\n"), groupname);
		ret = SA_NO_SUCH_GROUP;
	}
	/*
	 * we have a group and potentially legal additions
	 */

	/*
	 * Commit to configuration if not a dryrunp and properties
	 * have changed.
	 */
	if (!dryrun && ret == SA_OK && change && worklist != NULL)
		/* properties changed, so update all shares */
		(void) enable_all_groups(handle, worklist, 0, 0, protocol);

	if (worklist != NULL)
		free_list(worklist);
	return (ret);
}

/*
 * space_set(groupname, optlist, protocol, sharepath, dryrun)
 *
 * This function implements "set" when a name space (-S) is
 * specified. It is a namespace set. Options and other CLI parsing has
 * already been done.
 */

static int
space_set(sa_handle_t handle, char *groupname, struct options *optlist,
		char *protocol,	char *sharepath, int dryrun, char *sectype)
{
	sa_group_t group;
	int ret = SA_OK;
	int change = 0;
	struct list *worklist = NULL;

	/*
	 * make sure protcol and sectype are valid
	 */

	if (sa_proto_valid_space(protocol, sectype) == 0) {
		(void) printf(gettext("Option space \"%s\" not valid "
		    "for protocol.\n"), sectype);
		return (SA_INVALID_SECURITY);
	}

	group = sa_get_group(handle, groupname);
	if (group != NULL) {
		sa_share_t share = NULL;
		if (sharepath != NULL) {
			share = sa_get_share(group, sharepath);
			if (share == NULL) {
				(void) printf(gettext(
				    "Share does not exist in group %s\n"),
				    groupname, sharepath);
				ret = SA_NO_SUCH_PATH;
			} else {
				/* if ZFS and OK, then only group */
				ret = zfscheck(group, share);
				if (ret == SA_OK &&
				    sa_group_is_zfs(group))
					share = NULL;
				if (ret == SA_NOT_ALLOWED)
					(void) printf(gettext(
					    "Properties on ZFS group shares "
					    "not supported: %s\n"), sharepath);
			}
		}
		if (ret == SA_OK) {
			/* group must exist */
			ret = valid_options(optlist, protocol,
			    share == NULL ? group : share, sectype);
			if (ret == SA_OK && !dryrun) {
				if (share != NULL)
					change = add_security(share, sectype,
					    optlist, protocol, &ret);
				else
					change = add_security(group, sectype,
					    optlist, protocol, &ret);
				if (ret != SA_OK)
					(void) printf(gettext(
					    "Could not set property: %s\n"),
					    sa_errorstr(ret));
			}
			if (ret == SA_OK && change)
				worklist = add_list(worklist, group, share);
		}
		free_opt(optlist);
	} else {
		(void) printf(gettext("Group \"%s\" not found\n"), groupname);
		ret = SA_NO_SUCH_GROUP;
	}
	/*
	 * we have a group and potentially legal additions
	 */

	/* Commit to configuration if not a dryrun */
	if (!dryrun && ret == 0) {
		if (change && worklist != NULL) {
			/* properties changed, so update all shares */
			(void) enable_all_groups(handle, worklist, 0, 0,
			    protocol);
		}
		ret = sa_update_config(handle);
	}
	if (worklist != NULL)
		free_list(worklist);
	return (ret);
}

/*
 * sa_set(flags, argc, argv)
 *
 * Implements the set subcommand. It keys off of -S to determine which
 * set of operations to actually do.
 */

int
sa_set(sa_handle_t handle, int flags, int argc, char *argv[])
{
	char *groupname;
	int verbose = 0;
	int dryrun = 0;
	int c;
	char *protocol = NULL;
	int ret = SA_OK;
	struct options *optlist = NULL;
	char *sharepath = NULL;
	char *optset = NULL;
	int auth;

	while ((c = getopt(argc, argv, "?hvnP:p:s:S:")) != EOF) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		case 'n':
			dryrun++;
			break;
		case 'P':
			protocol = optarg;
			if (!sa_valid_protocol(protocol)) {
				(void) printf(gettext(
				    "Invalid protocol specified: %s\n"),
				    protocol);
				return (SA_INVALID_PROTOCOL);
			}
			break;
		case 'p':
			ret = add_opt(&optlist, optarg, 0);
			switch (ret) {
			case OPT_ADD_SYNTAX:
				(void) printf(gettext("Property syntax error:"
				    " %s\n"), optarg);
				return (SA_SYNTAX_ERR);
			case OPT_ADD_MEMORY:
				(void) printf(gettext("No memory to set "
				    "property: %s\n"), optarg);
				return (SA_NO_MEMORY);
			default:
				break;
			}
			break;
		case 's':
			sharepath = optarg;
			break;
		case 'S':
			optset = optarg;
			break;
		default:
		case 'h':
		case '?':
			(void) printf(gettext("usage: %s\n"),
			    sa_get_usage(USAGE_SET));
			return (SA_OK);
		}
	}

	if (optlist != NULL)
		ret = chk_opt(optlist, optset != NULL, protocol);

	if (optind >= argc || (optlist == NULL && optset == NULL) ||
	    protocol == NULL || ret != OPT_ADD_OK) {
		char *sep = "\t";

		(void) printf(gettext("usage: %s\n"), sa_get_usage(USAGE_SET));
		if (optind >= argc) {
			(void) printf(gettext("%sgroup must be specified"),
			    sep);
			sep = ", ";
		}
		if (optlist == NULL) {
			(void) printf(gettext("%sat least one property must be"
			    " specified"), sep);
			sep = ", ";
		}
		if (protocol == NULL) {
			(void) printf(gettext("%sprotocol must be specified"),
			    sep);
			sep = ", ";
		}
		(void) printf("\n");
		ret = SA_SYNTAX_ERR;
	} else {
		/*
		 * Group already exists so we can proceed after a few
		 * additional checks related to ZFS handling.
		 */

		groupname = argv[optind];
		if (strcmp(groupname, "zfs") == 0) {
			(void) printf(gettext("Changing properties for group "
			    "\"zfs\" not allowed\n"));
			return (SA_NOT_ALLOWED);
		}

		auth = check_authorizations(groupname, flags);
		if (optset == NULL)
			ret = basic_set(handle, groupname, optlist, protocol,
			    sharepath, dryrun);
		else
			ret = space_set(handle, groupname, optlist, protocol,
			    sharepath, dryrun, optset);
		if (dryrun && ret == SA_OK && !auth && verbose) {
			(void) printf(gettext("Command would fail: %s\n"),
			    sa_errorstr(SA_NO_PERMISSION));
		}
	}
	return (ret);
}

/*
 * remove_options(group, optlist, proto, *err)
 *
 * Helper function to actually remove options from a group after all
 * preprocessing is done.
 */

static int
remove_options(sa_group_t group, struct options *optlist,
		char *proto, int *err)
{
	struct options *cur;
	sa_optionset_t optionset;
	sa_property_t prop;
	int change = 0;
	int ret = SA_OK;

	optionset = sa_get_optionset(group, proto);
	if (optionset != NULL) {
		for (cur = optlist; cur != NULL; cur = cur->next) {
			prop = sa_get_property(optionset, cur->optname);
			if (prop != NULL) {
				ret = sa_remove_property(prop);
				if (ret != SA_OK)
					break;
				change = 1;
			}
		}
	}
	if (ret == SA_OK && change)
		ret = sa_commit_properties(optionset, 0);

	if (err != NULL)
		*err = ret;
	return (change);
}

/*
 * valid_unset(group, optlist, proto)
 *
 * Sanity check the optlist to make sure they can be removed. Issue an
 * error if a property doesn't exist.
 */

static int
valid_unset(sa_group_t group, struct options *optlist, char *proto)
{
	struct options *cur;
	sa_optionset_t optionset;
	sa_property_t prop;
	int ret = SA_OK;

	optionset = sa_get_optionset(group, proto);
	if (optionset != NULL) {
		for (cur = optlist; cur != NULL; cur = cur->next) {
			prop = sa_get_property(optionset, cur->optname);
			if (prop == NULL) {
				(void) printf(gettext(
				    "Could not unset property %s: not set\n"),
				    cur->optname);
				ret = SA_NO_SUCH_PROP;
			}
		}
	}
	return (ret);
}

/*
 * valid_unset_security(group, optlist, proto)
 *
 * Sanity check the optlist to make sure they can be removed. Issue an
 * error if a property doesn't exist.
 */

static int
valid_unset_security(sa_group_t group, struct options *optlist, char *proto,
	    char *sectype)
{
	struct options *cur;
	sa_security_t security;
	sa_property_t prop;
	int ret = SA_OK;
	char *sec;

	sec = sa_proto_space_alias(proto, sectype);
	security = sa_get_security(group, sec, proto);
	if (security != NULL) {
		for (cur = optlist; cur != NULL; cur = cur->next) {
			prop = sa_get_property(security, cur->optname);
			if (prop == NULL) {
				(void) printf(gettext(
				    "Could not unset property %s: not set\n"),
				    cur->optname);
				ret = SA_NO_SUCH_PROP;
			}
		}
	} else {
		(void) printf(gettext(
		    "Could not unset %s: space not defined\n"), sectype);
		ret = SA_NO_SUCH_SECURITY;
	}
	if (sec != NULL)
		sa_free_attr_string(sec);
	return (ret);
}

/*
 * remove_security(group, optlist, proto)
 *
 * Remove the properties since they were checked as valid.
 */

static int
remove_security(sa_group_t group, char *sectype,
		struct options *optlist, char *proto, int *err)
{
	sa_security_t security;
	int ret = SA_OK;
	int change = 0;

	sectype = sa_proto_space_alias(proto, sectype);
	security = sa_get_security(group, sectype, proto);
	if (sectype != NULL)
		sa_free_attr_string(sectype);

	if (security != NULL) {
		while (optlist != NULL) {
			sa_property_t prop;
			prop = sa_get_property(security, optlist->optname);
			if (prop != NULL) {
				ret = sa_remove_property(prop);
				if (ret != SA_OK)
					break;
				change = 1;
			}
			optlist = optlist->next;
		}
		/*
		 * when done, properties may have all been removed but
		 * we need to keep the security type itself until
		 * explicitly removed.
		 */
		if (ret == SA_OK && change)
			ret = sa_commit_properties(security, 0);
	} else {
		ret = SA_NO_SUCH_PROP;
	}
	if (err != NULL)
		*err = ret;
	return (change);
}

/*
 * basic_unset(groupname, optlist, protocol, sharepath, dryrun)
 *
 * Unset non-named optionset properties.
 */

static int
basic_unset(sa_handle_t handle, char *groupname, struct options *optlist,
		char *protocol,	char *sharepath, int dryrun)
{
	sa_group_t group;
	int ret = SA_OK;
	int change = 0;
	struct list *worklist = NULL;
	sa_share_t share = NULL;

	group = sa_get_group(handle, groupname);
	if (group == NULL)
		return (ret);

	if (sharepath != NULL) {
		share = sa_get_share(group, sharepath);
		if (share == NULL) {
			(void) printf(gettext(
			    "Share does not exist in group %s\n"),
			    groupname, sharepath);
			ret = SA_NO_SUCH_PATH;
		}
	}
	if (ret == SA_OK) {
		/* group must exist */
		ret = valid_unset(share != NULL ? share : group,
		    optlist, protocol);
		if (ret == SA_OK && !dryrun) {
			if (share != NULL) {
				sa_optionset_t optionset;
				sa_property_t prop;
				change |= remove_options(share, optlist,
				    protocol, &ret);
				/*
				 * If a share optionset is
				 * empty, remove it.
				 */
				optionset = sa_get_optionset((sa_share_t)share,
				    protocol);
				if (optionset != NULL) {
					prop = sa_get_property(optionset, NULL);
					if (prop == NULL)
						(void) sa_destroy_optionset(
						    optionset);
				}
			} else {
				change |= remove_options(group,
				    optlist, protocol, &ret);
			}
			if (ret == SA_OK && change)
				worklist = add_list(worklist, group,
				    share);
			if (ret != SA_OK)
				(void) printf(gettext(
				    "Could not remove properties: "
				    "%s\n"), sa_errorstr(ret));
		}
	} else {
		(void) printf(gettext("Group \"%s\" not found\n"),
		    groupname);
		ret = SA_NO_SUCH_GROUP;
	}
	free_opt(optlist);

	/*
	 * We have a group and potentially legal additions
	 *
	 * Commit to configuration if not a dryrun
	 */
	if (!dryrun && ret == SA_OK) {
		if (change && worklist != NULL) {
			/* properties changed, so update all shares */
			(void) enable_all_groups(handle, worklist, 0, 0,
			    protocol);
		}
	}
	if (worklist != NULL)
		free_list(worklist);
	return (ret);
}

/*
 * space_unset(groupname, optlist, protocol, sharepath, dryrun)
 *
 * Unset named optionset properties.
 */
static int
space_unset(sa_handle_t handle, char *groupname, struct options *optlist,
		char *protocol, char *sharepath, int dryrun, char *sectype)
{
	sa_group_t group;
	int ret = SA_OK;
	int change = 0;
	struct list *worklist = NULL;
	sa_share_t share = NULL;

	group = sa_get_group(handle, groupname);
	if (group == NULL) {
		(void) printf(gettext("Group \"%s\" not found\n"), groupname);
		return (SA_NO_SUCH_GROUP);
	}
	if (sharepath != NULL) {
		share = sa_get_share(group, sharepath);
		if (share == NULL) {
			(void) printf(gettext(
			    "Share does not exist in group %s\n"),
			    groupname, sharepath);
			return (SA_NO_SUCH_PATH);
		}
	}
	ret = valid_unset_security(share != NULL ? share : group, optlist,
	    protocol, sectype);

	if (ret == SA_OK && !dryrun) {
		if (optlist != NULL) {
			if (share != NULL) {
				sa_security_t optionset;
				sa_property_t prop;
				change = remove_security(share,
				    sectype, optlist, protocol, &ret);

				/* If a share security is empty, remove it */
				optionset = sa_get_security((sa_group_t)share,
				    sectype, protocol);
				if (optionset != NULL) {
					prop = sa_get_property(optionset,
					    NULL);
					if (prop == NULL)
						ret = sa_destroy_security(
						    optionset);
				}
			} else {
				change = remove_security(group, sectype,
				    optlist, protocol, &ret);
			}
		} else {
			sa_security_t security;
			char *sec;
			sec = sa_proto_space_alias(protocol, sectype);
			security = sa_get_security(group, sec, protocol);
			if (sec != NULL)
				sa_free_attr_string(sec);
			if (security != NULL) {
				ret = sa_destroy_security(security);
				if (ret == SA_OK)
					change = 1;
			} else {
				ret = SA_NO_SUCH_PROP;
			}
		}
		if (ret != SA_OK)
			(void) printf(gettext("Could not unset property: %s\n"),
			    sa_errorstr(ret));
	}

	if (ret == SA_OK && change)
		worklist = add_list(worklist, group, 0);

	free_opt(optlist);
	/*
	 * We have a group and potentially legal additions
	 */

	/* Commit to configuration if not a dryrun */
	if (!dryrun && ret == 0) {
		/* properties changed, so update all shares */
		if (change && worklist != NULL)
			(void) enable_all_groups(handle, worklist, 0, 0,
			    protocol);
		ret = sa_update_config(handle);
	}
	if (worklist != NULL)
		free_list(worklist);
	return (ret);
}

/*
 * sa_unset(flags, argc, argv)
 *
 * Implements the unset subcommand. Parsing done here and then basic
 * or space versions of the real code are called.
 */

int
sa_unset(sa_handle_t handle, int flags, int argc, char *argv[])
{
	char *groupname;
	int verbose = 0;
	int dryrun = 0;
	int c;
	char *protocol = NULL;
	int ret = SA_OK;
	struct options *optlist = NULL;
	char *sharepath = NULL;
	char *optset = NULL;
	int auth;

	while ((c = getopt(argc, argv, "?hvnP:p:s:S:")) != EOF) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		case 'n':
			dryrun++;
			break;
		case 'P':
			protocol = optarg;
			if (!sa_valid_protocol(protocol)) {
				(void) printf(gettext(
				    "Invalid protocol specified: %s\n"),
				    protocol);
				return (SA_INVALID_PROTOCOL);
			}
			break;
		case 'p':
			ret = add_opt(&optlist, optarg, 1);
			switch (ret) {
			case OPT_ADD_SYNTAX:
				(void) printf(gettext("Property syntax error "
				    "for property %s\n"), optarg);
				return (SA_SYNTAX_ERR);

			case OPT_ADD_PROPERTY:
				(void) printf(gettext("Properties need to be "
				    "set with set command: %s\n"), optarg);
				return (SA_SYNTAX_ERR);

			default:
				break;
			}
			break;
		case 's':
			sharepath = optarg;
			break;
		case 'S':
			optset = optarg;
			break;
		default:
		case 'h':
		case '?':
			(void) printf(gettext("usage: %s\n"),
			    sa_get_usage(USAGE_UNSET));
			return (SA_OK);
		}
	}

	if (optlist != NULL)
		ret = chk_opt(optlist, optset != NULL, protocol);

	if (optind >= argc || (optlist == NULL && optset == NULL) ||
	    protocol == NULL) {
		char *sep = "\t";
		(void) printf(gettext("usage: %s\n"),
		    sa_get_usage(USAGE_UNSET));
		if (optind >= argc) {
			(void) printf(gettext("%sgroup must be specified"),
			    sep);
			sep = ", ";
		}
		if (optlist == NULL) {
			(void) printf(gettext("%sat least one property must "
			    "be specified"), sep);
			sep = ", ";
		}
		if (protocol == NULL) {
			(void) printf(gettext("%sprotocol must be specified"),
			    sep);
			sep = ", ";
		}
		(void) printf("\n");
		ret = SA_SYNTAX_ERR;
	} else {

		/*
		 * If a group already exists, we can only add a new
		 * protocol to it and not create a new one or add the
		 * same protocol again.
		 */

		groupname = argv[optind];
		auth = check_authorizations(groupname, flags);
		if (optset == NULL)
			ret = basic_unset(handle, groupname, optlist, protocol,
			    sharepath, dryrun);
		else
			ret = space_unset(handle, groupname, optlist, protocol,
			    sharepath, dryrun, optset);

		if (dryrun && ret == SA_OK && !auth && verbose)
			(void) printf(gettext("Command would fail: %s\n"),
			    sa_errorstr(SA_NO_PERMISSION));
	}
	return (ret);
}

/*
 * sa_enable_group(flags, argc, argv)
 *
 * Implements the enable subcommand
 */

int
sa_enable_group(sa_handle_t handle, int flags, int argc, char *argv[])
{
	int verbose = 0;
	int dryrun = 0;
	int all = 0;
	int c;
	int ret = SA_OK;
	char *protocol = NULL;
	char *state;
	struct list *worklist = NULL;
	int auth = 1;
	sa_group_t group;

	while ((c = getopt(argc, argv, "?havnP:")) != EOF) {
		switch (c) {
		case 'a':
			all = 1;
			break;
		case 'n':
			dryrun++;
			break;
		case 'P':
			protocol = optarg;
			if (!sa_valid_protocol(protocol)) {
				(void) printf(gettext(
				    "Invalid protocol specified: %s\n"),
				    protocol);
				return (SA_INVALID_PROTOCOL);
			}
			break;
		case 'v':
			verbose++;
			break;
		default:
		case 'h':
		case '?':
			(void) printf(gettext("usage: %s\n"),
			    sa_get_usage(USAGE_ENABLE));
			return (0);
		}
	}

	if (optind == argc && !all) {
		(void) printf(gettext("usage: %s\n"),
		    sa_get_usage(USAGE_ENABLE));
		(void) printf(gettext("\tmust specify group\n"));
		return (SA_NO_SUCH_PATH);
	}
	if (!all) {
		while (optind < argc) {
			group = sa_get_group(handle, argv[optind]);
			if (group != NULL) {
				auth &= check_authorizations(argv[optind],
				    flags);
				state = sa_get_group_attr(group, "state");
				if (state != NULL &&
				    strcmp(state, "enabled") == 0) {
					/* already enabled */
					if (verbose)
						(void) printf(gettext(
						    "Group \"%s\" is already "
						    "enabled\n"),
						    argv[optind]);
					ret = SA_BUSY; /* already enabled */
				} else {
					worklist = add_list(worklist, group,
					    0);
					if (verbose)
						(void) printf(gettext(
						    "Enabling group \"%s\"\n"),
						    argv[optind]);
				}
				if (state != NULL)
					sa_free_attr_string(state);
			} else {
				ret = SA_NO_SUCH_GROUP;
			}
			optind++;
		}
	} else {
		for (group = sa_get_group(handle, NULL);
		    group != NULL;
		    group = sa_get_next_group(group)) {
			worklist = add_list(worklist, group, 0);
		}
	}
	if (!dryrun && ret == SA_OK)
		ret = enable_all_groups(handle, worklist, 1, 0, NULL);

	if (ret != SA_OK && ret != SA_BUSY)
		(void) printf(gettext("Could not enable group: %s\n"),
		    sa_errorstr(ret));
	if (ret == SA_BUSY)
		ret = SA_OK;

	if (worklist != NULL)
		free_list(worklist);
	if (dryrun && ret == SA_OK && !auth && verbose) {
		(void) printf(gettext("Command would fail: %s\n"),
		    sa_errorstr(SA_NO_PERMISSION));
	}
	return (ret);
}

/*
 * disable_group(group, setstate)
 *
 * Disable all the shares in the specified group honoring the setstate
 * argument. This is a helper for disable_all_groups in order to
 * simplify regular and subgroup (zfs) disabling. Group has already
 * been checked for non-NULL.
 */

static int
disable_group(sa_group_t group)
{
	sa_share_t share;
	int ret = SA_OK;

	for (share = sa_get_share(group, NULL);
	    share != NULL && ret == SA_OK;
	    share = sa_get_next_share(share)) {
		ret = sa_disable_share(share, NULL);
		if (ret == SA_NO_SUCH_PATH) {
			/*
			 * this is OK since the path is gone. we can't
			 * re-share it anyway so no error.
			 */
			ret = SA_OK;
		}
	}
	return (ret);
}


/*
 * disable_all_groups(work, setstate)
 *
 * helper function that disables the shares in the list of groups
 * provided. It optionally marks the group as disabled. Used by both
 * enable and start subcommands.
 */

static int
disable_all_groups(sa_handle_t handle, struct list *work, int setstate)
{
	int ret = SA_OK;
	sa_group_t subgroup, group;

	while (work != NULL && ret == SA_OK) {
		group = (sa_group_t)work->item;
		if (setstate)
			ret = sa_set_group_attr(group, "state", "disabled");
		if (ret == SA_OK) {
			char *name;
			name = sa_get_group_attr(group, "name");
			if (name != NULL && strcmp(name, "zfs") == 0) {
				/* need to get the sub-groups for stopping */
				for (subgroup = sa_get_sub_group(group);
				    subgroup != NULL;
				    subgroup = sa_get_next_group(subgroup)) {
					ret = disable_group(subgroup);
				}
			} else {
				ret = disable_group(group);
			}
			/*
			 * We don't want to "disable" since it won't come
			 * up after a reboot.  The SMF framework should do
			 * the right thing. On enable we do want to do
			 * something.
			 */
		}
		work = work->next;
	}
	if (ret == SA_OK)
		ret = sa_update_config(handle);
	return (ret);
}

/*
 * sa_disable_group(flags, argc, argv)
 *
 * Implements the disable subcommand
 */

int
sa_disable_group(sa_handle_t handle, int flags, int argc, char *argv[])
{
	int verbose = 0;
	int dryrun = 0;
	int all = 0;
	int c;
	int ret = SA_OK;
	char *protocol;
	char *state;
	struct list *worklist = NULL;
	sa_group_t group;
	int auth = 1;

	while ((c = getopt(argc, argv, "?havn")) != EOF) {
		switch (c) {
		case 'a':
			all = 1;
			break;
		case 'n':
			dryrun++;
			break;
		case 'P':
			protocol = optarg;
			if (!sa_valid_protocol(protocol)) {
				(void) printf(gettext(
				    "Invalid protocol specified: %s\n"),
				    protocol);
				return (SA_INVALID_PROTOCOL);
			}
			break;
		case 'v':
			verbose++;
			break;
		default:
		case 'h':
		case '?':
			(void) printf(gettext("usage: %s\n"),
			    sa_get_usage(USAGE_DISABLE));
			return (0);
		}
	}

	if (optind == argc && !all) {
		(void) printf(gettext("usage: %s\n"),
		    sa_get_usage(USAGE_DISABLE));
		(void) printf(gettext("\tmust specify group\n"));
		return (SA_NO_SUCH_PATH);
	}
	if (!all) {
		while (optind < argc) {
			group = sa_get_group(handle, argv[optind]);
			if (group != NULL) {
				auth &= check_authorizations(argv[optind],
				    flags);
				state = sa_get_group_attr(group, "state");
				if (state == NULL ||
				    strcmp(state, "disabled") == 0) {
					/* already disabled */
					if (verbose)
						(void) printf(gettext(
						    "Group \"%s\" is "
						    "already disabled\n"),
						    argv[optind]);
					ret = SA_BUSY; /* already disable */
				} else {
					worklist = add_list(worklist, group, 0);
					if (verbose)
						(void) printf(gettext(
						    "Disabling group "
						    "\"%s\"\n"), argv[optind]);
				}
				if (state != NULL)
					sa_free_attr_string(state);
			} else {
				ret = SA_NO_SUCH_GROUP;
			}
			optind++;
		}
	} else {
		for (group = sa_get_group(handle, NULL);
		    group != NULL;
		    group = sa_get_next_group(group))
			worklist = add_list(worklist, group, 0);
	}

	if (ret == SA_OK && !dryrun)
		ret = disable_all_groups(handle, worklist, 1);
	if (ret != SA_OK && ret != SA_BUSY)
		(void) printf(gettext("Could not disable group: %s\n"),
		    sa_errorstr(ret));
	if (ret == SA_BUSY)
		ret = SA_OK;
	if (worklist != NULL)
		free_list(worklist);
	if (dryrun && ret == SA_OK && !auth && verbose)
		(void) printf(gettext("Command would fail: %s\n"),
		    sa_errorstr(SA_NO_PERMISSION));
	return (ret);
}

/*
 * sa_start_group(flags, argc, argv)
 *
 * Implements the start command.
 * This is similar to enable except it doesn't change the state
 * of the group(s) and only enables shares if the group is already
 * enabled.
 */
/*ARGSUSED*/
int
sa_start_group(sa_handle_t handle, int flags, int argc, char *argv[])
{
	int verbose = 0;
	int all = 0;
	int c;
	int ret = SMF_EXIT_OK;
	char *protocol = NULL;
	char *state;
	struct list *worklist = NULL;
	sa_group_t group;

	while ((c = getopt(argc, argv, "?havP:")) != EOF) {
		switch (c) {
		case 'a':
			all = 1;
			break;
		case 'P':
			protocol = optarg;
			if (!sa_valid_protocol(protocol)) {
				(void) printf(gettext(
				    "Invalid protocol specified: %s\n"),
				    protocol);
				return (SA_INVALID_PROTOCOL);
			}
			break;
		case 'v':
			verbose++;
			break;
		default:
		case 'h':
		case '?':
			(void) printf(gettext("usage: %s\n"),
			    sa_get_usage(USAGE_START));
			return (SA_OK);
		}
	}

	if (optind == argc && !all) {
		(void) printf(gettext("usage: %s\n"),
		    sa_get_usage(USAGE_START));
		return (SMF_EXIT_ERR_FATAL);
	}

	if (!all) {
		while (optind < argc) {
			group = sa_get_group(handle, argv[optind]);
			if (group != NULL) {
				state = sa_get_group_attr(group, "state");
				if (state == NULL ||
				    strcmp(state, "enabled") == 0) {
					worklist = add_list(worklist, group, 0);
					if (verbose)
						(void) printf(gettext(
						    "Starting group \"%s\"\n"),
						    argv[optind]);
				} else {
					/*
					 * Determine if there are any
					 * protocols.  if there aren't any,
					 * then there isn't anything to do in
					 * any case so no error.
					 */
					if (sa_get_optionset(group,
					    protocol) != NULL) {
						ret = SMF_EXIT_OK;
					}
				}
				if (state != NULL)
					sa_free_attr_string(state);
			}
			optind++;
		}
	} else {
		for (group = sa_get_group(handle, NULL); group != NULL;
		    group = sa_get_next_group(group)) {
			state = sa_get_group_attr(group, "state");
			if (state == NULL || strcmp(state, "enabled") == 0)
				worklist = add_list(worklist, group, 0);
			if (state != NULL)
				sa_free_attr_string(state);
		}
	}

	(void) enable_all_groups(handle, worklist, 0, 1, NULL);

	if (worklist != NULL)
		free_list(worklist);
	return (ret);
}

/*
 * sa_stop_group(flags, argc, argv)
 *
 * Implements the stop command.
 * This is similar to disable except it doesn't change the state
 * of the group(s) and only disables shares if the group is already
 * enabled.
 */
/*ARGSUSED*/
int
sa_stop_group(sa_handle_t handle, int flags, int argc, char *argv[])
{
	int verbose = 0;
	int all = 0;
	int c;
	int ret = SMF_EXIT_OK;
	char *protocol = NULL;
	char *state;
	struct list *worklist = NULL;
	sa_group_t group;

	while ((c = getopt(argc, argv, "?havP:")) != EOF) {
		switch (c) {
		case 'a':
			all = 1;
			break;
		case 'P':
			protocol = optarg;
			if (!sa_valid_protocol(protocol)) {
				(void) printf(gettext(
				    "Invalid protocol specified: %s\n"),
				    protocol);
				return (SA_INVALID_PROTOCOL);
			}
			break;
		case 'v':
			verbose++;
			break;
		default:
		case 'h':
		case '?':
			(void) printf(gettext("usage: %s\n"),
			    sa_get_usage(USAGE_STOP));
			return (0);
		}
	}

	if (optind == argc && !all) {
		(void) printf(gettext("usage: %s\n"),
		    sa_get_usage(USAGE_STOP));
		return (SMF_EXIT_ERR_FATAL);
	} else if (!all) {
		while (optind < argc) {
			group = sa_get_group(handle, argv[optind]);
			if (group != NULL) {
				state = sa_get_group_attr(group, "state");
				if (state == NULL ||
				    strcmp(state, "enabled") == 0) {
					worklist = add_list(worklist, group, 0);
					if (verbose)
						(void) printf(gettext(
						    "Stopping group \"%s\"\n"),
						    argv[optind]);
				} else {
					ret = SMF_EXIT_OK;
				}
				if (state != NULL)
					sa_free_attr_string(state);
			}
			optind++;
		}
	} else {
		for (group = sa_get_group(handle, NULL); group != NULL;
		    group = sa_get_next_group(group)) {
			state = sa_get_group_attr(group, "state");
			if (state == NULL || strcmp(state, "enabled") == 0)
				worklist = add_list(worklist, group, 0);
			if (state != NULL)
				sa_free_attr_string(state);
		}
	}

	(void) disable_all_groups(handle, worklist, 0);
	ret = sa_update_config(handle);

	if (worklist != NULL)
		free_list(worklist);
	return (ret);
}

/*
 * remove_all_options(share, proto)
 *
 * Removes all options on a share.
 */

static void
remove_all_options(sa_share_t share, char *proto)
{
	sa_optionset_t optionset;
	sa_security_t security;
	sa_security_t prevsec = NULL;

	optionset = sa_get_optionset(share, proto);
	if (optionset != NULL)
		(void) sa_destroy_optionset(optionset);
	for (security = sa_get_security(share, NULL, NULL);
	    security != NULL;
	    security = sa_get_next_security(security)) {
		char *type;
		/*
		 * We walk through the list.  prevsec keeps the
		 * previous security so we can delete it without
		 * destroying the list.
		 */
		if (prevsec != NULL) {
			/* remove the previously seen security */
			(void) sa_destroy_security(prevsec);
			/* set to NULL so we don't try multiple times */
			prevsec = NULL;
		}
		type = sa_get_security_attr(security, "type");
		if (type != NULL) {
			/*
			 * if the security matches the specified protocol, we
			 * want to remove it. prevsec holds it until either
			 * the next pass or we fall out of the loop.
			 */
			if (strcmp(type, proto) == 0)
				prevsec = security;
			sa_free_attr_string(type);
		}
	}
	/* in case there is one left */
	if (prevsec != NULL)
		(void) sa_destroy_security(prevsec);
}


/*
 * for legacy support, we need to handle the old syntax. This is what
 * we get if sharemgr is called with the name "share" rather than
 * sharemgr.
 */

static int
format_legacy_path(char *buff, int buffsize, char *proto, char *cmd)
{
	int err;

	err = snprintf(buff, buffsize, "/usr/lib/fs/%s/%s", proto, cmd);
	if (err > buffsize)
		return (-1);
	return (0);
}


/*
 * check_legacy_cmd(proto, cmd)
 *
 * Check to see if the cmd exists in /usr/lib/fs/<proto>/<cmd> and is
 * executable.
 */

static int
check_legacy_cmd(char *path)
{
	struct stat st;
	int ret = 0;

	if (stat(path, &st) == 0) {
		if (S_ISREG(st.st_mode) &&
		    st.st_mode & (S_IXUSR|S_IXGRP|S_IXOTH))
			ret = 1;
	}
	return (ret);
}

/*
 * run_legacy_command(proto, cmd, argv)
 *
 * We know the command exists, so attempt to execute it with all the
 * arguments. This implements full legacy share support for those
 * protocols that don't have plugin providers.
 */

static int
run_legacy_command(char *path, char *argv[])
{
	int ret;

	ret = execv(path, argv);
	if (ret < 0) {
		switch (errno) {
		case EACCES:
			ret = SA_NO_PERMISSION;
			break;
		default:
			ret = SA_SYSTEM_ERR;
			break;
		}
	}
	return (ret);
}

/*
 * out_share(out, group, proto)
 *
 * Display the share information in the format that the "share"
 * command has traditionally used.
 */

static void
out_share(FILE *out, sa_group_t group, char *proto)
{
	sa_share_t share;
	char resfmt[128];

	for (share = sa_get_share(group, NULL);
	    share != NULL;
	    share = sa_get_next_share(share)) {
		char *path;
		char *type;
		char *resource;
		char *description;
		char *groupname;
		char *sharedstate;
		int shared = 1;
		char *soptions;

		sharedstate = sa_get_share_attr(share, "shared");
		path = sa_get_share_attr(share, "path");
		type = sa_get_share_attr(share, "type");
		resource = sa_get_share_attr(share, "resource");
		groupname = sa_get_group_attr(group, "name");

		if (groupname != NULL && strcmp(groupname, "default") == 0) {
			sa_free_attr_string(groupname);
			groupname = NULL;
		}
		description = sa_get_share_description(share);

		/* Want the sharetab version if it exists */
		soptions = sa_get_share_attr(share, "shareopts");

		if (sharedstate == NULL)
			shared = 0;

		if (soptions == NULL)
			soptions = sa_proto_legacy_format(proto, share, 1);

		if (shared) {
			/* only active shares go here */
			(void) snprintf(resfmt, sizeof (resfmt), "%s%s%s",
			    resource != NULL ? resource : "-",
			    groupname != NULL ? "@" : "",
			    groupname != NULL ? groupname : "");
			(void) fprintf(out, "%-14.14s  %s   %s   \"%s\"  \n",
			    resfmt, path,
			    (soptions != NULL && strlen(soptions) > 0) ?
			    soptions : "rw",
			    (description != NULL) ? description : "");
		}

		if (path != NULL)
			sa_free_attr_string(path);
		if (type != NULL)
			sa_free_attr_string(type);
		if (resource != NULL)
			sa_free_attr_string(resource);
		if (groupname != NULL)
			sa_free_attr_string(groupname);
		if (description != NULL)
			sa_free_share_description(description);
		if (sharedstate != NULL)
			sa_free_attr_string(sharedstate);
		if (soptions != NULL)
			sa_format_free(soptions);
	}
}

/*
 * output_legacy_file(out, proto)
 *
 * Walk all of the groups for the specified protocol and call
 * out_share() to format and write in the format displayed by the
 * "share" command with no arguments.
 */

static void
output_legacy_file(FILE *out, char *proto, sa_handle_t handle)
{
	sa_group_t group;

	for (group = sa_get_group(handle, NULL); group != NULL;
	    group = sa_get_next_group(group)) {
		char *options;
		char *zfs;

		/*
		 * Get default options preformated, being careful to
		 * handle legacy shares differently from new style
		 * shares. Legacy share have options on the share.
		 */

		zfs = sa_get_group_attr(group, "zfs");
		if (zfs != NULL) {
			sa_group_t zgroup;
			sa_free_attr_string(zfs);
			options = sa_proto_legacy_format(proto, group, 1);
			for (zgroup = sa_get_sub_group(group);
			    zgroup != NULL;
			    zgroup = sa_get_next_group(zgroup)) {

				/* got a group, so display it */
				out_share(out, zgroup, proto);
			}
		} else {
			options = sa_proto_legacy_format(proto, group, 1);
			out_share(out, group, proto);
		}
		if (options != NULL)
			free(options);
	}
}

/*ARGSUSED*/
int
sa_legacy_share(sa_handle_t handle, int flags, int argc, char *argv[])
{
	char *protocol = "nfs";
	char *options = NULL;
	char *description = NULL;
	char *groupname = NULL;
	char *sharepath = NULL;
	char *resource = NULL;
	char *groupstatus = NULL;
	int persist = SA_SHARE_TRANSIENT;
	int argsused = 0;
	int c;
	int ret = SA_OK;
	int zfs = 0;
	int true_legacy = 0;
	int curtype = SA_SHARE_TRANSIENT;
	char cmd[MAXPATHLEN];
	sa_group_t group = NULL;
	sa_share_t share;
	char dir[MAXPATHLEN];

	while ((c = getopt(argc, argv, "?hF:d:o:p")) != EOF) {
		switch (c) {
		case 'd':
			description = optarg;
			argsused++;
			break;
		case 'F':
			protocol = optarg;
			if (!sa_valid_protocol(protocol)) {
				if (format_legacy_path(cmd, MAXPATHLEN,
				    protocol, "share") == 0 &&
				    check_legacy_cmd(cmd)) {
					true_legacy++;
				} else {
					(void) fprintf(stderr, gettext(
					    "Invalid protocol specified: "
					    "%s\n"), protocol);
					return (SA_INVALID_PROTOCOL);
				}
			}
			break;
		case 'o':
			options = optarg;
			argsused++;
			break;
		case 'p':
			persist = SA_SHARE_PERMANENT;
			argsused++;
			break;
		case 'h':
		case '?':
		default:
			(void) fprintf(stderr, gettext("usage: %s\n"),
			    sa_get_usage(USAGE_SHARE));
			return (SA_OK);
		}
	}

	/* Have the info so construct what is needed */
	if (!argsused && optind == argc) {
		/* display current info in share format */
		(void) output_legacy_file(stdout, "nfs", handle);
		return (ret);
	}

	/* We are modifying the configuration */
	if (optind == argc) {
		(void) fprintf(stderr, gettext("usage: %s\n"),
		    sa_get_usage(USAGE_SHARE));
		return (SA_LEGACY_ERR);
	}
	if (true_legacy) {
		/* If still using legacy share/unshare, exec it */
		ret = run_legacy_command(cmd, argv);
		return (ret);
	}

	sharepath = argv[optind++];
	if (optind < argc) {
		resource = argv[optind];
		groupname = strchr(resource, '@');
		if (groupname != NULL)
			*groupname++ = '\0';
	}
	if (realpath(sharepath, dir) == NULL)
		ret = SA_BAD_PATH;
	else
		sharepath = dir;
	if (ret == SA_OK)
		share = sa_find_share(handle, sharepath);
	else
		share = NULL;

	if (groupname != NULL) {
		ret = SA_NOT_ALLOWED;
	} else if (ret == SA_OK) {
		char *legacygroup = "default";
		/*
		 * The legacy group is always present and zfs groups
		 * come and go.  zfs shares may be in sub-groups and
		 * the zfs share will already be in that group so it
		 * isn't an error.
		 */
		/*
		 * If the share exists (not NULL), then make sure it
		 * is one we want to handle by getting the parent
		 * group.
		 */
		if (share != NULL)
			group = sa_get_parent_group(share);
		else
			group = sa_get_group(handle, legacygroup);

		if (group != NULL) {
			groupstatus = group_status(group);
			if (share == NULL) {
				share = sa_add_share(group, sharepath,
				    persist, &ret);
				if (share == NULL &&
				    ret == SA_DUPLICATE_NAME) {
					/*
					 * Could be a ZFS path being started
					 */
					if (sa_zfs_is_shared(handle,
					    sharepath)) {
						ret = SA_OK;
						group = sa_get_group(handle,
						    "zfs");
						if (group == NULL) {
							/*
							 * This shouldn't
							 * happen.
							 */
							ret = SA_CONFIG_ERR;
						} else {
							share = sa_add_share(
							    group, sharepath,
							    persist, &ret);
						}
					}
				}
			} else {
				char *type;
				/*
				 * May want to change persist state, but the
				 * important thing is to change options. We
				 * need to change them regardless of the
				 * source.
				 */
				if (sa_zfs_is_shared(handle, sharepath)) {
					zfs = 1;
				}
				remove_all_options(share, protocol);
				type = sa_get_share_attr(share, "type");
				if (type != NULL &&
				    strcmp(type, "transient") != 0) {
					curtype = SA_SHARE_PERMANENT;
				}
				if (type != NULL)
					sa_free_attr_string(type);
				if (curtype != persist) {
					(void) sa_set_share_attr(share, "type",
					    persist == SA_SHARE_PERMANENT ?
					    "persist" : "transient");
				}
			}
			/* Have a group to hold this share path */
			if (ret == SA_OK && options != NULL &&
			    strlen(options) > 0) {
				ret = sa_parse_legacy_options(share,
				    options,
				    protocol);
			}
			if (!zfs) {
				/*
				 * ZFS shares never have resource or
				 * description and we can't store the values
				 * so don't try.
				 */
				if (ret == SA_OK && description != NULL)
					ret = sa_set_share_description(share,
					    description);
				if (ret == SA_OK && resource != NULL)
					ret = sa_set_share_attr(share,
					    "resource", resource);
			}
			if (ret == SA_OK) {
				if (strcmp(groupstatus, "enabled") == 0)
					ret = sa_enable_share(share, protocol);
				if (ret == SA_OK &&
				    persist == SA_SHARE_PERMANENT) {
					(void) sa_update_legacy(share,
					    protocol);
				}
				if (ret == SA_OK)
					ret = sa_update_config(handle);
			}
		} else {
			ret = SA_SYSTEM_ERR;
		}
	}
	if (ret != SA_OK) {
		(void) fprintf(stderr, gettext("Could not share: %s: %s\n"),
		    sharepath, sa_errorstr(ret));
		ret = SA_LEGACY_ERR;

	}
	return (ret);
}

/*
 * sa_legacy_unshare(flags, argc, argv)
 *
 * Implements the original unshare command.
 */
/*ARGSUSED*/
int
sa_legacy_unshare(sa_handle_t handle, int flags, int argc, char *argv[])
{
	char *protocol = "nfs"; /* for now */
	char *options = NULL;
	char *sharepath = NULL;
	int persist = SA_SHARE_TRANSIENT;
	int argsused = 0;
	int c;
	int ret = SA_OK;
	int true_legacy = 0;
	char cmd[MAXPATHLEN];

	while ((c = getopt(argc, argv, "?hF:o:p")) != EOF) {
		switch (c) {
		case 'h':
		case '?':
			break;
		case 'F':
			protocol = optarg;
			if (!sa_valid_protocol(protocol)) {
				if (format_legacy_path(cmd, MAXPATHLEN,
				    protocol, "unshare") == 0 &&
				    check_legacy_cmd(cmd)) {
					true_legacy++;
				} else {
					(void) printf(gettext(
					    "Invalid file system name\n"));
					return (SA_INVALID_PROTOCOL);
				}
			}
			break;
		case 'o':
			options = optarg;
			argsused++;
			break;
		case 'p':
			persist = SA_SHARE_PERMANENT;
			argsused++;
			break;
		default:
			(void) printf(gettext("usage: %s\n"),
			    sa_get_usage(USAGE_UNSHARE));
			return (SA_OK);
		}
	}

	/* Have the info so construct what is needed */
	if (optind == argc || (optind + 1) < argc || options != NULL) {
		ret = SA_SYNTAX_ERR;
	} else {
		sa_share_t share;
		char dir[MAXPATHLEN];
		if (true_legacy) {
			/* if still using legacy share/unshare, exec it */
			ret = run_legacy_command(cmd, argv);
			return (ret);
		}
		/*
		 * Find the path in the internal configuration. If it
		 * isn't found, attempt to resolve the path via
		 * realpath() and try again.
		 */
		sharepath = argv[optind++];
		share = sa_find_share(handle, sharepath);
		if (share == NULL) {
			if (realpath(sharepath, dir) == NULL) {
				ret = SA_NO_SUCH_PATH;
			} else {
				share = sa_find_share(handle, dir);
			}
		}
		if (share != NULL) {
			ret = sa_disable_share(share, protocol);
			/*
			 * Errors are ok and removal should still occur. The
			 * legacy unshare is more forgiving of errors than the
			 * remove-share subcommand which may need the force
			 * flag set for some error conditions. That is, the
			 * "unshare" command will always unshare if it can
			 * while "remove-share" might require the force option.
			 */
			if (persist == SA_SHARE_PERMANENT) {
				ret = sa_remove_share(share);
				if (ret == SA_OK)
					ret = sa_update_config(handle);
			}
		} else {
			ret = SA_NOT_SHARED;
		}
	}
	switch (ret) {
	default:
		(void) printf("%s: %s\n", sharepath, sa_errorstr(ret));
		ret = SA_LEGACY_ERR;
		break;
	case SA_SYNTAX_ERR:
		(void) printf(gettext("usage: %s\n"),
		    sa_get_usage(USAGE_UNSHARE));
		break;
	case SA_OK:
		break;
	}
	return (ret);
}

/*
 * Common commands that implement the sub-commands used by all
 * protcols. The entries are found via the lookup command
 */

static sa_command_t commands[] = {
	{"add-share", 0, sa_addshare, USAGE_ADD_SHARE, SVC_SET},
	{"create", 0, sa_create, USAGE_CREATE, SVC_SET|SVC_ACTION},
	{"delete", 0, sa_delete, USAGE_DELETE, SVC_SET|SVC_ACTION},
	{"disable", 0, sa_disable_group, USAGE_DISABLE, SVC_SET|SVC_ACTION},
	{"enable", 0, sa_enable_group, USAGE_ENABLE, SVC_SET|SVC_ACTION},
	{"list", 0, sa_list, USAGE_LIST},
	{"move-share", 0, sa_moveshare, USAGE_MOVE_SHARE, SVC_SET},
	{"remove-share", 0, sa_removeshare, USAGE_REMOVE_SHARE, SVC_SET},
	{"set", 0, sa_set, USAGE_SET, SVC_SET},
	{"set-share", 0, sa_set_share, USAGE_SET_SHARE, SVC_SET},
	{"show", 0, sa_show, USAGE_SHOW},
	{"share", 0, sa_legacy_share, USAGE_SHARE, SVC_SET|SVC_ACTION},
	{"start", CMD_NODISPLAY, sa_start_group, USAGE_START,
		SVC_SET|SVC_ACTION},
	{"stop", CMD_NODISPLAY, sa_stop_group, USAGE_STOP, SVC_SET|SVC_ACTION},
	{"unset", 0, sa_unset, USAGE_UNSET, SVC_SET},
	{"unshare", 0, sa_legacy_unshare, USAGE_UNSHARE, SVC_SET|SVC_ACTION},
	{NULL, 0, NULL, NULL}
};

static char *
sa_get_usage(sa_usage_t index)
{
	char *ret = NULL;
	switch (index) {
	case USAGE_ADD_SHARE:
		ret = gettext("add-share [-nth] [-r resource-name] "
		    "[-d \"description text\"] -s sharepath group");
		break;
	case USAGE_CREATE:
		ret = gettext(
		    "create [-nvh] [-P proto [-p property=value]] group");
		break;
	case USAGE_DELETE:
		ret = gettext("delete [-nvh] [-P proto] [-f] group");
		break;
	case USAGE_DISABLE:
		ret = gettext("disable [-nvh] {-a | group ...}");
		break;
	case USAGE_ENABLE:
		ret = gettext("enable [-nvh] {-a | group ...}");
		break;
	case USAGE_LIST:
		ret = gettext("list [-vh] [-P proto]");
		break;
	case USAGE_MOVE_SHARE:
		ret = gettext(
		    "move-share [-nvh] -s sharepath destination-group");
		break;
	case USAGE_REMOVE_SHARE:
		ret = gettext("remove-share [-fnvh] -s sharepath group");
		break;
	case USAGE_SET:
		ret = gettext("set [-nvh] -P proto [-S optspace] "
		    "[-p property=value]* [-s sharepath] group");
		break;
	case USAGE_SET_SECURITY:
		ret = gettext("set-security [-nvh] -P proto -S security-type "
		    "[-p property=value]* group");
		break;
	case USAGE_SET_SHARE:
		ret = gettext("set-share [-nh] [-r resource] "
		    "[-d \"description text\"] -s sharepath group");
		break;
	case USAGE_SHOW:
		ret = gettext("show [-pvxh] [-P proto] [group ...]");
		break;
	case USAGE_SHARE:
		ret = gettext("share [-F fstype] [-p] [-o optionlist]"
		    "[-d description] [pathname [resourcename]]");
		break;
	case USAGE_START:
		ret = gettext("start [-vh] [-P proto] {-a | group ...}");
		break;
	case USAGE_STOP:
		ret = gettext("stop [-vh] [-P proto] {-a | group ...}");
		break;
	case USAGE_UNSET:
		ret = gettext("unset [-nvh] -P proto [-S optspace] "
		    "[-p property]* group");
		break;
	case USAGE_UNSET_SECURITY:
		ret = gettext("unset-security [-nvh] -P proto -S security-type"
		    " [-p property]* group");
		break;
	case USAGE_UNSHARE:
		ret = gettext(
		    "unshare [-F fstype] [-p] sharepath");
		break;
	}
	return (ret);
}

/*
 * sa_lookup(cmd, proto)
 *
 * Lookup the sub-command. proto isn't currently used, but it may
 * eventually provide a way to provide protocol specific sub-commands.
 */
/*ARGSUSED*/
sa_command_t *
sa_lookup(char *cmd, char *proto)
{
	int i;
	size_t len;

	len = strlen(cmd);
	for (i = 0; commands[i].cmdname != NULL; i++) {
		if (strncmp(cmd, commands[i].cmdname, len) == 0)
			return (&commands[i]);
	}
	return (NULL);
}

/*ARGSUSED*/
void
sub_command_help(char *proto)
{
	int i;

	(void) printf(gettext("\tsub-commands:\n"));
	for (i = 0; commands[i].cmdname != NULL; i++) {
		if (!(commands[i].flags & (CMD_ALIAS|CMD_NODISPLAY)))
			(void) printf("\t%s\n",
			    sa_get_usage((sa_usage_t)commands[i].cmdidx));
	}
}
