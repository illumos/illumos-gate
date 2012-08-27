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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Service Management Facility (SMF) interfaces.
 */

#include <stdio.h>
#include <libscf.h>
#include <meta.h>

static void enable(char *svc_names[], md_error_t *ep);
static void disable(char *svc_names[], md_error_t *ep);
static int enabled(char *svc_name);
static int online(char *svc_names[], char **names);
static void wait_online(char *svc_names[]);
static int is_online(char *svc_name);

static char
*svm_core_svcs[] = {
	"system/metainit:default",
	"system/metasync:default",
	"system/mdmonitor:default",
	"network/rpc/meta:default",
	NULL
};

static char
*svm_diskset_svcs[] = {
	"network/rpc/metamed:default",
	"network/rpc/metamh:default",
	NULL
};

static char
*svm_mn_diskset_svcs[] = {
	"network/rpc/mdcomm:default",
	NULL
};

/*
 * Enable the specified SVM services through the SMF.
 */
int
meta_smf_enable(uint_t flags, md_error_t *ep)
{
	if (flags & META_SMF_CORE) {
		enable(svm_core_svcs, ep);
		wait_online(svm_core_svcs);
	}

	if (flags & META_SMF_DISKSET) {
		enable(svm_diskset_svcs, ep);
		wait_online(svm_diskset_svcs);
	}

	if (flags & META_SMF_MN_DISKSET) {
		enable(svm_mn_diskset_svcs, ep);
		wait_online(svm_mn_diskset_svcs);
	}

	if (ep != NULL)
		return ((mdisok(ep)) ? 0 : -1);
	else
		return (0);
}

/*
 * Disable the specified SVM services through the SMF.
 */
int
meta_smf_disable(uint_t flags, md_error_t *ep)
{
	if (flags & META_SMF_CORE) {
		disable(svm_core_svcs, ep);
	}

	if (flags & META_SMF_DISKSET) {
		disable(svm_diskset_svcs, ep);
	}

	if (flags & META_SMF_MN_DISKSET) {
		disable(svm_mn_diskset_svcs, ep);
	}

	if (ep != NULL)
		return ((mdisok(ep)) ? 0 : -1);
	else
		return (0);
}

/*
 * Determine if desired services are online.  If all services in the
 * classes specified by flags are online, 1 is returned.  Otherwise
 * 0 is returned.
 */

int
meta_smf_isonline(uint_t flags, md_error_t *ep)
{
	int	ret = 1;
	char	*names = NULL;

	if (flags & META_SMF_CORE) {
		if (online(svm_core_svcs, &names) == 0)
			ret = 0;
	}
	if (flags & META_SMF_DISKSET) {
		if (online(svm_diskset_svcs, &names) == 0)
			ret = 0;
	}
	if (flags & META_SMF_MN_DISKSET) {
		if (online(svm_mn_diskset_svcs, &names) == 0)
			ret = 0;
	}

	if (ret == 0) {
		(void) mderror(ep, MDE_SMF_NO_SERVICE, names);
		Free(names);
	}

	return (ret);
}

/*
 * Return a bitmask of the META_SMF_* flags indicating which services should be
 * online given the current SVM configuration.
 */
int
meta_smf_getmask()
{
	int		mask = 0;
	mdsetname_t	*sp = NULL;
	mddb_config_t	c;
	md_error_t	status = mdnullerror;
	md_error_t	*ep = &status;
	int		max_sets;

	/*
	 * If there are any local metadbs configured then the core services
	 * are needed.
	 */
	(void) memset(&c, 0, sizeof (c));
	c.c_setno = MD_LOCAL_SET;
	if (metaioctl(MD_DB_GETDEV, &c, &c.c_mde, NULL) != 0 || c.c_dbcnt == 0)
		return (mask);

	mask |= META_SMF_CORE;

	/*
	 * If any disksets configured then the diskset services are needed.
	 * Also check for multi-node sets.
	 */
	if ((max_sets = get_max_sets(ep)) > 0) {
		int i;

		mdclrerror(ep);
		for (i = 1; i < max_sets; i++) {
			md_set_desc	*sd;

			if ((sp = metasetnosetname(i, ep)) == NULL) {
				if (!mdisok(ep) && !mdiserror(ep, MDE_NO_SET) &&
				    !mdiserror(ep, MDE_NOTENOUGH_DB) &&
				    !mdiserror(ep, MDE_SMF_NO_SERVICE) &&
				    ep->info.errclass != MDEC_RPC) {
					/*
					 * metad rpc program not registered
					 * can't get diskset info
					 */
					break;
				}

			} else {
				mask |= META_SMF_DISKSET;

				if ((sd = metaget_setdesc(sp, ep)) != NULL) {
					if (MD_MNSET_DESC(sd)) {
						mask |= META_SMF_MN_DISKSET;

						/*
						 * we don't have to check the
						 * rest of the disksets at this
						 * point
						 */
						break;
					}
				}
			}

			mdclrerror(ep);
		}
	}

	return (mask);
}

static void
enable(char *svc_names[], md_error_t *ep)
{
	int i;

	for (i = 0; svc_names[i]; i++) {
		if (!enabled(svc_names[i]))
			if (smf_enable_instance(svc_names[i], 0) != 0) {
				if (ep != NULL) {
					(void) mderror(ep, MDE_SMF_FAIL,
					    svc_names[i]);
				}
			}
	}
}

static void
disable(char *svc_names[], md_error_t *ep)
{
	int i;

	for (i = 0; svc_names[i]; i++) {
		if (enabled(svc_names[i]))
			if (smf_disable_instance(svc_names[i], 0) != 0) {
				if (ep != NULL) {
					(void) mderror(ep, MDE_SMF_FAIL,
					    svc_names[i]);
				}
			}
	}
}

static int
enabled(char *svc_name)
{
	scf_simple_prop_t	*prop;
	int			rval = 0;

	prop = scf_simple_prop_get(NULL, svc_name, SCF_PG_GENERAL,
	    SCF_PROPERTY_ENABLED);

	if (scf_simple_prop_numvalues(prop) == 1) {
		if (*scf_simple_prop_next_boolean(prop) != 0)
			rval = 1;
	}

	scf_simple_prop_free(prop);

	return (rval);
}

/*
 * There can be a delay while the RPC services get going.  Try to
 * make sure the RPC daemons are ready to run before we return.
 * Check 15 times (15 seconds total wait time) and then just
 * return.
 */
static void
wait_online(char *svc_names[])
{
	int i;
	char	*names = NULL;

	for (i = 0; i < 15; i++) {
		if (online(svc_names, &names))
			break;
		(void) sleep(1);
	}

	if (names != NULL)
		Free(names);
}

/*
 * Check to see if all services in the svc_names are online.  If they are
 * all online 1 is returned, otherwise 0 is returned.
 */

static int
online(char *svc_names[], char **names)
{
	int i;
	int rv = 1;

	for (i = 0; svc_names[i]; i++) {
		if (is_online(svc_names[i]) == 0) {
			int sz;
			char *p;

			/*
			 * Need space for the name, the new line, the
			 * tab and the null terminator.
			 */
			sz = strlen(svc_names[i]) + 3;

			if (*names == NULL) {
				p = Malloc(sz);
				(void) snprintf(p, sz, "\n\t%s", svc_names[i]);

			} else {
				/* Add space for existing names */
				sz += strlen(*names);
				p = Malloc(sz);
				(void) snprintf(p, sz, "%s\n\t%s", *names,
				    svc_names[i]);
				Free(*names);
			}

			*names = p;
			rv = 0;
		}
	}
	return (rv);
}

/*
 * Return 1 if the specified service is online.  Otherwise, return 0.
 */
static int
is_online(char *svc_name)
{
	int	rval = 0;
	char	*s;

	if ((s = smf_get_state(svc_name)) != NULL) {
		if (strcmp(s, "online") == 0)
			rval = 1;
		free(s);
	}
	return (rval);
}
