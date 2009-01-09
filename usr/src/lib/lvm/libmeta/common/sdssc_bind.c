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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Block comment which describes the contents of this file.
 */

#include <dlfcn.h>
#include <meta.h>
#include <metadyn.h>
#include <sdssc.h>

#define	SDSSC_PATH SDSSC_CL_LIBDIR "/sc/libsds_sc.so"

static func_table_t dl_table[] = {
	{ "_sdssc_version",		(void **)&sdssc_version },
	{ "_sdssc_create_begin",	(void **)&sdssc_create_begin },
	{ "_sdssc_mo_create_begin",	(void **)&sdssc_mo_create_begin },
	{ "_sdssc_create_end",		(void **)&sdssc_create_end },
	{ "_sdssc_delete_begin",	(void **)&sdssc_delete_begin },
	{ "_sdssc_delete_end",		(void **)&sdssc_delete_end },
	{ "_sdssc_get_index",		(void **)&sdssc_get_index },
	{ "_sdssc_add_hosts",		(void **)&sdssc_add_hosts },
	{ "_sdssc_delete_hosts",	(void **)&sdssc_delete_hosts },
	{ "_sdssc_get_primary_host",	(void **)&sdssc_get_primary_host },
	{ "_sdssc_cmd_proxy",		(void **)&sdssc_cmd_proxy },
	{ "_sdssc_getnodelist",		(void **)&sdssc_getnodelist },
	{ "_sdssc_freenodelist",	(void **)&sdssc_freenodelist },
	{ "_sdssc_binddevs",		(void **)&sdssc_binddevs },
	{ "_sdssc_bindclusterdevs",	(void **)&sdssc_bindclusterdevs },
	{ "_sdssc_gettransportbynode",	(void **)&sdssc_gettransportbynode },
	{ "_sdssc_free_mdcerr_list",	(void **)&sdssc_free_mdcerr_list },
	{ "_sdssc_property_get",	(void **)&sdssc_property_get },
	{ "_sdssc_property_set",	(void **)&sdssc_property_set },
	{ "_sdssc_get_services",	(void **)&sdssc_get_services },
	{ "_sdssc_get_services_free",	(void **)&sdssc_get_services_free },
	{ "_sdssc_suspend",		(void **)&sdssc_suspend },
	{ "_sdssc_convert_cluster_path",
	    (void **)&sdssc_convert_cluster_path },
	{ "_sdssc_convert_ctd_path",
	    (void **)&sdssc_convert_ctd_path },
	{ "_sdssc_convert_path_free",
	    (void **)&sdssc_convert_path_free },
	{ "_sdssc_notify_service",	(void **)&sdssc_notify_service },
	{ "_sdssc_cm_nm2nid",	(void **)&sdssc_cm_nm2nid },
	{ "_sdssc_cm_sr_nm2nid",	(void **)&sdssc_cm_sr_nm2nid },
	{ "_sdssc_cm_nid2nm",	(void **)&sdssc_cm_nid2nm },
	{ "_sdssc_cm_sr_nid2nm",	(void **)&sdssc_cm_sr_nid2nm },
	{ "_sdssc_get_priv_ipaddr",	(void **)&sdssc_get_priv_ipaddr },
	{ (char *)0,			(void **)0 }
};

static rval_e
just_dup_string(const char *source, char **dest)
{
	*dest = strdup(source);
	return (SDSSC_OKAY);
}

static void
free_dup_string(char *source)
{
	free(source);
}

/*
 * not_bound -- routine to always return NOT_BOUND
 */
static rval_e
not_bound(void)
{
	return (SDSSC_NOT_BOUND);
}

/*
 * not_bound_error -- routine to always return SDSSC_NOT_BOUND_ERROR since
 * routine is not bound.  This is used when using an older version
 * of libsdssc that doesn't support MN disksets.  When an MN specific
 * routine is called (such as sdssc_mo_create_set) an SDSSC_NOT_BOUND_ERROR
 * will be returned.
 */
static rval_e
not_bound_error(void)
{
	return (SDSSC_NOT_BOUND_ERROR);
}


/*
 * set_common_routine -- set cluster interface routines to return NOT_BOUND
 */
static void
set_common_routine()
{
	func_table_p	f;

	for (f = dl_table; f->fptr != (void *)0; f++) {
		if (strcmp(f->fname, "_sdssc_convert_cluster_path") == 0) {
			*f->fptr = (void *)&just_dup_string;
		} else if (strcmp(f->fname, "_sdssc_free_convert_cluster_path")
		    == 0) {
			*f->fptr = (void *)&free_dup_string;
		} else {
			*f->fptr = (void *)&not_bound;
		}
	}
}

/*
 * sdssc_bind_library -- entry point which resolves all cluster interface pts.
 */
rval_e
sdssc_bind_library(void)
{
	void		*dp;
	int		(*lb)();
	func_table_p	ftp;
	static int	initialised = 0;

	/*
	 * If already bound then just return okay so this routine
	 * becomes idempotent. If this check isn't made then we'll
	 * fail when calling the "_bind_library" function because
	 * dcs_initialize() can only be called once.
	 * If not bound first time we try it again.
	 */
	if (initialised && (void *)sdssc_version != (void *)not_bound) {
		return (SDSSC_OKAY);
	}
	initialised = 1;

	if ((dp = dlopen(SDSSC_PATH, RTLD_LAZY)) == NULL) {
		set_common_routine();
		return (SDSSC_NOT_BOUND);
	} else {

		/*
		 * Allow the binding library to initialize state if
		 * necessary. Currently this calls the DCS initialize()
		 * routine which checks to see if we're part of a cluster.
		 */
		if ((lb = (int (*)())dlsym(dp, "_bind_library")) != NULL) {
			if (lb() != 0) {
				set_common_routine();
				return (SDSSC_NOT_BOUND);
			}
		}

		/*
		 * Load 'em up. Pick up the function address and store
		 * the values in the global pointers for other routines
		 * to use.
		 */
		for (ftp = dl_table; ftp->fptr != (void *)0; ftp++) {
			if ((*ftp->fptr = dlsym(dp, ftp->fname)) == NULL) {

				/*
				 * If old libsdssc library is there, then
				 * sdssc_mo_create_begin is not yet supported.
				 */
				if (strcmp(ftp->fname,
				    "sdssc_mo_create_begin")) {
					*ftp->fptr = (void *)&not_bound_error;
					continue;
				}
				/*
				 * If this routine fails to find a single
				 * entry point that it's expecting
				 * (except sdssc_mo_create_begin) then
				 * setup non-sdssc stubs routines
				 * as function pointers.
				 */
				set_common_routine();
				return (SDSSC_ERROR);
			}
		}

		return (SDSSC_OKAY);
	}
}
