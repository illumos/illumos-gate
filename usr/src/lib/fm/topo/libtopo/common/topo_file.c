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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <limits.h>
#include <string.h>
#include <sys/param.h>
#include <topo_error.h>
#include <topo_tree.h>
#include <topo_subr.h>
#include <topo_file.h>

/*
 * topo_file.c
 *
 *	This file hides the details of any file manipulation to
 *	establish topology for a given scheme.  It has two outward
 *	facing interfaces topo_file_load() and topo_file_unload().
 */

#define	TOPO_DEFAULT_FILE	"%s-topology.xml"
#define	PLATFORM_TOPO_PATH	"%susr/platform/%s/lib/fm/topo/%s"
#define	COMMON_TOPO_PATH	"%susr/lib/fm/topo/%s"

static char _topo_file[MAXNAMELEN * 2];
static char _topo_path[PATH_MAX];

static int
xml_read(topo_hdl_t *hp, ttree_t *tp)
{
	topo_file_t *tfp;
	char *pplat, *pmach;
	int err, e;

	tfp = (topo_file_t *)tp->tt_file;

	(void) snprintf(_topo_file,
	    2 * MAXNAMELEN, TOPO_DEFAULT_FILE, tp->tt_scheme);

	/*
	 * Look for a platform-specific topology file first
	 */
	e = topo_prop_get_string(tp->tt_root, TOPO_PGROUP_SYSTEM,
	    TOPO_PROP_PLATFORM, &pplat, &err);
	if (e < 0)
		return (topo_hdl_seterrno(hp, err));
	(void) snprintf(_topo_path, PATH_MAX, PLATFORM_TOPO_PATH,
	    hp->th_rootdir, pplat, _topo_file);

	tfp->tf_fileinfo =
	    topo_xml_read(tfp->tf_mod, _topo_path, tp->tt_scheme);
	if (tfp->tf_fileinfo != NULL) {
		topo_hdl_strfree(hp, pplat);
		return (0);
	}

	topo_dprintf(TOPO_DBG_MOD, "failed to load topology file %s: %s\n",
	    _topo_path, topo_strerror(topo_hdl_errno(hp)));

	/*
	 * No luck with the platform-specific file, how about a
	 * machine-specific one?
	 */
	e = topo_prop_get_string(tp->tt_root, TOPO_PGROUP_SYSTEM,
	    TOPO_PROP_MACHINE, &pmach, &err);
	if (e < 0) {
		topo_hdl_strfree(hp, pplat);
		return (topo_hdl_seterrno(hp, err));
	}
	/*
	 * Don't waste time trying to open the same file twice in the
	 * cases where the platform name is identical to the machine
	 * name
	 */
	if (strcmp(pplat, pmach) != 0) {
		(void) snprintf(_topo_path, PATH_MAX, PLATFORM_TOPO_PATH,
		    hp->th_rootdir, pmach, _topo_file);
		tfp->tf_fileinfo =
		    topo_xml_read(tfp->tf_mod, _topo_path, tp->tt_scheme);
	}
	if (tfp->tf_fileinfo != NULL) {
		topo_hdl_strfree(hp, pplat);
		topo_hdl_strfree(hp, pmach);
		return (0);
	} else {
		topo_dprintf(TOPO_DBG_MOD,
		    "failed to load topology file %s: %s\n",
		    _topo_path, topo_strerror(topo_hdl_errno(hp)));
	}
	topo_hdl_strfree(hp, pplat);
	topo_hdl_strfree(hp, pmach);
	(void) snprintf(_topo_path, PATH_MAX, COMMON_TOPO_PATH,
	    hp->th_rootdir, _topo_file);
	tfp->tf_fileinfo =
	    topo_xml_read(tfp->tf_mod, _topo_path, tp->tt_scheme);
	if (tfp->tf_fileinfo == NULL) {
		topo_dprintf(TOPO_DBG_MOD,
		    "failed to load topology file %s: %s\n",
		    _topo_path, topo_strerror(topo_hdl_errno(hp)));
		return (topo_hdl_seterrno(hp, ETOPO_FILE_NOENT));
	}
	return (0);
}

int
topo_file_load(topo_hdl_t *thp, topo_mod_t *mod, ttree_t *tp)
{
	topo_file_t *tfp;

	if ((tfp = topo_hdl_zalloc(thp, sizeof (topo_file_t))) == NULL)
		return (topo_hdl_seterrno(thp, ETOPO_NOMEM));

	tp->tt_file = tfp;

	tfp->tf_mod = mod;

	if (xml_read(thp, tp) < 0) {
		topo_file_unload(thp, tp);
		return (-1);
	}

	if (topo_xml_enum(tfp->tf_mod, tfp->tf_fileinfo, tp->tt_root) < 0) {
		topo_dprintf(TOPO_DBG_ERR,
		    "Failed to enumerate topology: %s\n",
		    topo_strerror(topo_hdl_errno(thp)));
		topo_file_unload(thp, tp);
		return (-1);
	}
	return (0);
}

void
topo_file_unload(topo_hdl_t *thp, ttree_t *tp)
{
	topo_file_t *tfp = tp->tt_file;

	if (tfp == NULL)
		return;

	if (tfp->tf_fileinfo != NULL)
		tf_info_free(tfp->tf_mod, tfp->tf_fileinfo);

	topo_hdl_free(thp, tfp, sizeof (topo_file_t));
	tp->tt_file = NULL;
}
