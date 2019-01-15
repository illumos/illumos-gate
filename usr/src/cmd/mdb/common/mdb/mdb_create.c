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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2018 Joyent, Inc.
 */

#include <mdb/mdb.h>
#include <mdb/mdb_conf.h>
#include <mdb/mdb_module.h>

#include <sys/types.h>
#include <limits.h>

#include <dirent.h>

void
mdb_create_builtin_tgts(void)
{
	mdb_module_t *mp;

	if ((mp = mdb_module_load_builtin("mdb_kvm")) != NULL)
		mp->mod_tgt_ctor = mdb_kvm_tgt_create;

	if ((mp = mdb_module_load_builtin("mdb_proc")) != NULL)
		mp->mod_tgt_ctor = mdb_proc_tgt_create;

	if ((mp = mdb_module_load_builtin("mdb_kproc")) != NULL)
		mp->mod_tgt_ctor = mdb_kproc_tgt_create;

	if ((mp = mdb_module_load_builtin("mdb_raw")) != NULL)
		mp->mod_tgt_ctor = mdb_rawfile_tgt_create;

#ifdef __amd64
	if ((mp = mdb_module_load_builtin("mdb_bhyve")) != NULL)
		mp->mod_tgt_ctor = mdb_bhyve_tgt_create;
#endif
}

void
mdb_create_loadable_disasms(void)
{
	DIR *dir;
	struct dirent *dp;
	char buf[PATH_MAX], *p, *q;
	size_t len;

#ifdef _LP64
	len = mdb_snprintf(buf, sizeof (buf), "%s/usr/lib/mdb/disasm/%s",
	    mdb.m_root, mdb_conf_isa());
#else
	len = mdb_snprintf(buf, sizeof (buf), "%s/usr/lib/mdb/disasm",
	    mdb.m_root);
#endif
	p = &buf[len];

	if ((dir = opendir(buf)) == NULL)
		return;

	while ((dp = readdir(dir)) != NULL) {
		if (dp->d_name[0] == '.')
			continue; /* skip "." and ".." */
		if ((q = strrchr(dp->d_name, '.')) == NULL ||
		    strcmp(q, ".so") != 0)
			continue;

		(void) mdb_snprintf(p, sizeof (buf) - len, "/%s", dp->d_name);

		(void) mdb_module_load(buf, MDB_MOD_SILENT);
	}

	(void) closedir(dir);
}
