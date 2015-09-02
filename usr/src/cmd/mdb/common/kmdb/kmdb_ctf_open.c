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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2015, Joyent, Inc.
 */

/*
 * libctf open/close interposition layer
 *
 * This interposition layer serves two purposes.  First, it allows the
 * introduction of a kmdb-specific implementation of ctf_open().  The normal
 * ctf_open() call open(2)s a file, and reads the CTF data directly from it.
 * No such facility is available in kmdb, as kmdb does not run in userland.  We
 * can, however, observe that kmdb uses this interface only to read CTF data
 * from dmods.  dmods, as viewed by kmdb, do have CTF data, but they have it
 * in a form that is best accessed by ctf_bufopen().  This interposition layer
 * allows us to translate ctf_open() calls into ctf_bufopen() calls.
 *
 * The second purpose of the interposition layer is to reduce the work needed
 * to call mdb_ctf_bufopen.
 */

#include <sys/types.h>
#include <sys/kobj.h>
#include <libctf.h>
#include <ctf_impl.h>

#include <kmdb/kmdb_module.h>
#include <mdb/mdb_ctf.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb.h>

static kmdb_modctl_t *
mdb_ctf_name2ctl(const char *pathname)
{
	mdb_var_t *v;

	if ((v = mdb_nv_lookup(&mdb.m_dmodctl, strbasename(pathname))) ==
	    NULL)
		return (NULL);

	return ((kmdb_modctl_t *)MDB_NV_COOKIE(v));
}

ctf_file_t *
mdb_ctf_open(const char *pathname, int *errp)
{
	struct module *mp;
	kmdb_modctl_t *kmc;
	ctf_file_t *ctfp;

	if ((kmc = mdb_ctf_name2ctl(pathname)) == NULL) {
		if (errp != NULL)
			*errp = ENOENT;
		return (NULL);
	}

	mp = kmc->kmc_modctl->mod_mp;
	if (mp->ctfdata == NULL) {
		if (errp != NULL)
			*errp = ECTF_NOCTFDATA;
		return (NULL);
	}

	if ((ctfp = mdb_ctf_bufopen(mp->ctfdata, mp->ctfsize, mp->symtbl,
	    mp->symhdr, mp->strings, mp->strhdr, errp)) == NULL)
		return (NULL);

	mdb_dprintf(MDB_DBG_MODULE, "loaded %lu bytes of CTF data for %s\n",
	    (ulong_t)mp->ctfsize, kmc->kmc_modname);

	return (ctfp);
}

void
mdb_ctf_close(ctf_file_t *fp)
{
	ctf_close(fp);
}

/*ARGSUSED*/
int
mdb_ctf_write(const char *file, ctf_file_t *fp)
{
	return (ENOTSUP);
}
