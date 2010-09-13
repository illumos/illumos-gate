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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <dlfcn.h>
#include <sys/modctl.h>
#include <sys/kobj.h>

#include <kmdb/kmdb_module.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_gelf.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb.h>

/*
 * kmdb libdl-style interface for the manipulation of dmods.
 */

static char *dl_errstr;

static kmdb_modctl_t *
dl_name2ctl(const char *pathname)
{
	mdb_var_t *v;

	if ((v = mdb_nv_lookup(&mdb.m_dmodctl, strbasename(pathname))) ==
	    NULL)
		return (NULL);

	return ((kmdb_modctl_t *)MDB_NV_COOKIE(v));
}

/*ARGSUSED*/
void *
dlmopen(Lmid_t lmid, const char *pathname, int mode)
{
	kmdb_modctl_t *kmc;

	if ((kmc = dl_name2ctl(pathname)) == NULL) {
		dl_errstr = "unregistered module";
		return (NULL);
	}

	kmc->kmc_dlrefcnt++;

	dl_errstr = NULL;

	return (kmc);
}

int
dlclose(void *dlp)
{
	kmdb_modctl_t *kmc = dlp;

	dl_errstr = NULL;

	ASSERT(kmc->kmc_dlrefcnt > 0);
	if (--kmc->kmc_dlrefcnt > 0)
		return (0);

	return (0);
}

char *
dlerror(void)
{
	char *str = dl_errstr;

	dl_errstr = NULL;

	return (str);
}

static void *
dl_findsym(kmdb_modctl_t *kmc, const char *name)
{
	GElf_Sym sym;
	uint_t symid;

	if (mdb_gelf_symtab_lookup_by_name(kmc->kmc_symtab, name, &sym,
	    &symid) < 0)
		return (NULL);

	return ((void *)(uintptr_t)sym.st_value);
}

/*ARGSUSED*/
void *
dlsym(void *dlp, const char *name)
{
	kmdb_modctl_t *kmc = dlp;
	mdb_var_t *v;
	void *addr;

	switch ((uintptr_t)dlp) {
	case (uintptr_t)RTLD_NEXT:
		mdb_nv_rewind(&mdb.m_dmodctl);
		while ((v = mdb_nv_advance(&mdb.m_dmodctl)) != NULL) {
			if ((addr = dl_findsym(MDB_NV_COOKIE(v), name)) != NULL)
				break;
		}
		break;

	case (uintptr_t)RTLD_DEFAULT:
	case (uintptr_t)RTLD_SELF:
		dl_errstr = "invalid handle";
		return (NULL);

	default:
		addr = dl_findsym(kmc, name);
	}

	dl_errstr = (addr == NULL) ? "symbol not found" : NULL;

	return (addr);
}

#pragma weak _dladdr1 = dladdr1
/*ARGSUSED*/
int
dladdr1(void *address, Dl_info *dlip, void **info, int flags)
{
	/*
	 * umem uses this for debugging information.  We'll pretend to fail.
	 */

	return (0);
}
