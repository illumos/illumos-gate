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

#include <kmdb/kctl/kctl.h>

#include <sys/modctl.h>
#include <sys/bootconf.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/kmdb.h>

static uintptr_t
kctl_lookup_by_name(char *modname, char *symname)
{
	struct modctl *mctl;
	Sym *ksym;
	uintptr_t addr;

	if ((mctl = mod_hold_by_name(modname)) == NULL)
		return (0);
	if ((ksym = kobj_lookup_all(mctl->mod_mp, symname, 1)) == NULL) {
		mod_release_mod(mctl);
		return (0);
	}

	addr = ksym->st_value;

	mod_release_mod(mctl);

	return (addr);
}

static uintptr_t
kctl_boot_lookup_by_name(char *modname, char *symname)
{
	struct modctl *mctl;
	Sym *ksym;

	if ((mctl = kobj_boot_mod_lookup(modname)) == NULL)
		return (0);

	if ((ksym = kobj_lookup_all(mctl->mod_mp, symname, 1)) == NULL)
		return (0);

	return (ksym->st_value);
}

void
kctl_auxv_init(kmdb_auxv_t *kav, const char *cfg, const char **argv, void *romp)
{
	bzero(kav, sizeof (kmdb_auxv_t));
	kav->kav_dseg = kctl.kctl_dseg;
	kav->kav_dseg_size = kctl.kctl_dseg_size;
	kav->kav_pagesize = PAGESIZE;
	kav->kav_ncpu = NCPU;
	kav->kav_kdi = &kobj_kdi;
	kav->kav_wrintr_fire = kctl_wrintr_fire;

	kav->kav_config = cfg;
	kav->kav_argv = argv;
	kav->kav_modpath = kobj_module_path;

	kctl_dprintf("kctl_auxv_init: modpath '%s'", kav->kav_modpath);

	if (kctl.kctl_boot_loaded) {
		kav->kav_lookup_by_name = kctl_boot_lookup_by_name;
		kav->kav_flags |= KMDB_AUXV_FL_NOUNLOAD;
	} else
		kav->kav_lookup_by_name = kctl_lookup_by_name;

	if (kctl.kctl_flags & KMDB_F_TRAP_NOSWITCH)
		kav->kav_flags |= KMDB_AUXV_FL_NOTRPSWTCH;

	kctl_auxv_init_isadep(kav, romp); /* can modify anything in kav */
}

void
kctl_auxv_fini(kmdb_auxv_t *kav)
{
	kctl_auxv_fini_isadep(kav);
}
