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
 * Tracking of kernel module loads and unloads
 */

#include <kmdb/kmdb_kdi.h>
#include <kmdb/kctl/kctl.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/ctf_api.h>

static kobj_notify_list_t kctl_mod_notifiers[] = {
	{ kctl_mod_changed, KOBJ_NOTIFY_MODLOADED },
	{ kctl_mod_changed, KOBJ_NOTIFY_MODUNLOADING },
	{ NULL, 0 }
};

int
kctl_mod_decompress(struct modctl *modp)
{
	ctf_file_t *fp;
	struct module *mp = modp->mod_mp;
	int rc;

	if ((kmdb_kdi_get_flags() & KMDB_KDI_FL_NOCTF) || mp->ctfdata == NULL)
		return (0);

	if ((fp = ctf_modopen(mp, &rc)) == NULL)
		return (rc);

	ctf_close(fp);

	return (0);
}

void
kctl_mod_loaded(struct modctl *modp)
{
	int rc;

	mutex_enter(&mod_lock);
	if (modp->mod_mp == NULL) {
		mutex_exit(&mod_lock);
		return;
	}

	if ((rc = kctl_mod_decompress(modp)) != 0) {
		cmn_err(CE_WARN, "failed to decompress CTF data for %s: %s\n",
		    modp->mod_modname, ctf_errmsg(rc));
	}
	mutex_exit(&mod_lock);

	if (!(kmdb_kdi_get_flags() & KMDB_KDI_FL_NOMODS))
		kctl_dmod_autoload(modp->mod_modname);
}

/*ARGSUSED*/
void
kctl_mod_changed(uint_t why, struct modctl *what)
{
	if (why == KOBJ_NOTIFY_MODLOADED)
		kctl_mod_loaded(what);
}

/*
 * Tell krtld to notify kmdb when modules have been loaded and unloaded
 */
void
kctl_mod_notify_reg(void)
{
	kobj_notify_list_t *kn;

	for (kn = kctl_mod_notifiers; kn->kn_func != NULL; kn++)
		(void) kobj_notify_add(kn);
}

void
kctl_mod_notify_unreg(void)
{
	kobj_notify_list_t *kn;

	for (kn = kctl_mod_notifiers; kn->kn_func != NULL; kn++)
		(void) kobj_notify_remove(kn);
}
