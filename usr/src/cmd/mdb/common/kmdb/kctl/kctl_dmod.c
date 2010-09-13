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
 * Driver-side functions for loading and unloading dmods.
 */

#include <sys/types.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/modctl.h>
#include <sys/systm.h>
#include <sys/ctf_api.h>
#include <sys/kmdb.h>

#include <kmdb/kctl/kctl.h>
#include <kmdb/kctl/kctl_wr.h>
#include <kmdb/kmdb_wr_impl.h>
#include <kmdb/kmdb_kdi.h>
#include <mdb/mdb_errno.h>

struct modctl		*kdi_dmods;

/*
 * When a load is attempted, a check is first made of the modules on the
 * kctl_dmods list.  If a module is found, the load will not proceed.
 * kctl_dmods_lock must be held while traversing kctl_dmods, and while adding
 * to and subtracting from it.
 */
static struct modctl	kctl_dmods;
static kmutex_t		kctl_dmods_lock;

static kmdb_wr_path_t	*kctl_dmod_path;

/*
 * Used to track outstanding driver-initiated load notifications.  These
 * notifications have been allocated by driver, and thus must be freed by the
 * driver in the event of an emergency unload.  If we don't free them free
 * them ourselves, they'll leak.  Granted, the world is probably melting down
 * at that point, but there's no reason why we shouldn't tidy up the deck
 * chairs before we go.
 */
static kmdb_wr_load_t	*kctl_dmod_loads;
static kmutex_t 	kctl_dmod_loads_lock;

static int
kctl_find_module(char *modname, char *fullname, size_t fullnamelen)
{
	intptr_t fd;
	int i;

	/* If they gave us an absolute path, we don't need to search */
	if (modname[0] == '/') {
		if (strlen(modname) + 1 > fullnamelen) {
			cmn_err(CE_WARN, "Can't load dmod %s - name too long",
			    modname);
			return (0);
		}

		if ((fd = kobj_open(modname)) == -1)
			return (0);
		kobj_close(fd);

		(void) strcpy(fullname, modname);

		return (1);
	}

	for (i = 0; kctl_dmod_path->dpth_path[i] != NULL; i++) {
		const char *path = kctl_dmod_path->dpth_path[i];

		if (strlen(path) + 1 + strlen(modname) + 1 > fullnamelen) {
			kctl_dprintf("Can't load dmod from %s/%s - "
			    "name too long", path, modname);
			continue;
		}

		(void) snprintf(fullname, fullnamelen, "%s/%s", path, modname);

		if ((fd = kobj_open(fullname)) == -1)
			continue;

		kobj_close(fd);

		kctl_dprintf("kobj_open %s found", fullname);

		/* Found it */
		return (1);
	}

	/* No luck */
	return (0);
}

static void
kctl_dlr_free(kmdb_wr_load_t *dlr)
{
	if (dlr->dlr_node.wn_flags & WNFLAGS_NOFREE)
		return;

	kctl_strfree(dlr->dlr_fname);
	kmem_free(dlr, sizeof (kmdb_wr_load_t));
}

int
kctl_dmod_load(kmdb_wr_load_t *dlr)
{
	struct modctl *modp;
	char modpath[MAXPATHLEN];
	const char *modname = kctl_basename(dlr->dlr_fname);
	int rc;

	mutex_enter(&kctl_dmods_lock);

	/* Have we already loaded this dmod? */
	for (modp = kctl_dmods.mod_next; modp != &kctl_dmods;
	    modp = modp->mod_next) {
		if (strcmp(modname, modp->mod_modname) == 0) {
			mutex_exit(&kctl_dmods_lock);
			dlr->dlr_errno = EEXIST;
			return (-1);
		}
	}

	/*
	 * If we find something that looks like a dmod, create a modctl for it,
	 * and add said modctl to our dmods list.  This will allow us to drop
	 * the dmods lock, while still preventing duplicate loads.  If we aren't
	 * able to actually load the dmod, we can always remove the modctl
	 * later.
	 */
	if (!kctl_find_module(dlr->dlr_fname, modpath, sizeof (modpath))) {
		mutex_exit(&kctl_dmods_lock);
		dlr->dlr_errno = ENOENT;
		return (-1);
	}

	modp = kobj_zalloc(sizeof (struct modctl), KM_SLEEP);

	modp->mod_filename = kctl_strdup(modpath);
	modp->mod_modname = kctl_basename(modp->mod_filename);
	modp->mod_busy = 1;
	modp->mod_loadflags |= MOD_NOAUTOUNLOAD | MOD_NONOTIFY;
	modp->mod_next = &kctl_dmods;
	modp->mod_prev = kctl_dmods.mod_prev;
	modp->mod_prev->mod_next = modp;
	kctl_dmods.mod_prev = modp;

	mutex_exit(&kctl_dmods_lock);

	if (kctl.kctl_boot_ops == NULL)
		rc = kobj_load_module(modp, 0);
	else
		rc = kobj_load_primary_module(modp);

	if (rc != 0) {
		kctl_warn("failed to load dmod %s", modp->mod_modname);

		if (kctl.kctl_boot_ops == NULL)
			mod_release_requisites(modp);

		mutex_enter(&kctl_dmods_lock);
		modp->mod_next->mod_prev = modp->mod_prev;
		modp->mod_prev->mod_next = modp->mod_next;
		mutex_exit(&kctl_dmods_lock);

		kctl_strfree(modp->mod_filename);
		kobj_free(modp, sizeof (struct modctl));

		dlr->dlr_errno = EMDB_NOMOD;
		return (-1);
	}

	/*
	 * It worked!  If the module has any CTF data, decompress it, and make a
	 * note of the load.
	 */
	mutex_enter(&mod_lock);
	if ((rc = kctl_mod_decompress(modp)) != 0) {
		kctl_warn("failed to decompress CTF data for dmod %s: %s",
		    modpath, ctf_errmsg(rc));
	}
	mutex_exit(&mod_lock);

	kctl_dprintf("loaded dmod %s at %p", modpath, modp);

	modp->mod_ref = 1;
	modp->mod_loaded = 1;

	dlr->dlr_modctl = modp;

	return (0);
}

/*
 * Driver-initiated loads.  Load the module and announce it to the debugger.
 */
void
kctl_dmod_autoload(const char *fname)
{
	kmdb_wr_load_t *dlr;

	dlr = kobj_zalloc(sizeof (kmdb_wr_load_t), KM_SLEEP);
	dlr->dlr_node.wn_task = WNTASK_DMOD_LOAD;
	dlr->dlr_fname = kctl_strdup(fname);

	/*
	 * If we're loading at boot, the kmdb_wr_load_t will have been
	 * "allocated" by krtld, and will thus not be under the control of
	 * kmem.  We need to ensure that we don't attempt to free it when
	 * we get it back from the debugger.
	 */
	if (kctl.kctl_boot_ops != NULL)
		dlr->dlr_node.wn_flags |= WNFLAGS_NOFREE;

	if (kctl_dmod_load(dlr) < 0) {
		kctl_dlr_free(dlr);
		return;
	}

	/*
	 * Add to the list of open driver-initiated loads.  We need to track
	 * these so we can free them (and thus avoid leaks) in the event that
	 * the debugger needs to be blown away before it can return them.
	 */
	mutex_enter(&kctl_dmod_loads_lock);
	dlr->dlr_next = kctl_dmod_loads;
	if (kctl_dmod_loads != NULL)
		kctl_dmod_loads->dlr_prev = dlr;
	kctl_dmod_loads = dlr;
	mutex_exit(&kctl_dmod_loads_lock);

	kmdb_wr_debugger_notify(dlr);
}

void
kctl_dmod_load_all(void)
{
	/*
	 * The standard list of modules isn't populated until the tail end of
	 * kobj_init().  Prior to that point, the only available list is that of
	 * primaries.  We'll use that if the normal list isn't ready yet.
	 */
	if (modules.mod_mp == NULL) {
		/* modules hasn't been initialized yet -- use primaries */
		struct modctl_list *ml;

		for (ml = kobj_linkmaps[KOBJ_LM_PRIMARY]; ml != NULL;
		    ml = ml->modl_next)
			kctl_dmod_autoload(ml->modl_modp->mod_modname);

	} else {
		struct modctl *modp = &modules;

		do {
			if (modp->mod_mp != NULL)
				kctl_dmod_autoload(modp->mod_modname);
		} while ((modp = modp->mod_next) != &modules);
	}
}

void
kctl_dmod_load_ack(kmdb_wr_load_t *dlr)
{
	/* Remove from the list of open driver-initiated requests */
	mutex_enter(&kctl_dmod_loads_lock);
	if (dlr->dlr_prev == NULL)
		kctl_dmod_loads = dlr->dlr_next;
	else
		dlr->dlr_prev->dlr_next = dlr->dlr_next;

	if (dlr->dlr_next != NULL)
		dlr->dlr_next->dlr_prev = dlr->dlr_prev;
	mutex_exit(&kctl_dmod_loads_lock);

	kctl_dlr_free(dlr);
}

static int
kctl_dmod_unload_common(struct modctl *modp)
{
	struct modctl *m;

	kctl_dprintf("unloading dmod %s", modp->mod_modname);

	mutex_enter(&kctl_dmods_lock);
	for (m = kctl_dmods.mod_next; m != &kctl_dmods; m = m->mod_next) {
		if (m == modp)
			break;
	}
	mutex_exit(&kctl_dmods_lock);

	if (m != modp)
		return (ENOENT);

	/* Found it */
	modp->mod_ref = 0;
	modp->mod_loaded = 0;

	kobj_unload_module(modp);

	mod_release_requisites(modp);

	/* Remove it from our dmods list */
	mutex_enter(&kctl_dmods_lock);
	modp->mod_next->mod_prev = modp->mod_prev;
	modp->mod_prev->mod_next = modp->mod_next;
	mutex_exit(&kctl_dmods_lock);

	kctl_strfree(modp->mod_filename);
	kmem_free(modp, sizeof (struct modctl));

	return (0);
}

void
kctl_dmod_unload(kmdb_wr_unload_t *dur)
{
	int rc;

	if ((rc = kctl_dmod_unload_common(dur->dur_modctl)) != 0) {
		cmn_err(CE_WARN, "unexpected dmod unload failure: %d", rc);
		dur->dur_errno = rc;
	}
}

/*
 * This will be called during shutdown.  The debugger has been stopped, we're
 * off the module notification list, and we've already processed everything in
 * the driver's work queue.  We should have received (and processed) unload
 * requests for each of the dmods we've loaded.  To be safe, however, we'll
 * double-check.
 *
 * If we're doing an emergency shutdown, there may be outstanding
 * driver-initiated messages that haven't been returned to us.  The debugger is
 * dead, so it's not going to be returning them.  We'll leak them unless we
 * find and free them ourselves.
 */
void
kctl_dmod_unload_all(void)
{
	kmdb_wr_load_t *dlr;
	struct modctl *modp;

	while ((modp = kctl_dmods.mod_next) != &kctl_dmods)
		(void) kctl_dmod_unload_common(modp);

	while ((dlr = kctl_dmod_loads) != NULL) {
		kctl_dmod_loads = dlr->dlr_next;

		kctl_dprintf("freed orphan load notification for %s",
		    dlr->dlr_fname);
		kctl_dlr_free(dlr);
	}
}

kmdb_wr_path_t *
kctl_dmod_path_set(kmdb_wr_path_t *pth)
{
	kmdb_wr_path_t *opth;

	if (kctl.kctl_flags & KMDB_F_DRV_DEBUG) {
		if (pth != NULL) {
			int i;
			kctl_dprintf("changing dmod path to: %p", pth);
			for (i = 0; pth->dpth_path[i] != NULL; i++)
				kctl_dprintf(" %s", pth->dpth_path[i]);
		} else {
			kctl_dprintf("changing dmod path to NULL");
		}
	}

	opth = kctl_dmod_path;
	kctl_dmod_path = pth;

	return (opth);
}

void
kctl_dmod_path_reset(void)
{
	kmdb_wr_path_t *pth;

	if ((pth = kctl_dmod_path_set(NULL)) != NULL) {
		WR_ACK(pth);
		kmdb_wr_debugger_notify(pth);
	}
}

void
kctl_dmod_sync(void)
{
	struct modctl *modp;

	/*
	 * kobj_sync() has no visibility into our dmods, so we need to
	 * explicitly tell krtld to export the portions of our dmods that were
	 * allocated using boot scratch memory.
	 */
	for (modp = kctl_dmods.mod_next; modp != &kctl_dmods;
	    modp = modp->mod_next)
		kobj_export_module(modp->mod_mp);
}

void
kctl_dmod_init(void)
{
	mutex_init(&kctl_dmod_loads_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&kctl_dmods_lock, NULL, MUTEX_DRIVER, NULL);

	bzero(&kctl_dmods, sizeof (struct modctl));
	kctl_dmods.mod_next = kctl_dmods.mod_prev = &kctl_dmods;
	kdi_dmods = &kctl_dmods;
}

void
kctl_dmod_fini(void)
{
	mutex_destroy(&kctl_dmods_lock);
	mutex_destroy(&kctl_dmod_loads_lock);
	kdi_dmods = NULL;
}
