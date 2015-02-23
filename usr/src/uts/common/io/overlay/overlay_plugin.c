/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Joyent, Inc.
 */

/*
 * Overlay device encapsulation plugin management
 *
 * For more information, see the big theory statement in
 * uts/common/io/overlay/overlay.c
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/errno.h>
#include <sys/sysmacros.h>
#include <sys/modctl.h>

#include <sys/overlay_impl.h>

static kmem_cache_t *overlay_plugin_cache;
static kmutex_t overlay_plugin_lock;
static list_t overlay_plugin_list;

#define	OVERLAY_MODDIR	"overlay"

/* ARGSUSED */
static int
overlay_plugin_cache_constructor(void *buf, void *arg, int kmflags)
{
	overlay_plugin_t *opp = buf;

	mutex_init(&opp->ovp_mutex, NULL, MUTEX_DRIVER, NULL);
	list_link_init(&opp->ovp_link);

	return (0);
}

/* ARGSUSED */
static void
overlay_plugin_cache_destructor(void *buf, void *arg)
{
	overlay_plugin_t *opp = buf;
	ASSERT(list_link_active(&opp->ovp_link) == 0);
	mutex_destroy(&opp->ovp_mutex);
}

void
overlay_plugin_init(void)
{
	mutex_init(&overlay_plugin_lock, NULL, MUTEX_DRIVER, 0);

	/*
	 * In the future we may want to have a reaper to unload unused modules
	 * to help the kernel be able to reclaim memory.
	 */
	overlay_plugin_cache = kmem_cache_create("overlay_plugin_cache",
	    sizeof (overlay_plugin_t), 0, overlay_plugin_cache_constructor,
	    overlay_plugin_cache_destructor, NULL, NULL, NULL, 0);
	list_create(&overlay_plugin_list, sizeof (overlay_plugin_t),
	    offsetof(overlay_plugin_t, ovp_link));
}

void
overlay_plugin_fini(void)
{
	mutex_enter(&overlay_plugin_lock);
	VERIFY(list_is_empty(&overlay_plugin_list));
	mutex_exit(&overlay_plugin_lock);

	list_destroy(&overlay_plugin_list);
	kmem_cache_destroy(overlay_plugin_cache);
	mutex_destroy(&overlay_plugin_lock);
}

overlay_plugin_register_t *
overlay_plugin_alloc(uint_t version)
{
	overlay_plugin_register_t *ovrp;
	/* Version 1 is the only one that exists */
	if (version != OVEP_VERSION_ONE)
		return (NULL);

	ovrp = kmem_zalloc(sizeof (overlay_plugin_register_t), KM_SLEEP);
	ovrp->ovep_version = version;
	return (ovrp);
}

void
overlay_plugin_free(overlay_plugin_register_t *ovrp)
{
	kmem_free(ovrp, sizeof (overlay_plugin_register_t));
}

int
overlay_plugin_register(overlay_plugin_register_t *ovrp)
{
	overlay_plugin_t *opp, *ipp;

	/* Sanity check parameters of the registration */
	if (ovrp->ovep_version != OVEP_VERSION_ONE)
		return (EINVAL);

	if (ovrp->ovep_name == NULL || ovrp->ovep_ops == NULL)
		return (EINVAL);

	if ((ovrp->ovep_flags & ~(OVEP_F_VLAN_TAG)) != 0)
		return (EINVAL);

	if (ovrp->ovep_id_size < 1)
		return (EINVAL);

	/* Don't support anything that has an id size larger than 8 bytes */
	if (ovrp->ovep_id_size > 8)
		return (ENOTSUP);

	if (ovrp->ovep_dest == OVERLAY_PLUGIN_D_INVALID)
		return (EINVAL);

	if ((ovrp->ovep_dest & ~OVERLAY_PLUGIN_D_MASK) != 0)
		return (EINVAL);

	if (ovrp->ovep_ops->ovpo_callbacks != 0)
		return (EINVAL);
	if (ovrp->ovep_ops->ovpo_init == NULL)
		return (EINVAL);
	if (ovrp->ovep_ops->ovpo_fini == NULL)
		return (EINVAL);
	if (ovrp->ovep_ops->ovpo_encap == NULL)
		return (EINVAL);
	if (ovrp->ovep_ops->ovpo_decap == NULL)
		return (EINVAL);
	if (ovrp->ovep_ops->ovpo_socket == NULL)
		return (EINVAL);
	if (ovrp->ovep_ops->ovpo_getprop == NULL)
		return (EINVAL);
	if (ovrp->ovep_ops->ovpo_setprop == NULL)
		return (EINVAL);
	if (ovrp->ovep_ops->ovpo_propinfo == NULL)
		return (EINVAL);


	opp = kmem_cache_alloc(overlay_plugin_cache, KM_SLEEP);
	opp->ovp_active = 0;
	opp->ovp_name = ovrp->ovep_name;
	opp->ovp_ops = ovrp->ovep_ops;
	opp->ovp_props = ovrp->ovep_props;
	opp->ovp_id_size = ovrp->ovep_id_size;
	opp->ovp_flags = ovrp->ovep_flags;
	opp->ovp_dest = ovrp->ovep_dest;

	opp->ovp_nprops = 0;
	if (ovrp->ovep_props != NULL) {
		while (ovrp->ovep_props[opp->ovp_nprops] != NULL) {
			if (strlen(ovrp->ovep_props[opp->ovp_nprops]) >=
			    OVERLAY_PROP_NAMELEN) {
				mutex_exit(&overlay_plugin_lock);
				kmem_cache_free(overlay_plugin_cache, opp);
				return (EINVAL);
			}
			opp->ovp_nprops++;
		}
	}

	mutex_enter(&overlay_plugin_lock);
	for (ipp = list_head(&overlay_plugin_list); ipp != NULL;
	    ipp = list_next(&overlay_plugin_list, ipp)) {
		if (strcmp(ipp->ovp_name, opp->ovp_name) == 0) {
			mutex_exit(&overlay_plugin_lock);
			kmem_cache_free(overlay_plugin_cache, opp);
			return (EEXIST);
		}
	}
	list_insert_tail(&overlay_plugin_list, opp);
	mutex_exit(&overlay_plugin_lock);

	return (0);
}

int
overlay_plugin_unregister(const char *name)
{
	overlay_plugin_t *opp;

	mutex_enter(&overlay_plugin_lock);
	for (opp = list_head(&overlay_plugin_list); opp != NULL;
	    opp = list_next(&overlay_plugin_list, opp)) {
		if (strcmp(opp->ovp_name, name) == 0)
			break;
	}

	if (opp == NULL) {
		mutex_exit(&overlay_plugin_lock);
		return (ENOENT);
	}

	mutex_enter(&opp->ovp_mutex);
	if (opp->ovp_active > 0) {
		mutex_exit(&opp->ovp_mutex);
		mutex_exit(&overlay_plugin_lock);
		return (EBUSY);
	}
	mutex_exit(&opp->ovp_mutex);

	list_remove(&overlay_plugin_list, opp);
	mutex_exit(&overlay_plugin_lock);

	kmem_cache_free(overlay_plugin_cache, opp);
	return (0);
}

overlay_plugin_t *
overlay_plugin_lookup(const char *name)
{
	overlay_plugin_t *opp;
	boolean_t trymodload = B_FALSE;

	for (;;) {
		mutex_enter(&overlay_plugin_lock);
		for (opp = list_head(&overlay_plugin_list); opp != NULL;
		    opp = list_next(&overlay_plugin_list, opp)) {
			if (strcmp(name, opp->ovp_name) == 0) {
				mutex_enter(&opp->ovp_mutex);
				opp->ovp_active++;
				mutex_exit(&opp->ovp_mutex);
				mutex_exit(&overlay_plugin_lock);
				return (opp);
			}
		}
		mutex_exit(&overlay_plugin_lock);

		if (trymodload == B_TRUE)
			return (NULL);

		/*
		 * If we didn't find it, it may still exist, but just not have
		 * been a loaded module. In that case, we'll do one attempt to
		 * load it.
		 */
		if (modload(OVERLAY_MODDIR, (char *)name) == -1)
			return (NULL);
		trymodload = B_TRUE;
	}

}

void
overlay_plugin_rele(overlay_plugin_t *opp)
{
	mutex_enter(&opp->ovp_mutex);
	ASSERT(opp->ovp_active > 0);
	opp->ovp_active--;
	mutex_exit(&opp->ovp_mutex);
}

void
overlay_plugin_walk(overlay_plugin_walk_f func, void *arg)
{
	overlay_plugin_t *opp;
	mutex_enter(&overlay_plugin_lock);
	for (opp = list_head(&overlay_plugin_list); opp != NULL;
	    opp = list_next(&overlay_plugin_list, opp)) {
		if (func(opp, arg) != 0) {
			mutex_exit(&overlay_plugin_lock);
			return;
		}
	}
	mutex_exit(&overlay_plugin_lock);
}
