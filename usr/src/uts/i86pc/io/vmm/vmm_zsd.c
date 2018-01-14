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
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <sys/cpuvar.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/ksynch.h>
#include <sys/list.h>
#include <sys/types.h>
#include <sys/vmm.h>
#include <sys/vmm_impl.h>
#include <sys/zone.h>

/*
 * zone specific data
 *
 * Zone specific data is used to keep an association between zones and the vmm
 * instances that may be running in them.  This is used to ensure that vmm
 * instances do not outlive their parent zone.
 *
 * Locking strategy
 *
 * The global vmm_zsd_lock is held while modifying vmm_zsd_list.
 *
 * The per zone vz_lock in vmm_zsd_t is held while reading or writing anything
 * within in vmm_zsd_t instance.  This is important to ensure that there's not
 * an accidental VM creating as a zone is going down.
 */

/*
 * One of these per zone.
 */
struct vmm_zsd {
	list_t		vz_vmms;	/* vmm instances in the zone */
	list_node_t	vz_linkage;	/* link to other zones */
	boolean_t	vz_active;	/* B_FALSE early in shutdown callback */
	zoneid_t	vz_zoneid;
	kmutex_t	vz_lock;
};

static kmutex_t vmm_zsd_lock;		/* Protects vmm_zsd_list */
static list_t vmm_zsd_list;		/* Linkage between all zsd instances */

static zone_key_t vmm_zsd_key;

int
vmm_zsd_add_vm(vmm_softc_t *sc)
{
	vmm_zsd_t *zsd;

	ASSERT(sc->vmm_zone != NULL);

	mutex_enter(&vmm_zsd_lock);

	for (zsd = list_head(&vmm_zsd_list); zsd != NULL;
	    zsd = list_next(&vmm_zsd_list, zsd)) {
		if (zsd->vz_zoneid == sc->vmm_zone->zone_id) {
			break;
		}
	}

	VERIFY(zsd != NULL);
	mutex_exit(&vmm_zsd_lock);

	mutex_enter(&zsd->vz_lock);
	if (!zsd->vz_active) {
		mutex_exit(&zsd->vz_lock);
		return (ENOSYS);
	}

	sc->vmm_zsd = zsd;
	list_insert_tail(&zsd->vz_vmms, sc);

	mutex_exit(&zsd->vz_lock);

	return (0);
}

void
vmm_zsd_rem_vm(vmm_softc_t *sc)
{
	vmm_zsd_t *zsd = sc->vmm_zsd;

	mutex_enter(&zsd->vz_lock);

	list_remove(&zsd->vz_vmms, sc);
	sc->vmm_zsd = NULL;

	mutex_exit(&zsd->vz_lock);
}

static void *
vmm_zsd_create(zoneid_t zid)
{
	vmm_zsd_t *zsd;

	zsd = kmem_zalloc(sizeof (*zsd), KM_SLEEP);

	list_create(&zsd->vz_vmms, sizeof (vmm_softc_t),
	    offsetof(vmm_softc_t, vmm_zsd_linkage));

	zsd->vz_zoneid = zid;

	mutex_init(&zsd->vz_lock, NULL, MUTEX_DEFAULT, NULL);
	zsd->vz_active = B_TRUE;

	mutex_enter(&vmm_zsd_lock);
	list_insert_tail(&vmm_zsd_list, zsd);
	mutex_exit(&vmm_zsd_lock);

	return (zsd);
}

/*
 * Tells all runing VMs in the zone to poweroff.  This does not reclaim guest
 * resources (memory, etc.).
 */
static void
vmm_zsd_shutdown(zoneid_t zid, void *data)
{
	vmm_zsd_t *zsd = data;
	vmm_softc_t *sc;

	mutex_enter(&zsd->vz_lock);
	ASSERT(zsd->vz_active);
	zsd->vz_active = B_FALSE;

	for (sc = list_head(&zsd->vz_vmms); sc != NULL;
	    sc = list_next(&zsd->vz_vmms, sc)) {
		/* Send a poweroff to the VM, whether running or not. */
		(void) vm_suspend(sc->vmm_vm, VM_SUSPEND_POWEROFF);
	}
	mutex_exit(&zsd->vz_lock);
}

/*
 * Reap all VMs that remain and free up guest resources.
 */
static void
vmm_zsd_destroy(zoneid_t zid, void *data)
{
	vmm_zsd_t *zsd = data;
	vmm_softc_t *sc;

	mutex_enter(&zsd->vz_lock);
	ASSERT(!zsd->vz_active);

	while ((sc = list_remove_head(&zsd->vz_vmms)) != NULL) {
		int err;

		/*
		 * This frees all resources associated with the vm, including
		 * sc.
		 */
		err = vmm_do_vm_destroy(sc, B_FALSE);
		ASSERT3S(err, ==, 0);
	}

	mutex_exit(&zsd->vz_lock);
	mutex_destroy(&zsd->vz_lock);

	list_remove(&vmm_zsd_list, zsd);
	kmem_free(zsd, sizeof (*zsd));
}

void
vmm_zsd_init(void)
{
	mutex_init(&vmm_zsd_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&vmm_zsd_list, sizeof (vmm_zsd_t),
	    offsetof(vmm_zsd_t, vz_linkage));
	zone_key_create(&vmm_zsd_key, vmm_zsd_create, vmm_zsd_shutdown,
	    vmm_zsd_destroy);
}

void
vmm_zsd_fini(void)
{
	/* Calls vmm_zsd_destroy() on all zones. */
	zone_key_delete(vmm_zsd_key);
	ASSERT(list_is_empty(&vmm_zsd_list));

	list_destroy(&vmm_zsd_list);
	mutex_destroy(&vmm_zsd_lock);
}
