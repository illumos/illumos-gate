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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * Kernel Sensor Framework
 *
 * The kernel sensor framework exists to provide a simple and straightforward
 * means for various parts of the system to declare and instantiate sensor
 * information. Between this and the ksensor character device
 * (uts/common/io/ksensor/ksensor_drv.c) this exposes per-device sensors and
 * character devices.
 *
 * --------------------------
 * Driver and User Interfaces
 * --------------------------
 *
 * Each sensor that is registered with the framework is exposed as a character
 * device under /dev/sensors. The device class and node name are often ':'
 * delineated and must begin with 'ddi_sensor'. Everything after 'ddi_sensor'
 * will be created in a directory under /dev/sensors. So for example the Intel
 * PCH driver uses a class "ddi_sensor:temperature:pch" and a node name of
 * 'ts.%d'. This creates the node /dev/sensors/temperature/pch/ts.0. The
 * devfsadm plugin automatically handles the creation of directories which makes
 * the addition of additional sensor types easy to create.
 *
 * Strictly speaking, any device can manage their own sensors and minor nodes by
 * using the appropriate class and implementing the corresponding ioctls. That
 * was how the first kernel sensors were written; however, there are a lot of
 * issues with that which led to this:
 *
 * 1. Every driver had to actually implement character devices.
 *
 * 2. Every driver had to duplicate a lot of the logic around open(9E),
 *    close(9E), and ioctl(9E).
 *
 * 3. Drivers that tied into frameworks like mac(9E) or SCSAv3 needed a lot more
 *    work to fit into this model. For example, because the minor state is
 *    shared between all the instances and the frameworks, they would have
 *    required shared, global state that they don't have today.
 *
 * Ultimately, having an operations vector and a callback argument makes work a
 * lot simpler for the producers of sensor data and that simplicity makes it
 * worthwhile to take on additional effort and work here.
 *
 * ----------
 * Components
 * ----------
 *
 * The ksensor framework is made of a couple of different pieces:
 *
 * 1. This glue that is a part of genunix.
 * 2. The ksensor character device driver.
 * 3. Sensor providers, which are generally drivers that register with the
 *    ksensor framework.
 *
 * The implementation of (1) is all in this file. The implementation of (2) is
 * in uts/common/io/ksensor/ksensor_drv.c. The implementation of (3) is found in
 * all of the different leaf devices. Examples of (3) include pchtemp(4D) and
 * igb(4D).
 *
 * We separate numbers one and two into two different components for a few
 * reasons. The most important thing is that drivers that provide sensors should
 * not be dependent on some other part of the system having been loaded. This
 * makes a compelling argument for it being a part of the core kernel. However,
 * like other subsystems (e.g. kstats, smbios, etc.), it's useful to separate
 * out the thing that provides the interface to users with the thing that is
 * used to glue together providers in the kernel. There's the added benefit that
 * it's practically simpler to spin up a pseudo-device through a module.
 *
 * The ksensor character device driver (2) registers with the main genunix
 * ksensor code (1) when it attaches and when it detaches. The kernel only
 * allows a single driver to be attached to it. When that character device
 * driver attaches, the ksensor framework will walk through all of the currently
 * registered sensors and inform the character device driver of the nodes that
 * it needs to create. While the character device driver is attached, the
 * ksensor framework will also call back into it when a sensor needs to be
 * removed.
 *
 * Generally speaking, this distinction of responsibilities allows the kernel
 * sensor character device driver to attach and detach without impact to the
 * sensor providers or them even being notified at all, it's all transparent to
 * them.
 *
 * ------------------------------
 * Sensor Lifetime and detach(9E)
 * ------------------------------
 *
 * Traditionally, a device driver may be detached by the broader kernel whenever
 * the kernel desires it. On debug builds this happens by a dedicated thread. On
 * a non-debug build this may happen due to memory pressure or as an attempt to
 * reclaim idle resources (though this is much less common). However, when the
 * module is detached, the system remembers that minor nodes previously existed
 * and that entries in /devices had been created. When something proceeds to
 * access an entry in /devices again, the system will use that to bring a driver
 * back to life. It doesn't matter whether it's a pseudo-device driver or
 * something else, this can happen.
 *
 * One downside to the sensor framework, is that we need to emulate this
 * behavior which leads to some amount of complexity here. But this is a
 * worthwhile tradeoff as it makes things much simpler for providers and it's
 * not too hard for us to emulate this behavior.
 *
 * When a sensor provider registers the sensor, the sensor becomes available to
 * the system. When the sensor provider unregisters with the system, which
 * happens during its detach routine, then we note that it has been detached;
 * however, we don't delete its minor node and if something accesses it, we
 * attempt to load the driver again, the same way that devfs (the file system
 * behind /devices) does.
 *
 * For each dev_info_t that registers a sensor we register a callback such that
 * when the device is removed, e.g. someone called rem_drv or physically pulls
 * the device, then we'll be able to finally clean up the device. This lifetime
 * can be represented in the following image:
 *
 *         |
 *         |
 *         +-----<-------------------------------------+
 *         |                                           |
 *         | . . call ksensor_create()                 |
 *         v                                           |
 *     +-------+                                       |
 *     | Valid |                                       |
 *     +-------+                                       |
 *         |                                           ^
 *         | . . call ksensor_remove()                 |
 *         v                                           |
 *    +---------+                                      |
 *    | Invalid |                                      |
 *    +---------+                                      |
 *      |     |                                        |
 *      |     | . . user uses sensor again             |
 *      |     |                                        |
 *      |     +-------------------+                    |
 *      |                         |                    |
 *      |                         v                    |
 *      |                 +---------------+            |
 *      |                 | Attatching... |-->---------+
 *      |                 +---------------+
 *      | . . ddi unbind cb       |
 *      |                         |
 *      v                         | . . attatch fails or
 *   +---------+                  |     no call to ksensor_create()
 *   | Deleted |--<---------------+     again
 *   +---------+
 *
 * When the DDI unbind callback is called, we know that the device is going to
 * be removed. However, this happens within a subtle context with a majority of
 * the device tree held (at least the dip's parent). In particular, another
 * thread may be trying to obtain a hold on it and be blocked in
 * ndi_devi_enter(). As the callback thread holds that, that could lead to a
 * deadlock. As a result, we clean things up in two phases. One during the
 * synchronous callback and the other via a taskq. In the first phase we
 * logically do the following:
 *
 *  o Remove the dip from the list of ksensor dips and set the flag that
 *    indicates that it's been removed.
 *  o Remove all of the sensors from the global avl to make sure that new
 *    threads cannot look it up.
 *
 * Then, after the taskq is dispatched, we do the following in taskq context:
 *
 *  o Tell the ksensor driver that it should remove the minor node.
 *  o Block on each sensor until it is no-longer busy and then clean it up.
 *  o Clean up the ksensor_dip_t.
 *
 * ------------------
 * Accessing a Sensor
 * ------------------
 *
 * Access to a particular sensor is serialized in the system. In addition to
 * that, a number of steps are required to access one that is not unlike
 * accessing a character device. When a given sensor is held the KSENSOR_F_BUSY
 * flag is set in the ksensor_flags member. In addition, as part of taking a
 * hold a number of side effects occur that ensure that the sensor provider's
 * dev_info_t is considered busy and can't be detached.
 *
 * To obtain a hold on a sensor the following logical steps are required (see
 * ksensor_hold_by_id() for the implementation):
 *
 *  1. Map the minor to the ksensor_t via the avl tree
 *  2. Check that the ksensor's dip is valid
 *  3. If the sensor is busy, wait until it is no longer so, and restart from
 *     the top. Otherwise, mark the sensor as busy.
 *  4. Enter the parent and place a hold on the sensor provider's dip.
 *  5. Once again check if the dip is removed or not because we have to drop
 *     locks during that operation.
 *  6. Check if the ksensor has the valid flag set. If not, attempt to configure
 *     the dip.
 *  7. Assuming the sensor is now valid, we can return it.
 *
 * After this point, the sensor is considered valid for use. Once the consumer
 * is finished with the sensor, it should be released by calling
 * ksensor_release().
 *
 * An important aspect of the above scheme is that the KSENSOR_F_BUSY flag is
 * required to progress through the validation and holding of the device. This
 * makes sure that only one thread is attempting to attach it at a given time. A
 * reasonable future optimization would be to amortize this cost in open(9E)
 * and close(9E) of the minor and to bump a count as it being referenced as long
 * as it is open.
 *
 * -----------------------------
 * Character Device Registration
 * -----------------------------
 *
 * The 'ksensor' character device driver can come and go. To support this, the
 * ksensor framework communicates with the ksensor character device by a
 * well-defined set of callbacks, used to indicate sensor addition and removal.
 * The ksensor character device is found in uts/common/io/ksensor/ksensor_drv.c.
 * The ksensor character device is responsible for creating and destroying minor
 * nodes.
 *
 * Each ksensor_t has a flag, KSENSOR_F_NOTIFIED, that is used to indicate
 * whether or not the registered driver has been notified of the sensor. When a
 * callback is first registered, we'll walk through the entire list of nodes to
 * make sure that its minor has been created. When unregistering, the minor node
 * remove callback will not be called; however, this can generally by dealt with
 * by calling something like ddi_remove_minor_node(dip, NULL).
 *
 * -------
 * Locking
 * -------
 *
 * The following rules apply to dealing with lock ordering:
 *
 * 1. The global ksensor_g_mutex protects all global data and must be taken
 *    before a ksensor_t's individual mutex.
 *
 * 2. A thread should not hold any two ksensor_t's mutex at any time.
 *
 * 3. No locks should be held when attempting to grab or manipulate a
 *    dev_info_t, e.g. ndi_devi_enter().
 *
 * 4. Unless the ksensor is actively being held, whenever a ksensor is found,
 *    one must check whether the ksensor_dip_t flag KSENSOR_DIP_F_REMOVED is
 *    set or not and whether the ksensor_t's KSENSOR_F_VALID flag is set.
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/esunddi.h>
#include <sys/ksensor_impl.h>
#include <sys/ddi_impldefs.h>
#include <sys/pci.h>
#include <sys/avl.h>
#include <sys/list.h>
#include <sys/stddef.h>
#include <sys/sysmacros.h>
#include <sys/fs/dv_node.h>

typedef enum {
	/*
	 * This flag indicates that the subscribing ksensor character device has
	 * been notified about this flag.
	 */
	KSENSOR_F_NOTIFIED	= 1 << 0,
	/*
	 * This indicates that the sensor is currently valid, meaning that the
	 * ops vector and argument are safe to use. This is removed when a
	 * driver with a sensor is detached.
	 */
	KSENSOR_F_VALID		= 1 << 1,
	/*
	 * Indicates that a client has a hold on the sensor for some purpose.
	 * This must be set before trying to get an NDI hold. Once this is set
	 * and a NDI hold is in place, it is safe to use the operations vector
	 * and argument.
	 */
	KSENSOR_F_BUSY		= 1 << 2,
} ksensor_flags_t;

typedef enum {
	KSENSOR_DIP_F_REMOVED	= 1 << 0
} ksensor_dip_flags_t;

typedef struct {
	list_node_t ksdip_link;
	ksensor_dip_flags_t ksdip_flags;
	dev_info_t *ksdip_dip;
	ddi_unbind_callback_t ksdip_cb;
	list_t ksdip_sensors;
} ksensor_dip_t;

typedef struct {
	kmutex_t ksensor_mutex;
	kcondvar_t ksensor_cv;
	ksensor_flags_t ksensor_flags;
	list_node_t ksensor_dip_list;
	avl_node_t ksensor_id_avl;
	uint_t ksensor_nwaiters;
	ksensor_dip_t *ksensor_ksdip;
	char *ksensor_name;
	char *ksensor_class;
	id_t ksensor_id;
	const ksensor_ops_t *ksensor_ops;
	void *ksensor_arg;
} ksensor_t;

static kmutex_t ksensor_g_mutex;
static id_space_t *ksensor_ids;
static list_t ksensor_dips;
static avl_tree_t ksensor_avl;
static dev_info_t *ksensor_cb_dip;
static ksensor_create_f ksensor_cb_create;
static ksensor_remove_f ksensor_cb_remove;

static int
ksensor_avl_compare(const void *l, const void *r)
{
	const ksensor_t *kl = l;
	const ksensor_t *kr = r;

	if (kl->ksensor_id > kr->ksensor_id) {
		return (1);
	} else if (kl->ksensor_id < kr->ksensor_id) {
		return (-1);
	} else {
		return (0);
	}
}

static ksensor_t *
ksensor_find_by_id(id_t id)
{
	ksensor_t k, *ret;

	ASSERT(MUTEX_HELD(&ksensor_g_mutex));

	k.ksensor_id = id;
	return (avl_find(&ksensor_avl, &k, NULL));

}

static ksensor_t *
ksensor_search_ksdip(ksensor_dip_t *ksdip, const char *name, const char *class)
{
	ksensor_t *s;

	ASSERT(MUTEX_HELD(&ksensor_g_mutex));

	for (s = list_head(&ksdip->ksdip_sensors); s != NULL;
	    s = list_next(&ksdip->ksdip_sensors, s)) {
		if (strcmp(s->ksensor_name, name) == 0 &&
		    strcmp(s->ksensor_class, class) == 0) {
			return (s);
		}
	}

	return (NULL);
}

static void
ksensor_free_sensor(ksensor_t *sensor)
{
	strfree(sensor->ksensor_name);
	strfree(sensor->ksensor_class);
	id_free(ksensor_ids, sensor->ksensor_id);
	mutex_destroy(&sensor->ksensor_mutex);
	kmem_free(sensor, sizeof (ksensor_t));
}

static void
ksensor_free_dip(ksensor_dip_t *ksdip)
{
	list_destroy(&ksdip->ksdip_sensors);
	kmem_free(ksdip, sizeof (ksensor_dip_t));
}

static void
ksensor_dip_unbind_taskq(void *arg)
{
	ksensor_dip_t *k = arg;
	ksensor_t *sensor;

	/*
	 * First notify an attached driver that the nodes are going away
	 * before we block and wait on them.
	 */
	mutex_enter(&ksensor_g_mutex);
	for (sensor = list_head(&k->ksdip_sensors); sensor != NULL;
	    sensor = list_next(&k->ksdip_sensors, sensor)) {
		mutex_enter(&sensor->ksensor_mutex);
		if (sensor->ksensor_flags & KSENSOR_F_NOTIFIED) {
			ksensor_cb_remove(sensor->ksensor_id,
			    sensor->ksensor_name);
			sensor->ksensor_flags &= ~KSENSOR_F_NOTIFIED;
		}
		mutex_exit(&sensor->ksensor_mutex);
	}
	mutex_exit(&ksensor_g_mutex);

	/*
	 * Now that the driver has destroyed its minor, wait for anything that's
	 * still there.
	 */
	while ((sensor = list_remove_head(&k->ksdip_sensors)) != NULL) {
		mutex_enter(&sensor->ksensor_mutex);
		while ((sensor->ksensor_flags & KSENSOR_F_BUSY) != 0 ||
		    sensor->ksensor_nwaiters > 0) {
			cv_wait(&sensor->ksensor_cv, &sensor->ksensor_mutex);
		}
		mutex_exit(&sensor->ksensor_mutex);
		ksensor_free_sensor(sensor);
	}
	ksensor_free_dip(k);
}

static void
ksensor_dip_unbind_cb(void *arg, dev_info_t *dip)
{
	ksensor_dip_t *k = arg;
	ksensor_t *sensor;

	/*
	 * Remove the dip and the associated sensors from global visibility.
	 * This will ensure that no new clients can find this; however, others
	 * may have extent attempts to grab it (but lost the race in an NDI
	 * hold).
	 */
	mutex_enter(&ksensor_g_mutex);
	list_remove(&ksensor_dips, k);
	k->ksdip_flags |= KSENSOR_DIP_F_REMOVED;
	for (sensor = list_head(&k->ksdip_sensors); sensor != NULL;
	    sensor = list_next(&k->ksdip_sensors, sensor)) {
		avl_remove(&ksensor_avl, sensor);
	}
	mutex_exit(&ksensor_g_mutex);

	(void) taskq_dispatch(system_taskq, ksensor_dip_unbind_taskq, k,
	    TQ_SLEEP);
}

static ksensor_dip_t *
ksensor_dip_create(dev_info_t *dip)
{
	ksensor_dip_t *k;

	k = kmem_zalloc(sizeof (ksensor_dip_t), KM_SLEEP);
	k->ksdip_dip = dip;
	k->ksdip_cb.ddiub_cb = ksensor_dip_unbind_cb;
	k->ksdip_cb.ddiub_arg = k;
	list_create(&k->ksdip_sensors, sizeof (ksensor_t),
	    offsetof(ksensor_t, ksensor_dip_list));
	e_ddi_register_unbind_callback(dip, &k->ksdip_cb);

	return (k);
}

static ksensor_dip_t *
ksensor_dip_find(dev_info_t *dip)
{
	ksensor_dip_t *k;

	ASSERT(MUTEX_HELD(&ksensor_g_mutex));
	for (k = list_head(&ksensor_dips); k != NULL;
	    k = list_next(&ksensor_dips, k)) {
		if (dip == k->ksdip_dip) {
			return (k);
		}
	}

	return (NULL);
}

int
ksensor_create(dev_info_t *dip, const ksensor_ops_t *ops, void *arg,
    const char *name, const char *class, id_t *idp)
{
	ksensor_dip_t *ksdip;
	ksensor_t *sensor;

	if (dip == NULL || ops == NULL || name == NULL || class == NULL ||
	    idp == NULL) {
		return (EINVAL);
	}

	if (!DEVI_IS_ATTACHING(dip)) {
		return (EAGAIN);
	}

	mutex_enter(&ksensor_g_mutex);
	ksdip = ksensor_dip_find(dip);
	if (ksdip == NULL) {
		ksdip = ksensor_dip_create(dip);
		list_insert_tail(&ksensor_dips, ksdip);
	}

	sensor = ksensor_search_ksdip(ksdip, name, class);
	if (sensor != NULL) {
		ASSERT3P(sensor->ksensor_ksdip, ==, ksdip);
		if ((sensor->ksensor_flags & KSENSOR_F_VALID) != 0) {
			mutex_exit(&ksensor_g_mutex);
			dev_err(dip, CE_WARN, "tried to create sensor %s:%s "
			    "which is currently active", class, name);
			return (EEXIST);
		}

		sensor->ksensor_ops = ops;
		sensor->ksensor_arg = arg;
	} else {
		sensor = kmem_zalloc(sizeof (ksensor_t), KM_SLEEP);
		sensor->ksensor_ksdip = ksdip;
		sensor->ksensor_name = ddi_strdup(name, KM_SLEEP);
		sensor->ksensor_class = ddi_strdup(class, KM_SLEEP);
		sensor->ksensor_id = id_alloc(ksensor_ids);
		sensor->ksensor_ops = ops;
		sensor->ksensor_arg = arg;
		list_insert_tail(&ksdip->ksdip_sensors, sensor);
		avl_add(&ksensor_avl, sensor);
	}

	sensor->ksensor_flags |= KSENSOR_F_VALID;

	if (ksensor_cb_create != NULL) {

		if (ksensor_cb_create(sensor->ksensor_id, sensor->ksensor_class,
		    sensor->ksensor_name) == 0) {
			sensor->ksensor_flags |= KSENSOR_F_NOTIFIED;
		}
	}

	*idp = sensor->ksensor_id;
	mutex_exit(&ksensor_g_mutex);

	return (0);
}

int
ksensor_create_scalar_pcidev(dev_info_t *dip, uint64_t kind,
    const ksensor_ops_t *ops, void *arg, const char *name, id_t *idp)
{
	char *pci_name, *type;
	const char *class;
	int *regs, ret;
	uint_t nregs;
	uint16_t bus, dev;

	switch (kind) {
	case SENSOR_KIND_TEMPERATURE:
		class = "ddi_sensor:temperature:pci";
		break;
	case SENSOR_KIND_VOLTAGE:
		class = "ddi_sensor:voltage:pci";
		break;
	case SENSOR_KIND_CURRENT:
		class = "ddi_sensor:current:pci";
		break;
	default:
		return (ENOTSUP);
	}

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, 0, "device_type",
	    &type) != DDI_PROP_SUCCESS) {
		return (EINVAL);
	}

	if (strcmp(type, "pciex") != 0 && strcmp(type, "pci") != 0) {
		ddi_prop_free(type);
		return (EINVAL);
	}
	ddi_prop_free(type);

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, 0, "reg",
	    &regs, &nregs) != DDI_PROP_SUCCESS) {
		return (EINVAL);
	}

	if (nregs < 1) {
		ddi_prop_free(regs);
		return (EIO);
	}

	bus = PCI_REG_BUS_G(regs[0]);
	dev = PCI_REG_DEV_G(regs[0]);
	ddi_prop_free(regs);

	pci_name = kmem_asprintf("%x.%x:%s", bus, dev, name);

	ret = ksensor_create(dip, ops, arg, pci_name, class, idp);
	strfree(pci_name);
	return (ret);
}

/*
 * When a driver removes a sensor, we basically mark it as invalid. This happens
 * because drivers can detach and we will need to reattach them when the sensor
 * is used again.
 */
int
ksensor_remove(dev_info_t *dip, id_t id)
{
	ksensor_dip_t *kdip;
	ksensor_t *sensor;

	if (!DEVI_IS_ATTACHING(dip) && !DEVI_IS_DETACHING(dip)) {
		return (EAGAIN);
	}

	mutex_enter(&ksensor_g_mutex);
	kdip = ksensor_dip_find(dip);
	if (kdip == NULL) {
		mutex_exit(&ksensor_g_mutex);
		return (ENOENT);
	}

	for (sensor = list_head(&kdip->ksdip_sensors); sensor != NULL;
	    sensor = list_next(&kdip->ksdip_sensors, sensor)) {
		if (sensor->ksensor_id == id || id == KSENSOR_ALL_IDS) {
			mutex_enter(&sensor->ksensor_mutex);
			sensor->ksensor_flags &= ~KSENSOR_F_VALID;
			sensor->ksensor_ops = NULL;
			sensor->ksensor_arg = NULL;
			mutex_exit(&sensor->ksensor_mutex);
		}
	}
	mutex_exit(&ksensor_g_mutex);
	return (0);
}

static void
ksensor_release(ksensor_t *sensor)
{
	dev_info_t *pdip;

	ddi_release_devi(sensor->ksensor_ksdip->ksdip_dip);

	mutex_enter(&sensor->ksensor_mutex);
	sensor->ksensor_flags &= ~KSENSOR_F_BUSY;
	cv_broadcast(&sensor->ksensor_cv);
	mutex_exit(&sensor->ksensor_mutex);
}

static int
ksensor_hold_by_id(id_t id, ksensor_t **outp)
{
	ksensor_t *sensor;
	dev_info_t *pdip;

restart:
	mutex_enter(&ksensor_g_mutex);
	sensor = ksensor_find_by_id(id);
	if (sensor == NULL) {
		mutex_exit(&ksensor_g_mutex);
		*outp = NULL;
		return (ESTALE);
	}

	if ((sensor->ksensor_ksdip->ksdip_flags & KSENSOR_DIP_F_REMOVED) != 0) {
		mutex_exit(&ksensor_g_mutex);
		*outp = NULL;
		return (ESTALE);
	}

	mutex_enter(&sensor->ksensor_mutex);
	if ((sensor->ksensor_flags & KSENSOR_F_BUSY) != 0) {
		mutex_exit(&ksensor_g_mutex);
		sensor->ksensor_nwaiters++;
		while ((sensor->ksensor_flags & KSENSOR_F_BUSY) != 0) {
			int cv = cv_wait_sig(&sensor->ksensor_cv,
			    &sensor->ksensor_mutex);
			if (cv == 0) {
				sensor->ksensor_nwaiters--;
				cv_broadcast(&sensor->ksensor_cv);
				mutex_exit(&sensor->ksensor_mutex);
				*outp = NULL;
				return (EINTR);
			}
		}
		sensor->ksensor_nwaiters--;
		cv_broadcast(&sensor->ksensor_cv);
		mutex_exit(&sensor->ksensor_mutex);
		goto restart;
	}

	/*
	 * We have obtained ownership of the sensor. At this point, we should
	 * check to see if it's valid or not.
	 */
	sensor->ksensor_flags |= KSENSOR_F_BUSY;
	pdip = ddi_get_parent(sensor->ksensor_ksdip->ksdip_dip);
	mutex_exit(&sensor->ksensor_mutex);
	mutex_exit(&ksensor_g_mutex);

	/*
	 * Grab a reference on the device node to ensure that it won't go away.
	 */
	ndi_devi_enter(pdip);
	e_ddi_hold_devi(sensor->ksensor_ksdip->ksdip_dip);
	ndi_devi_exit(pdip);

	/*
	 * Now that we have an NDI hold, check if it's valid or not. It may have
	 * become invalid while we were waiting due to a race.
	 */
	mutex_enter(&ksensor_g_mutex);
	if ((sensor->ksensor_ksdip->ksdip_flags & KSENSOR_DIP_F_REMOVED) != 0) {
		mutex_exit(&ksensor_g_mutex);
		ksensor_release(sensor);
		return (ESTALE);
	}

	mutex_enter(&sensor->ksensor_mutex);
	if ((sensor->ksensor_flags & KSENSOR_F_VALID) == 0) {
		mutex_exit(&sensor->ksensor_mutex);
		mutex_exit(&ksensor_g_mutex);
		(void) ndi_devi_config(pdip, NDI_NO_EVENT);
		mutex_enter(&ksensor_g_mutex);
		mutex_enter(&sensor->ksensor_mutex);

		/*
		 * If we attempted to reattach it and it isn't now valid, fail
		 * this request.
		 */
		if ((sensor->ksensor_ksdip->ksdip_flags &
		    KSENSOR_DIP_F_REMOVED) != 0 ||
		    (sensor->ksensor_flags & KSENSOR_F_VALID) == 0) {
			mutex_exit(&sensor->ksensor_mutex);
			mutex_exit(&ksensor_g_mutex);
			ksensor_release(sensor);
			return (ESTALE);
		}
	}
	mutex_exit(&sensor->ksensor_mutex);
	mutex_exit(&ksensor_g_mutex);
	*outp = sensor;

	return (0);
}

int
ksensor_op_kind(id_t id, sensor_ioctl_kind_t *kind)
{
	int ret;
	ksensor_t *sensor;

	if ((ret = ksensor_hold_by_id(id, &sensor)) != 0) {
		return (ret);
	}

	ret = sensor->ksensor_ops->kso_kind(sensor->ksensor_arg, kind);
	ksensor_release(sensor);

	return (ret);
}

int
ksensor_op_scalar(id_t id, sensor_ioctl_scalar_t *scalar)
{
	int ret;
	ksensor_t *sensor;

	if ((ret = ksensor_hold_by_id(id, &sensor)) != 0) {
		return (ret);
	}

	ret = sensor->ksensor_ops->kso_scalar(sensor->ksensor_arg, scalar);
	ksensor_release(sensor);

	return (ret);
}

void
ksensor_unregister(dev_info_t *reg_dip)
{
	ksensor_t *sensor;

	mutex_enter(&ksensor_g_mutex);
	if (ksensor_cb_dip != reg_dip) {
		dev_err(reg_dip, CE_PANIC, "asked to unregister illegal dip");
	}

	for (sensor = avl_first(&ksensor_avl); sensor != NULL; sensor =
	    AVL_NEXT(&ksensor_avl, sensor)) {
		mutex_enter(&sensor->ksensor_mutex);
		sensor->ksensor_flags &= ~KSENSOR_F_NOTIFIED;
		mutex_exit(&sensor->ksensor_mutex);
	}

	ksensor_cb_dip = NULL;
	ksensor_cb_create = NULL;
	ksensor_cb_remove = NULL;
	mutex_exit(&ksensor_g_mutex);
}

int
ksensor_register(dev_info_t *reg_dip, ksensor_create_f create,
    ksensor_remove_f remove)
{
	ksensor_t *sensor;

	mutex_enter(&ksensor_g_mutex);
	if (ksensor_cb_dip != NULL) {
		dev_err(reg_dip, CE_WARN, "kernel sensors are already "
		    "registered");
		mutex_exit(&ksensor_g_mutex);
		return (EEXIST);
	}

	ksensor_cb_dip = reg_dip;
	ksensor_cb_create = create;
	ksensor_cb_remove = remove;

	for (sensor = avl_first(&ksensor_avl); sensor != NULL; sensor =
	    AVL_NEXT(&ksensor_avl, sensor)) {
		mutex_enter(&sensor->ksensor_mutex);
		ASSERT0(sensor->ksensor_flags & KSENSOR_F_NOTIFIED);

		if (ksensor_cb_create(sensor->ksensor_id, sensor->ksensor_class,
		    sensor->ksensor_name) == 0) {
			sensor->ksensor_flags |= KSENSOR_F_NOTIFIED;
		}

		mutex_exit(&sensor->ksensor_mutex);
	}

	mutex_exit(&ksensor_g_mutex);

	return (0);
}

int
ksensor_kind_temperature(void *unused, sensor_ioctl_kind_t *k)
{
	k->sik_kind = SENSOR_KIND_TEMPERATURE;
	return (0);
}

int
ksensor_kind_current(void *unused, sensor_ioctl_kind_t *k)
{
	k->sik_kind = SENSOR_KIND_CURRENT;
	return (0);
}

int
ksensor_kind_voltage(void *unused, sensor_ioctl_kind_t *k)
{
	k->sik_kind = SENSOR_KIND_VOLTAGE;
	return (0);
}

void
ksensor_init(void)
{
	mutex_init(&ksensor_g_mutex, NULL, MUTEX_DRIVER, NULL);
	list_create(&ksensor_dips, sizeof (ksensor_dip_t),
	    offsetof(ksensor_dip_t, ksdip_link));
	ksensor_ids = id_space_create("ksensor", 1, L_MAXMIN32);
	avl_create(&ksensor_avl, ksensor_avl_compare, sizeof (ksensor_t),
	    offsetof(ksensor_t, ksensor_id_avl));
}
