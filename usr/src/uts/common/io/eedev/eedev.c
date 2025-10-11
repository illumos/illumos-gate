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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * eedev(4D): EEPROM support module.
 *
 * This module exists to make it easier to read and write various eeprom style
 * devices and have a single implementation for the surrounding character glue.
 * It provides and exposes the minor nodes.
 *
 * --------------------------
 * Driver and User Interfaces
 * --------------------------
 *
 * Drivers can register a number of logical devices by creating an eedev_hdl_t
 * and registering it by calling eedev_create(). Once created, the eedev driver
 * creates a corresponding minor node which will show up under /dev/eeprom as
 * /dev/eeprom/<driver>/<instance>/<name>. When the driver doesn't provide a
 * name, "eeprom" is used. The way that this name is communicated to userland
 * and understood by the devfsadm plugin is to use a ':' delineated minor node
 * name. So when we create a node we use "<driver>:<instance>:<name>".
 *
 * As part of registering with us, the driver provides a bunch of information
 * about the device in question including:
 *
 *  1. The overall capacity of the device. We set the 64-bit DDI "Size" property
 *     with this information. This is used by specfs in its VOP_GETATTR()
 *     implementation allowing userland to see the size of the device.
 *
 *  2. The number of bytes per-device logical address. Consider a 512-byte
 *     EEPROM. You can think of this generally as 512 1-byte registers. Some
 *     devices may phrase this as 256 2-byte registers. This is not the same as
 *     a device's page size. A different way to put it is that this is the
 *     device's smallest read and write it can perform.
 *
 *  3. The device also gives us page segment information. This segmentation
 *     information is used to make sure that I/O requests don't cross device
 *     boundaries that would cause the device to read/write from the start of
 *     the segment. For example, a device with a 32-byte page would can only
 *     write bytes in a single 32-byte aligned region at a time. Exceeding this
 *     leads it to continue writing at the start of the 32-byte region.
 *     Something most folks don't want!
 *
 *  4. The device gives us information about the maximum amount of read and
 *     write I/O it can do at any time. This may be a property of the device or
 *     the property of the I/O bus that it's operating on. For example, an I2C
 *     based EEPROM is going to be constrained by its controller. Some SMBus
 *     controllers will limit the I/O to up to 32-bytes.
 *
 * When issuing a read() or write() request, the framework will inherently limit
 * the amount of I/O to be in accordance with this. In addition, today it always
 * returns short reads and short writes. This is that case where read(2) or
 * write(2) say they can return less data than was requested! We mostly do that
 * for simplicity at our end today.
 *
 * Finally, when it comes to device interfaces, we explicitly don't guarantee
 * any serialization to the device. We leave that at the discretion of the
 * device implementer.
 *
 * ----------------
 * Device Lifetimes
 * ----------------
 *
 * A side effect of the eedev pseudo-device owning the minor nodes is that it
 * means there is no way for us to correlate a call to detach() eedev(4D) with
 * that of a driver providing the EEPROM. Effectively, we end up implementing
 * the same logic as /devices. When a device detaches, we don't actually remove
 * the minor node. It is only when the driver is actually removed from the
 * system that we do.
 *
 * Instead, when someone calls open(2) on a device, we will ensure that the
 * provider module is loaded and that it has recreated its existing minor node.
 * Once that happens, as long as someone holds the eedev minor open we will have
 * a corresponding NDI hold on the device, ensuring it cannot disappear until
 * close(2) has been called. There is one bit of trickiness to be aware of: the
 * DDI will call open(2) multiple times, but it will only call close(2) at the
 * final time. In general, this is what we want, but it means that we don't
 * actually track the number of open(2) calls today because everything is using
 * the same minor. If we were to use cloning opens, then that would generally
 * change.
 *
 * This leads to the following overall locking rules:
 *
 *  1. Entering the NDI must be done while no other locks are held. It is
 *     acceptable to put an NDI hold on a parent and then exit the NDI devi
 *     lock.
 *
 *  2. No NDI operations should be performed while holding the eedev mutex. In
 *     particular, alls to ndi_devi_config_one() (or others) should not be
 *     performed while holding locks.
 *
 *  3. The eedev.eedev_mutex should be the first mutex taken in the driver and
 *     used when looking at information about the overall state of the devices
 *     and the corresponding list_t structures. Only one thread should attempt
 *     to call into and bring a driver back to life.
 *
 *  4. When calling into devices to perform read() and write() operations, one
 *     should not hold any locks. In general, only read-only information should
 *     be required in those operations.
 *
 * -----------
 * Future Work
 * -----------
 *
 * There are a few areas and things that the eedev framework doesn't handle
 * today, that we think would be good for the future:
 *
 *  1. It would be nice to have support for FEXCL. We would implement this by
 *     using a cloning open. If we do this, we should also add a corresponding
 *     ioctl() to allow for similar behavior at non-open time that would go
 *     alongside this like we have for other devices with transactions.
 *
 *  2. Today we don't plumb through any information about device security
 *     features. Many devices support some form of write-protection. It would be
 *     good to plumb this through and allow it be set from a series of ioctls
 *     and to have a corresponding user command.
 *
 *  3. It may end up making sense to revisit the constraints that we have around
 *     alignment and not performing read-modify-write if we have devices with a
 *     multi-byte read/write granularity.
 *
 *  4. Similarly, based on experience from additional consumers, we may need to
 *     revisit the fact that we don't try to perform I/O to completion. In
 *     general, these devices are on the smaller end (< 1 MiB) and are not
 *     designed assuming massive I/O, so this is hopefully not a problem.
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/stat.h>
#include <sys/open.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/conf.h>
#include <sys/avl.h>
#include <sys/stddef.h>
#include <sys/sysmacros.h>
#include <sys/id_space.h>
#include <sys/mkdev.h>
#include <sys/sunndi.h>
#include <sys/esunddi.h>
#include <sys/ctype.h>
#include <sys/fs/dv_node.h>

#include "eedev.h"

/*
 * Minimum and maximum minors. These currently are designed to cover devices
 * which keep us in the range of [1, MAXMIN32]. 0 is reserved for a control
 * interface if it's ever required. If we end up with minors that cover user
 * state, then we should create a second range starting at MAXMIN32 + 1 and
 * covering a generous number of entries.
 */
#define	EEDEV_MINOR_MIN	1
#define	EEDEV_MINOR_MAX	MAXMIN32

typedef struct eedev {
	kmutex_t eedev_mutex;
	list_t eedev_list;
	list_t eedev_dips;
	id_space_t *eedev_idspace;
	dev_info_t *eedev_dip;
} eedev_t;

static eedev_t eedev;

typedef enum {
	/*
	 * Indicates that the device should be treated as read-only.
	 */
	EEDEV_F_READ_ONLY	= 1 << 0,
	/*
	 * Indicates that the handle has allocated an id_t for a minor node.
	 */
	EEDEV_F_ID_ALLOC	= 1 << 1,
	/*
	 * Indicates that the appropriate properties have been set on the minor.
	 */
	EEDEV_F_MINOR_PROPS	= 1 << 2,
	/*
	 * Indicates that the actual minor node has been created.
	 */
	EEDEV_F_MINOR_VALID	= 1 << 3,
	/*
	 * Indicates that someone is trying to actively check / validate that
	 * this sensor is usable.
	 */
	EEDEV_F_BUSY		= 1 << 4,
	/*
	 * This indicates that the eeprom driver is currently usable.
	 * Effectively that no one has called detach on the provider driver yet.
	 */
	EEDEV_F_USABLE		= 1 << 5,
	/*
	 * Indicates that this eeprom has a hold on its dev_info_t. This is set
	 * between an open() and close(). Only a single open can set this.
	 */
	EEDEV_F_HELD		= 1 << 6
} eedev_flags_t;

typedef enum {
	EEDEV_DIP_F_REMOVED	= 1 << 0
} eedev_dip_flags_t;

typedef struct eedev_dip {
	list_node_t ed_link;
	dev_info_t *ed_dip;
	char *ed_ua;
	eedev_dip_flags_t ed_flags;
	ddi_unbind_callback_t ed_cb;
	list_t ed_devs;
} eedev_dip_t;

struct eedev_hdl {
	list_node_t eh_link;
	list_node_t eh_dip_link;
	eedev_dip_t *eh_dip;
	kcondvar_t eh_cv;
	void *eh_driver;
	char *eh_name;
	const eedev_ops_t *eh_ops;
	id_t eh_minor;
	dev_t eh_dev;
	uint32_t eh_size;
	uint32_t eh_seg;
	uint32_t eh_read_gran;
	uint32_t eh_write_gran;
	uint32_t eh_max_read;
	uint32_t eh_max_write;
	eedev_flags_t eh_flags;
	uint32_t eh_nwaiters;
};

/*
 * A token number of maximum bytes to read/write in one go to a device if it
 * doesn't give us something more specific. This number was mostly a guess based
 * on common I2C device sizes and the resulting bus utilization time they
 * implied.
 *
 * This value will want to be revisited if SPI devices use this framework. In
 * general, they'd want to be able to at least send a full erased page in a
 * single I/O. They also have a different bus utilization as compared to a 100
 * kHz I2C standard speed, those devices usually run at least at 10 MHz if not
 * faster.
 */
static uint32_t eedev_default_max_io = 128;

static eedev_dip_t *
eedev_dip_find(dev_info_t *dip)
{
	VERIFY(MUTEX_HELD(&eedev.eedev_mutex));
	for (eedev_dip_t *e = list_head(&eedev.eedev_dips); e != NULL;
	    e = list_next(&eedev.eedev_dips, e)) {
		if (dip == e->ed_dip) {
			return (e);
		}
	}

	return (NULL);
}

/*
 * This is used in the various operations to look up an existing eedev based on
 * its dev_t. This is meant to be used by everything other than open(9E), as it
 * will assume that a hold already exists.
 */
static eedev_hdl_t *
eedev_lookup_by_id(dev_t dev)
{
	mutex_enter(&eedev.eedev_mutex);
	for (eedev_hdl_t *h = list_head(&eedev.eedev_list); h != NULL;
	    h = list_next(&eedev.eedev_list, h)) {
		if (h->eh_dev != dev)
			continue;

		if ((h->eh_flags & EEDEV_F_HELD) == 0)
			break;

		mutex_exit(&eedev.eedev_mutex);
		return (h);
	}

	mutex_exit(&eedev.eedev_mutex);
	return (NULL);
}

/*
 * We are called here by one or more threads that are trying to open a specific
 * eeprom. When an eeprom is opened, we may need to cons the provider driver
 * back into existence. We serialize opens, but also have to drop all of our
 * locks along the way.
 *
 * While multiple threads can call open() on the same minor, we will only
 * receive a single close. Therefore, we also need to make sure that we don't go
 * overboard and put too many references on.
 */
static int
eedev_hold_by_id(dev_t dev)
{
	eedev_hdl_t *hdl = NULL;

	mutex_enter(&eedev.eedev_mutex);
	for (eedev_hdl_t *h = list_head(&eedev.eedev_list); h != NULL;
	    h = list_next(&eedev.eedev_list, h)) {
		if (h->eh_dev == dev) {
			hdl = h;
			break;
		}
	}

	if (hdl == NULL) {
		mutex_exit(&eedev.eedev_mutex);
		return (ESTALE);
	}

restart:
	if ((hdl->eh_dip->ed_flags & EEDEV_DIP_F_REMOVED) != 0) {
		mutex_exit(&eedev.eedev_mutex);
		return (ESTALE);
	}

	/*
	 * We have our eeprom. If it's already held, then there's nothing more
	 * for us to do. The kernel guarantees that it won't call close() on
	 * this dev_t while open() is running. If it's not both held and usable
	 * then there is work to do.
	 */
	const eedev_flags_t targ = EEDEV_F_HELD | EEDEV_F_USABLE;
	if ((hdl->eh_flags & targ) == targ) {
		VERIFY0(hdl->eh_flags & EEDEV_F_BUSY);
		mutex_exit(&eedev.eedev_mutex);
		return (0);
	}

	/*
	 * This eeprom isn't both held and usable right now. That means we would
	 * like to hold it and potentially reattach the provider, which means
	 * entering its parent NDI locks. We will indicate that we're trying to
	 * use this node and serialize this.
	 */
	if ((hdl->eh_flags & EEDEV_F_BUSY) != 0) {
		hdl->eh_nwaiters++;
		while ((hdl->eh_flags & EEDEV_F_BUSY) != 0) {
			int cv = cv_wait_sig(&hdl->eh_cv, &eedev.eedev_mutex);
			if (cv == 0) {
				hdl->eh_nwaiters--;
				cv_broadcast(&hdl->eh_cv);
				mutex_exit(&eedev.eedev_mutex);
				return (EINTR);
			}
		}
		hdl->eh_nwaiters--;
		goto restart;
	}

	/*
	 * We technically have ownership of this node now. Set that we're trying
	 * to be the ones to hold it.
	 */
	hdl->eh_flags |= EEDEV_F_BUSY;
	dev_info_t *pdip = ddi_get_parent(hdl->eh_dip->ed_dip);
	mutex_exit(&eedev.eedev_mutex);

	ndi_devi_enter(pdip);
	e_ddi_hold_devi(hdl->eh_dip->ed_dip);
	ndi_devi_exit(pdip);

	/*
	 * Now that we have an NDI hold, check if this is valid or not. There's
	 * a chance we were racing with a detach.
	 */
	mutex_enter(&eedev.eedev_mutex);
	hdl->eh_flags |= EEDEV_F_HELD;

	if ((hdl->eh_dip->ed_flags & EEDEV_DIP_F_REMOVED) != 0) {
		hdl->eh_flags &= ~(EEDEV_F_HELD | EEDEV_F_BUSY);
		cv_broadcast(&hdl->eh_cv);
		mutex_exit(&eedev.eedev_mutex);
		ddi_release_devi(hdl->eh_dip->ed_dip);
		return (ESTALE);
	}

	/*
	 * If it's not usable, try to configure the driver. This requires us to
	 * drop the lock again, and thus have another chance of a race
	 * condition.
	 */
	if ((hdl->eh_dip->ed_flags & EEDEV_F_USABLE) == 0) {
		dev_info_t *child;
		mutex_exit(&eedev.eedev_mutex);
		if (ndi_devi_config_one(pdip, hdl->eh_dip->ed_ua, &child,
		    NDI_CONFIG | NDI_ONLINE_ATTACH | NDI_NO_EVENT) ==
		    NDI_SUCCESS) {
			/*
			 * When this is successful, a hold on the child is
			 * placed. We already have one. Release this one.
			 */
			ddi_release_devi(child);
		}
		mutex_enter(&eedev.eedev_mutex);

		if ((hdl->eh_dip->ed_flags & EEDEV_DIP_F_REMOVED) != 0 ||
		    (hdl->eh_flags & EEDEV_F_USABLE) == 0) {
			hdl->eh_flags &= ~(EEDEV_F_HELD | EEDEV_F_BUSY);
			cv_broadcast(&hdl->eh_cv);
			mutex_exit(&eedev.eedev_mutex);
			ddi_release_devi(hdl->eh_dip->ed_dip);
			return (ESTALE);
		}
	}

	hdl->eh_flags &= ~EEDEV_F_BUSY;
	cv_broadcast(&hdl->eh_cv);
	VERIFY3U(hdl->eh_flags & targ, ==, targ);
	mutex_exit(&eedev.eedev_mutex);

	return (0);
}

static void
eedev_dip_free(eedev_dip_t *e)
{
	list_destroy(&e->ed_devs);
	strfree(e->ed_ua);
	kmem_free(e, sizeof (eedev_dip_t));
}

static void
eedev_free(eedev_hdl_t *eh)
{
	if ((eh->eh_flags & EEDEV_F_MINOR_VALID) != 0) {
		ddi_remove_minor_node(eedev.eedev_dip, eh->eh_name);
		eh->eh_flags &= ~EEDEV_F_MINOR_VALID;
	}

	if ((eh->eh_flags & EEDEV_F_MINOR_PROPS) != 0) {
		(void) ddi_prop_remove(eh->eh_dev, eedev.eedev_dip, "Size");
		eh->eh_flags &= ~EEDEV_F_MINOR_PROPS;
	}

	if ((eh->eh_flags & EEDEV_F_ID_ALLOC) != 0) {
		id_free(eedev.eedev_idspace, eh->eh_minor);
	}

	strfree(eh->eh_name);
	cv_destroy(&eh->eh_cv);
	kmem_free(eh, sizeof (eedev_hdl_t));
}

void
eedev_fini(eedev_hdl_t *eh)
{
	if (eh == NULL) {
		return;
	}

	mutex_enter(&eedev.eedev_mutex);
	VERIFY0(eh->eh_flags & EEDEV_F_HELD);
	VERIFY0(eh->eh_flags & EEDEV_F_BUSY);
	VERIFY3U(eh->eh_flags & EEDEV_F_USABLE, !=, 0);
	eh->eh_flags &= ~EEDEV_F_USABLE;
	eh->eh_ops = NULL;
	eh->eh_driver = NULL;
	mutex_exit(&eedev.eedev_mutex);
}

static void
eedev_dip_unbind_taskq(void *arg)
{
	eedev_hdl_t *hdl;
	eedev_dip_t *ed = arg;

	mutex_enter(&eedev.eedev_mutex);
	while ((hdl = list_remove_head(&ed->ed_devs)) != NULL) {
		while ((hdl->eh_flags & EEDEV_F_BUSY) != 0 ||
		    hdl->eh_nwaiters > 0) {
			cv_wait(&hdl->eh_cv, &eedev.eedev_mutex);
		}
		eedev_free(hdl);
	}

	/*
	 * Ensure that any stale minors that we've created have been removed.
	 */
	(void) devfs_clean(ddi_get_parent(eedev.eedev_dip), NULL, 0);
	eedev_dip_free(ed);
	mutex_exit(&eedev.eedev_mutex);
}

/*
 * We're being called back because a node is being destroyed. Set that this is
 * being removed, remove them from our global lists, and then dispatch a taskq
 * to finish clean up outside of the actual NDI context.
 */
static void
eedev_dip_unbind_cb(void *arg, dev_info_t *dip)
{
	eedev_dip_t *ed = arg;

	mutex_enter(&eedev.eedev_mutex);
	ed->ed_flags |= EEDEV_DIP_F_REMOVED;
	list_remove(&eedev.eedev_dips, ed);

	for (eedev_hdl_t *h = list_head(&ed->ed_devs); h != NULL;
	    h = list_next(&ed->ed_devs, h)) {
		list_remove(&eedev.eedev_list, h);
	}
	mutex_exit(&eedev.eedev_mutex);

	(void) taskq_dispatch(system_taskq, eedev_dip_unbind_taskq, ed,
	    TQ_SLEEP);
}

static eedev_dip_t *
eedev_dip_create(dev_info_t *dip)
{
	eedev_dip_t *e;

	e = kmem_zalloc(sizeof (eedev_dip_t), KM_SLEEP);
	e->ed_dip = dip;
	e->ed_ua = kmem_asprintf("%s@%s", ddi_node_name(dip),
	    ddi_get_name_addr(dip));
	e->ed_cb.ddiub_cb = eedev_dip_unbind_cb;
	e->ed_cb.ddiub_arg = e;
	list_create(&e->ed_devs, sizeof (eedev_hdl_t),
	    offsetof(eedev_hdl_t, eh_dip_link));
	e_ddi_register_unbind_callback(dip, &e->ed_cb);

	return (e);
}

static bool
eedev_minor_create(eedev_hdl_t *hdl)
{
	VERIFY(MUTEX_HELD(&eedev.eedev_mutex));

	hdl->eh_dev = makedevice(ddi_driver_major(eedev.eedev_dip),
	    hdl->eh_minor);

	if ((hdl->eh_flags & EEDEV_F_MINOR_PROPS) == 0) {
		if (ddi_prop_update_int64(hdl->eh_dev, eedev.eedev_dip, "Size",
		    hdl->eh_size) != DDI_PROP_SUCCESS) {
			dev_err(eedev.eedev_dip, CE_WARN, "!failed to set Size "
			    "property for minor %s (%d) for %s%d", hdl->eh_name,
			    hdl->eh_minor, ddi_driver_name(hdl->eh_dip->ed_dip),
			    ddi_get_instance(hdl->eh_dip->ed_dip));
			return (false);
		}
		hdl->eh_flags |= EEDEV_F_MINOR_PROPS;
	}

	if ((hdl->eh_flags & EEDEV_F_MINOR_VALID) == 0) {
		if (ddi_create_minor_node(eedev.eedev_dip, hdl->eh_name,
		    S_IFCHR, hdl->eh_minor, DDI_NT_EEPROM, 0) != DDI_SUCCESS) {
			dev_err(eedev.eedev_dip, CE_WARN, "!failed to create "
			    "eeprom minor %s (%d) for %s%d", hdl->eh_name,
			    hdl->eh_minor, ddi_driver_name(hdl->eh_dip->ed_dip),
			    ddi_get_instance(hdl->eh_dip->ed_dip));
			return (false);
		}
	}

	hdl->eh_flags |= EEDEV_F_MINOR_VALID;
	return (true);
}

int
eedev_create(const eedev_reg_t *reg, eedev_hdl_t **hdlp)
{
	eedev_hdl_t *hdl;
	eedev_dip_t *dip;
	char *name;

	if (reg->ereg_vers != EEDEV_REG_VERS0) {
		return (ENOTSUP);
	}

	if (reg->ereg_size == 0 || reg->ereg_dip == NULL ||
	    reg->ereg_ops == NULL || reg->ereg_ops->eo_read == NULL) {
		return (EINVAL);
	}

	if (!reg->ereg_ro && reg->ereg_ops->eo_write == NULL) {
		return (EINVAL);
	}

	if (reg->ereg_seg > reg->ereg_size ||
	    reg->ereg_read_gran > reg->ereg_size ||
	    reg->ereg_write_gran > reg->ereg_size) {
		return (EINVAL);
	}

	if (reg->ereg_name != NULL) {
		size_t len = strnlen(reg->ereg_name, EEDEV_NAME_MAX);
		if (len >= EEDEV_NAME_MAX || len == 0) {
			return (EINVAL);
		}

		for (size_t i = 0; i < len; i++) {
			if (!ISALNUM(reg->ereg_name[i])) {
				return (EINVAL);
			}
		}
	}

	mutex_enter(&eedev.eedev_mutex);

	/*
	 * Make sure the dip tracking this exists so we can bring this device
	 * back if required.
	 */
	dip = eedev_dip_find(reg->ereg_dip);
	if (dip == NULL) {
		dip = eedev_dip_create(reg->ereg_dip);
		list_insert_tail(&eedev.eedev_dips, dip);
	}

	if (reg->ereg_name != NULL) {
		name = kmem_asprintf("%s:%d:%s", ddi_driver_name(reg->ereg_dip),
		    ddi_get_instance(reg->ereg_dip), reg->ereg_name);
	} else {
		name = kmem_asprintf("%s:%d:eeprom",
		    ddi_driver_name(reg->ereg_dip),
		    ddi_get_instance(reg->ereg_dip));
	}

	/*
	 * Check to see if this handle is something that's come back from the
	 * first time it was created because it was reattached.
	 */
	hdl = NULL;
	for (eedev_hdl_t *h = list_head(&dip->ed_devs); h != NULL;
	    h = list_next(&dip->ed_devs, h)) {
		if (strcmp(h->eh_name, name) == 0) {
			hdl = h;
			break;
		}
	}

	if (hdl != NULL) {
		VERIFY0(hdl->eh_flags & EEDEV_F_USABLE);

		strfree(name);
		name = NULL;
		hdl->eh_ops = reg->ereg_ops;
		hdl->eh_driver = reg->ereg_driver;

		VERIFY3U(hdl->eh_size, ==, reg->ereg_size);
		VERIFY3U(hdl->eh_seg, ==, reg->ereg_seg);
		VERIFY3U(hdl->eh_read_gran, ==, reg->ereg_read_gran);
		VERIFY3U(hdl->eh_write_gran, ==, reg->ereg_write_gran);
		if (reg->ereg_max_read != 0) {
			VERIFY3U(hdl->eh_max_read, ==, reg->ereg_max_read);
		}

		if (reg->ereg_max_write != 0) {
			VERIFY3U(hdl->eh_max_write, ==, reg->ereg_max_write);
		}
	} else {
		hdl = kmem_zalloc(sizeof (eedev_hdl_t), KM_SLEEP);
		cv_init(&hdl->eh_cv, NULL, CV_DRIVER, NULL);
		hdl->eh_dip = dip;
		hdl->eh_driver = reg->ereg_driver;
		hdl->eh_name = name;
		name = NULL;
		hdl->eh_ops = reg->ereg_ops;
		hdl->eh_minor = id_alloc_nosleep(eedev.eedev_idspace);
		if (hdl->eh_minor == -1) {
			eedev_free(hdl);
			return (EOVERFLOW);
		}
		hdl->eh_flags |= EEDEV_F_ID_ALLOC;

		hdl->eh_ops = reg->ereg_ops;
		hdl->eh_driver = reg->ereg_driver;
		hdl->eh_size = reg->ereg_size;
		hdl->eh_seg = reg->ereg_seg;
		hdl->eh_read_gran = reg->ereg_read_gran;
		hdl->eh_write_gran = reg->ereg_write_gran;
		hdl->eh_max_read = reg->ereg_max_read;
		hdl->eh_max_write = reg->ereg_max_write;
		if (hdl->eh_max_read == 0) {
			hdl->eh_max_read = MIN(eedev_default_max_io,
			    hdl->eh_size);
		}

		if (hdl->eh_max_write == 0) {
			hdl->eh_max_write = MIN(eedev_default_max_io,
			    hdl->eh_size);
		}

		if (reg->ereg_ro) {
			hdl->eh_flags |= EEDEV_F_READ_ONLY;
		}

		/*
		 * Check to make sure that this name is unique across all
		 * devices.
		 */
		for (eedev_hdl_t *h = list_head(&eedev.eedev_list); h != NULL;
		    h = list_next(&eedev.eedev_list, h)) {
			if (strcmp(h->eh_name, hdl->eh_name) == 0) {
				eedev_free(hdl);
				mutex_exit(&eedev.eedev_mutex);
				return (EEXIST);
			}
		}

		list_insert_tail(&eedev.eedev_list, hdl);
		list_insert_tail(&dip->ed_devs, hdl);
	}

	/*
	 * Because we're being called and created, by definition this is usable
	 * in the sense that the operations vector and driver has to be valid.
	 */
	hdl->eh_flags |= EEDEV_F_USABLE;

	if (eedev.eedev_dip != NULL) {
		if (!eedev_minor_create(hdl)) {
			list_remove(&eedev.eedev_list, hdl);
			list_remove(&dip->ed_devs, hdl);
			eedev_free(hdl);
			mutex_exit(&eedev.eedev_mutex);
			return (ENXIO);
		}
	}
	mutex_exit(&eedev.eedev_mutex);

	*hdlp = hdl;
	return (0);
}

static int
eedev_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	if (drv_priv(credp) != 0)
		return (EPERM);

	if (otyp != OTYP_CHR)
		return (ENOTSUP);

	/*
	 * In the future we should perform cloning opens to allow for FEXCL
	 * support.
	 */
	if ((flag & (FNDELAY | FNONBLOCK | FEXCL)) != 0)
		return (EINVAL);

	if ((flag & (FREAD | FWRITE)) == 0)
		return (EINVAL);

	/*
	 * Establish a hold on this if doesn't already exist.
	 */
	return (eedev_hold_by_id(*devp));
}

static int
eedev_read(dev_t dev, struct uio *uio, cred_t *credp)
{
	uint32_t page, off, nbytes, end;
	eedev_hdl_t *hdl = eedev_lookup_by_id(dev);

	if (hdl == NULL)
		return (ENXIO);

	if ((uio->uio_fmode & FREAD) == 0)
		return (EBADF);

	if ((uio->uio_fmode & (FNONBLOCK | FNDELAY)) != 0)
		return (EINVAL);

	/*
	 * Determine if this read is aligned. The read granularity
	 * basically tells us the units in which the device reads. It
	 * must be at least one granularity long and granularity
	 * aligned.
	 */
	if ((uio->uio_offset % hdl->eh_read_gran) != 0 ||
	    (uio->uio_resid % hdl->eh_read_gran) != 0) {
		return (EINVAL);
	}

	if (uio->uio_offset >= hdl->eh_size || uio->uio_resid == 0) {
		return (0);
	}

	/*
	 * Determine if we have a page segment to consider. Devices that do
	 * should not cross that in a single I/O.
	 */
	if (hdl->eh_seg != 0) {
		page = uio->uio_offset / hdl->eh_seg;
		off = uio->uio_offset % hdl->eh_seg;
		end = (page + 1) * hdl->eh_seg;
	} else {
		page = 0;
		off = uio->uio_offset;
		end = hdl->eh_size;
	}

	/*
	 * Determine how many bytes to tell the device to read. This is governed
	 * by both how many bytes are left in the device / page region and the
	 * device's maximum read I/O size.
	 */
	nbytes = MIN(uio->uio_resid, end - uio->uio_offset);
	nbytes = MIN(nbytes, hdl->eh_max_read);

	return (hdl->eh_ops->eo_read(hdl->eh_driver, uio, page, off, nbytes));
}

static int
eedev_write(dev_t dev, struct uio *uio, cred_t *credp)
{
	uint32_t page, off, nbytes, end;
	eedev_hdl_t *hdl = eedev_lookup_by_id(dev);

	if (hdl == NULL)
		return (ENXIO);

	if ((uio->uio_fmode & FWRITE) == 0)
		return (EBADF);

	if ((uio->uio_fmode & (FNONBLOCK | FNDELAY)) != 0)
		return (EINVAL);

	/*
	 * Determine if this write is aligned. The write granularity
	 * basically tells us the units in which the device writes. It
	 * must be at least one granularity long and granularity
	 * aligned.
	 */
	if ((uio->uio_offset % hdl->eh_write_gran) != 0 ||
	    (uio->uio_resid % hdl->eh_write_gran) != 0) {
		return (EINVAL);
	}

	if (uio->uio_offset >= hdl->eh_size || uio->uio_resid <= 0) {
		return (EINVAL);
	}

	/*
	 * Determine if we have a page segment to consider. Devices that do
	 * should not cross that in a single I/O.
	 */
	if (hdl->eh_seg != 0) {
		page = uio->uio_offset / hdl->eh_seg;
		off = uio->uio_offset % hdl->eh_seg;
		end = (page + 1) * hdl->eh_seg;
	} else {
		page = 0;
		off = uio->uio_offset;
		end = hdl->eh_size;
	}

	/*
	 * Determine how many bytes to tell the device to write. This is
	 * governed by both how many bytes are left in the device / page region
	 * and the device's maximum write I/O size.
	 */
	nbytes = MIN(uio->uio_resid, end - uio->uio_offset);
	nbytes = MIN(nbytes, hdl->eh_max_write);

	return (hdl->eh_ops->eo_write(hdl->eh_driver, uio, page, off, nbytes));
}

static int
eedev_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	eedev_hdl_t *hdl;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	hdl = eedev_lookup_by_id(dev);
	if (hdl == NULL)
		return (ENXIO);

	/*
	 * If we support FEXCL tagged cloned opens, then we should clean that up
	 * here.
	 */

	/*
	 * This releases our hold on the eeprom provider driver. There may be
	 * other holds if there is more than one EEPROM here.
	 */
	mutex_enter(&eedev.eedev_mutex);
	VERIFY0(hdl->eh_flags & EEDEV_F_BUSY);
	VERIFY3U(hdl->eh_flags & EEDEV_F_HELD, !=, 0);
	VERIFY3U(hdl->eh_flags & EEDEV_F_USABLE, !=, 0);
	hdl->eh_flags &= ~EEDEV_F_HELD;
	mutex_exit(&eedev.eedev_mutex);
	ddi_release_devi(hdl->eh_dip->ed_dip);

	return (0);
}

static struct cb_ops eedev_cb_ops = {
	.cb_open = eedev_open,
	.cb_close = eedev_close,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = eedev_read,
	.cb_write = eedev_write,
	.cb_ioctl = nodev,
	.cb_devmap = nodev,
	.cb_mmap = nodev,
	.cb_segmap = nodev,
	.cb_chpoll = nochpoll,
	.cb_prop_op = ddi_prop_op,
	.cb_flag = D_MP,
	.cb_rev = CB_REV,
	.cb_aread = nodev,
	.cb_awrite = nodev
};


static int
eedev_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd == DDI_RESUME) {
		return (DDI_SUCCESS);
	} else if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (ddi_get_instance(dip) != 0) {
		dev_err(dip, CE_WARN, "only a single instance of eedev is "
		    "supported");
		return (DDI_FAILURE);
	}

	mutex_enter(&eedev.eedev_mutex);
	VERIFY3P(eedev.eedev_dip, ==, NULL);
	eedev.eedev_dip = dip;

	/*
	 * It is possible for devices to have registered prior to us being
	 * attached. Specifically, modules that use eedev have a dependency on
	 * the module, not on an instance. If they have already called
	 * eedev_create(), then they will already be in eedev.eedev_list. We
	 * need to go through and create a minor node now.
	 */
	for (eedev_hdl_t *h = list_head(&eedev.eedev_list); h != NULL;
	    h = list_next(&eedev.eedev_list, h)) {
		eedev_flags_t need = EEDEV_F_MINOR_PROPS | EEDEV_F_MINOR_VALID;
		if ((h->eh_flags & need) != need) {
			(void) eedev_minor_create(h);
		}
	}
	mutex_exit(&eedev.eedev_mutex);

	return (DDI_SUCCESS);
}

static int
eedev_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **outp)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		VERIFY3P(eedev.eedev_dip, !=, NULL);
		*outp = eedev.eedev_dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		VERIFY3P(eedev.eedev_dip, !=, NULL);
		*outp = eedev.eedev_dip;
		*outp = (void *)(uintptr_t)ddi_get_instance(eedev.eedev_dip);
		break;
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
eedev_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd == DDI_SUSPEND) {
		return (DDI_FAILURE);
	} else if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	VERIFY3P(dip, ==, eedev.eedev_dip);
	mutex_enter(&eedev.eedev_mutex);
	if (list_is_empty(&eedev.eedev_list)) {
		mutex_exit(&eedev.eedev_mutex);
		return (DDI_FAILURE);
	}

	ddi_remove_minor_node(eedev.eedev_dip, NULL);
	eedev.eedev_dip = NULL;
	mutex_exit(&eedev.eedev_mutex);

	return (DDI_SUCCESS);
}

static struct dev_ops eedev_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = eedev_getinfo,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = eedev_attach,
	.devo_detach = eedev_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed,
	.devo_cb_ops = &eedev_cb_ops
};

static struct modldrv eedev_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "EEPROM support module",
	.drv_dev_ops = &eedev_dev_ops
};

static struct modlinkage eedev_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &eedev_modldrv, NULL }
};

static int
eedev_mod_init(void)
{
	eedev.eedev_idspace = id_space_create("eedev_minors", EEDEV_MINOR_MIN,
	    EEDEV_MINOR_MAX);
	if (eedev.eedev_idspace == NULL) {
		return (ENOMEM);
	}
	mutex_init(&eedev.eedev_mutex, NULL, MUTEX_DRIVER, NULL);
	list_create(&eedev.eedev_list, sizeof (eedev_hdl_t),
	    offsetof(eedev_hdl_t, eh_link));
	list_create(&eedev.eedev_dips, sizeof (eedev_dip_t),
	    offsetof(eedev_dip_t, ed_link));

	return (0);
}

static void
eedev_mod_fini(void)
{
	list_destroy(&eedev.eedev_dips);
	list_destroy(&eedev.eedev_list);
	mutex_destroy(&eedev.eedev_mutex);
	id_space_destroy(eedev.eedev_idspace);
}

int
_init(void)
{
	int ret;

	if ((ret = eedev_mod_init()) != 0) {
		return (ret);
	}

	if ((ret = mod_install(&eedev_modlinkage)) != 0) {
		eedev_mod_fini();
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&eedev_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&eedev_modlinkage)) == 0) {
		eedev_mod_fini();
	}

	return (ret);
}
