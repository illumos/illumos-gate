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
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/avl.h>
#include <sys/ddi_ufm.h>
#include <sys/ddi_ufm_impl.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>
#include <sys/stddef.h>

/*
 * The UFM subsystem tracks its internal state with respect to device
 * drivers that participate in the DDI UFM subsystem on a per-instance basis
 * via ddi_ufm_handle_t structures (see ddi_ufm_impl.h).  This is known as the
 * UFM handle.  The UFM handle contains a pointer to the driver's UFM ops,
 * which the ufm(7D) pseudo driver uses to invoke the UFM entry points in
 * response to DDI UFM ioctls.  Additionally, the DDI UFM subsystem uses the
 * handle to maintain cached UFM image and slot data.
 *
 * In order to track and provide fast lookups of a driver instance's UFM
 * handle, the DDI UFM subsystem stores a pointer to the handle in a global AVL
 * tree. UFM handles are added to the tree when a driver calls ddi_ufm_init(9E)
 * and removed from the tree when a driver calls ddi_ufm_fini(9E).
 *
 * Some notes on the locking strategy/rules.
 *
 * All access to the tree is serialized via the mutex, ufm_lock.
 * Additionally, each UFM handle is protected by a per-handle mutex.
 *
 * Code must acquire ufm_lock in order to walk the tree.  Before reading or
 * modifying the state of any UFM handle, code must then acquire the
 * UFM handle lock.  Once the UFM handle lock has been acquired, ufm_lock
 * should be dropped.
 *
 * Only one UFM handle lock should be held at any time.
 * If a UFM handle lock is held, it must be released before attempting to
 * re-acquire ufm_lock.
 *
 * For example, the lock sequence for calling a UFM entry point and/or
 * reading/modifying UFM handle state would be as follows:
 * - acquire ufm_lock
 * - walk tree to find UFH handle
 * - acquire UFM handle lock
 * - release ufm_lock
 * - call entry point and/or access handle state
 *
 * Testing
 * -------
 * A set of automated tests for the DDI UFM subsystem exists at:
 * usr/src/test/os-tests/tests/ddi_ufm/
 *
 * These tests should be run whenever changes are made to the DDI UFM
 * subsystem or the ufm driver.
 */
static avl_tree_t ufm_handles;
static kmutex_t ufm_lock;

static int ufm_handle_compare(const void *, const void *);

static void
ufm_cache_invalidate(ddi_ufm_handle_t *ufmh)
{
	ASSERT(MUTEX_HELD(&ufmh->ufmh_lock));

	if (ufmh->ufmh_images == NULL)
		return;

	for (uint_t i = 0; i < ufmh->ufmh_nimages; i++) {
		struct ddi_ufm_image *img = &ufmh->ufmh_images[i];

		if (img->ufmi_slots == NULL)
			continue;

		for (uint_t s = 0; s < img->ufmi_nslots; s++) {
			struct ddi_ufm_slot *slot = &img->ufmi_slots[s];

			if (slot->ufms_version != NULL)
				strfree(slot->ufms_version);
			nvlist_free(slot->ufms_misc);
		}
		kmem_free(img->ufmi_slots,
		    (img->ufmi_nslots * sizeof (ddi_ufm_slot_t)));
		if (img->ufmi_desc != NULL)
			strfree(img->ufmi_desc);
		nvlist_free(img->ufmi_misc);
	}

	kmem_free(ufmh->ufmh_images,
	    (ufmh->ufmh_nimages * sizeof (ddi_ufm_image_t)));
	ufmh->ufmh_images = NULL;
	ufmh->ufmh_nimages = 0;
	ufmh->ufmh_caps = 0;
	nvlist_free(ufmh->ufmh_report);
	ufmh->ufmh_report = NULL;
}

static void
free_nvlist_array(nvlist_t **nvlarr, uint_t nelems)
{
	for (uint_t i = 0; i < nelems; i++) {
		if (nvlarr[i] != NULL)
			nvlist_free(nvlarr[i]);
	}
	kmem_free(nvlarr, nelems * sizeof (nvlist_t *));
}

int
ufm_cache_fill(ddi_ufm_handle_t *ufmh)
{
	int ret;
	uint_t nimgs;
	ddi_ufm_cap_t caps;
	nvlist_t **images = NULL, **slots = NULL;

	ASSERT(MUTEX_HELD(&ufmh->ufmh_lock));

	/*
	 * Check whether we already have a cached report and if so, return
	 * straight away.
	 */
	if (ufmh->ufmh_report != NULL)
		return (0);

	/*
	 * First check which UFM caps this driver supports.  If it doesn't
	 * support DDI_UFM_CAP_REPORT, then there's nothing to cache and we
	 * can just return.
	 */
	ret = ufmh->ufmh_ops->ddi_ufm_op_getcaps(ufmh, ufmh->ufmh_arg, &caps);
	if (ret != 0)
		return (ret);

	ufmh->ufmh_caps = caps;
	if ((ufmh->ufmh_caps & DDI_UFM_CAP_REPORT) == 0)
		return (ENOTSUP);

	/*
	 * Next, figure out how many UFM images the device has.  If a
	 * ddi_ufm_op_nimages entry point wasn't specified, then we assume
	 * that the device has a single image.
	 */
	if (ufmh->ufmh_ops->ddi_ufm_op_nimages != NULL) {
		ret = ufmh->ufmh_ops->ddi_ufm_op_nimages(ufmh, ufmh->ufmh_arg,
		    &nimgs);
		if (ret == 0 && nimgs > 0)
			ufmh->ufmh_nimages = nimgs;
		else
			goto cache_fail;
	} else {
		ufmh->ufmh_nimages = 1;
	}

	/*
	 * Now that we know how many images we're dealing with, allocate space
	 * for an appropriately-sized array of ddi_ufm_image_t structs and then
	 * iterate through them calling the ddi_ufm_op_fill_image entry point
	 * so that the driver can fill them in.
	 */
	ufmh->ufmh_images =
	    kmem_zalloc((sizeof (ddi_ufm_image_t) * ufmh->ufmh_nimages),
	    KM_NOSLEEP | KM_NORMALPRI);
	if (ufmh->ufmh_images == NULL)
		return (ENOMEM);

	for (uint_t i = 0; i < ufmh->ufmh_nimages; i++) {
		struct ddi_ufm_image *img = &ufmh->ufmh_images[i];

		ret = ufmh->ufmh_ops->ddi_ufm_op_fill_image(ufmh,
		    ufmh->ufmh_arg, i, img);

		if (ret != 0)
			goto cache_fail;

		if (img->ufmi_desc == NULL || img->ufmi_nslots == 0) {
			ret = EIO;
			goto cache_fail;
		}

		img->ufmi_slots =
		    kmem_zalloc((sizeof (ddi_ufm_slot_t) * img->ufmi_nslots),
		    KM_NOSLEEP | KM_NORMALPRI);
		if (img->ufmi_slots == NULL) {
			ret = ENOMEM;
			goto cache_fail;
		}

		for (uint_t s = 0; s < img->ufmi_nslots; s++) {
			struct ddi_ufm_slot *slot = &img->ufmi_slots[s];

			ret = ufmh->ufmh_ops->ddi_ufm_op_fill_slot(ufmh,
			    ufmh->ufmh_arg, i, s, slot);

			if (ret != 0)
				goto cache_fail;

			ASSERT(slot->ufms_attrs & DDI_UFM_ATTR_EMPTY ||
			    slot->ufms_version != NULL);
		}
	}
	images = kmem_zalloc(sizeof (nvlist_t *) * ufmh->ufmh_nimages,
	    KM_SLEEP);
	for (uint_t i = 0; i < ufmh->ufmh_nimages; i ++) {
		ddi_ufm_image_t *img = &ufmh->ufmh_images[i];

		images[i] = fnvlist_alloc();
		fnvlist_add_string(images[i], DDI_UFM_NV_IMAGE_DESC,
		    img->ufmi_desc);
		if (img->ufmi_misc != NULL) {
			fnvlist_add_nvlist(images[i], DDI_UFM_NV_IMAGE_MISC,
			    img->ufmi_misc);
		}

		slots = kmem_zalloc(sizeof (nvlist_t *) * img->ufmi_nslots,
		    KM_SLEEP);
		for (uint_t s = 0; s < img->ufmi_nslots; s++) {
			ddi_ufm_slot_t *slot = &img->ufmi_slots[s];

			slots[s] = fnvlist_alloc();
			fnvlist_add_uint32(slots[s], DDI_UFM_NV_SLOT_ATTR,
			    slot->ufms_attrs);
			if (slot->ufms_attrs & DDI_UFM_ATTR_EMPTY)
				continue;

			fnvlist_add_string(slots[s], DDI_UFM_NV_SLOT_VERSION,
			    slot->ufms_version);
			if (slot->ufms_misc != NULL) {
				fnvlist_add_nvlist(slots[s],
				    DDI_UFM_NV_SLOT_MISC, slot->ufms_misc);
			}
		}
		fnvlist_add_nvlist_array(images[i], DDI_UFM_NV_IMAGE_SLOTS,
		    slots, img->ufmi_nslots);
		free_nvlist_array(slots, img->ufmi_nslots);
	}
	ufmh->ufmh_report = fnvlist_alloc();
	fnvlist_add_nvlist_array(ufmh->ufmh_report, DDI_UFM_NV_IMAGES, images,
	    ufmh->ufmh_nimages);
	free_nvlist_array(images, ufmh->ufmh_nimages);

	return (0);

cache_fail:
	ufm_cache_invalidate(ufmh);
	return (ret);
}

/*
 * This gets called early in boot by setup_ddi().
 */
void
ufm_init(void)
{
	mutex_init(&ufm_lock, NULL, MUTEX_DEFAULT, NULL);

	avl_create(&ufm_handles, ufm_handle_compare,
	    sizeof (ddi_ufm_handle_t),
	    offsetof(ddi_ufm_handle_t, ufmh_link));
}

static int
ufm_handle_compare(const void *a1, const void *a2)
{
	const struct ddi_ufm_handle *hdl1, *hdl2;
	int cmp;

	hdl1 = (struct ddi_ufm_handle *)a1;
	hdl2 = (struct ddi_ufm_handle *)a2;

	cmp = strcmp(hdl1->ufmh_devpath, hdl2->ufmh_devpath);

	if (cmp > 0)
		return (1);
	else if (cmp < 0)
		return (-1);
	else
		return (0);
}

/*
 * This is used by the ufm driver to lookup the UFM handle associated with a
 * particular devpath.
 *
 * On success, this function returns the reqested UFH handle, with its lock
 * held.  Caller is responsible to dropping the lock when it is done with the
 * handle.
 */
struct ddi_ufm_handle *
ufm_find(const char *devpath)
{
	struct ddi_ufm_handle find = { 0 }, *ufmh;

	(void) strlcpy(find.ufmh_devpath, devpath, MAXPATHLEN);

	mutex_enter(&ufm_lock);
	ufmh = avl_find(&ufm_handles, &find, NULL);
	if (ufmh != NULL)
		mutex_enter(&ufmh->ufmh_lock);
	mutex_exit(&ufm_lock);

	return (ufmh);
}

int
ddi_ufm_init(dev_info_t *dip, uint_t version, ddi_ufm_ops_t *ufmops,
    ddi_ufm_handle_t **ufmh, void *arg)
{
	ddi_ufm_handle_t *old_ufmh;
	char devpath[MAXPATHLEN];

	VERIFY(version != 0 && ufmops != NULL);
	VERIFY(ufmops->ddi_ufm_op_fill_image != NULL &&
	    ufmops->ddi_ufm_op_fill_slot != NULL &&
	    ufmops->ddi_ufm_op_getcaps != NULL);

	if (version < DDI_UFM_VERSION_ONE || version > DDI_UFM_CURRENT_VERSION)
		return (ENOTSUP);

	/*
	 * First we check if we already have a UFM handle for this device
	 * instance.  This can happen if the module got unloaded or the driver
	 * was suspended after previously registering with the UFM subsystem.
	 *
	 * If we find an old handle then we simply reset its state and hand it
	 * back to the driver.
	 *
	 * If we don't find an old handle then this is a new registration, so
	 * we allocate and initialize a new handle.
	 *
	 * In either case, we don't need to NULL-out the other fields (like
	 * ufmh_report) as in order for them to be referenced, ufmh_state has to
	 * first transition to DDI_UFM_STATE_READY.  The only way that can
	 * happen is for the driver to call ddi_ufm_update(), which will call
	 * ufm_cache_invalidate(), which in turn will take care of properly
	 * cleaning up and reinitializing the other fields in the handle.
	 */
	(void) ddi_pathname(dip, devpath);
	if ((old_ufmh = ufm_find(devpath)) != NULL) {
		*ufmh = old_ufmh;
	} else {
		*ufmh = kmem_zalloc(sizeof (ddi_ufm_handle_t), KM_SLEEP);
		(void) strlcpy((*ufmh)->ufmh_devpath, devpath, MAXPATHLEN);
		mutex_init(&(*ufmh)->ufmh_lock, NULL, MUTEX_DEFAULT, NULL);
	}
	(*ufmh)->ufmh_ops = ufmops;
	(*ufmh)->ufmh_arg = arg;
	(*ufmh)->ufmh_version = version;
	(*ufmh)->ufmh_state = DDI_UFM_STATE_INIT;

	/*
	 * If this is a new registration, add the UFM handle to the global AVL
	 * tree of handles.
	 *
	 * Otherwise, if it's an old registration then ufm_find() will have
	 * returned the old handle with the lock already held, so we need to
	 * release it before returning.
	 */
	if (old_ufmh == NULL) {
		mutex_enter(&ufm_lock);
		avl_add(&ufm_handles, *ufmh);
		mutex_exit(&ufm_lock);
	} else {
		mutex_exit(&old_ufmh->ufmh_lock);
	}

	return (DDI_SUCCESS);
}

void
ddi_ufm_fini(ddi_ufm_handle_t *ufmh)
{
	VERIFY(ufmh != NULL);

	mutex_enter(&ufmh->ufmh_lock);
	ufmh->ufmh_state |= DDI_UFM_STATE_SHUTTING_DOWN;
	ufm_cache_invalidate(ufmh);
	mutex_exit(&ufmh->ufmh_lock);
}

void
ddi_ufm_update(ddi_ufm_handle_t *ufmh)
{
	VERIFY(ufmh != NULL);

	mutex_enter(&ufmh->ufmh_lock);
	if (ufmh->ufmh_state & DDI_UFM_STATE_SHUTTING_DOWN) {
		mutex_exit(&ufmh->ufmh_lock);
		return;
	}
	ufm_cache_invalidate(ufmh);
	ufmh->ufmh_state |= DDI_UFM_STATE_READY;
	mutex_exit(&ufmh->ufmh_lock);
}

void
ddi_ufm_image_set_desc(ddi_ufm_image_t *uip, const char *desc)
{
	VERIFY(uip != NULL && desc != NULL);
	if (uip->ufmi_desc != NULL)
		strfree(uip->ufmi_desc);

	uip->ufmi_desc = ddi_strdup(desc, KM_SLEEP);
}

void
ddi_ufm_image_set_nslots(ddi_ufm_image_t *uip, uint_t nslots)
{
	VERIFY(uip != NULL);
	uip->ufmi_nslots = nslots;
}

void
ddi_ufm_image_set_misc(ddi_ufm_image_t *uip, nvlist_t *misc)
{
	VERIFY(uip != NULL && misc != NULL);
	nvlist_free(uip->ufmi_misc);
	uip->ufmi_misc = misc;
}

void
ddi_ufm_slot_set_version(ddi_ufm_slot_t *usp, const char *version)
{
	VERIFY(usp != NULL && version != NULL);
	if (usp->ufms_version != NULL)
		strfree(usp->ufms_version);

	usp->ufms_version = ddi_strdup(version, KM_SLEEP);
}

void
ddi_ufm_slot_set_attrs(ddi_ufm_slot_t *usp, ddi_ufm_attr_t attr)
{
	VERIFY(usp != NULL && attr <= DDI_UFM_ATTR_MAX);
	usp->ufms_attrs = attr;
}

void
ddi_ufm_slot_set_misc(ddi_ufm_slot_t *usp, nvlist_t *misc)
{
	VERIFY(usp != NULL && misc != NULL);
	nvlist_free(usp->ufms_misc);
	usp->ufms_misc = misc;
}
