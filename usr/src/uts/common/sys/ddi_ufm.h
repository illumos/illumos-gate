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

#ifndef _SYS_DDI_UFM_H
#define	_SYS_DDI_UFM_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL
#include <sys/cred.h>
#include <sys/dditypes.h>
#include <sys/nvpair.h>
#include <sys/param.h>
#else
#include <sys/nvpair.h>
#include <sys/param.h>
#include <sys/types.h>
#endif /* _KERNEL */

#define	DDI_UFM_DEV		"/dev/ufm"
#define	DDI_UFM_CURRENT_VERSION	1
#define	DDI_UFM_VERSION_ONE	1

#define	UFM_IOC			('u' << 24) | ('f' << 16) | ('m' << 8)
#define	UFM_IOC_GETCAPS		(UFM_IOC | 1)
#define	UFM_IOC_REPORTSZ	(UFM_IOC | 2)
#define	UFM_IOC_REPORT		(UFM_IOC | 3)
#define	UFM_IOC_MAX		UFM_IOC_REPORT

/*
 * Bitfield enumerating the DDI UFM capabilities supported by this device
 * instance.  Currently there is only a single capability of being able to
 * report UFM information.  Future UFM versions may add additional capabilities
 * such as the ability to obtain a raw dump the firmware image or ability to
 * upgrade the firmware.  When support for new capabilties are added to the DDI
 * UFM subsystem, it should be reflected in this enum and the implementation of
 * the UFM_IOC_GETCAPS should be extended appropriately.
 */
typedef enum {
	DDI_UFM_CAP_REPORT	= 1 << 0,
} ddi_ufm_cap_t;

/*
 * This struct defines the input/output data for the UFM_IOC_GETCAPS ioctl.
 * Callers should specify the ufmg_version and ufmg_devpath fields.  On success
 * the ufmg_caps field will be filled in with a value indicating the supported
 * UFM capabilities of the device specified in ufmg_devpath.
 */
typedef struct ufm_ioc_getcaps {
	uint_t 		ufmg_version;	/* DDI_UFM_VERSION */
	uint_t		ufmg_caps;	/* UFM Caps */
	char 		ufmg_devpath[MAXPATHLEN];
} ufm_ioc_getcaps_t;

/*
 * This struct defines the input/output data for the UFM_IOC_REPORTSZ ioctl.
 * Callers should specify the ufbz_version and ufbz_devpath fields.  On success
 * the ufmg_size field will be filled in with the amount of space (in bytes)
 * required to hold the UFM data for this device instance.  This should be used
 * to allocate a sufficiently size buffer for the UFM_IOC_REPORT ioctl.
 */
typedef struct ufm_ioc_bufsz {
	uint_t 		ufbz_version;	/* DDI_UFM_VERSION */
	size_t		ufbz_size;	/* sz of buf to be returned by ioctl */
	char		ufbz_devpath[MAXPATHLEN];
} ufm_ioc_bufsz_t;

#ifdef _KERNEL
typedef struct ufm_ioc_bufsz32 {
	uint_t		ufbz_version;
	size32_t	ufbz_size;
	char		ufbz_devpath[MAXPATHLEN];
} ufm_ioc_bufsz32_t;
#endif	/* _KERNEL */

/*
 * This struct defines the input/output data for the UFM_IOC_REPORT ioctl.
 * Callers should specify the ufmr_version, ufmr_bufsz and ufmr_devpath fields.
 * On success, the ufmr_buf field will point to a packed nvlist containing the
 * UFM data for the specified device instance.  The value of ufmr_bufsz will be
 * updated to reflect the actual size of data copied out.
 */
typedef struct ufm_ioc_report {
	uint_t		ufmr_version;	/* DDI_UFM_VERSION */
	size_t		ufmr_bufsz;	/* size of caller-supplied buffer */
	caddr_t		ufmr_buf;	/* buf to hold packed output nvl */
	char		ufmr_devpath[MAXPATHLEN];
} ufm_ioc_report_t;

#ifdef _KERNEL
typedef struct ufm_ioc_report32 {
	uint_t		ufmr_version;
	size32_t	ufmr_bufsz;
	caddr32_t	ufmr_buf;
	char		ufmr_devpath[MAXPATHLEN];
} ufm_ioc_report32_t;
#endif	/* _KERNEL */

/*
 * The UFM_IOC_REPORT ioctl return UFM image and slot data in the form of a
 * packed nvlist.  The nvlist contains and array of nvlists (one-per-image).
 * Each image nvlist contains will contain a string nvpair containing a
 * description of the image and an optional nvlist nvpair containing
 * miscellaneous image information.
 */
#define	DDI_UFM_NV_IMAGES		"ufm-images"
#define	DDI_UFM_NV_IMAGE_DESC		"ufm-image-description"
#define	DDI_UFM_NV_IMAGE_MISC		"ufm-image-misc"

/*
 * Each image nvlist also contains an array of nvlists representing the slots.
 */
#define	DDI_UFM_NV_IMAGE_SLOTS		"ufm-image-slots"

/*
 * Each slot nvlist as a string nvpair describing the firmware image version
 * and an uint32 nvpair describing the slot attributes (see ddi_ufm_attr_t
 * above).  An option nvlist nvpar may be present containing additional
 * miscellaneous slot data.
 */
#define	DDI_UFM_NV_SLOT_VERSION		"ufm-slot-version"

typedef enum {
	DDI_UFM_ATTR_READABLE	= 1 << 0,
	DDI_UFM_ATTR_WRITEABLE	= 1 << 1,
	DDI_UFM_ATTR_ACTIVE	= 1 << 2,
	DDI_UFM_ATTR_EMPTY	= 1 << 3
} ddi_ufm_attr_t;

#define	DDI_UFM_ATTR_MAX	DDI_UFM_ATTR_READABLE | \
				DDI_UFM_ATTR_WRITEABLE | \
				DDI_UFM_ATTR_ACTIVE | \
				DDI_UFM_ATTR_EMPTY

#define	DDI_UFM_NV_SLOT_ATTR		"ufm-slot-attributes"

#define	DDI_UFM_NV_SLOT_MISC		"ufm-slot-misc"

#ifdef _KERNEL
/* opaque structures */
typedef struct ddi_ufm_handle ddi_ufm_handle_t;
typedef struct ddi_ufm_image ddi_ufm_image_t;
typedef struct ddi_ufm_slot ddi_ufm_slot_t;

/*
 * DDI UFM Operations vector
 */
typedef struct ddi_ufm_ops {
	int (*ddi_ufm_op_nimages)(ddi_ufm_handle_t *, void *, uint_t *);
	int (*ddi_ufm_op_fill_image)(ddi_ufm_handle_t *, void *, uint_t,
	    ddi_ufm_image_t *);
	int (*ddi_ufm_op_fill_slot)(ddi_ufm_handle_t *, void *, uint_t, uint_t,
	    ddi_ufm_slot_t *);
	int (*ddi_ufm_op_getcaps)(ddi_ufm_handle_t *, void *, ddi_ufm_cap_t *);
} ddi_ufm_ops_t;

/*
 * During a device driver's attach(9E) entry point, a device driver should
 * register with the UFM subsystem by filling out a UFM operations vector
 * (see above) and then calling ddi_ufm_init(9F).  The driver may pass in a
 * value, usually a pointer to its soft state pointer, which it will then
 * receive when its subsequent entry points are called.
 */
int ddi_ufm_init(dev_info_t *, uint_t version, ddi_ufm_ops_t *,
    ddi_ufm_handle_t **, void *);

/*
 * Device drivers should call ddi_ufm_update(9F) after driver initialization is
 * complete and after calling ddi_ufm_init(9F), in order to indicate to the
 * UFM subsystem that the driver is in a state where it is ready to receive
 * calls to its UFM entry points.
 *
 * Additionally, whenever the driver detects a change in the state of a UFM, it
 * should call ddi_ufm_update(9F).  This will cause the UFM subsystem to
 * invalidate any cached state regarding this driver's UFM(s)
 */
void ddi_ufm_update(ddi_ufm_handle_t *);

/*
 * A device driver should call ddi_ufm_fini(9F) during its detach(9E) entry
 * point.  Upon return, the driver is gaurunteed that no further DDI UFM entry
 * points will be called and thus any related state can be safely torn down.
 *
 * After return, the UFM handle is no longer valid and should not be used in
 * any future ddi_ufm_* calls.
 */
void ddi_ufm_fini(ddi_ufm_handle_t *);

/*
 * These interfaces should only be called within the context of a
 * ddi_ufm_op_fill_image callback.
 */
void ddi_ufm_image_set_desc(ddi_ufm_image_t *, const char *);
void ddi_ufm_image_set_nslots(ddi_ufm_image_t *, uint_t);
void ddi_ufm_image_set_misc(ddi_ufm_image_t *, nvlist_t *);

/*
 * These interfaces should only be called within the context of a
 * ddi_ufm_op_fill_slot callback.
 */
void ddi_ufm_slot_set_version(ddi_ufm_slot_t *, const char *);
void ddi_ufm_slot_set_attrs(ddi_ufm_slot_t *, ddi_ufm_attr_t);
void ddi_ufm_slot_set_misc(ddi_ufm_slot_t *, nvlist_t *);
#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_DDI_UFM_H */
