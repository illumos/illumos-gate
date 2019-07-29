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

#ifndef _SYS_DDI_UFM_IMPL_H
#define	_SYS_DDI_UFM_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/avl.h>
#include <sys/ddi_ufm.h>
#include <sys/mutex.h>
#include <sys/nvpair.h>
#include <sys/types.h>

typedef enum {
	DDI_UFM_STATE_INIT		= 1 << 0,
	DDI_UFM_STATE_READY		= 1 << 1,
	DDI_UFM_STATE_SHUTTING_DOWN	= 1 << 2
} ddi_ufm_state_t;

/* private interface for startup_ddi() */
void ufm_init();

/* private interfaces for ufm driver */
struct ddi_ufm_handle *ufm_find(const char *);
int ufm_cache_fill(struct ddi_ufm_handle *ufmh);

struct ddi_ufm_slot {
	uint_t			ufms_slotno;
	char			*ufms_version;
	ddi_ufm_attr_t		ufms_attrs;
	nvlist_t		*ufms_misc;
};

struct ddi_ufm_image {
	uint_t			ufmi_imageno;
	char			*ufmi_desc;
	nvlist_t		*ufmi_misc;
	struct ddi_ufm_slot	*ufmi_slots;
	uint_t			ufmi_nslots;
};

struct ddi_ufm_handle {
	/*
	 * The following fields get filled in when a UFM-aware driver calls
	 * ddi_ufm_init(9E).  They remain valid until the driver calls
	 * ddi_ufm_fini(9E).  You can test for validity of these fields by
	 * checking if the DDI_UFM_STATE_INIT flag is set in ufmh_state.
	 */
	kmutex_t		ufmh_lock;
	char			ufmh_devpath[MAXPATHLEN];
	ddi_ufm_ops_t		*ufmh_ops;
	void			*ufmh_arg;
	uint_t			ufmh_state;
	uint_t			ufmh_version;
	/*
	 * The following four fields represent lazily cached UFM data
	 * retrieved from a UFM-aware driver.  If ufmh_report is non-NULL
	 * then all four of these fields will contain valid data.
	 */
	struct ddi_ufm_image	*ufmh_images;
	uint_t			ufmh_nimages;
	ddi_ufm_cap_t		ufmh_caps;
	nvlist_t		*ufmh_report;

	avl_node_t		ufmh_link;
};

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_DDI_UFM_IMPL_H */
