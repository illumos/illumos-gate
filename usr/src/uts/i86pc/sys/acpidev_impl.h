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
 * Copyright (c) 2009-2010, Intel Corporation.
 * All rights reserved.
 */

#ifndef	_SYS_ACPIDEV_IMPL_H
#define	_SYS_ACPIDEV_IMPL_H
#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/bitmap.h>
#include <sys/synch.h>
#include <sys/sunddi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/acpidev.h>
#include <sys/acpidev_dr.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

#define	ACPIDEV_ARRAY_PARAM(a)		(a), (sizeof (a) / sizeof ((a)[0]))

/* Debug support facilities. */
extern int acpidev_debug;
#define	ACPIDEV_DEBUG(lvl, ...)	if (acpidev_debug) cmn_err((lvl), __VA_ARGS__)

/* Data attached to an ACPI object to maintain device status information. */
struct acpidev_data_impl {
	uint32_t			aod_eflag;	/* External flags */
	uint32_t			aod_iflag;	/* Internal flags */
	uint32_t			aod_level;
	int				aod_status;	/* Cached _STA value */
	ACPI_HANDLE			*aod_hdl;
	dev_info_t			*aod_dip;
	acpidev_class_t			*aod_class;
	acpidev_class_list_t		**aod_class_list;
	acpidev_board_type_t		aod_bdtype;	/* Type of board. */
	uint32_t			aod_bdnum;	/* Board # for DR. */
	uint32_t			aod_portid;	/* Port id for DR. */
	uint32_t			aod_bdidx;	/* Index # of AP */
	volatile uint32_t		aod_chidx;	/* Index # of child */
	uint32_t			aod_memidx;	/* Index # of memory */
	acpidev_class_id_t		aod_class_id;	/* Dev type for DR. */
};

#define	ACPIDEV_ODF_STATUS_VALID	0x1
#define	ACPIDEV_ODF_DEVINFO_CREATED	0x2
#define	ACPIDEV_ODF_DEVINFO_TAGGED	0x4
#define	ACPIDEV_ODF_HOTPLUG_CAPABLE	0x100
#define	ACPIDEV_ODF_HOTPLUG_READY	0x200
#define	ACPIDEV_ODF_HOTPLUG_FAILED	0x400

#define	ACPIDEV_DR_IS_BOARD(hdl)	\
	((hdl)->aod_iflag & ACPIDEV_ODF_HOTPLUG_CAPABLE)

#define	ACPIDEV_DR_SET_BOARD(hdl)	\
	(hdl)->aod_iflag |= ACPIDEV_ODF_HOTPLUG_CAPABLE

#define	ACPIDEV_DR_IS_READY(hdl)	\
	((hdl)->aod_iflag & ACPIDEV_ODF_HOTPLUG_READY)

#define	ACPIDEV_DR_SET_READY(hdl)	\
	(hdl)->aod_iflag |= ACPIDEV_ODF_HOTPLUG_READY

#define	ACPIDEV_DR_IS_FAILED(hdl)	\
	((hdl)->aod_iflag & ACPIDEV_ODF_HOTPLUG_FAILED)

#define	ACPIDEV_DR_SET_FAILED(hdl)	\
	(hdl)->aod_iflag |= ACPIDEV_ODF_HOTPLUG_FAILED

#define	ACPIDEV_DR_IS_WORKING(hdl)	\
	(((hdl)->aod_iflag & (ACPIDEV_ODF_HOTPLUG_READY | \
	ACPIDEV_ODF_HOTPLUG_FAILED)) == ACPIDEV_ODF_HOTPLUG_READY)

#define	ACPIDEV_DR_IS_PROCESSED(hdl)	\
	((hdl)->aod_iflag & (ACPIDEV_ODF_HOTPLUG_READY | \
	ACPIDEV_ODF_HOTPLUG_FAILED | ACPIDEV_ODF_HOTPLUG_CAPABLE))

#define	ACPIDEV_DR_BOARD_READY(hdl)	\
	(((hdl)->aod_iflag & \
	(ACPIDEV_ODF_HOTPLUG_READY | ACPIDEV_ODF_HOTPLUG_CAPABLE)) == \
	(ACPIDEV_ODF_HOTPLUG_READY | ACPIDEV_ODF_HOTPLUG_CAPABLE))

/*
 * List of registered device class drivers.
 * Class drivers on the same list will be called from head to tail in turn.
 */
struct acpidev_class_list {
	acpidev_class_list_t		*acl_next;
	acpidev_class_t			*acl_class;
};

typedef struct acpidev_pseudo_uid {
	struct acpidev_pseudo_uid	*apu_next;
	char				*apu_uid;
	acpidev_class_id_t		apu_cid;
	uint_t				apu_nid;
} acpidev_pseudo_uid_t;

typedef struct acpidev_pseudo_uid_head {
	kmutex_t			apuh_lock;
	uint32_t			apuh_id;
	acpidev_pseudo_uid_t		*apuh_first;
} acpidev_pseudo_uid_head_t;

typedef struct acpidev_dr_capacity {
	uint_t				cpu_vendor;
	uint_t				cpu_family;
	uint_t				cpu_model_min;
	uint_t				cpu_model_max;
	uint_t				cpu_step_min;
	uint_t				cpu_step_max;
	boolean_t			hotplug_supported;
	uint64_t			memory_alignment;
} acpidev_dr_capacity_t;

extern int acpidev_dr_enable;
extern krwlock_t acpidev_class_lock;
extern ulong_t acpidev_object_type_mask[BT_BITOUL(ACPI_TYPE_NS_NODE_MAX + 1)];
extern ACPI_TABLE_SRAT *acpidev_srat_tbl_ptr;
extern ACPI_TABLE_SLIT *acpidev_slit_tbl_ptr;

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_ACPIDEV_IMPL_H */
