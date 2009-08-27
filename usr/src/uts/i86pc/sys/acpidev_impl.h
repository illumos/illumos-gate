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
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */

#ifndef	_SYS_ACPIDEV_IMPL_H
#define	_SYS_ACPIDEV_IMPL_H
#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/sunddi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/acpidev.h>

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
};

#define	ACPIDEV_ODF_STATUS_VALID	0x1
#define	ACPIDEV_ODF_DEVINFO_CREATED	0x2
#define	ACPIDEV_ODF_DEVINFO_TAGGED	0x4
#define	ACPIDEV_ODF_DEVINFO_OFFLINE	0x8

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

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_ACPIDEV_IMPL_H */
