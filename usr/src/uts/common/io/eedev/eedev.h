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

#ifndef _EEDEV_H
#define	_EEDEV_H

/*
 * A small set of utilities to make reading and writing EEPROM class devices
 * simpler. Right now this mostly just facilitates reading and writing.
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/cred.h>
#include <sys/devops.h>
#include <sys/stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	EEDEV_REG_VERS0	0
#define	EEDEV_REG_VERS	EEDEV_REG_VERS0

/*
 * The maximum number of characters in a name for a device. Only alphanumeric
 * characters and '_' and '-' are allowed in the name.
 */
#define	EEDEV_NAME_MAX	32

typedef struct {
	int (*eo_read)(void *, uio_t *, uint32_t, uint32_t, uint32_t);
	int (*eo_write)(void *, uio_t *, uint32_t, uint32_t, uint32_t);
} eedev_ops_t;

typedef struct {
	uint32_t ereg_vers;
	/*
	 * Size of the device in bytes.
	 */
	uint32_t ereg_size;
	/*
	 * This is the size and alignment of a given page in a device. If this
	 * is left as zero, then the device can address all of the data without
	 * taking action.
	 */
	uint32_t ereg_seg;
	/*
	 * This is the access granularity or the number of bytes per address in
	 * the device. For example, a 512-byte device with an access granularity
	 * of 2, would have 256 2-byte addresses available.
	 */
	uint32_t ereg_read_gran;
	uint32_t ereg_write_gran;
	/*
	 * This is the maximum number of bytes that can be in a read or write
	 * request in one go. A value of zero means the device doesn't care.
	 */
	uint32_t ereg_max_read;
	uint32_t ereg_max_write;
	/*
	 * Is the device read-only. If this is false, then it is an error to not
	 * include a write operation.
	 */
	bool ereg_ro;
	uint8_t ereg_rsvd[3];
	/*
	 * Identifying information. The dip is what device this belongs to. The
	 * name is the name that should be used. If left NULL a default name of
	 * "eeprom" will be used. If the driver is going to create more than a
	 * single device per dev_info_t, it should fill this in. The minor
	 * should be a minor allocated by the driver for use here.
	 */
	dev_info_t *ereg_dip;
	void *ereg_driver;
	const char *ereg_name;
	const eedev_ops_t *ereg_ops;
} eedev_reg_t;

typedef struct eedev_hdl eedev_hdl_t;

/*
 * Functions to create and finish an eedev handle.
 */
extern int eedev_create(const eedev_reg_t *, eedev_hdl_t **);
extern void eedev_fini(eedev_hdl_t *);

#ifdef __cplusplus
}
#endif

#endif /* _EEDEV_H */
