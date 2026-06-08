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
 * Copyright 2026 Argo Technology East
 */

/*
 * Public ioctl interface to the efi(4D) pseudo-driver.
 *
 * The ioctl numbers and field names mirror FreeBSD <sys/efiio.h> so
 * shared userland code (libefivar, efibootmgr) is straightforward to
 * port; the pointer and size fields use fixed-width types here so the
 * struct layout is identical for ILP32 and LP64 callers.  See the UEFI
 * Specification, "Variable Services" for the meaning of name, vendor
 * GUID, attributes, and data.
 *
 * All variable-name strings carried by struct efi_var_ioc are UCS-2
 * (CHAR16, little-endian, NUL-terminated) as required by UEFI.
 */

#ifndef	_SYS_EFIIO_H
#define	_SYS_EFIIO_H

#include <sys/ioccom.h>
#include <sys/types.h>
#include <sys/uuid.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct efi_var_ioc {
	uint64_t	name;		/* CHAR16 * user address */
	uint32_t	namesize;	/* bytes in name (incl. NUL) */
	struct uuid	vendor;
	uint32_t	attrib;
	uint64_t	data;		/* user data buffer address */
	uint64_t	datasize;
};

#define	EFIIOC		('e' << 8)

/*
 * EFIIOC_VAR_GET   -- look up a variable by (name, vendor).  On entry
 *                    namesize and datasize describe input buffers; on
 *                    return datasize is set to the number of bytes
 *                    written to *data.  ENOENT if no such variable.
 *
 * EFIIOC_VAR_NEXT  -- enumerate variables.  On entry namesize is the
 *                    capacity of *name; on return *name and vendor are
 *                    overwritten with the next variable.  Pass an empty
 *                    name (name[0] == 0) to start.
 *
 * EFIIOC_VAR_SET   -- create, update or (datasize == 0) delete a
 *                    variable.
 */
#define	EFIIOC_VAR_GET		_IOWR('e', 4, struct efi_var_ioc)
#define	EFIIOC_VAR_NEXT		_IOWR('e', 5, struct efi_var_ioc)
#define	EFIIOC_VAR_SET		_IOWR('e', 6, struct efi_var_ioc)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_EFIIO_H */
