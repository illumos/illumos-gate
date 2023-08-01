/*
 *
 * Copyright (c)  1999 - 2002 Intel Corporation. All rights reserved
 * This software and associated documentation (if any) is furnished
 * under a license and may only be used or copied in accordance
 * with the terms of the license. Except as permitted by such
 * license, no part of this software or documentation may be
 * reproduced, stored in a retrieval system, or transmitted in any
 * form or by any means without the express written consent of
 * Intel Corporation.
 *
 * Module Name:
 *
 * efi.h
 *
 * Abstract:
 * Public EFI header files
 *
 * Revision History
 */

//
// Build flags on input
//  EFI32
//  EFI_DEBUG		- Enable debugging code
//  EFI_NT_EMULATOR	- Building for running under NT
//


#ifndef _EFI_INCLUDE_
#define	_EFI_INCLUDE_

#include <sys/cdefs.h>		/* Need __dead2. */
#include <Uefi.h>

#define	NextMemoryDescriptor(Ptr, Size) \
	((EFI_MEMORY_DESCRIPTOR *) (((UINT8 *) Ptr) + Size))

/* See also ENCODE_ERROR(). */
#define	DECODE_ERROR(StatusCode)	\
	(unsigned long)(StatusCode & ~MAX_BIT)

#include <stdbool.h>

/*
 * Global variables
 */
extern bool has_boot_services;

/*
 * illumos UUID
 */
#define	ILLUMOS_BOOT_VAR_GUID \
	{ 0x8B54B311, 0x7163, 0x40d3, \
		{0xA6, 0x7B, 0xE7, 0xB2, 0x95, 0x1B, 0x3D, 0x56} \
	}

extern EFI_GUID gillumosBootVarGuid;

#define	LZMA_COMPRESS_GUID \
	{ 0xee4e5898, 0x3914, 0x4259, \
		{0x9d, 0x6e, 0xdc, 0x7b, 0xd7, 0x94, 0x03, 0xcf} \
	}

#endif /* _EFI_INCLUDE_ */
