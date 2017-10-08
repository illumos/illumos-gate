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
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 */

#ifndef _SYS_EFI_H
#define	_SYS_EFI_H

/*
 * UEFI related data. Based on UEFI 2.5 specs.
 */
#include <sys/uuid.h>

#ifdef __cplusplus
extern "C" {
#endif

/* EFI GUIDS */

#define	EFI_GLOBAL_VARIABLE	\
	{ 0x8be4df61, 0x93ca, 0x11d2, 0xaa, 0x0d, \
	{ 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c } }

#define	MPS_TABLE_GUID	\
	{ 0xeb9d2d2f, 0x2d88, 0x11d3, 0x9a, 0x16, \
	{ 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } }

#define	ACPI_10_TABLE_GUID	\
	{ 0xeb9d2d30, 0x2d88, 0x11d3, 0x9a, 0x16, \
	{ 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } }

#define	EFI_ACPI_TABLE_GUID	\
	{ 0x8868e871, 0xe4f1, 0x11d3, 0xbc, 0x22, \
	{ 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81 } }

#define	SMBIOS_TABLE_GUID	\
	{ 0xeb9d2d31, 0x2d88, 0x11d3, 0x9a, 0x16, \
	{ 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } }

#define	SAL_SYSTEM_TABLE_GUID	\
	{ 0xeb9d2d32, 0x2d88, 0x11d3, 0x9a, 0x16, \
	{ 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } }

#define	SMBIOS3_TABLE_GUID	\
	{ 0xf2fd1544, 0x9794, 0x4a2c, 0x99, 0x2e, \
	{ 0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94 } }

#define	FDT_TABLE_GUID	\
	{ 0xb1b621d5, 0xf19c, 0x41a5, 0x83, 0x0b, \
	{ 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0 } }

#define	DXE_SERVICES_TABLE_GUID	\
	{ 0x5ad34ba, 0x6f02, 0x4214, 0x95, 0x2e, \
	{ 0x4d, 0xa0, 0x39, 0x8e, 0x2b, 0xb9 } }

#define	HOB_LIST_TABLE_GUID	\
	{ 0x7739f24c, 0x93d7, 0x11d4, 0x9a, 0x3a, \
	{ 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } }

#define	MEMORY_TYPE_INFORMATION_TABLE_GUID	\
	{ 0x4c19049f, 0x4137, 0x4dd3, 0x9c, 0x10, \
	{ 0x8b, 0x97, 0xa8, 0x3f, 0xfd, 0xfa } }

#define	DEBUG_IMAGE_INFO_TABLE_GUID	\
	{ 0x49152e77, 0x1ada, 0x4764, 0xb7, 0xa2, \
	{ 0x7a, 0xfe, 0xfe, 0xd9, 0x5e, 0x8b } }

#define	EFI_PROPERTIES_TABLE_GUID	\
	{ 0x880aaca3, 0x4adc, 0x4a04, 0x90, 0x79, \
	{ 0xb7, 0x47, 0x34, 0x8, 0x25, 0xe5 } }

typedef struct uuid efi_guid_t __aligned(8);

/* Memory data */
typedef uint64_t	EFI_PHYSICAL_ADDRESS;
typedef uint64_t	EFI_VIRTUAL_ADDRESS;

/*
 * EFI_MEMORY_TYPE enum is defined in UEFI v2.7 page 185.
 */
typedef enum {
	EfiReservedMemoryType,
	EfiLoaderCode,
	EfiLoaderData,
	EfiBootServicesCode,
	EfiBootServicesData,
	EfiRuntimeServicesCode,
	EfiRuntimeServicesData,
	EfiConventionalMemory,
	EfiUnusableMemory,
	EfiACPIReclaimMemory,
	EfiACPIMemoryNVS,
	EfiMemoryMappedIO,
	EfiMemoryMappedIOPortSpace,
	EfiPalCode,
	EfiPersistentMemory,
	EfiMaxMemoryType
} EFI_MEMORY_TYPE;

/* Possible caching types for the memory range */
#define	EFI_MEMORY_UC			0x0000000000000001
#define	EFI_MEMORY_WC			0x0000000000000002
#define	EFI_MEMORY_WT			0x0000000000000004
#define	EFI_MEMORY_WB			0x0000000000000008
#define	EFI_MEMORY_UCE			0x0000000000000010

/* Physical memory protection on range */
#define	EFI_MEMORY_WP			0x0000000000001000
#define	EFI_MEMORY_RP			0x0000000000002000
#define	EFI_MEMORY_XP			0x0000000000004000
#define	EFI_MEMORY_NV			0x0000000000008000
#define	EFI_MEMORY_MORE_RELIABLE	0x0000000000010000
#define	EFI_MEMORY_RO			0x0000000000020000

/* Range requires a runtime mapping */
#define	EFI_MEMORY_RUNTIME	0x8000000000000000

#define	EFI_MEMORY_DESCRIPTOR_VERSION	1
typedef struct {
	uint32_t		Type;
	EFI_PHYSICAL_ADDRESS	PhysicalStart;
	uint32_t		Pad;
	EFI_VIRTUAL_ADDRESS	VirtualStart;
	uint64_t		NumberOfPages;
	uint64_t		Attribute;
} __packed EFI_MEMORY_DESCRIPTOR;

/* Tables */

typedef struct {
	uint64_t Signature;
	uint32_t Revision;
	uint32_t HeaderSize;
	uint32_t CRC32;
	uint32_t Reserved;
} EFI_TABLE_HEADER;

/*
 * The upper 16 bits of the revision contain the major revision value,
 * and the lower 16 bits contain the minor revision value. The minor revision
 * values are binary coded decimals and are limited to the range of 00..99.
 * If the lower digit of the minor revision is 0, the version is printed as:
 * major.minor upper decimal
 * Otherwise the version is printed as:
 * major.minor upper decimal.minor lower decimal
 */
#define	EFI_REV(x, y)		(((x) << 16) || (y))
#define	EFI_REV_MAJOR(x)	(((x) >> 16) & 0xffff)
#define	EFI_REV_MINOR(x)	((x) & 0xffff)
#define	EFI_SYSTEM_TABLE_SIGNATURE	0x5453595320494249

typedef uint32_t	efiptr32_t;
typedef uint64_t	efiptr64_t;

typedef struct _EFI_CONFIGURATION_TABLE32 {
	efi_guid_t	VendorGuid;
	efiptr32_t	VendorTable;
} __packed EFI_CONFIGURATION_TABLE32;

typedef struct _EFI_CONFIGURATION_TABLE64 {
	efi_guid_t	VendorGuid;
	efiptr64_t	VendorTable;
} __packed EFI_CONFIGURATION_TABLE64;

typedef struct _EFI_SYSTEM_TABLE32 {
	EFI_TABLE_HEADER	Hdr;

	efiptr32_t		FirmwareVendor;
	uint32_t		FirmwareRevision;

	efiptr32_t		ConsoleInHandle;
	efiptr32_t		ConIn;

	efiptr32_t		ConsoleOutHandle;
	efiptr32_t		ConOut;

	efiptr32_t		StandardErrorHandle;
	efiptr32_t		StdErr;

	efiptr32_t		RuntimeServices;
	efiptr32_t		BootServices;

	uint32_t		NumberOfTableEntries;
	efiptr32_t		ConfigurationTable;
} __packed EFI_SYSTEM_TABLE32;

typedef struct _EFI_SYSTEM_TABLE64 {
	EFI_TABLE_HEADER	Hdr;

	efiptr64_t		FirmwareVendor;
	uint32_t		FirmwareRevision;
	uint32_t		Pad;

	efiptr64_t		ConsoleInHandle;
	efiptr64_t		ConIn;

	efiptr64_t		ConsoleOutHandle;
	efiptr64_t		ConOut;

	efiptr64_t		StandardErrorHandle;
	efiptr64_t		StdErr;

	efiptr64_t		RuntimeServices;
	efiptr64_t		BootServices;

	uint64_t		NumberOfTableEntries;
	efiptr64_t		ConfigurationTable;
} __packed EFI_SYSTEM_TABLE64;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_EFI_H */
