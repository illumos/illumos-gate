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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2018, Joyent, Inc.
 * Copyright 2023 Oxide Computer Company
 */

#ifndef	_SYS_DEVFM_H
#define	_SYS_DEVFM_H

#include <sys/types.h>
#include <sys/nvpair.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	FM_IOC_MAXBUFSZ		32768	/* 32 KiB */
#define	FM_IOC_OUT_BUFSZ	32768	/* 32 KiB */
#define	FM_IOC_OUT_MAXBUFSZ	1048576	/* 1 MiB */
#define	FM_DRV_VERSION		1

#define	FM_VERSIONS_VERSION	"fm-versions-version"
#define	FM_PAGE_OP_VERSION	"page-operation-version"
#define	FM_CPU_OP_VERSION	"cpu-operation-version"
#define	FM_CPU_INFO_VERSION	"cpu-info-version"
#define	FM_TOPO_LEGACY_VERSION	"topo-legacy-version"
#define	FM_CACHE_INFO_VERSION	"cache-info-version"

/*
 * FMA driver ioctl interfaces
 */
#define	FM_IOC			(0xFA << 16)
#define	FM_IOC_VERSIONS		(FM_IOC | 1)
#define	FM_IOC_PAGE_RETIRE	(FM_IOC | 2)
#define	FM_IOC_PAGE_STATUS	(FM_IOC | 3)
#define	FM_IOC_PAGE_UNRETIRE	(FM_IOC | 4)

#if defined(__x86)
#define	FM_IOC_PHYSCPU_INFO	(FM_IOC | 5)
#define	FM_IOC_CPU_RETIRE	(FM_IOC | 6)
#define	FM_IOC_CPU_STATUS	(FM_IOC | 7)
#define	FM_IOC_CPU_UNRETIRE	(FM_IOC | 8)
#define	FM_IOC_GENTOPO_LEGACY	(FM_IOC | 9)
#endif	/* __x86 */

/*
 * Information about caches. Each CPU that is in the physical CPU information
 * will be in here in the same ID order allowing one to map them directly.
 */
#define	FM_IOC_CACHE_INFO	(FM_IOC | 10)

/*
 * Types
 */
typedef struct fm_ioc_data {
	uint32_t	fid_version;	/* interface version */
	size_t		fid_insz;	/* size of packed input nvlist */
	caddr_t		fid_inbuf;	/* buf containing packed input nvl */
	size_t		fid_outsz;	/* size of packed output nvlist */
	caddr_t		fid_outbuf;	/* buf containing packed output nvl */
} fm_ioc_data_t;

#ifdef _KERNEL
typedef struct fm_ioc_data32 {
	uint32_t	fid_version;	/* interface version */
	size32_t	fid_insz;	/* size of packed input nvlist */
	caddr32_t	fid_inbuf;	/* buf containing packed input nvl */
	size32_t	fid_outsz;	/* size of packed output nvlist */
	caddr32_t	fid_outbuf;	/* buf containing packed output nvl */
} fm_ioc_data32_t;
#endif	/* _KERNEL */

/*
 * Constants
 */
#define	FM_PAGE_RETIRE_FMRI		"fmri"
#define	FM_PHYSCPU_INFO_CPUS		"cpus"
#define	FM_CPU_RETIRE_CHIP_ID		"chip_id"
#define	FM_PHYSCPU_INFO_NPROCNODES	"procnodes_per_pkg"
#define	FM_PHYSCPU_INFO_PROCNODE_ID	"procnodeid"
#define	FM_CPU_RETIRE_CORE_ID		"core_id"
#define	FM_CPU_RETIRE_STRAND_ID		"strand_id"
#define	FM_CPU_RETIRE_OLDSTATUS		"oldstatus"
#define	FM_GENTOPO_LEGACY		"gentopolegacy"
#define	FM_CACHE_INFO_NCPUS		"ncpus"

/*
 * Properties set by FM_PHYSCPU_INFO
 */
#define	FM_PHYSCPU_INFO_VENDOR_ID	"vendor_id"
#define	FM_PHYSCPU_INFO_FAMILY		"family"
#define	FM_PHYSCPU_INFO_MODEL		"model"
#define	FM_PHYSCPU_INFO_STEPPING	"stepping"

/*
 * When Multi-Chip-Module(MCM) support is added
 * chip_id should map to the processor package
 * and not the die in the processor package.
 * This is for FMA; kernel's perception of
 * chip_id could differ for MCM.
 */
#define	FM_PHYSCPU_INFO_CHIP_ID		"chip_id"

#define	FM_PHYSCPU_INFO_CORE_ID		"core_id"
#define	FM_PHYSCPU_INFO_STRAND_ID	"strand_id"
#define	FM_PHYSCPU_INFO_STRAND_APICID	"strand_initial_apicid"
#define	FM_PHYSCPU_INFO_SMBIOS_ID	"smbios_id"
#define	FM_PHYSCPU_INFO_CHIP_ROOTS	"chip_roots"
#define	FM_PHYSCPU_INFO_CHIP_REV	"chip_rev"
#define	FM_PHYSCPU_INFO_SOCKET_TYPE	"socket_type"
#define	FM_PHYSCPU_INFO_CPU_ID		"cpuid"
#define	FM_PHYSCPU_INFO_CHIP_IDENTSTR	"chip_identstr"

/*
 * Information exposed by the cache information structure. This is currently
 * organized by the given caches available to a CPU. There is a given nvlist_t
 * array for each cache level. The majority of these entries are meant to be
 * generic across all platforms and derived from the underlying architecture's
 * metadata (CPUID, CLIDR_EL1, etc.).
 *
 * The FM_CACHE_INFO_ID value is manufactured by the kernel. CPU architectures
 * generally present cache information as specific to a logical CPU. This allows
 * systems to determine what level caches are shared between different CPUs by
 * comparing these entries across CPUs. Items prefixed with a given architecture
 * are specific to it and will not show up on other platforms. These exist so
 * topology modules can have more information than just the cache-id. While it's
 * helpful, it doesn't tell us what level of the CPU (or whether it's internal
 * or external) it exists at. This is going to be architecture and potentially
 * platform specific given that ARMv8-A/ARMv9-A doesn't define a way to get this
 * for example.
 *
 * It is expected that callers will always fill out the sets and ways
 * appropriately. If a cache is fully-associative, we expects the number of sets
 * to be populated and set to 1 that way consumers can attempt to have a uniform
 * experience here.
 */
#define	FM_CACHE_INFO_LEVEL		"cache-level"	/* uint32_t */
#define	FM_CACHE_INFO_TYPE		"cache-type"	/* uint32_t */
typedef enum {
	FM_CACHE_INFO_T_DATA	= 1 << 0,
	FM_CACHE_INFO_T_INSTR	= 1 << 1,
	FM_CACHE_INFO_T_UNIFIED	= 1 << 2
} fm_cache_info_type_t;
#define	FM_CACHE_INFO_NSETS		"cache-sets"	/* uint64_t */
#define	FM_CACHE_INFO_NWAYS		"cache-ways"	/* uint32_t */
#define	FM_CACHE_INFO_LINE_SIZE		"line-size"	/* uint32_t */
#define	FM_CACHE_INFO_TOTAL_SIZE	"total-size"	/* uint64_t */
#define	FM_CACHE_INFO_FULLY_ASSOC	"fully-associative" /* boolean (key) */
#define	FM_CACHE_INFO_ID		"cache-id"	/* uint64_t */
#define	FM_CACHE_INFO_X86_APIC_SHIFT	"x86-apic-shift"	/* uint32_t */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DEVFM_H */
