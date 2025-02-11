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

#ifndef _SYS_NVME_WDC_H
#define	_SYS_NVME_WDC_H

/*
 * This header defines vendor-specific NVMe interfaces and is not a committed
 * interface. Its contents and existence are subject to change.
 *
 * This header contains all of the current vendor-specific entries for known WDC
 * devices as well as common structures and definitions that are shared across
 * multiple device families.
 */

#include <sys/nvme/wdc_sn840.h>
#include <sys/nvme/wdc_sn65x.h>
#include <sys/nvme/wdc_sn861.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	WDC_PCI_VID	0x1b96

/*
 * All data structures must be packed to account for the layout from the various
 * programmer's manuals.
 */
#pragma pack(1)

/*
 * WDC common device power samples log page data structure. All power samples
 * are in mW.
 */
typedef struct {
	uint32_t	pow_nsamples;
	uint32_t	pow_samples[];
} wdc_vul_power_t;

/*
 * This is a device generation agnostic structure that defines temperature
 * samples log page. The temperature is in degrees Celsius, but we do not
 * currently know the exact format of the data. Each device has a specific
 * enumeration that describes what each array entry is supposed to mean.
 */
typedef struct {
	uint32_t	temp_nsamples;
	uint32_t	temp_samples[];
} wdc_vul_temp_t;

/*
 * The device manageability log page consists of a series of variable length
 * entries which are guaranteed to always be 4-byte aligned. The length includes
 * the length of the header itself. This header is used to start the log itself
 * and in that case the id is the version.
 */
typedef struct {
	uint32_t	vsd_len;
	uint32_t	vsd_id;
	uint8_t		vsd_data[];
} wdc_vsd_t;

/*
 * This is the WDC 'Counted ByteString'. This is not a null-terminated string!
 * The length of data in bytes is stored in cbs_len (defined as little endian).
 * There may be additional padding following csd_data to make up the fact that
 * the device manageability log is units of four bytes.
 */
typedef struct {
	uint32_t	cbs_len;
	uint8_t		csd_data[];
} wdc_cbs_t;

/*
 * Vendor Unique Commands that span multiple devices.
 */

/*
 * The e6 command is a diagnostic dump that can be initiated that traces its
 * lineage back to the HDD world. The dump is variable sized and starts with an
 * 8 byte header (the wdc_e6_header_t) which indicates the total size of the
 * dump.
 *
 * The command accepts a number of dwords to read and uses cdw12 to indicate the
 * dword offset to start to read out.
 */
#define	WDC_VUC_E6_DUMP_OPC	0xe6

/*
 * The following is the WDC e6 dump diagnostic header. This is used to determine
 * the size of the full payload. The first member is a uint32_t. The second
 * member determines the size of the log. e6_size[0] is the upper 24 bits,
 * e6_size[1], bits 16-23, etc. This is a size in bytes, it cannot be passed to
 * commands directly which are in units of uint32_t's.
 */
typedef struct {
	uint32_t	e6_head;
	uint32_t	e6_size_be;
} wdc_e6_header_t;

CTASSERT((sizeof (wdc_e6_header_t) % 4) == 0);
CTASSERT(sizeof (wdc_e6_header_t) == 8);

/*
 * The drive diagnostic resize command allows certain devices to resize their
 * capacity. This is a fully destructive operation. It is known to be supported
 * by the SN840 and SN65x families. It utilizes a mode argument in cdw12 which
 * indicates whether to get, set, or query progress. That argument is in
 * bits[15:8]. To indicate that we are doing the resize operation of the opcode
 * we must set bits[7:0] to 3. The target size is specified in cdw13.
 */
#define	WDC_VUC_RESIZE_OPC	0xcc
#define	WDC_VUC_RESIZE_CMD	0x3
#define	WDC_VUC_RESIZE_SUB_GET		0x0
#define	WDC_VUC_RESIZE_SUB_SET		0x1
#define	WDC_VUC_RESIZE_SUB_PHASE	0x2

/*
 * Several WDC devices have a notion of an assert that is visible in the device
 * manageability log. As part of recovering devices, that assert must be cleared
 * through a vendor-specific command.
 */
#define	WDC_VUC_ASSERT_OPC	0xd8
#define	WDC_VUC_ASSERT_CMD	0x3
#define	WDC_VUC_ASSERT_SUB_CLEAR	0x5
#define	WDC_VUC_ASSERT_SUB_INJECT	0x6

#pragma	pack()	/* pack(1) */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NVME_WDC_H */
