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
 */

#ifndef	_SYS_DDITYPES_H
#define	_SYS_DDITYPES_H

#include <sys/isa_defs.h>
#ifndef	_ASM
#include <sys/types.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_ASM
/*
 * DMA types
 *
 * A DMA handle represent a "DMA object".  A DMA object is an abstraction
 * that represents the potential source or destination of DMA transfers to
 * or from a device.  The DMA object is the highest level description of
 * the source or destination and is not suitable for the actual transfer.
 *
 * Note, that we avoid the specific references to "mapping". The fact that
 * a transfer requires mapping is an artifact of the specific architectural
 * implementation.
 */
typedef	struct __ddi_dma_handle *ddi_dma_handle_t;

/*
 * A dma window type represents a "DMA window".  A DMA window is a portion
 * of a dma object or might be the entire object. A DMA window has had system
 * resources allocated to it and is prepared to be transferred into or
 * out of. Examples of system resources are DVMA mapping resources and
 * intermediate transfer buffer resources.
 *
 */
typedef	struct __ddi_dma_win *ddi_dma_win_t;


/*
 * A dma segment type represents a "DMA segment".  A dma segment is a
 * contiguous portion of a DMA window which is entirely addressable by the
 * device for a transfer operation.  One example where DMA segments are
 * required is where the system does not contain DVMA capability and
 * the object or window may be non-contiguous.  In this example the
 * object or window will be broken into smaller contiguous segments.
 * Another example is where a device or some intermediary bus adapter has
 * some upper limit on its transfer size (i.e. an 8-bit address register).
 * In this example the object or window will be broken into smaller
 * addressable segments.
 */
typedef	struct __ddi_dma_seg *ddi_dma_seg_t;

/*
 * A DMA cookie contains DMA address information required to
 * program a DMA engine
 */
typedef struct {
	union {
		uint64_t	_dmac_ll;	/* 64 bit DMA address */
		uint32_t 	_dmac_la[2];    /* 2 x 32 bit address */
	} _dmu;
	size_t		dmac_size;	/* DMA cookie size */
	uint_t		dmac_type;	/* bus specific type bits */
} ddi_dma_cookie_t;

#define	dmac_laddress	_dmu._dmac_ll
#ifdef _LONG_LONG_HTOL
#define	dmac_notused    _dmu._dmac_la[0]
#define	dmac_address    _dmu._dmac_la[1]
#else
#define	dmac_address	_dmu._dmac_la[0]
#define	dmac_notused	_dmu._dmac_la[1]
#endif

/*
 * Interrupt types
 */

/*
 * Both ddi_iblock_cookie_t and ddi_idevice_cookie_t are
 * obsolete data structures.
 *
 * lock initialization type
 */
typedef struct __ddi_iblock_cookie *ddi_iblock_cookie_t;
typedef union {
	struct {
		ushort_t	_idev_vector;	/* vector - bus dependent */
		ushort_t	_idev_priority;	/* priority - bus dependent */
	} idu;
	uint_t	idev_softint;	/* Soft interrupt register bit(s) */
} ddi_idevice_cookie_t;
#define	idev_vector	idu._idev_vector
#define	idev_priority	idu._idev_priority

/*
 * register specification
 */
typedef struct __ddi_regspec *ddi_regspec_t;

/*
 * interrupt specification
 */
typedef struct __ddi_intrspec *ddi_intrspec_t;

/*
 * ddi_softintr_t is an obsolete data structure.
 *
 * soft interrupt id
 */
typedef struct __ddi_softintr *ddi_softintr_t;

/*
 * opaque device info handle
 */
typedef struct __dev_info *dev_info_t;

/*
 * Mapping cookie for devmap(9E)
 */
typedef struct __ddi_devmap_data *ddi_devmap_data_t;

/*
 * Opaque Device id
 */
typedef struct __ddi_devid *ddi_devid_t;

/*
 * Device id types
 */
#define	DEVID_NONE		0
#define	DEVID_SCSI3_WWN		1
#define	DEVID_SCSI_SERIAL	2
#define	DEVID_FAB		3
#define	DEVID_ENCAP		4
#define	DEVID_ATA_SERIAL	5
#define	DEVID_SCSI3_VPD_T10	6
#define	DEVID_SCSI3_VPD_EUI	7
#define	DEVID_SCSI3_VPD_NAA	8
#define	DEVID_MAXTYPE		8

/*
 * Device id scsi encode versions (version of encode interface, not devid)
 */
#define	DEVID_SCSI_ENCODE_VERSION1		0
#define	DEVID_SCSI_ENCODE_VERSION2		1
#define	DEVID_SCSI_ENCODE_VERSION_LATEST	DEVID_SCSI_ENCODE_VERSION2

/*
 * Device id smp encode versions (version of encode interface, not devid)
 */
#define	DEVID_SMP_ENCODE_VERSION1		0
#define	DEVID_SMP_ENCODE_VERSION_LATEST		DEVID_SMP_ENCODE_VERSION1

/* minor name values for devid lookup interfaces */
#define	DEVID_MINOR_NAME_ALL		((char *)0)
#define	DEVID_MINOR_NAME_ALL_CHR	((char *)1)
#define	DEVID_MINOR_NAME_ALL_BLK	((char *)2)

/*
 * Define ddi_devmap_cmd types. This should probably be elsewhere.
 */
typedef enum {
	DDI_DEVMAP_VALIDATE = 0		/* Check mapping, but do nothing */
} ddi_devmap_cmd_t;

/*
 * Definitions for node state.
 *
 * NOTE: DS_ATTACHED and DS_READY should only be used by the devcfg.c state
 * model code itself, other code should use i_ddi_devi_attached() to avoid
 * logic errors associated with transient DS_READY->DS_ATTACHED->DS_READY
 * state changes while the node is attached.
 */
typedef enum {
	DS_INVAL = -1,
	DS_PROTO = 0,
	DS_LINKED,	/* in orphan list */
	DS_BOUND,	/* in per-driver list */
	DS_INITIALIZED, /* bus address assigned */
	DS_PROBED,	/* device known to exist */
	DS_ATTACHED,	/* don't use, see NOTE above: driver attached */
	DS_READY	/* don't use, see NOTE above: post attach complete */
} ddi_node_state_t;

/*
 * NDI Event Service
 */
typedef enum {EPL_KERNEL, EPL_INTERRUPT, EPL_HIGHLEVEL} ddi_plevel_t;
typedef struct ddi_event_cookie *ddi_eventcookie_t;
typedef struct ddi_event_callbacks *ddi_callback_id_t;

#endif	/* !_ASM */

#ifdef	_KERNEL
#ifndef _ASM

/*
 * Device Access Attributes
 */

typedef struct ddi_device_acc_attr {
	ushort_t devacc_attr_version;
	uchar_t devacc_attr_endian_flags;
	uchar_t devacc_attr_dataorder;
	uchar_t devacc_attr_access;		/* access error protection */
} ddi_device_acc_attr_t;

#define	DDI_DEVICE_ATTR_V0 	0x0001
#define	DDI_DEVICE_ATTR_V1 	0x0002

/*
 * endian-ness flags
 */
#define	 DDI_NEVERSWAP_ACC	0x00
#define	 DDI_STRUCTURE_LE_ACC	0x01
#define	 DDI_STRUCTURE_BE_ACC	0x02

/*
 * Data ordering values
 */
#define	DDI_STRICTORDER_ACC	0x00
#define	DDI_UNORDERED_OK_ACC    0x01
#define	DDI_MERGING_OK_ACC	0x02
#define	DDI_LOADCACHING_OK_ACC  0x03
#define	DDI_STORECACHING_OK_ACC 0x04

/*
 * Data size
 */
#define	DDI_DATA_SZ01_ACC	1
#define	DDI_DATA_SZ02_ACC	2
#define	DDI_DATA_SZ04_ACC	4
#define	DDI_DATA_SZ08_ACC	8

/*
 * Data Access Handle
 */
#define	VERS_ACCHDL 			0x0001

typedef struct __ddi_acc_handle *ddi_acc_handle_t;

typedef struct ddi_acc_hdl {
	int	ah_vers;		/* version number */
	void	*ah_bus_private;	/* bus private pointer */
	void 	*ah_platform_private; 	/* platform private pointer */
	dev_info_t *ah_dip;		/* requesting device */

	uint_t	ah_rnumber;		/* register number */
	caddr_t	ah_addr;		/* address of mapping */

	off_t	ah_offset;		/* offset of mapping */
	off_t	ah_len;			/* length of mapping */
	uint_t	ah_hat_flags;		/* hat flags used to map object */
	pfn_t	ah_pfn;			/* physical page frame number */
	uint_t	ah_pnum;		/* number of contiguous pages */
	ulong_t	ah_xfermodes;		/* data transfer modes, etc */
	ddi_device_acc_attr_t ah_acc;	/* device access attributes */
} ddi_acc_hdl_t;

/*
 * Used by DDI_CTLOPS_POKE and DDI_CTLOPS_PEEK for peek/poke and cautious acc
 */
typedef struct {
	size_t			size;
	uintptr_t		dev_addr;
	uintptr_t		host_addr;
	ddi_acc_handle_t	handle;
	size_t			repcount;
	uint_t			flags;
} peekpoke_ctlops_t;

/*
 * Used by the high resolution timeout functions
 */
typedef struct __ddi_periodic *ddi_periodic_t;

#endif	/* !_ASM */

/*
 * devacc_attr_access error protection types
 */
#define	DDI_DEFAULT_ACC		0x01	/* take default action */
#define	DDI_FLAGERR_ACC		0x02	/* protected against access faults */
#define	DDI_CAUTIOUS_ACC	0x03	/* high protection against faults */

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DDITYPES_H */
