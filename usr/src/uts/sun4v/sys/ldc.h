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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LDC_H
#define	_LDC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ioctl.h>
#include <sys/processor.h>
#include <sys/ontrap.h>

/* Types */
typedef uint64_t ldc_handle_t;		/* Channel handle */
typedef uint64_t ldc_mem_handle_t;	/* Channel memory handle */
typedef uint64_t ldc_dring_handle_t;	/* Descriptor ring handle */

/* LDC transport mode */
typedef enum {
	LDC_MODE_RAW,			/* Raw mode */
	LDC_MODE_UNRELIABLE,		/* Unreliable packet mode */
	_LDC_MODE_RESERVED_,		/* reserved */
	LDC_MODE_RELIABLE		/* Reliable packet mode */
} ldc_mode_t;

/* LDC message payload sizes */
#define	LDC_ELEM_SIZE			8		/* size in bytes */
#define	LDC_PACKET_SIZE			(LDC_ELEM_SIZE * 8)
#define	LDC_PAYLOAD_SIZE_RAW		(LDC_PACKET_SIZE)
#define	LDC_PAYLOAD_SIZE_UNRELIABLE	(LDC_PACKET_SIZE - LDC_ELEM_SIZE)
#define	LDC_PAYLOAD_SIZE_RELIABLE	(LDC_PACKET_SIZE - (LDC_ELEM_SIZE * 2))

/* LDC Channel Status */
typedef enum {
	LDC_INIT = 1,			/* Channel initialized */
	LDC_OPEN,			/* Channel open */
	LDC_READY,			/* Channel peer opened (hw-link-up) */
	LDC_UP				/* Channel UP - ready for data xfer */
} ldc_status_t;

/* Callback return values */
#define	LDC_SUCCESS	0
#define	LDC_FAILURE	1

/* LDC callback mode */
typedef enum {
	LDC_CB_ENABLE,			/* Enable callbacks */
	LDC_CB_DISABLE			/* Disable callbacks */
} ldc_cb_mode_t;

/* Callback events */
#define	LDC_EVT_DOWN		0x1	/* Channel DOWN, status = OPEN */
#define	LDC_EVT_RESET		0x2	/* Channel RESET, status = READY */
#define	LDC_EVT_UP		0x4	/* Channel UP, status = UP */
#define	LDC_EVT_READ		0x8	/* Channel has data for read */
#define	LDC_EVT_WRITE		0x10	/* Channel has space for write */

/* LDC device classes */
typedef enum {
	LDC_DEV_GENERIC = 1,		/* generic device */
	LDC_DEV_BLK,			/* block device, eg. vdc */
	LDC_DEV_BLK_SVC,		/* block device service, eg. vds */
	LDC_DEV_NT,			/* network device, eg. vnet */
	LDC_DEV_NT_SVC,			/* network service eg. vsw */
	LDC_DEV_SERIAL			/* serial device eg. vldc, vcc */
} ldc_dev_t;

/* Channel nexus registration */
typedef struct ldc_cnex {
	dev_info_t	*dip;		/* dip of channel nexus */
	int		(*reg_chan)();	/* interface for channel register */
	int		(*unreg_chan)(); /* interface for channel unregister */
	int		(*add_intr)();	/* interface for adding interrupts */
	int		(*rem_intr)();	/* interface for removing interrupts */
	int		(*clr_intr)();	/* interface for clearing interrupts */
} ldc_cnex_t;

/* LDC attribute structure */
typedef struct ldc_attr {
	ldc_dev_t	devclass;	/* device class */
	uint64_t	instance;	/* device class instance */
	ldc_mode_t	mode;		/* channel mode */
	uint64_t	mtu;		/* channel mtu */
} ldc_attr_t;

/* LDC memory cookie */
typedef struct ldc_mem_cookie {
	uint64_t	addr;		/* cookie address */
	uint64_t	size;		/* size @ offset */
} ldc_mem_cookie_t;

/*
 * LDC Memory Map Type
 * Specifies how shared memory being created is shared with its
 * peer and/or how the peer has mapped in the exported memory.
 */
#define	LDC_SHADOW_MAP		0x1	/* share mem via shadow copy only */
#define	LDC_DIRECT_MAP		0x2	/* share mem direct access */
#define	LDC_IO_MAP		0x4	/* share mem for IOMMU/DMA access */

/* LDC Memory Access Permissions  */
#define	LDC_MEM_R		0x1	/* Memory region is read only */
#define	LDC_MEM_W		0x2	/* Memory region is write only */
#define	LDC_MEM_X		0x4	/* Memory region is execute only */
#define	LDC_MEM_RW		(LDC_MEM_R|LDC_MEM_W)
#define	LDC_MEM_RWX		(LDC_MEM_R|LDC_MEM_W|LDC_MEM_X)

/* LDC Memory Copy Direction */
#define	LDC_COPY_IN		0x0	/* Copy data to VA from cookie mem */
#define	LDC_COPY_OUT		0x1	/* Copy data from VA to cookie mem */

/* LDC memory/dring (handle) status */
typedef enum {
	LDC_UNBOUND,			/* Memory handle is unbound */
	LDC_BOUND,			/* Memory handle is bound */
	LDC_MAPPED			/* Memory handle is mapped */
} ldc_mstatus_t;

/* LDC [dring] memory info */
typedef struct ldc_mem_info {
	uint8_t		mtype;		/* map type */
	uint8_t		perm;		/* RWX permissions */
	caddr_t		vaddr;		/* base VA */
	uintptr_t	raddr;		/* base RA */
	ldc_mstatus_t	status;		/* dring/mem handle status */
} ldc_mem_info_t;

/* API functions */
int ldc_register(ldc_cnex_t *cinfo);
int ldc_unregister(ldc_cnex_t *cinfo);

int ldc_init(uint64_t id, ldc_attr_t *attr, ldc_handle_t *handle);
int ldc_fini(ldc_handle_t handle);
int ldc_open(ldc_handle_t handle);
int ldc_close(ldc_handle_t handle);
int ldc_up(ldc_handle_t handle);
int ldc_down(ldc_handle_t handle);
int ldc_reg_callback(ldc_handle_t handle,
    uint_t(*callback)(uint64_t event, caddr_t arg), caddr_t arg);
int ldc_unreg_callback(ldc_handle_t handle);
int ldc_set_cb_mode(ldc_handle_t handle, ldc_cb_mode_t imode);
int ldc_chkq(ldc_handle_t handle, boolean_t *hasdata);
int ldc_read(ldc_handle_t handle, caddr_t buf, size_t *size);
int ldc_write(ldc_handle_t handle, caddr_t buf, size_t *size);
int ldc_status(ldc_handle_t handle, ldc_status_t *status);

int ldc_mem_alloc_handle(ldc_handle_t handle, ldc_mem_handle_t *mhandle);
int ldc_mem_free_handle(ldc_mem_handle_t mhandle);
int ldc_mem_bind_handle(ldc_mem_handle_t mhandle, caddr_t vaddr, size_t len,
    uint8_t mtype, uint8_t perm, ldc_mem_cookie_t *cookie, uint32_t *ccount);
int ldc_mem_unbind_handle(ldc_mem_handle_t mhandle);
int ldc_mem_info(ldc_mem_handle_t mhandle, ldc_mem_info_t *minfo);
int ldc_mem_nextcookie(ldc_mem_handle_t mhandle, ldc_mem_cookie_t *cookie);
int ldc_mem_copy(ldc_handle_t handle, caddr_t vaddr, uint64_t off, size_t *len,
    ldc_mem_cookie_t *cookies, uint32_t ccount, uint8_t direction);
int ldc_mem_rdwr_cookie(ldc_handle_t handle, caddr_t vaddr, size_t *size,
    caddr_t paddr, uint8_t  direction);
int ldc_mem_map(ldc_mem_handle_t mhandle, ldc_mem_cookie_t *cookie,
    uint32_t ccount, uint8_t mtype, uint8_t perm, caddr_t *vaddr,
    caddr_t *raddr);
int ldc_mem_unmap(ldc_mem_handle_t mhandle);
int ldc_mem_acquire(ldc_mem_handle_t mhandle, uint64_t offset, uint64_t size);
int ldc_mem_release(ldc_mem_handle_t mhandle, uint64_t offset, uint64_t size);

int ldc_mem_dring_create(uint32_t len, uint32_t dsize,
    ldc_dring_handle_t *dhandle);
int ldc_mem_dring_destroy(ldc_dring_handle_t dhandle);
int ldc_mem_dring_bind(ldc_handle_t handle, ldc_dring_handle_t dhandle,
    uint8_t mtype, uint8_t perm, ldc_mem_cookie_t *dcookie, uint32_t *ccount);
int ldc_mem_dring_nextcookie(ldc_dring_handle_t mhandle,
    ldc_mem_cookie_t *cookie);
int ldc_mem_dring_unbind(ldc_dring_handle_t dhandle);
int ldc_mem_dring_info(ldc_dring_handle_t dhandle, ldc_mem_info_t *minfo);
int ldc_mem_dring_map(ldc_handle_t handle, ldc_mem_cookie_t *cookie,
    uint32_t ccount, uint32_t len, uint32_t dsize, uint8_t mtype,
    ldc_dring_handle_t *dhandle);
int ldc_mem_dring_unmap(ldc_dring_handle_t dhandle);
int ldc_mem_dring_acquire(ldc_dring_handle_t dhandle, uint64_t start,
    uint64_t end);
int ldc_mem_dring_release(ldc_dring_handle_t dhandle, uint64_t start,
    uint64_t end);

/*
 * Shared Memory (Direct Map) Acquire and Release API
 *
 * LDC_MEM_BARRIER_OPEN and LDC_MEM_BARRIER_CLOSE provide on_trap
 * protection for clients accessing imported LDC_DIRECT_MAP'd shared
 * memory segments. Use of these macros is analogous to the
 * ldc_mem_acquire/release and ldc_mem_dring_acquire/release interfaces
 * for LDC_SHADOW_MAP'd segments. After LDC_MEM_BARRIER_OPEN is called,
 * unless an error is returned, LDC_MEM_BARRIER_CLOSE must be called.
 *
 * LDC_MEM_BARRIER_OPEN returns zero on success and EACCES if a data
 * access exception occurs after the OPEN call, but before the CLOSE
 * call. If EACCES is returned, the caller must not call
 * LDC_MEM_BARRIER_CLOSE. In order to handle the EACCES error return,
 * callers should take the same precautions that apply when calling
 * on_trap() when calling LDC_MEM_BARRIER_OPEN.
 *
 * LDC_MEM_BARRIER_OPEN is implemented as a macro so that on_trap
 * protection can be enabled without first executing a save instruction
 * and obtaining a new register window. Aside from LDC clients calling
 * on_trap() directly, one alternative approach is to implement the
 * OPEN function in assembly language without a save instruction and to
 * then call on_trap() as a tail call.
 */
#define	LDC_MEM_BARRIER_OPEN(otd)					\
	(on_trap((otd), OT_DATA_ACCESS) != 0 ?				\
	(no_trap(), EACCES) : 0)

#define	LDC_MEM_BARRIER_CLOSE()						\
	(no_trap(), 0)

#ifdef __cplusplus
}
#endif

#endif /* _LDC_H */
