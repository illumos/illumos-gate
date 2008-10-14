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
 * Copyright 2008 Emulex.  All rights reserved.
 * Use is subject to License terms.
 */


#ifndef _EMLXS_OS_H
#define	_EMLXS_OS_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	EMLXS_MODREV2	2	/* Old Solaris 8 & 9 interface */
#define	EMLXS_MODREV3	3	/* New Solaris 10 & 11 interface */
#define	EMLXS_MODREV4	4	/* Sun FC packet change */
/* Symbolic Node Name interface */
#define	EMLXS_MODREV5	5	/* New Sun NPIV Interface */

#define	EMLXS_MODREV2X	2	/* Old Solaris 8 & 9 x86 interface */
#define	EMLXS_MODREV3X	3	/* New Solaris 10 & 11 x86 interface */


/*
 *  DRIVER LEVEL FEATURES
 */
#define	DFC_SUPPORT		/* 2.20 driver */
#define	DHCHAP_SUPPORT		/* 2.21 driver */

#define	SATURN_MSI_SUPPORT	/* 2.30 driver */

#define	MENLO_SUPPORT		/* 2.30 driver */
#define	MENLO_TEST		/* 2.30 driver - Supports hornet test params */

#define	MBOX_EXT_SUPPORT	/* 2.30 driver */
#define	SLI3_SUPPORT		/* 2.30 driver - Required for NPIV */

/* #define IDLE_TIMER		Not yet - untested */


/*
 *   OS LEVEL FEATURES
 */

#ifdef S8
#define	EMLXS_MODREV EMLXS_MODREV2

#ifdef EMLXS_I386
#define	EMLXS_MODREVXEMLXS_MODREV2X
#endif	/* EMLXS_I386 */
#endif	/* S8 */


#ifdef S9
#define	EMLXS_MODREV EMLXS_MODREV2
#define	MSI_SUPPORT

#ifdef EMLXS_I386
#define	EMLXS_MODREVX EMLXS_MODREV2X
#endif	/* EMLXS_I386 */
#endif	/* S9 */


#ifdef S10
#define	EMLXS_MODREV EMLXS_MODREV3
#define	MSI_SUPPORT

#ifdef SLI3_SUPPORT
#define	NPIV_SUPPORT
#endif	/* SLI3_SUPPORT */

#ifdef EMLXS_I386
#define	EMLXS_MODREVX EMLXS_MODREV2X
#endif	/* EMLXS_I386 */
#endif	/* S10 */


#ifdef S11
#define	MSI_SUPPORT
#define	SFCT_SUPPORT	/* COMSTAR Support */

#ifdef SLI3_SUPPORT
#define	NPIV_SUPPORT

#ifdef NPIV_SUPPORT
#define	SUN_NPIV_SUPPORT	/* Nevada Build 91+ */
#endif	/* NPIV_SUPPORT */
#endif	/* SLI3_SUPPORT */

#ifdef SUN_NPIV_SUPPORT
#define	EMLXS_MODREV EMLXS_MODREV5	/* Sun NPIV Enhancement */
#else
#define	EMLXS_MODREV EMLXS_MODREV4
#endif	/* SUN_NPIV_SUPPORT */

#ifdef EMLXS_I386
#define	EMLXS_MODREVX EMLXS_MODREV2X
#endif	/* EMLXS_I386 */
#endif	/* S11 */

/*
 *    SUBFEATURES
 */
#ifdef SFCT_SUPPORT
#define	MODSYM_SUPPORT	/* Dynamic Module Loading Support */
#define	FCIO_SUPPORT	/* FCIO IOCTL support */
#endif	/* SFCT_SUPPORT */


#ifndef EMLXS_MODREV
#define	EMLXS_MODREV			0
#endif	/* EMLXS_MODREV */

#ifndef EMLXS_MODREVX
#define	EMLXS_MODREVX			0
#endif	/* EMLXS_MODREVX */

/* Create combined definition */
#if defined(S10) || defined(S11)
#define	S10S11
#endif	/* S10 or S11 */

#if defined(S8) || defined(S9)
#define	S8S9
#endif	/* S8 or S9 */


#define	DRIVER_NAME "emlxs"

#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/devops.h>
#include <sys/param.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/fcntl.h>

#include <sys/cmn_err.h>
#include <sys/stropts.h>
#include <sys/kmem.h>

#include <sys/errno.h>
#include <sys/open.h>
#include <sys/kmem.h>
#include <sys/poll.h>
#include <sys/thread.h>
#include <sys/taskq.h>
#include <sys/debug.h>
#include <sys/cpu.h>
#include <sys/autoconf.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/var.h>

#include <sys/map.h>
#include <sys/file.h>
#include <sys/syslog.h>
#include <sys/disp.h>
#include <sys/taskq.h>

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/promif.h>
#include <sys/ethernet.h>
#include <vm/seg_kmem.h>
#include <sys/utsname.h>
#include <sys/modctl.h>
#include <sys/scsi/scsi.h>
#include <sys/varargs.h>
#include <sys/atomic.h>

#include <emlxs_hbaapi.h>


#ifdef S11

/* ULP header files */
#include <sys/fibre-channel/fc.h>
#include <sys/fibre-channel/impl/fc_fcaif.h>

#else	/* !S11 */

/* ULP header files */
#include <sys/fibre-channel/fcio.h>
#include <sys/fibre-channel/fc.h>
#include <sys/fibre-channel/fc_appif.h>
#include <sys/fibre-channel/fc_types.h>
#include <sys/fibre-channel/impl/fc_error.h>
#include <sys/fibre-channel/impl/fc_fla.h>
#include <sys/fibre-channel/impl/fc_linkapp.h>
#include <sys/fibre-channel/impl/fcal.h>
#include <sys/fibre-channel/impl/fcgs2.h>
#include <sys/fibre-channel/impl/fcph.h>
#include <sys/fibre-channel/impl/fc_ulpif.h>
#include <sys/fibre-channel/impl/fc_fcaif.h>
#include <sys/fibre-channel/impl/fctl.h>
#include <sys/fibre-channel/impl/fctl_private.h>
#include <sys/fibre-channel/ulp/fcp.h>
#include <sys/fibre-channel/ulp/fcp_util.h>

#endif	/* S11 */


#ifndef FC_HBA_PORTSPEED_8GBIT
#define	FC_HBA_PORTSPEED_8GBIT		16
#endif	/* FC_HBA_PORTSPEED_8GBIT */

#ifndef FP_DEFAULT_SID
#define	FP_DEFAULT_SID		(0x000AE)
#endif	/* FP_DEFAULT_SID */

#ifndef FP_DEFAULT_DID
#define	FP_DEFAULT_DID		(0x000EA)
#endif	/* FP_DEFAULT_DID */

#ifdef MSI_SUPPORT
#pragma weak ddi_intr_get_supported_types
#pragma weak ddi_intr_get_nintrs
#pragma weak ddi_intr_add_handler
#pragma weak ddi_intr_remove_handler
#pragma weak ddi_intr_get_hilevel_pri
#pragma weak ddi_intr_enable
#pragma weak ddi_intr_disable
#pragma weak ddi_intr_get_cap
#pragma weak ddi_intr_get_pri
#pragma weak ddi_intr_alloc
#pragma weak ddi_intr_free
#pragma weak ddi_intr_block_enable
#pragma weak ddi_intr_block_disable
extern int ddi_intr_get_supported_types();

#ifdef S9
/* Obtained from /usr/include/sys/ddi_intr.h */
#ifndef ddi_intr_handle_t
typedef void *ddi_intr_handle_t;
#endif	/* ddi_intr_handle_t */

#ifndef DDI_INTR_TYPE_FIXED
#define	DDI_INTR_TYPE_FIXED	0x1
#endif

#ifndef DDI_INTR_TYPE_MSI
#define	DDI_INTR_TYPE_MSI	0x2
#endif

#ifndef DDI_INTR_TYPE_MSIX
#define	DDI_INTR_TYPE_MSIX	0x4
#endif

#ifndef DDI_INTR_ALLOC_NORMAL
#define	DDI_INTR_ALLOC_NORMAL	0	/* Non-strict alloc */
#endif

#ifndef DDI_INTR_FLAG_BLOCK
#define	DDI_INTR_FLAG_BLOCK	0x0100	/* (RO) requires block enable */
#endif
#endif	/* S9 */

#endif	/* MSI_SUPPORT */

#ifndef MODSYM_SUPPORT
#pragma weak fc_fca_init
#pragma weak fc_fca_attach
#pragma weak fc_fca_detach
#endif	/* MODSYM_SUPPORT */

/* S11 flag for dma_attr_flags for ddi_dma_attr_t */
#ifndef DDI_DMA_RELAXED_ORDERING
#define	DDI_DMA_RELAXED_ORDERING	0x400
#endif	/* DDI_DMA_RELAXED_ORDERING */


#ifdef EMLXS_SPARC
#define	EMLXS_BIG_ENDIAN
#endif	/* EMLXS_SPARC */

#ifdef EMLXS_I386
#define	EMLXS_LITTLE_ENDIAN
#endif	/* EMLXS_I386 */


/* Solaris 8 does not define this */
#ifndef TASKQ_DYNAMIC
#define	TASKQ_DYNAMIC			0x0004
#endif	/* TASKQ_DYNAMIC */

#ifdef _LP64
#define	DEAD_PTR 0xdeadbeefdeadbeef
#else
#define	DEAD_PTR 0xdeadbeef
#endif	/* _LP64 */

#ifndef FC_STATE_8GBIT_SPEED
/* This was obtained from OpenSolaris */
#define	FC_STATE_8GBIT_SPEED		0x0700	/* 8 Gbit/sec */
#endif	/* FC_STATE_8GBIT_SPEED */

#define	FC_STATE_QUAD_SPEED		0x0500

#ifndef BURSTSIZE
#define	BURSTSIZE
#define	BURST1				0x01
#define	BURST2				0x02
#define	BURST4				0x04
#define	BURST8				0x08
#define	BURST16				0x10
#define	BURST32				0x20
#define	BURST64				0x40
#ifdef _LP64
#define	BURSTSIZE_MASK			0x7f
#else
#define	BURSTSIZE_MASK			0x3f
#endif	/* _LP64 */
#define	DEFAULT_BURSTSIZE	(BURSTSIZE_MASK)	/* all burst sizes */
#endif	/* BURSTSIZE */

#define	putPaddrLow(addr) 	((uint32_t)((uint64_t)(addr) & 0xffffffff))
#define	putPaddrHigh(addr)	((uint32_t)((uint64_t)(addr) >> 32))
#define	getPaddr(high, low) 	((uint64_t)(((uint64_t)(high) << 32) | \
					((uint64_t)(low) & 0xffffffff)))

#ifndef TRUE
#define	TRUE	1
#endif	/* TRUE */

#ifndef FALSE
#define	FALSE	0
#endif	/* FALSE */

#define	DMA_READ_WRITE	0
#define	DMA_READ_ONLY 	1
#define	DMA_WRITE_ONLY	2

#define	DMA_SUCC	1

#define	MAX_FC_BRDS 	256	/* Maximum # boards per system */

#define	DELAYMS(ms)		drv_usecwait((ms*1000))
#define	DELAYUS(us)		drv_usecwait(us)

#define	emlxs_mpdata_sync(h, a, b, c)	\
	if (h) {\
		(void) ddi_dma_sync((ddi_dma_handle_t)(h),\
		    (off_t)(a), (size_t)(b), (uint_t)c);\
	}



#define	PKT2PRIV(pkt)		((emlxs_buf_t *)(pkt)->pkt_fca_private)
#define	PRIV2PKT(sbp)		sbp->pkt

#define	EMLXS_INUMBER		0
#define	EMLXS_MSI_INUMBER 	0

#define	EMLXS_DMA_ALIGN		BURST16

/*
 *   Register indices in PCI configuration space.
 */
#define	SBUS_FLASH_RD		0	/* FCODE-Flash Read only index */
#define	SBUS_FLASH_RDWR		1	/* FCODE-Flash Read/Write index */
#define	SBUS_DFLY_SLIM_RINDEX	2	/* DragonFly SLIM regs index */
#define	SBUS_DFLY_CSR_RINDEX	3	/* DragonFly I/O regs index */
#define	SBUS_TITAN_CORE_RINDEX	4	/* TITAN Core register index */
#define	SBUS_DFLY_PCI_CFG_RINDEX 5	/* DragonFly PCI ConfigSpace regs */
					/* index */
#define	SBUS_TITAN_PCI_CFG_RINDEX 6	/* TITAN PCI ConfigSpace regs index */
#define	SBUS_TITAN_CSR_RINDEX	7	/* TITAN Control/Status regs index */

#define	PCI_CFG_RINDEX		0
#define	PCI_SLIM_RINDEX		1
#define	PCI_CSR_RINDEX		2

#define	EMLXS_MAX_UBUFS		65535

/* Tokens < EMLXS_UB_TOKEN_OFFSET are reserved for ELS response oxids */
#define	EMLXS_UB_TOKEN_OFFSET 0x100

typedef struct emlxs_ub_priv {
	fc_unsol_buf_t *ubp;
	void *port;

	uint32_t bpl_size;
	uint8_t *bpl_virt;	/* virtual address ptr */
	uint64_t bpl_phys;	/* mapped address */
	void *bpl_data_handle;
	void *bpl_dma_handle;

	uint32_t ip_ub_size;
	uint8_t *ip_ub_virt;	/* virtual address ptr */
	ddi_dma_cookie_t ip_ub_dma_cookies[64];
	ddi_acc_handle_t ip_ub_data_handle;
	ddi_dma_handle_t ip_ub_dma_handle;
	uint32_t ip_ub_cookie_cnt;
	uint32_t FC4type;

	uint16_t flags;
#define	EMLXS_UB_FREE		0x0000
#define	EMLXS_UB_IN_USE		0x0001
#define	EMLXS_UB_REPLY		0x0002
#define	EMLXS_UB_RESV		0x0004
#define	EMLXS_UB_TIMEOUT	0x0008
#define	EMLXS_UB_INTERCEPT	0x0010

	uint16_t available;

	uint32_t timeout;	/* Timeout period in seconds */
	uint32_t time;		/* EMLXS_UB_IN_USE timestamp */
	uint32_t cmd;
	uint32_t token;

	struct emlxs_unsol_buf *pool;

	struct emlxs_ub_priv *next;

} emlxs_ub_priv_t;


typedef struct emlxs_unsol_buf {
	struct emlxs_unsol_buf *pool_prev;	/* ptr to prev type of */
						/* unsol_buf_header */
	struct emlxs_unsol_buf *pool_next;	/* ptr to next type of */
						/* unsol_buf_header */

	uint32_t pool_type;	/* FC-4 type */
	uint32_t pool_buf_size;	/* buffer size for this pool */

	uint32_t pool_nentries;		/* no.of bufs in pool */
	uint32_t pool_available;	/* no.of bufs avail in pool */

	uint32_t pool_flags;
#define	POOL_DESTROY	0x00000001	/* Pool is marked for destruction */

	uint32_t pool_free;		/* Number of free buffers */
	uint32_t pool_free_resv;	/* Number of free reserved buffers */

	uint32_t pool_first_token;	/* First ub_priv->token in pool */
	uint32_t pool_last_token;	/* Last  ub_priv->token in pool */

	fc_unsol_buf_t *fc_ubufs;	/* array of unsol buf structs */

} emlxs_unsol_buf_t;


#ifndef FC_REASON_NONE
#define	FC_REASON_NONE			0
#endif	/* FC_REASON_NONE */

#ifndef FC_ACTION_NONE
#define	FC_ACTION_NONE			0
#endif	/* FC_ACTION_NONE */

/*
 * emlx status translation table
 */
typedef struct emlxs_xlat_err {
	uint32_t emlxs_status;
	uint32_t pkt_state;
	uint32_t pkt_reason;
	uint32_t pkt_expln;
	uint32_t pkt_action;
} emlxs_xlat_err_t;


typedef struct emlxs_table {
	uint32_t code;
	char string[32];

} emlxs_table_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_OS_H */
