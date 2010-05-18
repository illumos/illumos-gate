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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_SDCARD_SDA_IMPL_H
#define	_SYS_SDCARD_SDA_IMPL_H

#include <sys/list.h>
#include <sys/ksynch.h>
#include <sys/note.h>
#include <sys/blkdev.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sdcard/sda.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Type and structure definitions.
 */
typedef struct sda_slot sda_slot_t;

/*
 * Per slot state.
 */
struct sda_slot {
	sda_host_t	*s_hostp;
	void		*s_prv;			/* bus private data */
	dev_info_t	*s_dip;			/* devinfo node for child */

	int		s_slot_num;
	boolean_t	s_inserted;
	boolean_t	s_failed;

	uint8_t		s_num_io;
	uint32_t	s_cur_ocr;		/* current ocr */

	uint16_t	s_rca;
	uint32_t	s_maxclk;		/* maximum freq for card */

	sda_cmd_t	*s_xfrp;		/* pending transfer cmd */
	hrtime_t	s_xfrtmo;		/* transfer timeout */

	boolean_t	s_reap;
	boolean_t	s_warn;
	boolean_t	s_ready;		/* target node ready */
	boolean_t	s_init;			/* slot initializing */

	/* these are protected by the evlock */
	boolean_t	s_wake;			/* wake up thread */
	boolean_t	s_detach;		/* detach in progress */
	boolean_t	s_suspend;		/* host has DDI_SUSPENDed */
	boolean_t	s_detect;		/* detect event occurred */
	sda_fault_t	s_fault;
	boolean_t	s_xfrdone;		/* transfer event occurred */
	sda_err_t	s_errno;

	uint16_t	s_flags;
#define	SLOTF_WRITABLE		0x0004
#define	SLOTF_4BITS		0x0008
#define	SLOTF_IFCOND		0x0010
#define	SLOTF_MMC		0x0020
#define	SLOTF_SDMEM		0x0040
#define	SLOTF_SDIO		0x0080
#define	SLOTF_SDHC		0x0100
#define	SLOTF_MEMORY		(SLOTF_MMC | SLOTF_SDMEM)
#define	SLOTF_SD		(SLOTF_SDMEM | SLOTF_SDIO)

	uint16_t	s_caps;
#define	SLOT_CAP_NOPIO		0x0002
#define	SLOT_CAP_HISPEED	0x0004
#define	SLOT_CAP_4BITS		0x0008

	list_t		s_cmdlist;
	list_t		s_abortlist;

	/*
	 * Slot operations.  Slot local copy for performance.
	 */
	sda_ops_t	s_ops;

	/*
	 * Recursive locking of slot.
	 */
	kmutex_t	s_lock;
	kcondvar_t	s_cv;
	kt_did_t	s_owner;	/* owner holding the slot */
	uint32_t	s_circular;	/* circular sda_slot_enter() calls */

	/*
	 * Event notification/thread wakeup.
	 */
	kmutex_t	s_evlock;
	kcondvar_t	s_evcv;

	/*
	 * Asynch. threads.
	 */
	ddi_taskq_t	*s_hp_tq;	/* insert taskq */
	ddi_taskq_t	*s_main_tq;	/* main processing taskq */

	/*
	 * Timestamping for cfgadm benefit.
	 */
	uint8_t		s_intransit;
	time_t		s_stamp;

	/*
	 * Memory card-specific.
	 */
	uint32_t	s_rcsd[4];	/* raw csd */
	uint32_t	s_rcid[4];	/* raw cid */
	uint32_t	s_nblks;	/* total blocks on device */
	uint16_t	s_blksz;	/* device block size (typ. 512) */
	uint16_t	s_bshift;	/* block address shift factor */
	uint32_t	s_speed;	/* max memory clock in hz */

	/* Other CID and CSD values */
	uint32_t	s_mfg;		/* mfg id */
	char		s_prod[8];	/* product id */
	char		s_oem[2];	/* oem id */
	uint32_t	s_serial;
	uint8_t		s_majver;
	uint8_t		s_minver;
	uint16_t	s_year;
	uint8_t		s_month;

	uint16_t	s_ccc;		/* card command classes */
	uint8_t		s_r2w;		/* read/write factor */
	uint8_t		s_dsr;		/* DSR implemented? */
	uint8_t		s_perm_wp;	/* permanent write protect set? */
	uint8_t		s_temp_wp;	/* temporary write protect set? */

	bd_handle_t	s_bdh;		/* block dev handle */
};

/*
 * Per host state.  One per devinfo node.  There could be multiple
 * slots per devinfo node.
 */
struct sda_host {
	dev_info_t	*h_dip;
	int		h_nslot;
	sda_slot_t	*h_slots;
	ddi_dma_attr_t	*h_dma;		/* dma attr, needed for mem */

	list_node_t	h_node;		/* nexus node linkage */

	uint32_t	h_flags;
#define	HOST_ATTACH	(1U << 0)	/* host attach completed */
#define	HOST_XOPEN	(1U << 2)	/* exclusive open */
#define	HOST_SOPEN	(1U << 3)	/* shared open */
};

/*
 * Useful function-like macros.
 */
#define	sda_setprop(s, p, v)	s->s_ops.so_setprop(s->s_prv, p, v)
#define	sda_getprop(s, p, v)	s->s_ops.so_getprop(s->s_prv, p, v)

/*
 * sda_cmd.c
 */
void sda_cmd_init(void);
void sda_cmd_fini(void);
void sda_cmd_list_init(list_t *);
void sda_cmd_list_fini(list_t *);
sda_cmd_t *sda_cmd_alloc(sda_slot_t *, sda_index_t, uint32_t, sda_rtype_t,
    void *, int);
sda_cmd_t *sda_cmd_alloc_acmd(sda_slot_t *, sda_index_t, uint32_t, sda_rtype_t,
    void *, int);
void sda_cmd_free(sda_cmd_t *);
sda_err_t sda_cmd_errno(sda_cmd_t *);
void *sda_cmd_data(sda_cmd_t *);
void sda_cmd_submit(sda_slot_t *, sda_cmd_t *, void (*)(sda_cmd_t *));
void sda_cmd_resubmit_acmd(sda_slot_t *, sda_cmd_t *);
void sda_cmd_notify(sda_cmd_t *, uint16_t, sda_err_t);
sda_err_t sda_cmd_exec(sda_slot_t *, sda_cmd_t *, uint32_t *);

/*
 * sda_init.c
 */
sda_err_t sda_init_card(sda_slot_t *);

/*
 * sda_mem.c
 */
void sda_mem_init(struct modlinkage *);
void sda_mem_fini(struct modlinkage *);
uint32_t sda_mem_maxclk(sda_slot_t *);
uint32_t sda_mem_getbits(uint32_t *, int, int);
int sda_mem_parse_cid_csd(sda_slot_t *);
int sda_mem_bd_read(void *, bd_xfer_t *);
int sda_mem_bd_write(void *, bd_xfer_t *);
void sda_mem_bd_driveinfo(void *, bd_drive_t *);
int sda_mem_bd_mediainfo(void *, bd_media_t *);


/*
 * sda_nexus.c
 */
void sda_nexus_init(void);
void sda_nexus_fini(void);
void sda_nexus_register(sda_host_t *);
void sda_nexus_unregister(sda_host_t *);
int sda_nexus_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
int sda_nexus_open(dev_t *, int, int, cred_t *);
int sda_nexus_close(dev_t, int, int, cred_t *);
int sda_nexus_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
int sda_nexus_bus_ctl(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *,
    void *);
void sda_nexus_remove(sda_slot_t *);
void sda_nexus_insert(sda_slot_t *);
void sda_nexus_reap(void *);

/*
 * sda_slot.c
 */
void sda_slot_init(sda_slot_t *);
void sda_slot_fini(sda_slot_t *);
void sda_slot_enter(sda_slot_t *);
void sda_slot_exit(sda_slot_t *);
boolean_t sda_slot_owned(sda_slot_t *);
void sda_slot_attach(sda_slot_t *);
void sda_slot_detach(sda_slot_t *);
void sda_slot_suspend(sda_slot_t *);
void sda_slot_resume(sda_slot_t *);
void sda_slot_reset(sda_slot_t *);
void sda_slot_wakeup(sda_slot_t *);
void sda_slot_detect(sda_slot_t *);
int sda_slot_power_on(sda_slot_t *);
void sda_slot_power_off(sda_slot_t *);
void sda_slot_reset(sda_slot_t *);
void sda_slot_shutdown(sda_slot_t *);
void sda_slot_transfer(sda_slot_t *, sda_err_t);
void sda_slot_fault(sda_slot_t *, sda_fault_t);
/*PRINTFLIKE2*/
void sda_slot_err(sda_slot_t *, const char *, ...);
/*PRINTFLIKE2*/
void sda_slot_log(sda_slot_t *, const char *, ...);

#ifdef	DEBUG
#define	sda_slot_debug(...)	sda_slot_log(__VA_ARGS__)
#else
#define	sda_slot_debug(...)
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_SDCARD_SDA_IMPL_H */
