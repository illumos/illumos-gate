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
 * Copyright 2013 Pluribus Networks Inc.
 * Copyright 2018 Joyent, Inc.
 * Copyright 2022 Oxide Computer Company
 */

#ifndef	_VIONA_IO_H_
#define	_VIONA_IO_H_

#define	VNA_IOC			(('V' << 16)|('C' << 8))
#define	VNA_IOC_CREATE		(VNA_IOC | 0x01)
#define	VNA_IOC_DELETE		(VNA_IOC | 0x02)
#define	VNA_IOC_VERSION		(VNA_IOC | 0x03)

#define	VNA_IOC_RING_INIT	(VNA_IOC | 0x10)
#define	VNA_IOC_RING_RESET	(VNA_IOC | 0x11)
#define	VNA_IOC_RING_KICK	(VNA_IOC | 0x12)
#define	VNA_IOC_RING_SET_MSI	(VNA_IOC | 0x13)
#define	VNA_IOC_RING_INTR_CLR	(VNA_IOC | 0x14)
#define	VNA_IOC_RING_SET_STATE	(VNA_IOC | 0x15)
#define	VNA_IOC_RING_GET_STATE	(VNA_IOC | 0x16)
#define	VNA_IOC_RING_PAUSE	(VNA_IOC | 0x17)

#define	VNA_IOC_INTR_POLL	(VNA_IOC | 0x20)
#define	VNA_IOC_SET_FEATURES	(VNA_IOC | 0x21)
#define	VNA_IOC_GET_FEATURES	(VNA_IOC | 0x22)
#define	VNA_IOC_SET_NOTIFY_IOP	(VNA_IOC | 0x23)


/*
 * Viona Interface Version
 *
 * Like bhyve, viona exposes Private interfaces which are nonetheless consumed
 * by out-of-gate consumers.  While those consumers assume all risk of breakage
 * incurred by subsequent changes, it would be nice to equip them to potentially
 * detect (and handle) those modifications.
 *
 * There are no established criteria for the magnitude of change which requires
 * this version to be incremented, and maintenance of it is considered a
 * best-effort activity.  Nothing is to be inferred about the magnitude of a
 * change when the version is modified.  It follows no rules like semver.
 *
 */
#define	VIONA_CURRENT_INTERFACE_VERSION	1

typedef struct vioc_create {
	datalink_id_t	c_linkid;
	int		c_vmfd;
} vioc_create_t;

typedef struct vioc_ring_init {
	uint16_t	ri_index;
	uint16_t	ri_qsize;
	uint64_t	ri_qaddr;
} vioc_ring_init_t;

typedef struct vioc_ring_state {
	uint16_t	vrs_index;
	uint16_t	vrs_avail_idx;
	uint16_t	vrs_used_idx;
	uint16_t	vrs_qsize;
	uint64_t	vrs_qaddr;
} vioc_ring_state_t;

typedef struct vioc_ring_msi {
	uint16_t	rm_index;
	uint64_t	rm_addr;
	uint64_t	rm_msg;
} vioc_ring_msi_t;

enum viona_vq_id {
	VIONA_VQ_RX = 0,
	VIONA_VQ_TX = 1,
	VIONA_VQ_MAX = 2
};

typedef struct vioc_intr_poll {
	uint32_t	vip_status[VIONA_VQ_MAX];
} vioc_intr_poll_t;


#endif	/* _VIONA_IO_H_ */
