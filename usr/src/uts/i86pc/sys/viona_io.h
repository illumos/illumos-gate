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
 */

#ifndef	_VIONA_IO_H_
#define	_VIONA_IO_H_

#define	VNA_IOC			(('V' << 16)|('C' << 8))
#define	VNA_IOC_CREATE		(VNA_IOC | 1)
#define	VNA_IOC_DELETE		(VNA_IOC | 2)
#define	VNA_IOC_RX_RING_INIT	(VNA_IOC | 3)
#define	VNA_IOC_TX_RING_INIT	(VNA_IOC | 4)
#define	VNA_IOC_RX_RING_RESET	(VNA_IOC | 5)
#define	VNA_IOC_TX_RING_RESET	(VNA_IOC | 6)
#define	VNA_IOC_RX_RING_KICK	(VNA_IOC | 7)
#define	VNA_IOC_TX_RING_KICK	(VNA_IOC | 8)
#define	VNA_IOC_RX_INTR_CLR	(VNA_IOC | 9)
#define	VNA_IOC_TX_INTR_CLR	(VNA_IOC | 10)
#define VNA_IOC_SET_FEATURES	(VNA_IOC | 11)
#define VNA_IOC_GET_FEATURES	(VNA_IOC | 12)

typedef struct vioc_create {
	datalink_id_t	c_linkid;
	char		c_vmname[64];
	size_t		c_lomem_size;
	size_t		c_himem_size;
} vioc_create_t;

typedef struct vioc_ring_init {
	uint16_t	ri_qsize;
	uint64_t	ri_qaddr;
} vioc_ring_init_t;

#endif	/* _VIONA_IO_H_ */
