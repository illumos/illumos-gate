/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * This file is part of the Chelsio T4 support code.
 *
 * Copyright (C) 2011-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __T4NEX_H
#define	__T4NEX_H

#ifdef __cplusplus
extern "C" {
#endif

#define	T4_IOCTL		((('t' << 16) | '4') << 8)
#define	T4_IOCTL_PCIGET32	(T4_IOCTL + 1)
#define	T4_IOCTL_PCIPUT32	(T4_IOCTL + 2)
#define	T4_IOCTL_GET32		(T4_IOCTL + 3)
#define	T4_IOCTL_PUT32		(T4_IOCTL + 4)
#define	T4_IOCTL_REGDUMP	(T4_IOCTL + 5)
#define	T4_IOCTL_SGE_CONTEXT	(T4_IOCTL + 6)
#define	T4_IOCTL_DEVLOG		(T4_IOCTL + 7)
#define	T4_IOCTL_GET_MEM	(T4_IOCTL + 8)
#define	T4_IOCTL_GET_TID_TAB	(T4_IOCTL + 9)
#define	T4_IOCTL_GET_MBOX	(T4_IOCTL + 10)
#define	T4_IOCTL_GET_CIM_LA	(T4_IOCTL + 11)
#define	T4_IOCTL_GET_CIM_QCFG	(T4_IOCTL + 12)
#define	T4_IOCTL_GET_CIM_IBQ	(T4_IOCTL + 13)
#define	T4_IOCTL_GET_EDC	(T4_IOCTL + 14)
#define	T4_IOCTL_LOAD_FW	(T4_IOCTL + 15)

enum {
	T4_CTXT_EGRESS,
	T4_CTXT_INGRESS,
	T4_CTXT_FLM
};

struct t4_reg32_cmd {
	uint32_t reg;
	uint32_t value;
};

#define	T4_REGDUMP_SIZE (160 * 1024)
#define	T5_REGDUMP_SIZE (332 * 1024)
struct t4_regdump {
	uint32_t  version;
	uint32_t  len;
	uint8_t   *data;
};

struct t4_sge_context {
	uint32_t version;
	uint32_t mem_id;
	uint32_t addr;
	uint32_t len;
	uint8_t  *data;
};

struct t4_mem_range {
	uint32_t addr;
	uint32_t len;
	uint32_t *data;
};

struct t4_tid_info {
	uint32_t len;
	uint32_t *data;
};

struct t4_mbox {
	uint32_t len;
	uint32_t *data;
};

struct t4_cim_la {
	uint32_t len;
	uint32_t *data;
};

struct t4_ibq {
	uint32_t len;
	uint32_t *data;
};

struct t4_edc {
	uint32_t len;
	uint32_t mem;
	uint32_t pos;
	char *data;
};

struct t4_cim_qcfg {
	uint16_t base[14];
	uint16_t size[14];
	uint16_t thres[6];
	uint32_t stat[4 * (6 + 8)];
	uint32_t obq_wr[2 * (8)];
	uint32_t num_obq;
};

#define	T4_DEVLOG_SIZE	32768
struct t4_devlog {
	uint32_t len;
	uint32_t data[0];
};

struct t4_ldfw {
	uint32_t len;
	uint32_t data[0];
};

#ifdef __cplusplus
}
#endif

#endif /* __T4NEX_H */
