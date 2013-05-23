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
 * Copyright (C) 2010-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CXGBE_OFFLOAD_H
#define	__CXGBE_OFFLOAD_H

/*
 * Max # of ATIDs.  The absolute HW max is 16K but we keep it lower.
 */
#define	MAX_ATIDS 8192U

#define	INIT_ULPTX_WR(w, wrlen, atomic, tid) do { \
	(w)->wr.wr_hi = htonl(V_FW_WR_OP(FW_ULPTX_WR) | \
		V_FW_WR_ATOMIC(atomic)); \
	(w)->wr.wr_mid = htonl(V_FW_WR_LEN16(DIV_ROUND_UP(wrlen, 16)) | \
		V_FW_WR_FLOWID(tid)); \
	(w)->wr.wr_lo = cpu_to_be64(0); \
} while (0)

#define	INIT_TP_WR(w, tid) do { \
	(w)->wr.wr_hi = htonl(V_FW_WR_OP(FW_TP_WR) | \
		V_FW_WR_IMMDLEN(sizeof (*w) - sizeof (w->wr))); \
	(w)->wr.wr_mid = htonl(V_FW_WR_LEN16(DIV_ROUND_UP(sizeof (*w), 16)) | \
		V_FW_WR_FLOWID(tid)); \
	(w)->wr.wr_lo = cpu_to_be64(0); \
} while (0)

#define	INIT_TP_WR_MIT_CPL(w, cpl, tid) do { \
	INIT_TP_WR(w, tid); \
	OPCODE_TID(w) = htonl(MK_OPCODE_TID(cpl, tid)); \
} while (0)

union serv_entry {
	void *data;
	union serv_entry *next;
};

union aopen_entry {
	void *data;
	union aopen_entry *next;
};

/*
 * Holds the size, base address, free list start, etc of the TID, server TID,
 * and active-open TID tables.  The tables themselves are allocated dynamically.
 */
struct tid_info {
	void **tid_tab;
	unsigned int ntids;

	union serv_entry *stid_tab;
	unsigned int nstids;
	unsigned int stid_base;

	union aopen_entry *atid_tab;
	unsigned int natids;

	struct filter_entry *ftid_tab;
	unsigned int nftids;
	unsigned int ftid_base;
	unsigned int ftids_in_use;

	kmutex_t atid_lock;
	union aopen_entry *afree;
	unsigned int atids_in_use;

	kmutex_t stid_lock;
	union serv_entry *sfree;
	unsigned int stids_in_use;

	unsigned int tids_in_use;
};

struct t4_range {
	unsigned int start;
	unsigned int size;
};

struct t4_virt_res {		/* virtualized HW resources */
	struct t4_range ddp;
	struct t4_range iscsi;
	struct t4_range stag;
	struct t4_range rq;
	struct t4_range pbl;
};

struct adapter;
struct port_info;

enum {
	ULD_TOM = 1,
};

enum cxgb4_control {
	CXGB4_CONTROL_SET_OFFLOAD_POLICY,
};

struct uld_info {
	SLIST_ENTRY(uld_info) link;
	int refcount;
	int uld_id;
	int (*attach)(struct adapter *, void **);
	int (*detach)(void *);
	int (*rx)(void *, const void *, mblk_t *);
	int (*control)(void *handle, enum cxgb4_control control, ...);
};

struct uld_softc {
	struct uld_info *uld;
	void *softc;
};

struct tom_tunables {
	int sndbuf;
	int ddp;
	int indsz;
	int ddp_thres;
};

#ifndef TCP_OFFLOAD_DISABLE
struct offload_req {
	__be32 sip[4];
	__be32 dip[4];
	__be16 sport;
	__be16 dport;
	__u8   ipvers_opentype;
	__u8   tos;
	__be16 vlan;
	__u32  mark;
};

enum { OPEN_TYPE_LISTEN, OPEN_TYPE_ACTIVE, OPEN_TYPE_PASSIVE };

struct offload_settings {
	__u8  offload;
	int8_t  ddp;
	int8_t  rx_coalesce;
	int8_t  cong_algo;
	int32_t	rssq;
	int16_t sched_class;
	int8_t  tstamp;
	int8_t  sack;

};
#endif

extern int t4_register_uld(struct uld_info *ui);
extern int t4_unregister_uld(struct uld_info *ui);

#endif /* __CXGBE_OFFLOAD_H */
