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
 * Copyright 1999 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SCSI_ADAPTERS_IFPIO_H
#define	_SYS_SCSI_ADAPTERS_IFPIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Include any headers you depend on.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	IFP_IOC	('I' << 8)

/*
 * Get ifp device map ioctl.
 */
#define	IFPIOCGMAP		(IFP_IOC|1)	/* Get device map/wwn's */
#define	IFPIO_ADISC_ELS		(IFP_IOC|2)	/* Get ADISC info */
#define	IFPIO_FORCE_LIP		(IFP_IOC|3)	/* Force a LIP */
#define	IFPIO_LINKSTATUS	(IFP_IOC|4)	/* Link Status */
#define	IFPIO_DIAG_GET_FWREV	(IFP_IOC|5)	/* SunVTS diag get fw rev */
#define	IFPIO_DIAG_NOP		(IFP_IOC|6)	/* SunVTS diag NOOP */
#define	IFPIO_DIAG_MBOXCMD	(IFP_IOC|7)	/* SunVTS diag mbox cmds */
#define	IFPIO_LOOPBACK_FRAME	(IFP_IOC|8)	/* Diagnostic loopback */
#define	IFPIO_DIAG_SELFTEST	(IFP_IOC|9)	/* Diagnostic selftest */
#define	IFPIO_BOARD_INFO	(IFP_IOC|10)	/* Get device id and rev's */
#define	IFPIO_FCODE_DOWNLOAD	(IFP_IOC|11)	/* Download fcode to flash */

struct ifp_board_info {
	uint16_t	ifpd_major;		/* FW major revision */
	uint16_t	ifpd_minor;		/* FW minor revision */
	uint16_t	ifpd_subminor;		/* FW subminor revision */
	uint16_t	chip_rev;		/* chip revision level */
	uint16_t	ctrl_id;		/* 2100 or 2200 */
};
typedef struct ifp_board_info ifp_board_info_t;

struct ifp_diag_fw_rev {
	uint16_t	ifpd_major;		/* FW major revision */
	uint16_t	ifpd_minor;		/* FW minor revision */
};
typedef struct ifp_diag_fw_rev ifp_diag_fw_rev_t;

struct ifp_lb_frame_cmd {
	uint16_t	options;		/* diag loop-back options */
	uint32_t	iter_cnt;		/* count of loopback ops */
	uint32_t	xfer_cnt;		/* transmit/receive xfer len */
	caddr_t		xmit_addr;		/* transmit data address */
	caddr_t		recv_addr;		/* receive data address */

	uint16_t	status;			/* completion status */
	uint16_t	crc_cnt;		/* crc error count */
	uint16_t	disparity_cnt;		/* disparity error count */
	uint16_t	frame_len_err_cnt;	/* frame length error count */
	uint32_t	fail_iter_cnt;		/* failing iteration count */
};
typedef struct ifp_lb_frame_cmd ifp_lb_frame_cmd_t;

#if defined(_LP64)
struct ifp_lb_frame_cmd32 {
	uint16_t	options;		/* diag loop-back options */
	uint32_t	iter_cnt;		/* count of loopback ops */
	uint32_t	xfer_cnt;		/* transmit/receive xfer len */
	caddr32_t	xmit_addr;		/* transmit data address */
	caddr32_t	recv_addr;		/* receive data address */

	uint16_t	status;			/* completion status */
	uint16_t	crc_cnt;		/* crc error count */
	uint16_t	disparity_cnt;		/* disparity error count */
	uint16_t	frame_len_err_cnt;	/* frame length error count */
	uint32_t	fail_iter_cnt;		/* failing iteration count */
};
#endif

/* defines for options field */
#define	LOOP_10BIT	0x0000		/* loopback at 10 bit interface */
#define	LOOP_1BIT	0x0001		/* loopback at 1 bit interface */
#define	LOOP_EXTERNAL	0x0002		/* loopback on external loop */
#define	LOOP_XMIT_OFF	0x0004		/* transmitter powered off */
#define	LOOP_XMIT_RAM	0x0010		/* xmit data from system ram */
#define	LOOP_RECV_RAM	0x0020		/* receive data to system ram */
#define	LOOP_ERR_STOP	0x0080		/* stop test on error */

struct ifp_diag_selftest {
	uint16_t	status;			/* completion status */
	uint16_t	test_num;		/* failing test number */
	uint16_t	fail_addr;		/* failure address */
	uint16_t	fail_data;		/* failure data */
};
typedef struct ifp_diag_selftest ifp_diag_selftest_t;

/* offset of the fcode from begining of file */
#define	FCODE_OFFSET	0x20
struct ifp_download {
	uint32_t	dl_fcode_len;		/* length of the fcode array */
	uint16_t	dl_chip_id;		/* Chip id for FCODE */
	uchar_t	dl_fcode[1];		/* the fcode */
};
typedef struct ifp_download ifp_download_t;

#define	IFP_NUM_ENTRIES_IN_MAP	127
#define	IFP_DIAG_MAX_MBOX	10

struct ifp_al_addr_pair {
	uchar_t	ifp_al_pa;
	uchar_t	ifp_hard_address;
	uchar_t	ifp_inq_dtype;
	uchar_t	ifp_node_wwn[FC_WWN_SIZE];
	uchar_t	ifp_port_wwn[FC_WWN_SIZE];
};
typedef struct ifp_al_addr_pair ifp_al_addr_pair_t;

struct ifp_al_map {
	short			ifp_count;
	ifp_al_addr_pair_t	ifp_addr_pair[IFP_NUM_ENTRIES_IN_MAP];
	ifp_al_addr_pair_t	ifp_hba_addr;
};
typedef struct ifp_al_map ifp_al_map_t;

struct adisc_payload {
	uint_t	adisc_hardaddr;
	uchar_t	adisc_portwwn[8];
	uchar_t	adisc_nodewwn[8];
	uint_t	adisc_dest;
};

struct rls_payload {
	uint_t	rls_portno;
	uint_t	rls_linkfail;
	uint_t	rls_syncfail;
	uint_t	rls_sigfail;
	uint_t	rls_primitiverr;
	uint_t	rls_invalidword;
	uint_t	rls_invalidcrc;
};
typedef struct rls_payload rls_payload_t;

struct ifp_target_stats {
	int	logouts_recvd;
					/*
					 * unsolicited LOGOs recvd from
					 * target
					 */
	int	task_mgmt_failures;
	int	data_ro_mismatches;
	int	dl_len_mismatches;
};
typedef struct ifp_target_stats ifp_target_stats_t;

struct ifp_stats {
	int	version;		/* version of this struct */
	int	lip_count;		/* lips forced by ifp */
	int	ncmds;			/* outstanding commands */
	ifp_target_stats_t tstats[IFP_NUM_ENTRIES_IN_MAP]; /* per tgt stats */
};
typedef struct ifp_stats ifp_stats_t;

/* XXX temp hack to get sf/socal ioctls used by luxadm to work with ifp */

#if !defined(SFIOCGMAP)
#define	SFIOCGMAP		((0xda << 8)|1)
#endif
#if !defined(FCIO_GETMAP)
#define	FCIO_GETMAP		(('F' << 8)|175)
struct lilpmap {
	ushort_t lilp_magic;
	ushort_t lilp_myalpa;
	uchar_t  lilp_length;
	uchar_t  lilp_list[127];
};
#endif

/*
 * Structure used for diag loopback commands.
 * This is copied from socalvar.h and must
 * remain the same as for the socal driver.
 */
typedef	struct flb_hdr {
	uint_t max_length;
	uint_t length;
} flb_hdr_t;
/* This is the max loopback transfer size */
#define	MAX_LOOPBACK		65536

#if !defined(FCIO_FORCE_LIP)
#define	FCIO_FORCE_LIP		(('F' << 8)|177)
#endif
#if !defined(FCIO_LINKSTATUS)
#define	FCIO_LINKSTATUS		(('F' << 8)|183)
#endif
#if !defined(FCIO_FCODE_MCODE_VERSION)
#define	FCIO_FCODE_MCODE_VERSION	(('F' << 8)|202)
#endif
struct ifp_fm_version {
	int	fcode_ver_len;
	int	mcode_ver_len;
	int	prom_ver_len;
	caddr_t	fcode_ver;
	caddr_t	mcode_ver;
	caddr_t	prom_ver;
};
#if defined(_LP64)
struct ifp_fm_version32 {
	int		fcode_ver_len;
	int		mcode_ver_len;
	int		prom_ver_len;
	caddr32_t	fcode_ver;
	caddr32_t	mcode_ver;
	caddr32_t	prom_ver;
};
#endif

/* XXX end temp hack to get sf/socal ioctls used by luxadm to work with ifp */

struct ifp_diag_mbox {
	ushort_t	ifp_in_mbox[8];	/* in regs -- from ISP */
	ushort_t	ifp_out_mbox[8];	/* out regs -- to ISP */
};
typedef struct ifp_diag_mbox ifp_diag_mbox_t;

struct ifp_diag_regs {
	ushort_t		ifpd_mailbox[8];
	ushort_t		ifpd_hccr;
	ushort_t		ifpd_bus_sema;
	ushort_t		ifpd_isr;
	ushort_t		ifpd_icr;
	ushort_t		ifpd_icsr;
	ushort_t		ifpd_cdma_count;
	uint_t			ifpd_cdma_addr;
	ushort_t		ifpd_cdma_status;
	ushort_t		ifpd_cdma_control;
	uint_t			ifpd_rdma_count;
	uint_t			ifpd_rdma_addr;
	ushort_t		ifpd_rdma_status;
	ushort_t		ifpd_rdma_control;
	uint_t			ifpd_tdma_count;
	uint_t			ifpd_tdma_addr;
	ushort_t		ifpd_tdma_status;
	ushort_t		ifpd_tdma_control;
	ushort_t		ifpd_risc_reg[16];
	ushort_t		ifpd_risc_psr;
	ushort_t		ifpd_risc_ivr;
	ushort_t		ifpd_risc_pcr;
	ushort_t		ifpd_risc_rar0;
	ushort_t		ifpd_risc_rar1;
	ushort_t		ifpd_risc_lcr;
	ushort_t		ifpd_risc_pc;
	ushort_t		ifpd_risc_mtr;
	ushort_t		ifpd_risc_sp;
	ushort_t		ifpd_request_in;
	ushort_t		ifpd_request_out;
	ushort_t		ifpd_response_in;
	ushort_t		ifpd_response_out;
	void			*ifpd_current_req_ptr;
	void			*ifpd_base_req_ptr;
	void			*ifpd_current_resp_ptr;
	void			*ifpd_base_resp_ptr;
};
typedef struct ifp_diag_regs ifp_diag_regs_t;

struct ifp_diag_cmd {
	short		ifp_cmds_rev;		/* revision */
	short		ifp_cmds_current_rev;	/* rev driver expects */
	short		ifp_cmds_count;		/* number of cmds */
	short		ifp_cmds_done;		/* number of cmds done */
	ifp_diag_regs_t	ifp_regs;		/* reg dump area */
	ifp_diag_mbox_t	ifp_mbox[IFP_DIAG_MAX_MBOX];	/* mbox values */
};
typedef struct ifp_diag_cmd ifp_diag_cmd_t;

#define	IFP_DIAG_CMD_REV	0x1		/* diag cmd rev supported */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_ADAPTERS_IFPIO_H */
