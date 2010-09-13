/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1998-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_FC4_FCIO_H
#define	_SYS_FC4_FCIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Include any headers you depend on.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/fc4/fcal_linkapp.h>

/*
 * ioctl definitions
 */
#define	FIOC	('F'<<8)
#define	SF_IOC	(0xda << 8)
#define	SFIOCGMAP	(SF_IOC|1)	/* Get device map */
#define	SF_NUM_ENTRIES_IN_MAP	127

#define	FCIO_GETMAP		(FIOC|175)	/* Get limited map */
#define	FCIO_FORCE_LIP		(FIOC|177)	/* Force LIP */
#define	FCIO_LINKSTATUS		(FIOC|183)	/* Get link status */
#define	FCIO_FCODE_MCODE_VERSION	(FIOC|202) /* Get code versions */

#define	IFPIOCGMAP		SFIOCGMAP
#define	IFP_NUM_ENTRIES_IN_MAP	SF_NUM_ENTRIES_IN_MAP
#define	IFPIO_FORCE_LIP		FCIO_FORCE_LIP
#define	IFPIO_LINKSTATUS	FCIO_LINKSTATUS

typedef struct sf_al_addr_pair {
	uchar_t	sf_al_pa;
	uchar_t	sf_hard_address;
	uchar_t	sf_inq_dtype;
	uchar_t	sf_node_wwn[FC_WWN_SIZE];
	uchar_t	sf_port_wwn[FC_WWN_SIZE];
} sf_al_addr_pair_t;

typedef struct sf_al_map {
	short			sf_count;
	sf_al_addr_pair_t	sf_addr_pair[SF_NUM_ENTRIES_IN_MAP];
	sf_al_addr_pair_t	sf_hba_addr;
} sf_al_map_t;



struct rls_payload {
	uint_t	rls_portno;
	uint_t	rls_linkfail;
	uint_t	rls_syncfail;
	uint_t	rls_sigfail;
	uint_t	rls_primitiverr;
	uint_t	rls_invalidword;
	uint_t	rls_invalidcrc;
};

struct lilpmap {
	ushort_t lilp_magic;
	ushort_t lilp_myalpa;
	uchar_t  lilp_length;
	uchar_t  lilp_list[127];
};


struct socal_fm_version {
	uint_t	fcode_ver_len;
	uint_t	mcode_ver_len;
	uint_t	prom_ver_len;
	char	*fcode_ver;
	char	*mcode_ver;
	char	*prom_ver;
};

/*
 * kstat structures
 */
typedef struct sf_target_stats {
	uint_t	els_failures;		/* failures on PLOGI, PRLI, ADISC etc */
	uint_t	timeouts;
					/*
					 * sf detected command timeouts,
					 * implies an ABTS
					 */
	uint_t	abts_failures;		/* ABTS failures */
	uint_t	task_mgmt_failures;
					/*
					 * SF task management(aborts,
					 * resets etc) failures
					 */
	uint_t	data_ro_mismatches;	/* SF_DATA RO mismatches */
	uint_t	dl_len_mismatches;
					/*
					 * SF_DATA length different from
					 * BURST_LEN
					 */
	uint_t	logouts_recvd;
					/*
					 * unsolicited LOGOs recvd from
					 * target
					 */
} sf_target_stats_t;

typedef	struct sf_stats {
	uint_t	version;		/* version of this struct, >1 */
	uint_t	lip_count;		/* lips forced by sf */
	uint_t	lip_failures;
					/*
					 * lip failures, ie, no ONLINE response
					 * after forcing lip
					 */
	uint_t	cralloc_failures;
					/*
					 * command/response block allocation
					 * failures
					 */
	uint_t	ncmds;			/* outstanding commands */
	uint_t	throttle_limit;		/* current throttle limit */
	uint_t	cr_pool_size;
					/*
					 * num of chunks in command/response
					 * pool, each chunk allows 128 packets
					 */
	struct	sf_target_stats tstats[127]; /* per target stats */
	char	drvr_name[MAXNAMELEN];	/* Name of driver, NULL term. */
} sf_stats_t;


/* SOCAL Host Adapter kstat structures. */
#define	FC_STATUS_ENTRIES	256
struct fc_pstats {
	uint_t   port;		/* which port  0 or 1 */
	uint_t   requests;	/* requests issued by this soc+ */
	uint_t   sol_resps;	/* solicited responses received */
	uint_t   unsol_resps;	/* unsolicited responses received */
	uint_t   lips;		/* forced loop initialization */
	uint_t   els_sent;	/* extended link service commands issued */
	uint_t   els_rcvd;	/* extended link service commands received */
	uint_t   abts;		/* aborts attempted */
	uint_t   abts_ok;	/* aborts successful */
	uint_t   offlines;	/* changes to offline state */
	uint_t   onlines;	/* changes to online state */
	uint_t   online_loops;	/* changes to online-loop state */
	uint_t   resp_status[FC_STATUS_ENTRIES];	/* response status */
};

/*
 * Fibre Channel Response codes
 */
#define	FCAL_STATUS_OK			0
#define	FCAL_STATUS_P_RJT		2
#define	FCAL_STATUS_F_RJT		3
#define	FCAL_STATUS_P_BSY		4
#define	FCAL_STATUS_F_BSY		5
#define	FCAL_STATUS_ONLINE		0x10
#define	FCAL_STATUS_OLDPORT_ONLINE	FCAL_STATUS_ONLINE
#define	FCAL_STATUS_ERR_OFFLINE		0x11
#define	FCAL_STATUS_TIMEOUT		0x12
#define	FCAL_STATUS_ERR_OVERRUN		0x13
#define	FCAL_STATUS_LOOP_ONLINE		0x14
#define	FCAL_STATUS_OLD_PORT		0x15
#define	FCAL_STATUS_AL_PORT		0x16
#define	FCAL_STATUS_UNKNOWN_CQ_TYPE	0x20	/* unknown request type */
#define	FCAL_STATUS_BAD_SEG_CNT		0x21	/* insufficient # of segments */
#define	FCAL_STATUS_MAX_XCHG_EXCEEDED	0x22
#define	FCAL_STATUS_BAD_XID		0x23
#define	FCAL_STATUS_XCHG_BUSY		0x24
#define	FCAL_STATUS_BAD_POOL_ID		0x25
#define	FCAL_STATUS_INSUFFICIENT_CQES	0x26
#define	FCAL_STATUS_ALLOC_FAIL		0x27
#define	FCAL_STATUS_BAD_SID		0x28
#define	FCAL_STATUS_NO_SEQ_INIT		0x29
#define	FCAL_STATUS_BAD_DID		0x2a
#define	FCAL_STATUS_ABORTED		0x30
#define	FCAL_STATUS_ABORT_FAILED	0x31
#define	FCAL_STATUS_DIAG_BUSY		0x32
#define	FCAL_STATUS_DIAG_INVALID	0x33
#define	FCAL_STATUS_INCOMPLETE_DMA_ERR	0x34
#define	FCAL_STATUS_CRC_ERR		0x35
#define	FCAL_STATUS_OPEN_FAIL		0x36
#define	FCAL_STATUS_ERROR		0x80
#define	FCAL_STATUS_ONLINE_TIMEOUT	0x81
#define	FCAL_STATUS_MAX_STATUS		FCAL_STATUS_CRC_ERR

typedef struct socal_stats {
	uint_t   version;	/* version of this struct, >1 */
	uint_t   resets;		/* chip resets */
	uint_t   reqq_intrs;	/* request queue interrupts */
	uint_t   qfulls;		/* request queue full encountered */
	struct	fc_pstats pstats[2]; /* per port kstats */
	char	drvr_name[MAXNAMELEN];	/* Name of driver, NULL term. */
	char	fw_revision[MAXNAMELEN];	/* Firmware date string.\0 */
	char	node_wwn[17];		/* Node WWN */
	char	port_wwn[2][17];	/* Port WWN \0 */
	uint_t	parity_chk_enabled;	/* != 0 if HBA checks parity. */
} socal_stats_t;


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
	int	version;		/* version of this struct, >1 */
	int	lip_count;		/* lips forced by ifp */
	int	ncmds;			/* outstanding commands */
	ifp_target_stats_t tstats[127]; /* per target stats */
	char	drvr_name[MAXNAMELEN];	/* Name of driver, NULL term. */
	char	fw_revision[MAXNAMELEN];	/* Firmware date string.\0 */
	char	node_wwn[17];		/* Node WWN */
	char	port_wwn[17];		/* Port WWN \0 */
	uint_t	parity_chk_enabled;	/* != 0 if HBA checks parity. */
	uint_t   resp_status[FC_STATUS_ENTRIES];	/* response status */
};
typedef struct ifp_stats ifp_stats_t;

/*
 * Defines for the QLA21xx resp_status -- this is the command completion status
 */
#define	IFP_CMD_CMPLT		0x00	/* no transport errors */
#define	IFP_CMD_INCOMPLETE	0x01	/* abnormal transport state */
#define	IFP_CMD_DMA_DERR	0x02	/* DMA direction error */
#define	IFP_CMD_TRAN_ERR	0x03	/* unspecified transport error */
#define	IFP_CMD_RESET		0x04	/* reset aborted transport */
#define	IFP_CMD_ABORTED		0x05	/* aborted on request */
#define	IFP_CMD_TIMEOUT		0x06	/* command timed out */
#define	IFP_CMD_DATA_OVR	0x07	/* data overrun--discard extra */
#define	IFP_CMD_ABORT_REJECTED	0x0e	/* target rejected abort msg */
#define	IFP_CMD_RESET_REJECTED	0x12	/* target rejected reset msg */
#define	IFP_CMD_DATA_UNDER	0x15	/* data underrun */
#define	IFP_CMD_QUEUE_FULL	0x1c	/* queue full SCSI status */
#define	IFP_CMD_PORT_UNAVAIL	0x28	/* port unavailable */
#define	IFP_CMD_PORT_LOGGED_OUT	0x29	/* port loged out */
#define	IFP_CMD_PORT_CONFIG_CHANGED 0x2a	/* port name changed */



#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FC4_FCIO_H */
