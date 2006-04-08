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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2006
 */

#ifndef _SCFTRACE_H
#define	_SCFTRACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/scfd/scfstate.h>

#define	TC_INFO_SIZE		8

/* SCF driver trace table */
typedef	struct scf_trctbl {
	ushort_t	line;			/* sorce kine No. */
	ushort_t	tmvl;			/* trace time (100ms) */
	ushort_t	code;			/* trace code */
	ushort_t	size;			/* info size */
	uchar_t		info[TC_INFO_SIZE];	/* detail info */
} scf_trctbl_t;

#define	TC_NRM_CNT		1920		/* normal trace entry count */
#define	TC_ERR_CNT		128		/* error trace entry count */

#define	SCF_DBGFLAG_REG		0x00000001

#define	SCF_DBGFLAG_IOCTL	0x00000010
#define	SCF_DBGFLAG_SYS		0x00000020
#define	SCF_DBGFLAG_DSCP	0x00000040
#define	SCF_DBGFLAG_SRV		0x00000080

#define	SCF_DBGFLAG_IOMP	0x00000100
#define	SCF_DBGFLAG_KSTAT	0x00000200
#define	SCF_DBGFLAG_FOCK	0x00000400

#define	SCF_DBGFLAG_DDI		0x00001000
#define	SCF_DBGFLAG_OPCLS	0x00002000
#define	SCF_DBGFLAG_TIMER	0x00004000

#define	SCF_DBGFLAG_SNAP	0x00010000
#define	SCF_DBGFLAG_TRACE	0x00020000
#define	SCF_DBGFLAG_DBG		0x00080000

#define	SCF_DBGFLAG_ALL		0xffffffff

/*
 * trace code define
 */
#define	TC_ERR			0x8000
#define	TC_ERRCD		0x4000
#define	TC_MSG			0x2000
#define	TC_R_REG		0x1000
#define	TC_W_REG		0x0800
#define	TC_R_CONTROL		(TC_R_REG | 0x0001)
#define	TC_R_INT_ST		(TC_R_REG | 0x0002)
#define	TC_R_COMMAND		(TC_R_REG | 0x0011)
#define	TC_R_COMMAND_ExR	(TC_R_REG | 0x0012)
#define	TC_R_STATUS		(TC_R_REG | 0x0013)
#define	TC_R_STATUS_ExR		(TC_R_REG | 0x0014)
#define	TC_R_TDATA0		(TC_R_REG | 0x0020)
#define	TC_R_TDATA1		(TC_R_REG | 0x0021)
#define	TC_R_TDATA2		(TC_R_REG | 0x0022)
#define	TC_R_TDATA3		(TC_R_REG | 0x0023)
#define	TC_R_RDATA0		(TC_R_REG | 0x0030)
#define	TC_R_RDATA1		(TC_R_REG | 0x0031)
#define	TC_R_RDATA2		(TC_R_REG | 0x0032)
#define	TC_R_RDATA3		(TC_R_REG | 0x0033)
#define	TC_R_ACR		(TC_R_REG | 0x0040)
#define	TC_R_ATR		(TC_R_REG | 0x0041)
#define	TC_R_DCR		(TC_R_REG | 0x0050)
#define	TC_R_DSR		(TC_R_REG | 0x0051)
#define	TC_R_TxDCR_C_FLAG	(TC_R_REG | 0x0052)
#define	TC_R_TxDCR_OFFSET	(TC_R_REG | 0x0053)
#define	TC_R_TxDCR_LENGTH	(TC_R_REG | 0x0054)
#define	TC_R_TxDSR_C_FLAG	(TC_R_REG | 0x0055)
#define	TC_R_TxDSR_OFFSET	(TC_R_REG | 0x0056)
#define	TC_R_RxDCR_C_FLAG	(TC_R_REG | 0x0057)
#define	TC_R_RxDCR_OFFSET	(TC_R_REG | 0x0058)
#define	TC_R_RxDCR_LENGTH	(TC_R_REG | 0x0059)
#define	TC_R_RxDSR_C_FLAG	(TC_R_REG | 0x005a)
#define	TC_R_RxDSR_OFFSET	(TC_R_REG | 0x005b)

#define	TC_W_CONTROL		(TC_W_REG | 0x0001)
#define	TC_W_INT_ST		(TC_W_REG | 0x0002)
#define	TC_W_COMMAND		(TC_W_REG | 0x0011)
#define	TC_W_COMMAND_ExR	(TC_W_REG | 0x0012)
#define	TC_W_STATUS		(TC_W_REG | 0x0013)
#define	TC_W_STATUS_ExR		(TC_W_REG | 0x0014)
#define	TC_W_TDATA0		(TC_W_REG | 0x0020)
#define	TC_W_TDATA1		(TC_W_REG | 0x0021)
#define	TC_W_TDATA2		(TC_W_REG | 0x0022)
#define	TC_W_TDATA3		(TC_W_REG | 0x0023)
#define	TC_W_RDATA0		(TC_W_REG | 0x0030)
#define	TC_W_RDATA1		(TC_W_REG | 0x0031)
#define	TC_W_RDATA2		(TC_W_REG | 0x0032)
#define	TC_W_RDATA3		(TC_W_REG | 0x0033)
#define	TC_W_ACR		(TC_W_REG | 0x0040)
#define	TC_W_ATR		(TC_W_REG | 0x0041)
#define	TC_W_DCR		(TC_W_REG | 0x0050)
#define	TC_W_DSR		(TC_W_REG | 0x0051)
#define	TC_W_TxDCR_C_FLAG	(TC_W_REG | 0x0052)
#define	TC_W_TxDCR_OFFSET	(TC_W_REG | 0x0053)
#define	TC_W_TxDCR_LENGTH	(TC_W_REG | 0x0054)
#define	TC_W_TxDSR_C_FLAG	(TC_W_REG | 0x0055)
#define	TC_W_TxDSR_OFFSET	(TC_W_REG | 0x0056)
#define	TC_W_RxDCR_C_FLAG	(TC_W_REG | 0x0057)
#define	TC_W_RxDCR_OFFSET	(TC_W_REG | 0x0058)
#define	TC_W_RxDCR_LENGTH	(TC_W_REG | 0x0059)
#define	TC_W_RxDSR_C_FLAG	(TC_W_REG | 0x005a)
#define	TC_W_RxDSR_OFFSET	(TC_W_REG | 0x005b)

#define	TC_TIMER		0x0400
#define	TC_T_TOUT		(TC_TIMER | 0x0001)
#define	TC_T_START		(TC_TIMER | 0x0002)
#define	TC_T_STOP		(TC_TIMER | 0x0003)

#define	TC_OUT			0x0200
#define	TC_IN			0x0100

/* scfconf.c */
#define	TC_PROBE		0x0001
#define	TC_ATTACH		0x0002
#define	TC_DETACH		0x0003
#define	TC_GETINFO		0x0004

/* scfopt.c */
#define	TC_OPEN			0x0011
#define	TC_CLOSE		0x0012
#define	TC_IOCTL		0x0013
#define	TC_CHPOLL		0x0014

/* scfhandler.c */
#define	TC_INTR			0x0021
#define	TC_DSENS		0x0022
#define	TC_SHUTDOWN		0x0023

/* scfreg.c scfhandler.c */
#define	TC_SEND			0x0031
#define	TC_RSTS			0x0032

/* kernel function code */
#define	TC_SIGNAL		0x0041
#define	TC_W_SIG		0x0042
#define	TC_T_WAIT		0x0043
#define	TC_KILL			0x004f

/* DSCP function code */
#define	TC_MB_INIT		0x0081
#define	TC_MB_FINI		0x0082
#define	TC_MB_PUTMSG		0x0083
#define	TC_MB_CANGET		0x0084
#define	TC_MB_GETMSG		0x0085
#define	TC_MB_FLUSH		0x0086
#define	TC_MB_CTRL		0x0087
#define	TC_MB_INTR		0x0088
#define	TC_MB_CALLBACK		0x0089

#define	TC_TxREQ		0x00a1
#define	TC_RxACK		0x00a5
#define	TC_RxEND		0x00a6
#define	TC_RxREQ		0x00a4
#define	TC_TxACK		0x00a2
#define	TC_TxEND		0x00a3

/* OS to SCF function code */
#define	TC_S_PUTINFO		0x0091
#define	TC_S_GETINFO		0x0092

/*
 * SCF driver trace flag
 */
extern ushort_t	scf_trace_exec;		/* 1:trace exec,  0:Trace no exec */
extern ushort_t	scf_trace_flag;

/*
 * SCF driver trace debug flag
 */
extern uint_t	scf_trace_msg_flag;	/* trace massege flag */

/*
 * External function
 */
extern void	scf_trace(ushort_t code, ushort_t line,
	uchar_t *info, ushort_t size);

#ifdef	__cplusplus
}
#endif

#endif /* _SCFTRACE_H */
