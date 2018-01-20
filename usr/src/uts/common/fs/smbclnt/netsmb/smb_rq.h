/*
 * Copyright (c) 2000-2001, Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: smb_rq.h,v 1.9 2005/01/22 22:20:58 lindak Exp $
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _NETSMB_SMB_RQ_H_
#define	_NETSMB_SMB_RQ_H_

#include <netsmb/mchain.h>
#include <sys/queue.h>

#define	SMBR_ALLOCED		0x0001	/* structure was malloced */
#define	SMBR_SENT		0x0002	/* request successfully transmitted */
#define	SMBR_REXMIT		0x0004	/* request should be retransmitted */
#define	SMBR_INTR		0x0008	/* request interrupted */
#define	SMBR_RESTART		0x0010	/* req should be repeated if possible */
#define	SMBR_NORESTART		0x0020	/* request is not restartable */
#define	SMBR_MULTIPACKET	0x0040	/* multiple pkts can be sent/received */
#define	SMBR_INTERNAL		0x0080	/* request enqueued by the IOD! */
#define	SMBR_NOINTR_SEND	0x0100	/* no interrupt in send wait */
#define	SMBR_NOINTR_RECV	0x0200	/* no interrupt in recv wait */
#define	SMBR_SENDWAIT		0x0400	/* waiting for send to complete */
#define	SMBR_NORECONNECT	0x0800	/* do not reconnect for this */
/* 	SMBR_VCREF		0x4000	 * took vc reference (obsolete) */
#define	SMBR_MOREDATA		0x8000	/* our buffer was too small */

#define	SMBT2_ALLSENT		0x0001	/* all data and params are sent */
#define	SMBT2_ALLRECV		0x0002	/* all data and params are received */
#define	SMBT2_ALLOCED		0x0004
#define	SMBT2_RESTART		0x0008
#define	SMBT2_NORESTART		0x0010
#define	SMBT2_MOREDATA		0x8000	/* our buffer was too small */

#define	SMBRQ_LOCK(rqp) 	mutex_enter(&(rqp)->sr_lock)
#define	SMBRQ_UNLOCK(rqp)	mutex_exit(&(rqp)->sr_lock)

enum smbrq_state {
	SMBRQ_NOTSENT,		/* rq have data to send */
	SMBRQ_SENT,		/* send procedure completed */
	SMBRQ_REPLYRECEIVED,
	SMBRQ_NOTIFIED		/* owner notified about completion */
};

struct smb_vc;

struct smb_rq {
	TAILQ_ENTRY(smb_rq)	sr_link;
	kmutex_t		sr_lock;
	kcondvar_t		sr_cond;
	enum smbrq_state	sr_state;
	struct smb_vc		*sr_vc;
	struct smb_share	*sr_share;
	struct _kthread 	*sr_owner;
	uint32_t		sr_seqno;	/* Seq. no. of request */
	uint32_t		sr_rseqno;	/* Seq. no. of reply */
	struct mbchain		sr_rq;
	uchar_t			sr_cmd;
	uint8_t			sr_rqflags;
	uint16_t		sr_rqflags2;
	uint16_t		sr_rqtid;
	uint16_t		sr_pid;
	uint16_t		sr_rquid;
	uint16_t		sr_mid;
	uchar_t			*sr_wcount;
	uchar_t			*sr_bcount;
	struct mdchain		sr_rp;
	int			sr_rpgen;
	int			sr_rplast;
	int			sr_flags;	/* SMBR_* */
	int			sr_rpsize;
	struct smb_cred		*sr_cred;
	int			sr_timo;
	int			sr_rexmit; /* how many more retries.  dflt 0 */
	int			sr_sendcnt;
	struct timespec 	sr_timesent;
	int			sr_lerror;
	uint8_t			sr_errclass;
	uint16_t		sr_serror;
	uint32_t		sr_error;
	uint8_t			sr_rpflags;
	uint16_t		sr_rpflags2;
	uint16_t		sr_rptid;
	uint16_t		sr_rppid;
	uint16_t		sr_rpuid;
	uint16_t		sr_rpmid;
};
typedef struct smb_rq smb_rq_t;

struct smb_t2rq {
	kmutex_t	t2_lock;
	kcondvar_t	t2_cond;
	uint16_t	t2_setupcount;
	uint16_t	*t2_setupdata;
	uint16_t	t2_setup[4];
	uint8_t		t2_maxscount;	/* max setup words to return */
	uint16_t	t2_maxpcount;	/* max param bytes to return */
	uint16_t	t2_maxdcount;	/* max data bytes to return */
	uint16_t	t2_fid;		/* for T2 request */
	char		*t_name;	/* for T, must be NULL for T2 */
	int		t_name_len;	/* t_name string length */
	int		t_name_maxlen;	/* t_name allocated size */
	int		t2_flags;	/* SMBT2_ */
	struct mbchain	t2_tparam;	/* parameters to transmit */
	struct mbchain	t2_tdata;	/* data to transmit */
	struct mdchain	t2_rparam;	/* received paramters */
	struct mdchain	t2_rdata;	/* received data */
	struct smb_cred	*t2_cred;
	struct smb_connobj	*t2_source;
	struct smb_rq	*t2_rq;
	struct smb_vc	*t2_vc;
	struct smb_share *t2_share;	/* for smb up/down */
	/* unmapped windows error detail */
	uint8_t		t2_sr_errclass;
	uint16_t	t2_sr_serror;
	uint32_t	t2_sr_error;
	uint16_t	t2_sr_rpflags2;
};
typedef struct smb_t2rq smb_t2rq_t;

struct smb_ntrq {
	kmutex_t	nt_lock;
	kcondvar_t	nt_cond;
	uint16_t	nt_function;
	uint8_t		nt_maxscount;	/* max setup words to return */
	uint32_t	nt_maxpcount;	/* max param bytes to return */
	uint32_t	nt_maxdcount;	/* max data bytes to return */
	int		nt_flags;	/* SMBT2_ */
	struct mbchain	nt_tsetup;	/* setup to transmit */
	struct mbchain	nt_tparam;	/* parameters to transmit */
	struct mbchain	nt_tdata;	/* data to transmit */
	struct mdchain	nt_rparam;	/* received paramters */
	struct mdchain	nt_rdata;	/* received data */
	struct smb_cred	*nt_cred;
	struct smb_connobj *nt_source;
	struct smb_rq	*nt_rq;
	struct smb_vc	*nt_vc;
	struct smb_share *nt_share;	/* for smb up/down */
	/* unmapped windows error details */
	uint32_t	nt_sr_error;
	uint16_t	nt_sr_rpflags2;
};
typedef struct smb_ntrq smb_ntrq_t;

#define	smb_rq_getrequest(RQ, MBPP) \
	*(MBPP) = &(RQ)->sr_rq
#define	smb_rq_getreply(RQ, MDPP) \
	*(MDPP) = &(RQ)->sr_rp

void smb_rq_done(struct smb_rq *rqp);
int   smb_rq_alloc(struct smb_connobj *layer, uchar_t cmd,
	struct smb_cred *scred, struct smb_rq **rqpp);
int  smb_rq_init(struct smb_rq *rqp, struct smb_connobj *layer,
	uchar_t cmd, struct smb_cred *scred);

void smb_rq_fillhdr(struct smb_rq *rqp);
void smb_rq_wstart(struct smb_rq *rqp);
void smb_rq_wend(struct smb_rq *rqp);
void smb_rq_bstart(struct smb_rq *rqp);
void smb_rq_bend(struct smb_rq *rqp);
int  smb_rq_intr(struct smb_rq *rqp);
int  smb_rq_simple(struct smb_rq *rqp);
int  smb_rq_simple_timed(struct smb_rq *rqp, int timeout);
int  smb_rq_internal(struct smb_rq *rqp, int timeout);

int  smb_t2_alloc(struct smb_connobj *layer, ushort_t setup,
	struct smb_cred *scred, struct smb_t2rq **rqpp);
int  smb_t2_init(struct smb_t2rq *rqp, struct smb_connobj *layer,
	ushort_t *setup, int setupcnt, struct smb_cred *scred);
void smb_t2_done(struct smb_t2rq *t2p);
int  smb_t2_request(struct smb_t2rq *t2p);

int  smb_nt_alloc(struct smb_connobj *layer, ushort_t fn,
	struct smb_cred *scred, struct smb_ntrq **rqpp);
int  smb_nt_init(struct smb_ntrq *rqp, struct smb_connobj *layer,
	ushort_t fn, struct smb_cred *scred);
void smb_nt_done(struct smb_ntrq *ntp);
int  smb_nt_request(struct smb_ntrq *ntp);

#endif /* _NETSMB_SMB_RQ_H_ */
