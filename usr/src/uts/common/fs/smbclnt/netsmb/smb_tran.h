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
 * $Id: smb_tran.h,v 1.2 2001/12/21 02:41:30 conrad Exp $
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NETSMB_SMB_TRAN_H_
#define	_NETSMB_SMB_TRAN_H_

#include <sys/socket.h>
#include <sys/stream.h>

/*
 * Known transports
 */
#define	SMBT_NBTCP	1

/*
 * Transport parameters
 */
#define	SMBTP_SNDSZ	1		/* R  - int */
#define	SMBTP_RCVSZ	2		/* R  - int */
#define	SMBTP_TIMEOUT	3		/* RW - struct timespec */

struct smb_tran_ops;

struct smb_tran_desc {
	sa_family_t	tr_type;
	int	(*tr_create)(struct smb_vc *vcp, cred_t *cr);
	int	(*tr_done)(struct smb_vc *vcp);
	int	(*tr_bind)(struct smb_vc *vcp, struct sockaddr *sap);
	int	(*tr_connect)(struct smb_vc *vcp, struct sockaddr *sap);
	int	(*tr_disconnect)(struct smb_vc *vcp);
	int	(*tr_send)(struct smb_vc *vcp, mblk_t *m);
	int	(*tr_recv)(struct smb_vc *vcp, mblk_t **mpp);
	int	(*tr_poll)(struct smb_vc *vcp, int ticks);
	int	(*tr_loan_fp)(struct smb_vc *, struct file *, cred_t *cr);
	int	(*tr_getparam)(struct smb_vc *vcp, int param, void *data);
	int	(*tr_setparam)(struct smb_vc *vcp, int param, void *data);
	int	(*tr_fatal)(struct smb_vc *vcp, int error);
	LIST_ENTRY(smb_tran_desc)	tr_link;
};
typedef struct smb_tran_desc smb_tran_desc_t;

#define	SMB_TRAN_CREATE(vcp, cr)	(vcp)->vc_tdesc->tr_create(vcp, cr)
#define	SMB_TRAN_DONE(vcp)		(vcp)->vc_tdesc->tr_done(vcp)
#define	SMB_TRAN_BIND(vcp, sap)		(vcp)->vc_tdesc->tr_bind(vcp, sap)
#define	SMB_TRAN_CONNECT(vcp, sap)	(vcp)->vc_tdesc->tr_connect(vcp, sap)
#define	SMB_TRAN_DISCONNECT(vcp)	(vcp)->vc_tdesc->tr_disconnect(vcp)
#define	SMB_TRAN_SEND(vcp, m)		(vcp)->vc_tdesc->tr_send(vcp, m)
#define	SMB_TRAN_RECV(vcp, m)		(vcp)->vc_tdesc->tr_recv(vcp, m)
#define	SMB_TRAN_POLL(vcp, t)		(vcp)->vc_tdesc->tr_poll(vcp, t)
#define	SMB_TRAN_LOAN_FP(vcp, f, cr)	(vcp)->vc_tdesc->tr_loan_fp(vcp, f, cr)
#define	SMB_TRAN_GETPARAM(vcp, par, data)	\
	(vcp)->vc_tdesc->tr_getparam(vcp, par, data)
#define	SMB_TRAN_SETPARAM(vcp, par, data)	\
	(vcp)->vc_tdesc->tr_setparam(vcp, par, data)
#define	SMB_TRAN_FATAL(vcp, error)	(vcp)->vc_tdesc->tr_fatal(vcp, error)

/* Ops vectors for each transport. */
extern struct smb_tran_desc smb_tran_nbtcp_desc;

#endif /* _NETSMB_SMB_TRAN_H_ */
