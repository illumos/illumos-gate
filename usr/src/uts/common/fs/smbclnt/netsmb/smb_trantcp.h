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
 * $Id: smb_trantcp.h,v 1.8 2004/08/03 23:50:01 lindak Exp $
 */
/*
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */
#ifndef _NETSMB_SMB_TRANTCP_H_
#define	_NETSMB_SMB_TRANTCP_H_

enum nbstate {
	NBST_CLOSED,
	NBST_IDLE,
	NBST_RQSENT,
	NBST_SESSION,
	NBST_RETARGET,
	NBST_REFUSED
};


/*
 * socket specific data
 */
struct nbpcb {
	struct smb_vc	*nbp_vc;
	struct tiuser	*nbp_tiptr;	/* KTLI transport handle... */
	mblk_t		*nbp_frag;	/* left-over from last recv */

	struct sockaddr_nb *nbp_laddr;	/* local address */
	struct sockaddr_nb *nbp_paddr;	/* peer address */
	void		*nbp_selectid;
	cred_t		*nbp_cred;

	int		nbp_flags;
#define	NBF_LOCADDR	0x0001		/* has local addr */
#define	NBF_CONNECTED	0x0002
#define	NBF_RECVLOCK	0x0004
#define	NBF_SENDLOCK	0x0008
#define	NBF_LOCKWAIT	0x0010

	ushort_t	nbp_fmode;
	enum nbstate	nbp_state;
	struct timespec	nbp_timo;
	int		nbp_sndbuf;
	int		nbp_rcvbuf;
	kmutex_t	nbp_lock;
	kcondvar_t	nbp_cv;
};
typedef struct nbpcb nbpcb_t;

/*
 * Nominal space allocated per a NETBIOS socket.
 */
#define	NB_SNDQ		(10 * 1024)
#define	NB_RCVQ		(20 * 1024)

/*
 * TCP slowstart presents a problem in conjunction with large
 * reads.  To ensure a steady stream of ACKs while reading using
 * large transaction sizes, we call soreceive() with a smaller
 * buffer size.  See nbssn_recv().
 */
#define	NB_SORECEIVE_CHUNK	(8 * 1024)

#define	SMBSBTIMO 15 /* seconds for sockbuf timeouts */

#endif /* !_NETSMB_SMB_TRANTCP_H_ */
