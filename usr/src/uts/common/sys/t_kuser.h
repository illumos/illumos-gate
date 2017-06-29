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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef	_SYS_T_KUSER_H
#define	_SYS_T_KUSER_H

#include <sys/types.h>
#include <sys/file.h>
#include <sys/cred.h>
#include <sys/stream.h>
#include <sys/tiuser.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Note this structure will need to be expanded to handle data
 * related to connection oriented transports.
 */
typedef struct tiuser {
	struct	file *fp;
	struct	t_info tp_info;	/* Transport provider Info. */
	int	flags;
} TIUSER;
#define		TIUSERSZ	sizeof (TIUSER)

struct knetbuf {
	mblk_t   *udata_mp;	/* current receive streams block */
	unsigned int maxlen;
	unsigned int len;
	char	*buf;
};

struct t_kunitdata {
	struct netbuf addr;
	struct netbuf opt;
	struct knetbuf udata;
};


#ifdef KTLIDEBUG
extern int	ktli_log();
extern int	ktlilog;

#define		KTLILOG(A, B, C) ((void)((ktlilog) && ktli_log((A), (B), (C))))
#else
#define		KTLILOG(A, B, C)
#endif

/*
 * flags
 */
#define		MADE_FP		0x02

extern int	t_kalloc(TIUSER *, int, int, char **);
extern int	t_kbind(TIUSER *, struct t_bind *, struct t_bind *);
extern int	t_kclose(TIUSER *, int);
extern int	t_kconnect(TIUSER *, struct t_call *, struct t_call *);
extern int	t_kfree(TIUSER *, char *, int);
extern int	t_kgetstate(TIUSER *, int *);
extern int	t_kopen(struct file *, dev_t, int, TIUSER **, struct cred *);
extern int	t_krcvudata(TIUSER *, struct t_kunitdata *, int *, int *);
extern int	t_ksndudata(TIUSER *, struct t_kunitdata *, frtn_t *);
extern int	t_kspoll(TIUSER *, int, int, int *);
extern int	t_kunbind(TIUSER *);
extern int	tli_send(TIUSER *, mblk_t *, int);
extern int	tli_recv(TIUSER *, mblk_t **, int);
extern int	t_tlitosyserr(int);
extern int	get_ok_ack(TIUSER *, int, int);

/*
 * these make life a lot easier
 */
#define		TCONNREQSZ	sizeof (struct T_conn_req)
#define		TCONNRESSZ	sizeof (struct T_conn_res)
#define		TDISCONREQSZ	sizeof (struct T_discon_req)
#define		TDATAREQSZ	sizeof (struct T_data_req)
#define		TEXDATAREQSZ	sizeof (struct T_exdata_req)
#define		TINFOREQSZ	sizeof (struct T_info_req)
#define		TBINDREQSZ	sizeof (struct T_bind_req)
#define		TUNBINDREQSZ	sizeof (struct T_unbind_req)
#define		TUNITDATAREQSZ	sizeof (struct T_unitdata_req)
#define		TOPTMGMTREQSZ	sizeof (struct T_optmgmt_req)
#define		TORDRELREQSZ	sizeof (struct T_ordrel_req)
#define		TCONNINDSZ	sizeof (struct T_conn_ind)
#define		TCONNCONSZ	sizeof (struct T_conn_con)
#define		TDISCONINDSZ	sizeof (struct T_discon_ind)
#define		TDATAINDSZ	sizeof (struct T_data_ind)
#define		TEXDATAINDSZ	sizeof (struct T_exdata_ind)
#define		TINFOACKSZ	sizeof (struct T_info_ack)
#define		TBINDACKSZ	sizeof (struct T_bind_ack)
#define		TERRORACKSZ	sizeof (struct T_error_ack)
#define		TOKACKSZ	sizeof (struct T_ok_ack)
#define		TUNITDATAINDSZ	sizeof (struct T_unitdata_ind)
#define		TUDERRORINDSZ	sizeof (struct T_uderror_ind)
#define		TOPTMGMTACKSZ	sizeof (struct T_optmgmt_ack)
#define		TORDRELINDSZ	sizeof (struct T_ordrel_ind)
#define		TPRIMITIVES	sizeof (struct T_primitives)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_T_KUSER_H */
