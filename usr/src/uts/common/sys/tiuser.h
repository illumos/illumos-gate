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
 * Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 * All Rights Reserved
 *
 */

/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2014 Gary Mills
 */

#ifndef _SYS_TIUSER_H
#define	_SYS_TIUSER_H

#include <sys/types.h>
/*
 * The following include file has declarations needed by both the kernel
 * level transport providers and the user level library.
 */
#include <sys/tpicommon.h>

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * The following are the events returned by t_look
 */
#define	T_LISTEN	0x0001	/* connection indication received	*/
#define	T_CONNECT	0x0002	/* connect confirmation received	*/
#define	T_DATA		0x0004	/* normal data received			*/
#define	T_EXDATA	0x0008	/* expedited data received		*/
#define	T_DISCONNECT	0x0010	/* disconnect received			*/
#define	T_UDERR		0x0040	/* data gram error indication		*/
#define	T_ORDREL	0x0080	/* orderly release indication		*/
#define	T_EVENTS	0x00ff	/* event mask				*/

/*
 * Flags for data primitives.
 */
#define	T_MORE		0x001	/* more data		*/
#define	T_EXPEDITED	0x002	/* expedited data	*/


/*
 * protocol specific service limits
 */

struct t_info {
	t_scalar_t addr;	/* size of protocol address		*/
	t_scalar_t options;	/* size of protocol options		*/
	t_scalar_t tsdu;	/* size of max transport service data unit */
	t_scalar_t etsdu;	/* size of max expedited tsdu		*/
	t_scalar_t connect;	/* max data for connection primitives	*/
	t_scalar_t discon;	/* max data for disconnect primitives	*/
	t_scalar_t servtype;	/* provider service type		*/
};

/*
 * netbuf structure
 */

struct netbuf {
	unsigned int	maxlen;
	unsigned int	len;
	char		*buf;
};

#ifdef _SYSCALL32
struct netbuf32 {
	uint32_t	maxlen;
	uint32_t	len;
	caddr32_t	buf;
};
#endif /* _SYSCALL32 */

/*
 * t_bind - format of the address and options arguments of bind
 */

struct t_bind {
	struct netbuf	addr;
	unsigned int	qlen;
};

/*
 * options management
 */
struct t_optmgmt {
	struct netbuf	opt;
	t_scalar_t	flags;
};

/*
 * disconnect structure
 */
struct t_discon {
	struct netbuf	udata;		/* user data		*/
	int		reason;		/* reason code		*/
	int		sequence;	/* sequence number	*/
};

/*
 * call structure
 */
struct t_call {
	struct netbuf	addr;		/*  address		*/
	struct netbuf	opt;		/* options		*/
	struct netbuf	udata;		/* user data		*/
	int		sequence;	/* sequence number	*/
};

/*
 * data gram structure
 */
struct t_unitdata {
	struct netbuf	addr;		/*  address		*/
	struct netbuf	opt;		/* options		*/
	struct netbuf	udata;		/* user data		*/
};

/*
 * unitdata error
 */
struct t_uderr {
	struct netbuf	addr;		/* address		*/
	struct netbuf	opt;		/* options 		*/
	t_scalar_t	error;		/* error code		*/
};

/*
 * The following are structure types used when dynamically
 * allocating the above structures via t_structalloc().
 */
#define	T_BIND		1		/* struct t_bind	*/
#define	T_OPTMGMT	2		/* struct t_optmgmt	*/
#define	T_CALL		3		/* struct t_call	*/
#define	T_DIS		4		/* struct t_discon	*/
#define	T_UNITDATA	5		/* struct t_unitdata	*/
#define	T_UDERROR	6		/* struct t_uderr	*/
#define	T_INFO		7		/* struct t_info	*/

/*
 * The following bits specify which fields of the above
 * structures should be allocated by t_structalloc().
 */
#define	T_ADDR	0x01			/* address		*/
#define	T_OPT	0x02			/* options		*/
#define	T_UDATA	0x04			/* user data		*/
#define	T_ALL	0x07			/* all the above	*/

/*
 * the following are the states for the user
 */

#define	T_UNINIT	0		/* uninitialized		*/
#define	T_UNBND		1		/* unbound			*/
#define	T_IDLE		2		/* idle				*/
#define	T_OUTCON	3		/* outgoing connection pending 	*/
#define	T_INCON		4		/* incoming connection pending	*/
#define	T_DATAXFER	5		/* data transfer		*/
#define	T_OUTREL	6		/* outgoing release pending	*/
#define	T_INREL		7		/* incoming release pending	*/
#define	T_BADSTATE	8		/* illegal state */

/*
 * Flags for t_getname.
 */
#define	LOCALNAME	0
#define	REMOTENAME	1

extern int t_accept(int fildes, int resfd, struct t_call *call);
extern char *t_alloc(int fildes, int struct_type, int fields);
extern int t_bind(int fildes, struct t_bind *req, struct t_bind *ret);
extern int t_close(int fildes);
extern int t_connect(int fildes, struct t_call *sndcall,
		    struct t_call *rcvcall);
extern void t_error(const char *errmsg);
extern int t_free(char *ptr, int struct_type);
extern int t_getinfo(int fildes, struct t_info *info);
extern int t_getname(int fildes, struct netbuf *name, int type);
extern int t_getstate(int fildes);
extern int t_listen(int fildes, struct t_call *call);
extern int t_look(int fildes);
extern int t_open(const char *path, int oflag, struct t_info *info);
extern int t_optmgmt(int fildes, struct t_optmgmt *req,
		    struct t_optmgmt *ret);
extern int t_rcv(int fildes, char *buf, unsigned nbytes, int *flags);
extern int t_rcvconnect(int fildes, struct t_call *call);
extern int t_rcvdis(int fildes, struct t_discon *discon);
extern int t_rcvrel(int fildes);
extern int t_rcvudata(int fildes, struct t_unitdata *unitdata, int *flags);
extern int t_rcvuderr(int fildes, struct t_uderr *uderr);
extern int t_snd(int fildes, char *buf, unsigned nbytes, int flags);
extern int t_snddis(int fildes, struct t_call *call);
extern int t_sndrel(int fildes);
extern int t_sndudata(int fildes, struct t_unitdata *unitdata);
extern char *t_strerror(int errnum);
extern int t_sync(int fildes);
extern int t_unbind(int fildes);

/*
 *	N.B.:  this interface is deprecated.  Use t_strerror() instead.
 */
extern char *t_errlist[];
extern int t_nerr;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TIUSER_H */
