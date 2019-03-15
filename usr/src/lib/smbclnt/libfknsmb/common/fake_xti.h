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
 */
/*	Copyright (c) 1996 Sun Microsystems, Inc.	*/
/*	  All Rights Reserved	*/
/*
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _XTI_H
#define	_XTI_H

#include <sys/types.h>

/*
 * The following include file has declarations needed by both the kernel
 * level transport providers and the user level library. This file includes
 * it to expose its namespaces to XTI user level interface.
 */
#include <sys/tpicommon.h>

/*
 * Include XTI interface level options management declarations
 */
#include <sys/xti_xtiopt.h>

#if !defined(_XPG5)

/*
 * Include declarations related to OSI transport and management data
 * structures, and the Internet Protocol Suite.
 * Note: The older Unix95/XNS4 XTI spec required these to be
 * exposed through the generic interface header.
 */
#include <sys/xti_osi.h>
#include <sys/xti_inet.h>

#endif /* !defined(_XPG5) */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The following t_errno error codes are included in the namespace by
 * inclusion of <sys/tpicommon.h> above. The english language error strings
 * associated with the error values are reproduced here for easy reference.
 *
 * Error		Value	Error message string
 * ----			-----	--------------------
 * TBADADDR		1	Incorrect address format
 * TBADOPT		2	Incorrect options format
 * TACCES		3	Illegal permissions
 * TBADF		4	Illegal file descriptor
 * TNOADDR		5	Couldn't allocate address
 * TOUTSTATE		6	Routine will place interface out of state
 * TBADSEQ		7	Illegal called/calling sequence number
 * TSYSERR		8	System error
 * TLOOK		9	An event requires attention
 * TBADDATA		10	Illegal amount of data
 * TBUFOVFLW		11	Buffer not large enough
 * TFLOW		12	Can't send message - (blocked)
 * TNODATA		13	No message currently available
 * TNODIS		14	Disconnect message not found
 * TNOUDERR		15	Unitdata error message not found
 * TBADFLAG		16	Incorrect flags specified
 * TNOREL		17	Orderly release message not found
 * TNOTSUPPORT		18	Primitive not supported by provider
 * TSTATECHNG		19	State is in process of changing
 * TNOSTRUCTYPE		20	Unsupported structure type requested
 * TBADNAME		21	Invalid transport provider name
 * TBADQLEN		22	Listener queue length limit is zero
 * TADDRBUSY		23	Transport address is in use
 * TINDOUT		24	Outstanding connection indications
 * TPROVMISMATCH	25	Listener-acceptor transport provider mismatch
 * TRESQLEN		26	Connection acceptor has listen queue length
 *				limit greater than zero
 * TRESADDR		27	Connection acceptor-listener addresses not
 *				same but required by transport
 * TQFULL		28	Incoming connection queue is full
 * TPROTO		29	Protocol error on transport primitive
 *
 */

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
#define	T_GODATA	0x0100	/* sending normal data is again possible */
#define	T_GOEXDATA	0x0200	/* sending expedited data is again possible */

/*
 * Flags for data primitives
 */
#define	T_MORE		0x001	/* more data		*/
#define	T_EXPEDITED	0x002	/* expedited data	*/
#define	T_PUSH		0x004	/* send data immediately */

/*
 * XTI error return
 */
#if defined(_REENTRANT) || defined(_TS_ERRNO)
extern int	*__t_errno();
#define	t_errno (*(__t_errno()))
#else
#error "extern int t_errno?"
#endif	/* defined(_REENTRANT) || defined(_TS_ERRNO) */


/*
 * The following are for t_sysconf()
 */
#ifndef T_IOV_MAX
#define	T_IOV_MAX	16	/* Maximum number of scatter/gather buffers */
#endif				/* Should be <= IOV_MAX */

#ifndef _SC_T_IOV_MAX
#define	_SC_T_IOV_MAX	79	/* Should be same in <unistd.h> for use by */
#endif				/* sysconf() */

struct t_iovec {
	void	*iov_base;
	size_t	iov_len;
};

/*
 * Translate source level interface to binary entry point names.
 *
 * Note: This is done to maintain co-existence of TLI and XTI
 * interfaces which have identical names for most functions but
 * different semantics. The XTI names are moved to the different
 * prefix space in the ABI. The #ifdef is required to make use of
 * of the compiler feature to allow redefinition of external names
 * where available. Otherwise a simple #define is used when this
 * header is used with other compilers.
 * The use of #define also has the effect of renaming all names (not
 * just function names) to the new name. The TLI function names
 * (e.g. t_bind) can have identical names for structure names
 * (e.g struct t_bind). Therefore, this redefinition of names needs
 * to be before all structure and function name declarations in the header.
 */

#ifdef __PRAGMA_REDEFINE_EXTNAME

#if defined(_XOPEN_SOURCE) && !defined(_XPG5)
#pragma redefine_extname t_accept	_xti_accept
#else
#pragma redefine_extname t_accept	_xti_xns5_accept
#endif
#pragma redefine_extname t_alloc	_xti_alloc
#pragma redefine_extname t_bind		_xti_bind
#pragma redefine_extname t_close	_xti_close
#pragma redefine_extname t_connect	_xti_connect
#pragma redefine_extname t_error	_xti_error
#pragma redefine_extname t_free		_xti_free
#pragma redefine_extname t_getinfo	_xti_getinfo
#pragma redefine_extname t_getstate	_xti_getstate
#pragma redefine_extname t_getprotaddr	_xti_getprotaddr
#pragma redefine_extname t_listen	_xti_listen
#pragma redefine_extname t_look		_xti_look
#pragma redefine_extname t_open		_xti_open
#pragma redefine_extname t_optmgmt	_xti_optmgmt
#pragma redefine_extname t_rcv		_xti_rcv
#pragma redefine_extname t_rcvconnect	_xti_rcvconnect
#pragma redefine_extname t_rcvdis	_xti_rcvdis
#pragma redefine_extname t_rcvrel	_xti_rcvrel
#pragma redefine_extname t_rcvreldata	_xti_rcvreldata
#pragma redefine_extname t_rcvudata	_xti_rcvudata
#pragma redefine_extname t_rcvuderr	_xti_rcvuderr
#pragma redefine_extname t_rcvv		_xti_rcvv
#pragma redefine_extname t_rcvvudata	_xti_rcvvudata
#if defined(_XOPEN_SOURCE) && !defined(_XPG5)
#pragma redefine_extname t_snd		_xti_snd
#else
#pragma redefine_extname t_snd		_xti_xns5_snd
#endif
#pragma redefine_extname t_snddis	_xti_snddis
#pragma redefine_extname t_sndrel	_xti_sndrel
#pragma redefine_extname t_sndreldata	_xti_sndreldata
#pragma redefine_extname t_sndudata	_xti_sndudata
#pragma redefine_extname t_sndv		_xti_sndv
#pragma redefine_extname t_sndvudata	_xti_sndvudata
#pragma redefine_extname t_strerror	_xti_strerror
#pragma redefine_extname t_sync		_xti_sync
#pragma redefine_extname t_sysconf	_xti_sysconf
#pragma redefine_extname t_unbind	_xti_unbind

#else /* __PRAGMA_REDEFINE_EXTNAME */

#if defined(_XOPEN_SOURCE) && !defined(_XPG5)
#define	t_accept	_xti_accept
#else
#define	t_accept	_xti_xns5_accept
#endif
#define	t_alloc		_xti_alloc
#define	t_bind(a,b,c)	_xti_bind(a,b,c)
#define	t_close		_xti_close
#define	t_connect	_xti_connect
#define	t_error		_xti_error
#define	t_free		_xti_free
#define	t_getinfo	_xti_getinfo
#define	t_getstate	_xti_getstate
#define	t_getprotaddr	_xti_getprotaddr
#define	t_listen	_xti_listen
#define	t_look		_xti_look
#define	t_open		_xti_open
#define	t_optmgmt(a,b,c)	_xti_optmgmt(a,b,c)
#define	t_rcv		_xti_rcv
#define	t_rcvconnect	_xti_rcvconnect
#define	t_rcvdis	_xti_rcvdis
#define	t_rcvrel	_xti_rcvrel
#define	t_rcvreldata	_xti_rcvreldata
#define	t_rcvudata	_xti_rcvudata
#define	t_rcvuderr	_xti_rcvuderr
#define	t_rcvv		_xti_rcvv
#define	t_rcvvudata	_xti_rcvvudata
#if defined(_XOPEN_SOURCE) && !defined(_XPG5)
#define	t_snd		_xti_snd
#else
#define	t_snd		_xti_xns5_snd
#endif
#define	t_snddis	_xti_snddis
#define	t_sndrel	_xti_sndrel
#define	t_sndreldata	_xti_sndreldata
#define	t_sndudata	_xti_sndudata
#define	t_sndv		_xti_sndv
#define	t_sndvudata	_xti_sndvudata
#define	t_strerror	_xti_strerror
#define	t_sync		_xti_sync
#define	t_sysconf	_xti_sysconf
#define	t_unbind	_xti_unbind

#endif /* __PRAGMA_REDEFINE_EXTNAME */

/*
 * All the rest of the standard xti.h removed because the structs:
 * netbuf, t_info, t_opthdr, t_optmgmt, t_bind, t_call, ...
 * all conflict with definitions in tiuser.h which we need
 * for the (simulated) kernel interfaces in fake_ktli.c.
 *
 * The XTI library functions below would normally be defined by
 * including tiuser.h after the defines above, which we can't.
 */

int _xti_accept(int, int, struct t_call *);
int _xti_xns5_accept(int, int, struct t_call *);
char *_xti_alloc(int, int, int);
int _xti_bind(int, struct t_bind *, struct t_bind *);
int _xti_close(int);
int _xti_connect(int, struct t_call *, struct t_call *);
int _xti_error(char *);
int _xti_free(char *, int);
int _xti_getinfo(int, struct t_info *);
int _xti_getprotaddr(int, struct t_bind *, struct t_bind *);
int _xti_getstate(int);
int _xti_listen(int, struct t_call *);
int _xti_look(int);
int _xti_open(char *, int, struct t_info *);
int _xti_optmgmt(int, struct t_optmgmt *, struct t_optmgmt *);
int _xti_rcv(int, char *, unsigned int, int *);
int _xti_rcvconnect(int, struct t_call *);
int _xti_rcvdis(int, struct t_discon *);
int _xti_rcvrel(int);
int _xti_rcvreldata(int, struct t_discon *);
int _xti_rcvudata(int, struct t_unitdata *, int *);
int _xti_rcvuderr(int, struct t_uderr *);
int _xti_rcvv(int, struct t_iovec *, unsigned int, int *);
int _xti_rcvvudata(int, struct t_unitdata *, struct t_iovec *,
    unsigned int, int *);
int _xti_snd(int, char *, unsigned int, int);
int _xti_xns5_snd(int, char *, unsigned int, int);
int _xti_snddis(int, struct t_call *);
int _xti_sndrel(int);
int _xti_sndreldata(int, struct t_discon *);
int _xti_sndudata(int, struct t_unitdata *);
int _xti_sndv(int, const struct t_iovec *, unsigned int, int);
int _xti_sndvudata(int, struct t_unitdata *, struct t_iovec *, unsigned int);
char *_xti_strerror(int);
int _xti_sync(int);
int _xti_sysconf(int);
int _xti_unbind(int);

#ifdef	__cplusplus
}
#endif

#endif	/* _XTI_H */
