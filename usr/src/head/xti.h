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
/*	  All Rights Reserved  	*/


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
extern int t_errno;
#endif	/* defined(_REENTRANT) || defined(_TS_ERRNO) */


/*
 * The following are for t_sysconf()
 */
#ifndef T_IOV_MAX
#define	T_IOV_MAX	16	/* Maximum number of scatter/gather buffers */
#endif				/* Should be <= IOV_MAX */

#ifndef _SC_T_IOV_MAX
#define	_SC_T_IOV_MAX 	79	/* Should be same in <unistd.h> for use by */
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
#define	t_bind		_xti_bind
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
#define	t_optmgmt	_xti_optmgmt
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
 * protocol specific service limits
 */
struct t_info {
	t_scalar_t addr;	/* max size of protocol address		*/
	t_scalar_t options;	/* max size of protocol options		*/
	t_scalar_t tsdu;	/* max size of max transport service	*/
				/* data unit	*/
	t_scalar_t etsdu;	/* max size of max expedited tsdu	*/
	t_scalar_t connect;	/* max data for connection primitives	*/
	t_scalar_t discon;	/* max data for disconnect primitives	*/
	t_scalar_t servtype;	/* provider service type		*/
	t_scalar_t flags;	/* other info about transport providers	*/
};

/*
 * Flags definitions for the t_info structure
 */
#define	T_SENDZERO	0x001	/* supports 0-length TSDUs */
#define	T_ORDRELDATA	0x002	/* supports orderly release data */

/*
 * netbuf structure
 */
struct netbuf {
	unsigned int maxlen;
	unsigned int len;
#if defined(_XPG5)
	void *buf;
#else
	char *buf;
#endif
};

/*
 * t_opthdr structure
 */
struct t_opthdr {
	t_uscalar_t	len;	/* total length of option */
	t_uscalar_t	level;	/* protocol level */
	t_uscalar_t	name;	/* option name */
	t_uscalar_t	status;	/* status value */
	/* followed by option value */
};

/*
 * t_bind - format of the addres and options arguments of bind
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
 * structures should be allocated by t_alloc().
 */
#define	T_ADDR	0x01			/* address		*/
#define	T_OPT	0x02			/* options		*/
#define	T_UDATA	0x04			/* user data		*/
#define	T_ALL	0xffff			/* all the above fields */


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


#define	T_UNUSED		-1
#define	T_NULL			0


/*
 * Allegedly general purpose constant. Used with (and needs to be bitwise
 * distinct from) T_NOPROTECT, T_PASSIVEPROTECT and T_ACTIVEPROTECT
 * which are OSI specific constants but part of this header (defined
 * in <xti_osi.h> which is included in this header for historical
 * XTI specification reasons)
 */
#define	T_ABSREQ		0x8000

/*
 * General definitions for option management
 *
 * Multiple variable length options may be packed into a single option buffer.
 * Each option consists of a fixed length header followed by variable length
 * data. The header and data will have to be aligned at appropriate
 * boundaries. The following macros are used to manipulate the options.
 *
 * Helper Macros: Macros beginning with a "_T" prefix are helper macros.
 *		  They are private, not meant for public use and may
 *		  change without notice. Users  should use the standard
 *		  XTI macros beginning with "T_" prefix
 */

#define	_T_OPT_HALIGN_SZ	(sizeof (t_scalar_t)) /* Hdr Alignment size  */
#define	_T_OPT_DALIGN_SZ	(sizeof (int32_t))    /* Data Alignment size */
#define	_T_OPTHDR_SZ	(sizeof (struct t_opthdr))

/* Align 'x' to the next 'asize' alignment  boundary */
#define	_T_OPT_ALIGN(x, asize) \
	(((uintptr_t)(x) + ((asize) - 1L)) & ~((asize) - 1L))

/* Align 'x' to the next header alignment  boundary */
#define	_T_OPTHDR_ALIGN(x) \
	(_T_OPT_ALIGN((x), _T_OPT_HALIGN_SZ))

/* Align 'x' to the next data alignment  boundary */
#define	_T_OPTDATA_ALIGN(x) \
	(_T_OPT_ALIGN((x), _T_OPT_DALIGN_SZ))

/*
 * struct t_opthdr *T_OPT_FIRSTHDR(struct netbuf *nbp):
 *     Get aligned start of first option header
 *
 * unsigned char *T_OPT_DATA(struct t_opthdr *tohp):
 *     Get aligned start of data part after option header
 *
 * struct t_opthdr *T_OPT_NEXTHDR(struct netbuf *nbp, struct t_opthdr *tohp):
 * 	Skip to next option header
 */

#define	T_OPT_FIRSTHDR(nbp)    \
	((nbp)->len >= _T_OPTHDR_SZ ? (struct t_opthdr *)(nbp)->buf : \
	    (struct t_opthdr *)0)

#define	T_OPT_DATA(tohp)	\
	((unsigned char *)_T_OPTDATA_ALIGN((char *)(tohp) + _T_OPTHDR_SZ))

#define	_T_NEXTHDR(pbuf, buflen, popt) \
	(((char *)_T_OPTHDR_ALIGN((char *)(popt) + (popt)->len) + \
	    _T_OPTHDR_SZ <= ((char *)(pbuf) + (buflen))) ? \
	(struct t_opthdr *)((char *)_T_OPTHDR_ALIGN((char *)(popt) + \
	    (popt)->len)) : (struct t_opthdr *)0)

#define	T_OPT_NEXTHDR(nbp, tohp)   (_T_NEXTHDR((nbp)->buf, (nbp)->len, (tohp)))

#if !defined(_XPG5)
/*
 * The macros below are meant for older applications for compatibility.
 * New applications should use the T_OPT_* macros, obviating the need
 * to explicitly use the T_ALIGN macro
 *
 * struct t_opthdr *OPT_NEXTHDR(char *pbuf, unsigned int buflen,
 *                               struct t_opthdr *popt):
 *         Skip to next option header
 */
#define	T_ALIGN(p)	(((uintptr_t)(p) + (sizeof (t_scalar_t) - 1))\
					& ~(sizeof (t_scalar_t) - 1))
#define	OPT_NEXTHDR(pbuf, buflen, popt)	(_T_NEXTHDR((pbuf), (buflen), (popt)))
#endif

/*
 * XTI LIBRARY FUNCTIONS
 */

#if defined(_XOPEN_SOURCE) && !defined(_XPG5)
extern int t_accept(int, int, struct t_call *);
extern char *t_alloc(int, int, int);
extern int t_bind(int, struct t_bind *, struct t_bind *);
extern int t_connect(int, struct t_call *, struct t_call *);
extern int t_error(char *);
extern int t_free(char *, int);
extern int t_open(char *, int, struct t_info *);
extern int t_optmgmt(int, struct t_optmgmt *, struct t_optmgmt *);
extern int t_rcv(int, char *, unsigned int, int *);
extern int t_snd(int, char *, unsigned int, int);
extern int t_snddis(int, struct t_call *);
extern int t_sndudata(int, struct t_unitdata *);
extern char *t_strerror(int);
#else
extern int t_accept(int, int, const struct t_call *);
extern void *t_alloc(int, int, int);
extern int t_bind(int, const struct t_bind *, struct t_bind *);
extern int t_connect(int, const struct t_call *, struct t_call *);
extern int t_error(const char *);
extern int t_free(void *, int);
extern int t_open(const char *, int, struct t_info *);
extern int t_optmgmt(int, const struct t_optmgmt *, struct t_optmgmt *);
extern int t_rcv(int, void *, unsigned int, int *);
extern int t_snd(int, void *, unsigned int, int);
extern int t_snddis(int, const struct t_call *);
extern int t_sndudata(int, const struct t_unitdata *);
extern const char *t_strerror(int);
#endif
extern int t_close(int);
extern int t_getinfo(int, struct t_info *);
extern int t_getstate(int);
extern int t_getprotaddr(int, struct t_bind *, struct t_bind *);
extern int t_listen(int, struct t_call *);
extern int t_look(int);
extern int t_rcvconnect(int, struct t_call *);
extern int t_rcvdis(int, struct t_discon *);
extern int t_rcvrel(int);
extern int t_rcvreldata(int, struct t_discon *);
extern int t_rcvudata(int, struct t_unitdata *, int *);
extern int t_rcvuderr(int, struct t_uderr *);
extern int t_rcvv(int, struct t_iovec *, unsigned int, int *);
extern int t_rcvvudata(int, struct t_unitdata *, struct t_iovec *,
	unsigned int, int *);
extern int t_sndrel(int);
extern int t_sndreldata(int, struct t_discon *);
extern int t_sndv(int, const struct t_iovec *,  unsigned int, int);
extern int t_sndvudata(int, struct t_unitdata *, struct t_iovec *,
	unsigned int);
extern int t_sync(int);
extern int t_sysconf(int);
extern int t_unbind(int);

#ifdef	__cplusplus
}
#endif

#endif	/* _XTI_H */
