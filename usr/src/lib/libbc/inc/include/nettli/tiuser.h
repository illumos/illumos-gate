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
/*	from S5R3 sys/tiuser.h	10.2.1.1" */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	Copyright (c) 1984 AT&T	*/
/*	  All Rights Reserved  	*/


/* #ident	"@(#)kern-port:sys/tiuser.h	10.2.1.1" */

#ifndef _nettli_tiuser_h
#define _nettli_tiuser_h

/*
 * The following are the error codes needed by both the kernel
 * level transport providers and the user level library.
 */
#define	TBADADDR		1	/* incorrect addr format         */
#define	TBADOPT			2	/* incorrect option format       */
#define	TACCES			3	/* incorrect permissions         */
#define TBADF			4	/* illegal transport fd	         */
#define TNOADDR			5	/* couldn't allocate addr        */
#define TOUTSTATE	        6	/* out of state                  */
#define TBADSEQ		        7       /* bad call sequnce number       */
#define TSYSERR			8	/* system error              */
#define TLOOK		        9	/* event requires attention  */
#define TBADDATA	       10	/* illegal amount of data    */
#define TBUFOVFLW	       11       /* buffer not large enough   */
#define TFLOW		       12 	/* flow control		     */
#define	TNODATA		       13	/* no data		     */
#define TNODIS		       14	/* discon_ind not found on q */
#define TNOUDERR	       15	/* unitdata error not found  */
#define TBADFLAG	       16       /* bad flags                 */
#define TNOREL		       17       /* no ord rel found on q     */
#define TNOTSUPPORT	       18       /* primitive not supported   */
#define TSTATECHNG	       19	/* state is in process of changing */

/* 
 * The following are the events returned by t_look
 */
#define T_LISTEN	0x0001 	/* connection indication received */
#define T_CONNECT	0x0002	/* connect confirmation received  */
#define T_DATA		0x0004	/* normal data received           */
#define	T_EXDATA	0x0008	/* expedited data received        */
#define T_DISCONNECT	0x0010	/* disconnect received            */
#define T_ERROR		0x0020	/* fatal error occurred		  */
#define T_UDERR	 	0x0040	/* data gram error indication     */
#define T_ORDREL	0x0080	/* orderly release indication     */
#define T_EVENTS	0x00ff	/* event mask	                  */

/*
 * The following are the flag definitions needed by the
 * user level library routines.
 */

#define T_MORE		0x001		/* more data        */
#define T_EXPEDITED	0x002		/* expedited data   */
#define T_NEGOTIATE	0x004		/* set opts         */
#define T_CHECK		0x008		/* check opts       */
#define T_DEFAULT	0x010		/* get default opts */
#define T_SUCCESS	0x020		/* successful       */
#define T_FAILURE	0x040		/* failure          */

/*
 * protocol specific service limits
 */

struct t_info {
	long addr;	/* size of protocol address                */
	long options;	/* size of protocol options                */
	long tsdu;	/* size of max transport service data unit */
	long etsdu;	/* size of max expedited tsdu              */
	long connect;	/* max data for connection primitives      */
	long discon;	/* max data for disconnect primitives      */
	long servtype;	/* provider service type		   */
};

/* 
 * Service type defines
 */
#define T_COTS	   01	/* connection oriented transport service  */
#define T_COTS_ORD 02	/* connection oriented w/ orderly release */
#define T_CLTS	   03	/* connectionless transport service       */

/*
 * netbuf structure
 */

struct netbuf {
	unsigned int maxlen;
	unsigned int len;
	char *buf;
};

/*
 * t_bind - format of the addres and options arguments of bind 
 */

struct t_bind {
	struct netbuf	addr;
	unsigned	qlen;
};

/* 
 * options management
 */
struct t_optmgmt {
	struct netbuf	opt;
	long		flags;
};

/*
 * disconnect structure
 */
struct t_discon {
	struct netbuf udata;		/* user data          */
	int reason;			/* reason code        */
	int sequence;			/* sequence number    */
};

/*
 * call structure
 */
struct t_call {
	struct netbuf addr;		/*  address           */
	struct netbuf opt;		/* options	      */
	struct netbuf udata;		/* user data          */
	int sequence;			/* sequence number    */
};

/*
 * data gram structure
 */
struct t_unitdata {
	struct netbuf addr;		/*  address           */
	struct netbuf opt;		/* options	      */
	struct netbuf udata;		/* user data          */
};

/*
 * unitdata error
 */
struct t_uderr {
	struct netbuf addr;		/* address		*/
	struct netbuf opt;		/* options 		*/
	long	      error;		/* error code		*/
};

/*
 * The following are structure types used when dynamically
 * allocating the above structures via t_structalloc().
 */
#define T_BIND		1		/* struct t_bind	*/
#define T_OPTMGMT	2		/* struct t_optmgmt	*/
#define T_CALL		3		/* struct t_call	*/
#define T_DIS		4		/* struct t_discon	*/
#define T_UNITDATA	5		/* struct t_unitdata	*/
#define T_UDERROR	6		/* struct t_uderr	*/
#define T_INFO		7		/* struct t_info	*/

/*
 * The following bits specify which fields of the above
 * structures should be allocated by t_structalloc().
 */
#define T_ADDR	0x01			/* address   */
#define T_OPT	0x02			/* options   */
#define T_UDATA	0x04			/* user data */
#define T_ALL	0x07			/* all the above */


/* 
 * the following are the states for the user
 */

#define T_UNINIT	0		/* uninitialized  		*/
#define T_UNBND		1		/* unbound 	      		*/
#define T_IDLE		2		/* idle				*/
#define	T_OUTCON	3		/* outgoing connection pending 	*/
#define T_INCON		4		/* incoming connection pending  */
#define T_DATAXFER	5		/* data transfer		*/
#define T_OUTREL        6               /* outgoing release pending     */
#define T_INREL		7		/* incoming release pending     */

#define T_NOSTATES 	8



#define ROUNDUP(X)	((X + 0x03)&~0x03)

/*
 * Macro for converting signal number to a mask suitable for
 * sigblock().
 */
#define sigmask(m)	(1 << ((m)-1))

#endif /*!_nettli_tiuser_h*/
