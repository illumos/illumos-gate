/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef	_NETINET_TCP_SEQ_H
#define	_NETINET_TCP_SEQ_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* tcp_seq.h 1.7 88/08/19 SMI; from UCB 7.1 6/5/85	*/

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * TCP sequence numbers are 32 bit integers operated
 * on with modular arithmetic.  These macros can be
 * used to compare such integers.
 */
#define	SEQ_LT(a, b)	((int32_t)((a)-(b)) < 0)
#define	SEQ_LEQ(a, b)	((int32_t)((a)-(b)) <= 0)
#define	SEQ_GT(a, b)	((int32_t)((a)-(b)) > 0)
#define	SEQ_GEQ(a, b)	((int32_t)((a)-(b)) >= 0)

/*
 * Macros to initialize tcp sequence numbers for
 * send and receive from initial send and receive
 * sequence numbers.
 */
#define	tcp_rcvseqinit(tp) \
	(tp)->rcv_adv = (tp)->rcv_nxt = (tp)->irs + 1

#define	tcp_sendseqinit(tp) \
	(tp)->snd_una = (tp)->snd_nxt = (tp)->snd_max = (tp)->snd_up = \
	    (tp)->iss

#define	TCP_ISSINCR	(125*1024)	/* increment for tcp_iss each second */

#ifdef	__cplusplus
}
#endif

#endif	/* _NETINET_TCP_SEQ_H */
