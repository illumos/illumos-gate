/*
 * Copyright (c) 1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * Kernel variables for tcp.
 */

#ifndef	_NETINET_TCP_VAR_H
#define	_NETINET_TCP_VAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* tcp_var.h 1.11 88/08/19 SMI; from UCB 7.3 6/30/87	*/

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Tcp control block, one per tcp; fields:
 */
struct tcpcb {
	struct	tcpiphdr *seg_next;	/* sequencing queue */
	struct	tcpiphdr *seg_prev;
	short	t_state;		/* state of this connection */
	short	t_timer[TCPT_NTIMERS];	/* tcp timers */
	short	t_rxtshift;		/* log(2) of rexmt exp. backoff */
	short	t_rxtcur;		/* current retransmit value */
	short	t_dupacks;		/* consecutive dup acks recd */
	ushort_t t_maxseg;		/* maximum segment size */
	char	t_force;		/* 1 if forcing out a byte */
	uchar_t	t_flags;
#define	TF_ACKNOW	0x01		/* ack peer immediately */
#define	TF_DELACK	0x02		/* ack, but try to delay it */
#define	TF_NODELAY	0x04		/* don't delay packets to coalesce */
#define	TF_NOOPT	0x08		/* don't use tcp options */
#define	TF_SENTFIN	0x10		/* have sent FIN */
	struct	tcpiphdr *t_template;	/* skeletal packet for transmit */
	struct	inpcb *t_inpcb;		/* back pointer to internet pcb */
/*
 * The following fields are used as in the protocol specification.
 * See RFC783, Dec. 1981, page 21.
 */
/* send sequence variables */
	tcp_seq	snd_una;		/* send unacknowledged */
	tcp_seq	snd_nxt;		/* send next */
	tcp_seq	snd_up;			/* send urgent pointer */
	tcp_seq	snd_wl1;		/* window update seg seq number */
	tcp_seq	snd_wl2;		/* window update seg ack number */
	tcp_seq	iss;			/* initial send sequence number */
	ushort_t snd_wnd;		/* send window */
/* receive sequence variables */
	ushort_t rcv_wnd;		/* receive window */
	tcp_seq	rcv_nxt;		/* receive next */
	tcp_seq	rcv_up;			/* receive urgent pointer */
	tcp_seq	irs;			/* initial receive sequence number */
/*
 * Additional variables for this implementation.
 */
/* receive variables */
	tcp_seq	rcv_adv;		/* advertised window */
/* retransmit variables */
	tcp_seq	snd_max;		/* highest sequence number sent */
					/* used to recognize retransmits */

/* congestion control (for slow start, source quench, retransmit after loss) */
	ushort_t snd_cwnd;		/* congestion-controlled window */
	ushort_t snd_ssthresh;		/* snd_cwnd size threshhold for */
					/* for slow start exponential to */
/*
 * transmit timing stuff.
 * srtt and rttvar are stored as fixed point; for convenience in smoothing,
 * srtt has 3 bits to the right of the binary point, rttvar has 2.
 * "Variance" is actually smoothed difference.
 */
	short	t_idle;			/* inactivity time */
	short	t_rtt;			/* round trip time */
	tcp_seq	t_rtseq;		/* sequence number being timed */
	short	t_srtt;			/* smoothed round-trip time */
	short	t_rttvar;		/* variance in round-trip time */
	ushort_t max_rcvd;		/* most peer has sent into window */
	ushort_t max_sndwnd;		/* largest window peer has offered */
/* out-of-band data */
	char	t_oobflags;		/* have some */
	char	t_iobc;			/* input character */
#define	TCPOOB_HAVEDATA	0x01
#define	TCPOOB_HADDATA	0x02
};

#define	intotcpcb(ip)	((struct tcpcb *)(ip)->inp_ppcb)
#define	sototcpcb(so)	(intotcpcb(sotoinpcb(so)))

/*
 * TCP statistics.
 * Many of these should be kept per connection,
 * but that's inconvenient at the moment.
 */
struct	tcpstat {
	uint_t	tcps_connattempt;	/* connections initiated */
	uint_t	tcps_accepts;		/* connections accepted */
	uint_t	tcps_connects;		/* connections established */
	uint_t	tcps_drops;		/* connections dropped */
	uint_t	tcps_conndrops;		/* embryonic connections dropped */
	uint_t	tcps_closed;		/* conn. closed (includes drops) */
	uint_t	tcps_segstimed;		/* segs where we tried to get rtt */
	uint_t	tcps_rttupdated;	/* times we succeeded */
	uint_t	tcps_delack;		/* delayed acks sent */
	uint_t	tcps_timeoutdrop;	/* conn. dropped in rxmt timeout */
	uint_t	tcps_rexmttimeo;	/* retransmit timeouts */
	uint_t	tcps_persisttimeo;	/* persist timeouts */
	uint_t	tcps_keeptimeo;		/* keepalive timeouts */
	uint_t	tcps_keepprobe;		/* keepalive probes sent */
	uint_t	tcps_keepdrops;		/* connections dropped in keepalive */

	uint_t	tcps_sndtotal;		/* total packets sent */
	uint_t	tcps_sndpack;		/* data packets sent */
	uint_t	tcps_sndbyte;		/* data bytes sent */
	uint_t	tcps_sndrexmitpack;	/* data packets retransmitted */
	uint_t	tcps_sndrexmitbyte;	/* data bytes retransmitted */
	uint_t	tcps_sndacks;		/* ack-only packets sent */
	uint_t	tcps_sndprobe;		/* window probes sent */
	uint_t	tcps_sndurg;		/* packets sent with URG only */
	uint_t	tcps_sndwinup;		/* window update-only packets sent */
	uint_t	tcps_sndctrl;		/* control (SYN|FIN|RST) packets sent */

	uint_t	tcps_rcvtotal;		/* total packets received */
	uint_t	tcps_rcvpack;		/* packets received in sequence */
	uint_t	tcps_rcvbyte;		/* bytes received in sequence */
	uint_t	tcps_rcvbadsum;		/* packets received with ccksum errs */
	uint_t	tcps_rcvbadoff;		/* packets received with bad offset */
	uint_t	tcps_rcvshort;		/* packets received too short */
	uint_t	tcps_rcvduppack;	/* duplicate-only packets received */
	uint_t	tcps_rcvdupbyte;	/* duplicate-only bytes received */
	uint_t	tcps_rcvpartduppack;	/* packets with some duplicate data */
	uint_t	tcps_rcvpartdupbyte;	/* dup. bytes in part-dup. packets */
	uint_t	tcps_rcvoopack;		/* out-of-order packets received */
	uint_t	tcps_rcvoobyte;		/* out-of-order bytes received */
	uint_t	tcps_rcvpackafterwin;	/* packets with data after window */
	uint_t	tcps_rcvbyteafterwin;	/* bytes rcvd after window */
	uint_t	tcps_rcvafterclose;	/* packets rcvd after "close" */
	uint_t	tcps_rcvwinprobe;	/* rcvd window probe packets */
	uint_t	tcps_rcvdupack;		/* rcvd duplicate acks */
	uint_t	tcps_rcvacktoomuch;	/* rcvd acks for unsent data */
	uint_t	tcps_rcvackpack;	/* rcvd ack packets */
	uint_t	tcps_rcvackbyte;	/* bytes acked by rcvd acks */
	uint_t	tcps_rcvwinupd;		/* rcvd window update packets */
};

#define	TCP_COMPAT_42

#ifdef	__cplusplus
}
#endif

#endif	/* _NETINET_TCP_VAR_H */
