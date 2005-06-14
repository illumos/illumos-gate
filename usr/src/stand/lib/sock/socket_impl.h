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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Internal socket-specific definitions
 */

#ifndef _SOCKET_IMPL_H
#define	_SOCKET_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/socket.h>

/*
 * Socket support definitions
 */

#define	MAXSOCKET	(10)
#define	SOCKETTYPE	(65536)
#define	MEDIA_LVL	0
#define	NETWORK_LVL	1
#define	TRANSPORT_LVL	2
#define	APP_LVL		3

/* Anonymous ports assigned by socket. */
#define	SMALLEST_ANON_PORT	32768
#define	LARGEST_ANON_PORT	((64 * 1024) - 1)

/* Socket state bits. */
#define	SS_ISCONNECTED		0x000001 /* socket connected to a peer */
#define	SS_ISCONNECTING		0x000002 /* in process of connecting to peer */

#define	SS_CANTRCVMORE		0x000010 /* can't receive more data from peer */
#define	SS_CANTSENDMORE		0x000008 /* can't send more data to peer */

enum { FALSE, TRUE };
enum SockType { INETBOOT_UNUSED, INETBOOT_DGRAM, INETBOOT_RAW,
    INETBOOT_STREAM };
enum Ports { SOURCE, DESTINATION };
#define	FD_TO_SOCKET(v)	((v) - SOCKETTYPE)

/*
 * Message block descriptor copied from usr/src/uts/common/sys/stream.h.
 * We need to do that to simplify the porting of TCP code from core
 * kernel to inetboot.  Note that fields which are not used by TCP
 * code are removed.
 */
typedef struct  msgb {
	struct  msgb	*b_next;
	struct  msgb	*b_prev;
	struct  msgb	*b_cont;
	unsigned char	*b_rptr;
	unsigned char	*b_wptr;
	unsigned char	*b_datap;
	size_t		b_size;
} mblk_t;

/* Modified stream routines to ease TCP porting. */
extern mblk_t *allocb(size_t, uint_t);
extern mblk_t *dupb(mblk_t *);
extern void freeb(mblk_t *);
extern void freemsg(mblk_t *);
extern size_t msgdsize(mblk_t *);

/*
 * "target" is needed for input prior to IP address assignment. It may
 * seem redundant given the binding information contained in the socket,
 * but that's only true if we have an IP address. If we don't, and we
 * try DHCP, we'll try to udp checksum using INADDR_ANY as the destination
 * IP address, when in fact the destination IP address was the IP address
 * we were OFFERED/Assigned.
 */
struct inetgram {
	/* Common */
	struct sockaddr_in	igm_saddr;	/* source address info */
	int			igm_level;	/* Stack level (LVL) of data */
	mblk_t			*igm_mp;
	struct inetgram		*igm_next;	/* next inetgram in list */
	union {
		struct {
			/* Input specific */
			struct in_addr	in_t;
			uint16_t	in_i;
		} _IN_un;
		struct {
			/* Output specific */
			struct in_addr	out_r;
			int		out_f;
		} _OUT_un;
	} _i_o_inet;
#define	igm_target	_i_o_inet._IN_un.in_t	/* See above comment block */
#define	igm_id		_i_o_inet._IN_un.in_i	/* IP id */
#define	igm_router	_i_o_inet._OUT_un.out_r	/* first router IP  ... */
#define	igm_oflags	_i_o_inet._OUT_un.out_f	/* flag: 0 or MSG_DONTROUTE */
};

struct inetboot_socket {
	enum SockType		type;		/* socket type */
	uint8_t			proto;		/* ip protocol */
	int			out_flags;	/* 0 or MSG_DONTROUTE */
	boolean_t		bound;		/* boolean */
	uint32_t		so_state;	/* Socket state */
	int			so_error;	/* Socket error */
	struct sockaddr_in	bind;		/* Binding info */
	struct sockaddr_in	remote;		/* Remote address */
	struct inetgram		*inq;		/* input queue */
	int			so_sndbuf;	/* max send buf size */
	int			so_rcvbuf;	/* max receive buf size */
	struct linger		so_linger;	/* close linger time */
	uint32_t		in_timeout;	/* Input timeout (msec) */
	uint32_t		so_opt;		/* socket level option */
	int			(*headerlen[APP_LVL])(struct inetgram *);
	int			(*input[APP_LVL])(int);
	int			(*output[APP_LVL])(int, struct inetgram *);
	int			(*close[APP_LVL])(int);
	in_port_t		(*ports)(uint16_t *, enum Ports);
	void			*pcb;		/* Protocol control block */
};

extern struct inetboot_socket	sockets[MAXSOCKET];

extern void add_grams(struct inetgram **, struct inetgram *);
extern void del_gram(struct inetgram **, struct inetgram *, int);
extern void nuke_grams(struct inetgram **);
extern struct inetgram *last_gram(struct inetgram *);

extern int so_check_fd(int, int *);

#ifdef	__cplusplus
}
#endif

#endif /* _SOCKET_IMPL_H */
