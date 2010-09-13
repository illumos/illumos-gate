/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_INTERFACES_H
#define	_INTERFACES_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	DSRVR_NUM_DESC	3	/* Number of socket descriptors */
typedef enum {
	DSRVR_LBCAST =	0,	/* Limited broadcast recv descriptor */
	DSRVR_DBCAST =	1,	/* Directed broadcast recv descriptor */
	DSRVR_UCAST =	2	/* Unicast send/recv descriptor */
} dsrvr_socktype_t;

typedef struct interfaces {
	char		nm[IFNAMSIZ];		/* Interface name */
	unsigned int	ifceno;			/* Interface index */
	short		mtu;			/* MTU of interface */
	int		descs[DSRVR_NUM_DESC];	/* recv/send sockets */
	uint_t		flags;			/* interface flags */
	struct in_addr	bcast;			/* interface broadcast */
	struct in_addr	mask;			/* interface netmask */
	struct in_addr	addr;			/* interface IP addr */
	ENCODE		*ecp;			/* IF specific options */
	uint_t		transmit;		/* # of transmitted pkts */
	uint_t		received;		/* # of received pkts */
	uint_t		duplicate;		/* # of duplicate pkts */
	uint_t		dropped;		/* # of dropped pkts */
	uint_t		expired;		/* # of expired pkts */
	uint_t		errors;			/* # of protocol errors */
	uint_t		processed;		/* # of processed pkts */
	uint_t		offers;			/* # of pending offers */
	thread_t	if_thread;		/* rcv service thread */
	int		thr_exit;		/* sent when time to exit */
	mutex_t		ifp_mtx;		/* mutex lock on this struct */
	struct interfaces *next;
} IF;

#define	DHCP_MON_SYSERRS	30	/* Max allowable interface errors */
#define	DHCP_MON_ERRINTVL	1	/* Time interval for IF errors (secs) */
#define	DHCP_MON_THRESHOLD	6	/* Max allowable pending pkts pcd */

/*
 * Pause interval (mins) if IF error threshold reached.
 */
#define	DHCP_MON_SLEEP		5

extern IF	*if_head;	/* head of monitored interfaces */
extern mutex_t	if_head_mtx;	/* lock to protect interfaces list */
extern char	*interfaces;	/* list of user-requested interfaces. */
extern int	open_interfaces(void);
extern int	write_interface(IF *, PKT *, int, struct sockaddr_in *);
extern void	close_interfaces(void);
extern void	detach_plp(dsvc_clnt_t *, PKT_LIST *);
extern void	free_pktlist(dsvc_clnt_t *);
extern PKT_LIST	*refresh_pktlist(dsvc_clnt_t *, PKT_LIST *);
extern int	set_arp(IF *, struct in_addr *, uchar_t *, int, uchar_t);

extern int	send_reply(IF *, PKT *, int, struct in_addr *);
extern void	disp_if_stats(IF *);

extern int	relay_agent(IF *, PKT_LIST *);
extern void	determine_network(IF *, PKT_LIST *, struct in_addr *,
		    struct in_addr *);
extern boolean_t is_our_address(in_addr_t);


#ifdef	__cplusplus
}
#endif

#endif	/* _INTERFACES_H */
