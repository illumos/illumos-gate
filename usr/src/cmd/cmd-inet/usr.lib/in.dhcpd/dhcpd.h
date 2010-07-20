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
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_DHCPD_H
#define	_DHCPD_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * dhcpd.h -- common header file for all the modules of the in.dhcpd program.
 */

#include <dhcp_svc_confopt.h>
#include <dhcp_svc_private.h>
#include <dhcp_svc_public.h>
#include <dhcp_impl.h>
#include <dhcp_symbol.h>
#include <libinetutil.h>
#include "hash.h"
#include "per_dnet.h"

/*
 * Raw encoded packet data. The final state. Note that 'code' not only
 * describes options: predefined: 1-60, site: 128-254, vendor: 42(*),
 * but it also defines packet fields for packet data as well.
 * Note that due to overlap of codes between various DSYM categories,
 * category must be used to distinguish (see libdhcputil).
 */
typedef	struct encoded {
	uchar_t		category; /* Option category */
	ushort_t	code;	/* Option code: 1--254, pkt loc */
	uchar_t		len;	/* len of data */
	uchar_t		*data;	/* Encoded DHCP packet field / option */
	struct encoded	*prev;	/* previous in list */
	struct encoded	*next;	/* next in list */
} ENCODE;

typedef struct {
	char	class[DSYM_CLASS_SIZE + 1];	/* client class */
	ENCODE	*head;				/* options of this class */
} VNDLIST;

typedef struct {
	char	nm[DN_MAX_CID_LEN + 1];		/* Macro name */
	ENCODE	*head;				/* head of encoded opts */
	int	classes;			/* num of client classes */
	VNDLIST	**list;				/* table of client classes */
} MACRO;

/* logging message categories */
typedef enum {
	L_ASSIGN =	0,	/* New assignment */
	L_REPLY =	1,	/* respond to existing client */
	L_RELEASE =	2,	/* client released IP */
	L_DECLINE =	3,	/* client declined IP */
	L_INFORM =	4,	/* client requested information only */
	L_NAK =		5,	/* client NAK'ed */
	L_ICMP_ECHO =	6,	/* Server detected IP in use */
	L_RELAY_REQ =	7,	/* Relay request to server(s) */
	L_RELAY_REP =	8	/* Relay reply to client */
} DHCP_MSG_CATEGORIES;

typedef enum {
	P_BOOTP =	0,	/* BOOT Protocol */
	P_DHCP =	1	/* DHC Protocol */
} DHCP_PROTO;

#define	DHCPD			"in.dhcpd"	/* daemon's name */
#define	DAEMON_VERS		"3.5"		/* daemon's version number */
#define	ENC_COPY		0		/* Copy encode list */
#define	ENC_DONT_COPY		1		/* don't copy encode list */
#define	DHCP_MAX_REPLY_SIZE	8192		/* should be big enough */
#define	DHCP_MIN_RECORDS	32		/* should be big enough */
#define	DHCP_ICMP_ATTEMPTS	1		/* Number of ping attempts */
#define	DHCP_ICMP_TIMEOUT	1000		/* Wait # millisecs for resp */
#define	DHCP_ARP_ADD		0		/* Add an ARP table entry */
#define	DHCP_ARP_DEL		1		/* Del an ARP table entry */
#define	DHCP_SCRATCH		128		/* scratch buffer size */
#define	NEW_DHCPTAB		0		/* load initial dhcptab */
#define	PRESERVE_DHCPTAB	1		/* preserve previous dhcptab */
#define	DEFAULT_LEASE		3600		/* Default if not specified */
#define	DHCP_RDCOP_RETRIES	3		/* Attempts to read options */
#define	HASHTABLESIZE		257		/* must be a prime number */
#define	DHCP_RESCAN_SCALE	60L		/* scale rescan_interval */

#define	DHCP_MIN_CLIENTS	32		/* minimum client structs */
#define	DHCP_DEFAULT_CLIENTS	1024		/* default client structs */
#define	DHCP_MINFREE_CLIENTS	8		/* minimum free clients */
#define	DHCP_NSS_LWP		32		/* free lwps for nss lib use */
#define	DHCP_NSS_TIME		3		/* name service cache time */
#define	DHCP_NO_NSU		(-1)		/* No Name service updates */

/* load option flags */
#define	DHCP_DHCP_CLNT		1		/* It's a DHCP client */
#define	DHCP_SEND_LEASE		2		/* Send lease parameters */
#define	DHCP_NON_RFC1048	4		/* non-rfc1048 magic cookie */
#define	DHCP_OVRLD_CLR		((uchar_t)0x00)	/* SNAME/FILE clear */
#define	DHCP_OVRLD_FILE		((uchar_t)0x01)	/* FILE in use */
#define	DHCP_OVRLD_SNAME	((uchar_t)0x02)	/* SNAME in use */
#define	DHCP_OVRLD_ALL		((uchar_t)0x03)	/* All overload space in use */

/* dhcp_lookup_dd_classify search flags */
#define	S_CID		0x01		/* find a client match */
#define	S_FREE		0x02		/* find a free record */
#define	S_LRU		0x04		/* find an lru record */

/* DHCP client states */
#define	INIT_STATE		1
#define	INIT_REBOOT_STATE	2
#define	RENEW_REBIND_STATE	3

extern int		debug;
extern boolean_t	verbose;
extern boolean_t	noping;
extern boolean_t	no_dhcptab;
extern boolean_t	server_mode;
extern boolean_t	be_automatic;
extern uchar_t		max_hops;
extern int		log_local;
extern int		icmp_tries;
extern time_t		off_secs;
extern time_t		cache_secs;
extern time_t		renog_secs;
extern time_t		min_lru;
extern time_t		icmp_timeout;
extern time_t		nsutimeout_secs;
extern boolean_t	time_to_go;
extern struct in_addr	server_ip;
extern struct in_addr	*owner_ip;
extern dsvc_datastore_t datastore;
extern int		max_threads;	/* maximum number of threads per net */
extern int		max_clients;	/* maximum number of clients per net */
extern ushort_t		port_offset;	/* offset to port for multiple server */
extern int 		net_thresh;	/* secs to keep pernet reference */
extern int 		clnt_thresh;	/* secs to keep client reference */
extern time_t		reinit_time;	/* reinitialization time */
extern struct __res_state resolv_conf;
#ifdef	DEBUG
extern char		*dbg_net;	/* simulated debug net (see misc.c) */
#endif	/* DEBUG */

extern void	*reinitialize(void *);
extern PKT	*gen_bootp_pkt(int, PKT *);
extern int	initmtab(void);
extern int	initntab(void);
extern int	checktab(void);
extern int	readtab(int);
extern void	resettab(boolean_t);
extern int	relay_agent_init(char *);
extern void	dhcpmsg(int, const char *, ...);
extern void 	*smalloc(unsigned);
extern void	*srealloc(void *, uint_t);
extern struct in_addr	*match_ownerip(in_addr_t);
extern void	*stack_create(unsigned int);
extern ENCODE 	*combine_encodes(ENCODE *, ENCODE *, int);
extern void	open_macros(void);
extern void	close_macros(void);
extern MACRO	*get_macro(char *);
extern ENCODE	*find_encode(ENCODE *, uchar_t, ushort_t);
extern ENCODE	*dup_encode(ENCODE *);
extern ENCODE	*make_encode(uchar_t, ushort_t, uchar_t, void *, int);
extern ENCODE	*dup_encode_list(ENCODE *);
extern void	free_encode_list(ENCODE *);
extern void	free_encode(ENCODE *);
extern void	replace_encode(ENCODE **, ENCODE *, int);
extern ENCODE	*vendor_encodes(MACRO *, char *);
extern char 	*disp_cid(PKT_LIST *, char *, int);
extern void	get_clnt_id(PKT_LIST *, uchar_t *, int, uchar_t *);
extern char	*get_class_id(PKT_LIST *, char *, int);
extern int	load_options(int, PKT_LIST *, PKT *, int, uchar_t *, ENCODE *,
		    ENCODE *);
extern void	free_plp(PKT_LIST *);
extern void	logtrans(DHCP_PROTO, DHCP_MSG_CATEGORIES, time_t,
		    struct in_addr, struct in_addr, PKT_LIST *);
extern int	icmp_echo_check(struct in_addr *, boolean_t *);
extern void	*monitor_client(void *);

extern void	dhcp(dsvc_clnt_t *, PKT_LIST *);
boolean_t	update_offer(dsvc_clnt_t *, dn_rec_list_t **, lease_t,
		    struct in_addr *, boolean_t);
extern void	bootp(dsvc_clnt_t *, PKT_LIST *);
extern void	get_netmask(struct in_addr *, struct in_addr *);
extern boolean_t select_offer(dsvc_dnet_t *dbp, PKT_LIST *, dsvc_clnt_t *,
		    dn_rec_list_t **);

extern int dhcp_open_dd(dsvc_handle_t *, dsvc_datastore_t *, dsvc_contype_t,
	    const char *, uint_t);
extern int dhcp_close_dd(dsvc_handle_t *);
extern int dhcp_modify_dd_entry(dsvc_handle_t, const void *, void *);
extern void dhcp_free_dd_list(dsvc_handle_t, void *);

extern void *dhcp_lookup_dd_classify(dsvc_dnet_t *, boolean_t, uint_t, int,
	    const dn_rec_t *, void **, int);

extern dn_rec_list_t *detach_dnrec_from_list(dn_rec_list_t *, dn_rec_list_t *,
			dn_rec_list_t **);

extern int qualify_hostname(char *, const char *, const char *, int, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _DHCPD_H */
