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

#ifndef	_MPD_TABLES_H
#define	_MPD_TABLES_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Terminology:
 *
 * phyint: A NIC eg. hme0. This is represented as 'struct phyint'
 *
 * phyint instance: A protocol instance of a phyint. Eg. the IPv4 instance of
 * 	hme0 or the IPv6 instance of hme0. (struct phyint_instance)
 *
 * logint: A logical interface eg. hme0:1 (struct logint)
 *
 * phyint_group: A group of phyints i.e. physical interfaces that are
 *	(i) connected to the same level 2 topology e.g. the same ethernet
 *	    switch AND
 *	(ii) share the same phyint group name.
 * Load spreading and failover occur across members of the same phyint group.
 * phyint group members must be homogeneous. i.e. if a phyint belonging to a
 * phyint group has a IPv6 protocol instance, then all members of the phyint
 * group, must have IPv6 protocol instances. (struct phyint_group)
 */

#define	MAXDEFERREDRTT		1	/* Maximum number of deferred rtts */

/*
 * Status of the phyint, expressed by the return code of failure_state()
 */
#define	PHYINT_OK	0		/* No failure detected */
#define	PHYINT_FAILURE	1		/* NIC failure detected */
#define	GROUP_FAILURE	2		/* All NICs have failed */

/*
 * Return values of phyint_inst_update_from_k()
 */
#define	PI_OK			1	/* Phyint matches in the kernel */
#define	PI_DELETED		2	/* Phyint has vanished in the kernel */
#define	PI_IFINDEX_CHANGED	3	/* Phyint's ifindex has changed */
#define	PI_IOCTL_ERROR		4	/* Some ioctl error */
#define	PI_GROUP_CHANGED	5	/* The phyint has changed group. */

#define	PHYINT_FLAGS(flags)	\
	(((flags) & (IFF_STANDBY | IFF_INACTIVE | IFF_FAILED | IFF_OFFLINE | \
	IFF_RUNNING)) | (handle_link_notifications ? 0 : IFF_RUNNING))

/* A Phyint can have up to 2 instances, the IPv4 and the IPv6 instance */
#define	PHYINT_INSTANCE(pi, af)	\
	((af) == AF_INET ? (pi)->pi_v4 : (pi)->pi_v6)

/*
 * A phyint instance is probe *enabled* if it has been configured with a
 * unique probe address (i.e., an IFF_NOFAILOVER address).  It is probe
 * *capable* if it is also able to send probes (i.e., has one or more
 * targets available).
 */
#define	PROBE_ENABLED(pii) \
	(((pii) != NULL) && ((pii)->pii_probe_sock != -1) &&	\
	((pii)->pii_probe_logint != NULL) &&			\
	(((pii)->pii_probe_logint->li_dupaddr == 0)))

#define	PROBE_CAPABLE(pii) \
	(PROBE_ENABLED(pii) && ((pii)->pii_ntargets != 0))

/* Subtract b from a modulo n. i.e. (a - b) mod n  */
#define	MOD_SUB(a, b, n)	\
	((((a) + (n)) - (b)) % (n))

/* Increment modulo n */
#define	MOD_INCR(a, n)		\
	(((a) + 1) % (n))

/* Decrement modulo n */
#define	MOD_DCR(a, n)		\
	MOD_SUB(a, 1, n)

/*
 * 'index' represents an index into the circular probe stats array of
 * size PROBE_STATS_COUNT.  0 <= index < PROBE_STATS_COUNT. This is used
 * to access members of the pii_probes[] array defined in the phyint_instance
 * structure.
 */
#define	PROBE_INDEX_PREV(index)	\
	MOD_DCR(index, PROBE_STATS_COUNT)

#define	PROBE_INDEX_NEXT(index)	\
	MOD_INCR(index, PROBE_STATS_COUNT)


/*
 * If we receive more than LINK_UP_PERMIN "link up" notifications in a minute,
 * then don't actually perform the repair operation until we've dropped back
 * below the threshold (or we have a probe address and our probes indicate
 * that the link is functioning again).  This is to prevent link flapping in
 * the case where we don't have a probe address.
 */
#define	LINK_UP_PERMIN	2

#define	LINK_DOWN(pi) ((pi)->pi_link_state == 0)
#define	LINK_UP(pi) (!LINK_DOWN(pi))
#define	FLAGS_TO_LINK_STATE(pi) (((pi)->pi_flags & IFF_RUNNING) != 0)
#define	UPDATE_LINK_STATE(pi) ((pi)->pi_link_state = \
	FLAGS_TO_LINK_STATE(pi) ? 1 : 0)
#define	INIT_LINK_STATE(pi) ((pi)->pi_link_state = 1)

/*
 * Phyint group states; see below for the phyint group definition.
 */
enum pg_state {
	PG_OK = 1,	/* all interfaces in the group are working */
	PG_DEGRADED,	/* some interfaces in the group are unusable */
	PG_FAILED	/* all interfaces in the group are unusable */
};

/*
 * Convenience macro to check if the whole group has failed.
 */
#define	GROUP_FAILED(pg)	((pg)->pg_state == PG_FAILED)

/*
 * A doubly linked list of all phyint groups in the system.
 * A phyint group is identified by its group name.
 */
struct phyint_group {
	char pg_name[LIFGRNAMSIZ];	/* Phyint group name */
	struct phyint *pg_phyint;	/* List of phyints in this group */
	struct phyint_group *pg_next;	/* Next phyint group */
	struct phyint_group *pg_prev;	/* Prev phyint group */
	uint64_t 	pg_sig;		/* Current signature of this group */
	int		pg_probeint;	/* Interval between probes */
	int		pg_fdt;		/* Time needed to detect failure */
	enum pg_state	pg_state;	/* Current group state */
	boolean_t	pg_in_use;	/* To detect removed groups */
	struct addrlist	*pg_addrs;	/* Data addresses in this group */
	boolean_t pg_failmsg_printed;	/* Group failure msg printed */
};

/*
 * Phyint states; see below for the phyint definition.
 */
enum pi_state {
	PI_NOTARGETS	= 1,	/* Phyint has no targets */
	PI_RUNNING	= 2,	/* Phyint is functioning */
	PI_FAILED	= 3,	/* Phyint is failed */
	PI_OFFLINE	= 4	/* Phyint is offline */
};

/*
 * Representation of a NIC or a phyint. There is a list of all known phyints.
 * There is also a list of phyints belonging to a phyint group, one list
 * per phyint group.
 */
struct phyint {
	char	pi_name[LIFNAMSIZ + 1]; /* Phyint name eg. le0 */
	struct phyint_instance *pi_v4;	/* The IPv4 instance */
	struct phyint_instance *pi_v6;	/* The IPv6 instance */
	struct phyint_group *pi_group;	/* Pointer to the group */
	struct phyint	*pi_next;	/* List of all phyints */
	struct phyint	*pi_prev;	/* List of all phyints */
	struct phyint	*pi_pgnext;	/* List of phyints in this group */
	struct phyint	*pi_pgprev;	/* List of phyints in this group */
	uint_t		pi_ifindex;	/* interface index */
	enum pi_state	pi_state;	/* State of the phyint */
	uint64_t	pi_flags;	/* Phyint flags from kernel */
	uint16_t	pi_icmpid;	/* icmp id in icmp echo request */
	uint64_t	pi_taddrthresh;	/* time (in secs) to delay logging */
					/* about missing test addresses */
	dlpi_handle_t	pi_dh;		/* DLPI handle to underlying link */
	uint_t		pi_notes; 	/* enabled DLPI notifications */
	uchar_t		pi_hwaddr[DLPI_PHYSADDR_MAX]; /* phyint's hw address */
	size_t		pi_hwaddrlen;	/* phyint's hw address length */

	/*
	 * The pi_whenup array is a circular buffer of the most recent
	 * times (in milliseconds since some arbitrary point of time in
	 * the past) that the interface was brought up; pi_whendx identifies
	 * the oldest element of the array.
	 */
	uint_t		pi_whenup[LINK_UP_PERMIN];
	unsigned int	pi_whendx;

	uint_t
		pi_taddrmsg_printed : 1,	/* testaddr msg printed */
		pi_duptaddrmsg_printed : 1,	/* dup testaddr msg printed */
		pi_cfgmsg_printed : 1,	/* bad config msg printed */
		pi_lfmsg_printed : 1,   /* link-flapping msg printed */
		pi_link_state : 1,	/* interface link state */
		pi_hwaddrdup : 1; 	/* disabled due to dup hw address */
};

/*
 * A doubly linked list of all phyint_instances each of which contains a
 * doubly linked list of logical interfaces and targets. For eg. if both
 * IPv4 and IPv6 are used over hme0, we have 2 phyint instances, 1 for each
 * protocol.
 */
struct phyint_instance {
	struct phyint_instance	*pii_next;	/* List of all phyint insts */
	struct phyint_instance	*pii_prev;	/* List of all phyint insts */

	struct phyint	*pii_phyint;	/* Back pointer to the phyint */
	struct target	*pii_targets;	/* List of targets on this link */
	struct logint	*pii_probe_logint; /* IFF_NOFAILOVER addr for probing */
	struct logint	*pii_logint;	/* Doubly linked list of logical ifs */

	int	pii_probe_sock;		/* Socket for ICMP Probe packets */
	int	pii_af;			/* Address family */
	uint16_t pii_rack;		/* highest acknowledged seq number */
	uint16_t pii_snxt;		/* sequence number of next probe */
	uint_t	pii_snxt_time;		/* actual next probe time that */
					/* includes some randomness */

	uint_t	pii_snxt_basetime; 	/* strictly periodic base probe time */
					/* for all periodic probes */
	uint_t	pii_fd_snxt_basetime; 	/* strictly periodic base probe time */
					/* for failure detection probes */

	hrtime_t 	pii_fd_hrtime;	/* hrtime_t before which we should */
					/* not send probes out this pii */

	uint64_t	pii_flags;	/* Phyint flags from kernel */

	struct probe_stats {
		uint_t		pr_id;		/* Full ID of probe */
		struct target	*pr_target;	/* Probe Target */
		uint_t		pr_time_lost; 	/* Time probe declared lost */
		struct timeval	pr_tv_sent;	/* Wall time probe was sent */
		hrtime_t pr_hrtime_start;	/* hrtime probe op started */
		hrtime_t pr_hrtime_sent;	/* hrtime probe was sent */
		hrtime_t pr_hrtime_ackrecv; 	/* hrtime probe ack received */
		hrtime_t pr_hrtime_ackproc;	/* hrtime probe ack processed */
		uint_t	pr_status;	/* probe status as below */
#define	PR_UNUSED	0		/* Probe slot unused */
#define	PR_UNACKED	1		/* Probe is unacknowledged */
#define	PR_ACKED	2		/* Probe has been acknowledged */
#define	PR_LOST		3		/* Probe is declared lost */
	} pii_probes[PROBE_STATS_COUNT];

	uint_t
		pii_in_use : 1,			/* To detect removed phyints */
		pii_basetime_inited : 1,	/* probe time initialized */
		pii_targets_are_routers : 1;	/* routers or hosts ? */

	uint_t	pii_probe_next;		/* next index to use in pii_probes[] */
	struct target *pii_target_next;	/* next target for probing */
	struct target *pii_rtt_target_next;
					/* next target for rtt probes */

	int	pii_ntargets;		/* Number of active targets */
	struct stats {			/* Cumulative statistics */
		uint64_t	lost;		/* Number of probes lost */
		uint64_t	acked;		/* Number of probes acked */
		uint64_t	sent;		/* Number of probes sent */
		uint64_t	unknown;	/* Number of ambiguous */
						/* probe acks */
	} pii_cum_stats;
};

#define	pii_name	pii_phyint->pi_name
#define	pii_ifindex	pii_phyint->pi_ifindex
#define	pii_state	pii_phyint->pi_state
#define	pii_icmpid	pii_phyint->pi_icmpid

#define	PR_STATUS_VALID(status)		((status) <= PR_LOST)


/*
 * A doubly linked list of prefixes or logicals, hanging off the
 * phyint instance.
 */
struct logint {
	struct logint	*li_next;	/* Next logint of this phyint inst. */
	struct logint	*li_prev;	/* Prev logint of this phyint inst. */
	struct phyint_instance	*li_phyint_inst;
					/* Back pointer to phyint inst. */

	char		li_name[LIFNAMSIZ + 1];	/* name Eg. hme0:1 */
	struct in6_addr	li_addr;	/* IP address */
	struct in6_addr	li_dstaddr;	/* Dst IP address for pointopoint */
	struct in6_addr	li_subnet;	/* prefix / subnet */
	uint_t		li_subnet_len;	/* prefix / subnet length */
	uint64_t	li_flags;	/* IFF_* flags */
	uint_t
			li_in_use : 1,	/* flag to detect deleted logints */
			li_dupaddr : 1;	/* test address is not unique */
};


/*
 * Doubly-linked list of probe targets on a phyint instance. Probe targets are
 * usually onlink routers. If no onlink routers can be found, onlink hosts
 * are used.
 */
struct target {
	struct target	*tg_next;	/* Next target for this phyint inst. */
	struct target	*tg_prev;	/* Prev target for this phyint inst. */
	struct phyint_instance	*tg_phyint_inst;
					/* Back pointer to phyint instance */

	struct in6_addr	tg_address;	/* Target IP address */
	int		tg_status;	/* Status of the target below */
#define	TG_ACTIVE	1		/* active probe target */
#define	TG_UNUSED	2		/* target not in use now */
#define	TG_SLOW		3		/* rtt is high - Not in use now */
#define	TG_DEAD		4		/* Target is not responding */

	hrtime_t	tg_latime;	/* Target's last active time */
	int64_t		tg_rtt_sa;	/* Scaled RTT average (in ns) */
	int64_t		tg_rtt_sd;	/* Scaled RTT deviation (in ns) */
	int		tg_crtt;	/* Conservative RTT = A + 4D (in ms) */
	uint32_t
			tg_in_use : 1;	/* In use flag */
	int64_t		tg_deferred[MAXDEFERREDRTT + 1];
					/* Deferred rtt data points */
	int		tg_num_deferred;
					/* Number of deferred rtt data points */
};

#define	TG_STATUS_VALID(status) \
	(((status) >= TG_ACTIVE) && ((status) <= TG_DEAD))

/*
 * Statistics about consecutive probe failures are passed around between
 * functions in this structure.
 */
struct probe_fail_count
{
	uint_t	pf_tff;		/* Earliest time of failure in a series */
	int	pf_nfail;	/* Number of consecutive probe failures */
	int	pf_nfail_tg;	/* Number of consecutive probe fails for */
				/* some given target 'tg' */
};

/*
 * Statistics about consecutive probe successes is passed around between
 * functions in this structure.
 */
struct probe_success_count
{
	uint_t ps_tls;		/* Most recent time of probe success */
	boolean_t ps_tls_valid;	/* is ps_tls valid */
	int	ps_nsucc;	/* Number of consecutive probe successes */
				/* starting from the most recent */
	int	ps_nsucc_tg;	/* Number of consecutive probe successes */
				/* for some given target 'tg' */
};

/*
 * Statistics about missed probes that were never sent.
 * Happens due to scheduling delay.
 */

struct probes_missed
{
	uint_t	pm_nprobes;	/* Cumulative number of missed probes */
	uint_t	pm_ntimes;	/* Total number of occasions */
};

typedef struct addrlist {
	struct addrlist		*al_next; 		/* next address */
	char			al_name[LIFNAMSIZ];	/* address lif name */
	uint64_t		al_flags;		/* address flags */
	struct sockaddr_storage	al_addr; 		/* address */
} addrlist_t;

/*
 * Globals
 */
extern addrlist_t *localaddrs;
			/* List of all local addresses, including local zones */
extern struct phyint *phyints;		/* List of all phyints */
extern struct phyint_group *phyint_groups; /* List of all phyint groups */
extern struct phyint_group *phyint_anongroup; /* Pointer to the anon group */
extern struct phyint_instance *phyint_instances;
					/* List of all phyint instances */
extern struct probes_missed probes_missed;
					/* statistics about missed probes */

/*
 * Function prototypes
 */
extern int phyint_init(void);
extern struct phyint *phyint_lookup(const char *name);
extern struct phyint_instance *phyint_inst_lookup(int af, char *name);
extern struct phyint_instance *phyint_inst_init_from_k(int af, char *name);
extern struct phyint_instance *phyint_inst_other(struct phyint_instance *pii);
extern int phyint_inst_update_from_k(struct phyint_instance *pii);
extern void phyint_inst_delete(struct phyint_instance *pii);
extern uint_t phyint_inst_timer(struct phyint_instance *pii);
extern boolean_t phyint_inst_sockinit(struct phyint_instance *pii);

extern void phyint_changed(struct phyint *pi);
extern void phyint_chstate(struct phyint *pi, enum pi_state state);
extern void phyint_group_chstate(struct phyint_group *pg, enum pg_state state);
extern struct phyint_group *phyint_group_create(const char *pg_name);
extern struct phyint_group *phyint_group_lookup(const char *pg_name);
extern void phyint_group_insert(struct phyint_group *pg);
extern void phyint_group_delete(struct phyint_group *pg);
extern void phyint_group_refresh_state(struct phyint_group *pg);
extern void phyint_check_for_repair(struct phyint *pi);
extern void phyint_transition_to_running(struct phyint *pi);
extern void phyint_activate_another(struct phyint *pi);
extern int phyint_offline(struct phyint *pi, unsigned int);
extern int phyint_undo_offline(struct phyint *pi);

extern void logint_init_from_k(struct phyint_instance *pii, char *li_name);
extern void logint_delete(struct logint *li);

extern struct target *target_lookup(struct phyint_instance *pii,
    struct in6_addr addr);
extern void target_create(struct phyint_instance *pii,
    struct in6_addr addr, boolean_t is_router);
extern void target_delete(struct target *tg);
extern struct target *target_next(struct target *tg);
extern void target_add(struct phyint_instance *pii, struct in6_addr addr,
    boolean_t is_router);

extern void in_data(struct phyint_instance *pii);
extern void in6_data(struct phyint_instance *pii);

extern void logperror_pii(struct phyint_instance *pii, const char *str);
extern void logperror_li(struct logint *li, const char *str);
extern char *pr_addr(int af, struct in6_addr addr, char *abuf, int len);
extern void addr2storage(int af, const struct in6_addr *addr,
    struct sockaddr_storage *ssp);
extern void phyint_inst_print_all(void);
extern boolean_t prefix_equal(struct in6_addr, struct in6_addr, uint_t);

extern void reset_crtt_all(struct phyint *pi);
extern int failure_state(struct phyint_instance *pii);
extern void process_link_state_changes(void);
extern void clear_pii_probe_stats(struct phyint_instance *pii);
extern void start_timer(struct phyint_instance *pii);
extern void stop_probing(struct phyint *pi);

extern boolean_t own_address(struct in6_addr addr);
extern boolean_t change_pif_flags(struct phyint *pi, uint64_t set,
    uint64_t clear);

extern void close_probe_socket(struct phyint_instance *pii, boolean_t flag);
extern int probe_state_event(struct probe_stats *, struct phyint_instance *);
extern void probe_chstate(struct probe_stats *, struct phyint_instance *, int);

extern unsigned int getgraddrinfo(const char *, struct sockaddr_storage *,
    ipmp_addrinfo_t **);
extern unsigned int getifinfo(const char *, ipmp_ifinfo_t **);
extern unsigned int getgroupinfo(const char *, ipmp_groupinfo_t **);
extern unsigned int getgrouplist(ipmp_grouplist_t **);
extern unsigned int getsnap(ipmp_snap_t **);

extern boolean_t addrlist_add(addrlist_t **, const char *, uint64_t,
    struct sockaddr_storage *);
extern void addrlist_free(addrlist_t **);

#ifdef	__cplusplus
}
#endif

#endif	/* _MPD_TABLES_H */
