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

#ifndef	_NDPD_TABLES_H
#define	_NDPD_TABLES_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <ndpd.h>

enum adv_states { NO_ADV = 0, REG_ADV, INIT_ADV, SOLICIT_ADV, FINAL_ADV };
enum adv_events { ADV_OFF, START_INIT_ADV, START_FINAL_ADV, RECEIVED_SOLICIT,
			ADV_TIMER };

enum solicit_states { NO_SOLICIT = 0, INIT_SOLICIT, DONE_SOLICIT };
enum solicit_events { SOLICIT_OFF, START_INIT_SOLICIT, SOL_TIMER,
			SOLICIT_DONE, RESTART_INIT_SOLICIT };

/*
 * A doubly linked list of all physical interfaces that each contain a
 * doubly linked list of prefixes (i.e. logical interfaces) and default
 * routers.
 */
struct phyint {
	struct phyint	*pi_next;
	struct phyint	*pi_prev;
	struct prefix	*pi_prefix_list;	/* Doubly linked prefixes */
	struct router	*pi_router_list;	/* Doubly linked routers */
	struct adv_prefix *pi_adv_prefix_list;	/* Doubly linked adv.prefixes */

	uint_t		pi_index;		/* Identifier > 0 */
	char		pi_name[LIFNAMSIZ];	/* Used to identify it */
	int		pi_sock;		/* For sending and receiving */
	struct in6_addr	pi_ifaddr;		/* Local address */
	uint64_t		pi_flags;		/* IFF_* flags */
	uint_t		pi_mtu;			/* From SIOCGLIFMTU */
	struct in6_addr pi_token;
	uint_t		pi_token_length;
	struct in6_addr	pi_tmp_token;		/* For RFC3041 addrs */
	struct in6_addr	pi_dst_token;		/* For POINTOPOINT */

	uint_t		pi_state;		/* PI_* below */
	uint_t		pi_kernel_state;	/* PI_* below */
	uint_t		pi_num_k_routers;	/* # routers in kernel */
	uint_t		pi_reach_time_since_random;	/* In milliseconds */

	/* Applies if pi_AdvSendAdvertisements */
	uint_t		pi_adv_time_left;	/* In milliseconds */
	uint_t		pi_adv_time_since_sent;	/* In milliseconds */
	enum adv_states	pi_adv_state;
	uint_t		pi_adv_count;

	/* Applies if not pi_AdvSendAdvertisements */
	uint_t		pi_sol_time_left;	/* In milliseconds */
	enum solicit_states pi_sol_state;
	uint_t		pi_sol_count;

	/* Interface specific configurable variables */
	struct confvar	pi_config[I_IFSIZE];
#define	pi_DupAddrDetectTransmits pi_config[I_DupAddrDetectTransmits].cf_value
#define	pi_AdvSendAdvertisements pi_config[I_AdvSendAdvertisements].cf_value
#define	pi_MaxRtrAdvInterval	pi_config[I_MaxRtrAdvInterval].cf_value
#define	pi_MinRtrAdvInterval	pi_config[I_MinRtrAdvInterval].cf_value
#define	pi_AdvManagedFlag	pi_config[I_AdvManagedFlag].cf_value
#define	pi_AdvOtherConfigFlag	pi_config[I_AdvOtherConfigFlag].cf_value
#define	pi_AdvLinkMTU		pi_config[I_AdvLinkMTU].cf_value
#define	pi_AdvReachableTime	pi_config[I_AdvReachableTime].cf_value
#define	pi_AdvRetransTimer	pi_config[I_AdvRetransTimer].cf_value
#define	pi_AdvCurHopLimit	pi_config[I_AdvCurHopLimit].cf_value
#define	pi_AdvDefaultLifetime	pi_config[I_AdvDefaultLifetime].cf_value
#define	pi_StatelessAddrConf	pi_config[I_StatelessAddrConf].cf_value
#define	pi_TmpAddrsEnabled	pi_config[I_TmpAddrsEnabled].cf_value
#define	pi_TmpValidLifetime	pi_config[I_TmpValidLifetime].cf_value
#define	pi_TmpPreferredLifetime	pi_config[I_TmpPreferredLifetime].cf_value
#define	pi_TmpRegenAdvance	pi_config[I_TmpRegenAdvance].cf_value
#define	pi_TmpMaxDesyncFactor	pi_config[I_TmpMaxDesyncFactor].cf_value
#define	pi_StatefulAddrConf	pi_config[I_StatefulAddrConf].cf_value

	/* Recorded variables for RFC3041 addresses */
	uint_t		pi_TmpDesyncFactor;		/* In milliseconds */
	uint_t		pi_TmpRegenCountdown;		/* In milliseconds */

	/* Recorded variables on node/host */
	uint_t		pi_LinkMTU;
	uint_t		pi_CurHopLimit;
	uint_t		pi_BaseReachableTime;		/* In milliseconds */
	uint_t		pi_ReachableTime;		/* In milliseconds */
	/*
	 * The above value should be a uniformly-distributed random
	 * value between ND_MIN_RANDOM_FACTOR and
	 * ND_MAX_RANDOM_FACTOR times BaseReachableTime
	 * milliseconds.  A new random value should be
	 * calculated when BaseReachableTime changes (due to
	 * Router Advertisements) or at least every few hours
	 * even if no Router Advertisements are received.
	 * Tracked using pi_each_time_since_random.
	 */
	uint_t		pi_RetransTimer;		/* In milliseconds */

	uint_t		pi_ra_flags;		/* Detect when to start DHCP */
};

/*
 * pi_state/pr_kernel_state values
 */
#define	PI_PRESENT		0x01
#define	PI_JOINED_ALLNODES	0x02	/* allnodes multicast joined */
#define	PI_JOINED_ALLROUTERS	0x04	/* allrouters multicast joined */

/*
 * Prefix configuration variable indices
 */
#define	I_AdvValidLifetime	0	/* In seconds */
#define	I_AdvOnLinkFlag		1
#define	I_AdvPreferredLifetime	2	/* In seconds */
#define	I_AdvAutonomousFlag	3
#define	I_AdvValidExpiration	4	/* Seconds left */
#define	I_AdvPreferredExpiration 5	/* Seconds left */
#define	I_PREFIXSIZE		6	/* # of variables */

/*
 * A doubly-linked list of prefixes for onlink and addrconf.
 * ("Prefixes" in this context are identical to logical interfaces.)
 */
struct prefix {
	struct prefix	*pr_next;	/* Next prefix for this physical */
	struct prefix	*pr_prev;	/* Prev prefix for this physical */
	struct phyint	*pr_physical;	/* Back pointer */

	struct in6_addr	pr_prefix;	/* Used to indentify prefix */
	uint_t		pr_prefix_len;	/* Num bits valid */

	char		pr_name[LIFNAMSIZ];
	struct in6_addr	pr_address;
	uint64_t	pr_flags;	/* IFF_* flags */

	uint_t		pr_state;	/* PR_ONLINK | PR_AUTO etc */
	uint_t		pr_kernel_state; /* PR_ONLINK | PR_AUTO etc */
	boolean_t	pr_in_use;	/* To detect removed prefixes */

	/* Recorded variables on node/host */
	uint_t		pr_ValidLifetime;	/* In ms w/ 2 hour rule */
	uint_t		pr_PreferredLifetime;	/* In millseconds */
	uint_t		pr_OnLinkLifetime;	/* ms valid w/o 2 hour rule */
	boolean_t	pr_OnLinkFlag;
	boolean_t	pr_AutonomousFlag;

	uint_t		pr_CreateTime;		/* tmpaddr creation time */
						/* in SECONDS */
	uint_t		pr_attempts;	/* attempts to configure */
};

/*
 * Flags used for pr_kernel_state and pr_state where the latter is
 * user-level state.
 */
#define	PR_ONLINK	0x01		/* On-link */
#define	PR_AUTO		0x02		/* Stateless addrconf */
#define	PR_DEPRECATED	0x04		/* Address is deprecated */
#define	PR_STATIC	0x08		/* Not created by ndpd */

/*
 * The sum of all possible state string lengths, plus terminating
 * null character; if new states are added, this needs to be updated.
 * Useful for passing an appropriately sized buffer to prefix_print_state().
 *
 * Current strings: "ONLINK ", "AUTO ", "DEPRECATED ", "STATIC ", "\n"
 *                      7     +   5    +     11       +    7     +  1
 */
#define	PREFIX_STATESTRLEN	31

/* Prefix used for storing advertisement specific stuff */
struct adv_prefix {
	struct adv_prefix	*adv_pr_next;	/* Next prefix */
	struct adv_prefix	*adv_pr_prev;	/* Prev prefix */
	struct phyint		*adv_pr_physical;	/* Back pointer */

	struct in6_addr		adv_pr_prefix;	/* Used to indentify prefix */
	uint_t			adv_pr_prefix_len;	/* Num bits valid */

	/* Used when sending advertisements */
	struct confvar		adv_pr_config[I_PREFIXSIZE];
#define	adv_pr_AdvValidLifetime	adv_pr_config[I_AdvValidLifetime].cf_value
#define	adv_pr_AdvOnLinkFlag	adv_pr_config[I_AdvOnLinkFlag].cf_value
#define	adv_pr_AdvPreferredLifetime	\
			adv_pr_config[I_AdvPreferredLifetime].cf_value
#define	adv_pr_AdvAutonomousFlag	\
			adv_pr_config[I_AdvAutonomousFlag].cf_value
#define	adv_pr_AdvValidExpiration	\
			adv_pr_config[I_AdvValidExpiration].cf_value
#define	adv_pr_AdvPreferredExpiration	\
			adv_pr_config[I_AdvPreferredExpiration].cf_value
	/* The two below are set if the timers decrement in real time */
#define	adv_pr_AdvValidRealTime		\
			adv_pr_config[I_AdvValidExpiration].cf_notdefault
#define	adv_pr_AdvPreferredRealTime	\
			adv_pr_config[I_AdvPreferredExpiration].cf_notdefault
};

/*
 * Doubly-linked list of default routers on a phyint.
 */
struct router {
	struct router	*dr_next;	/* Next router for this physical */
	struct router	*dr_prev;	/* Prev router for this physical */
	struct phyint	*dr_physical;	/* Back pointer */

	struct in6_addr	dr_address;	/* Used to identify the router */
	uint_t		dr_lifetime;	/* In milliseconds */
	boolean_t	dr_inkernel;	/* Route added to kernel */
};

/*
 * Globals
 */
extern struct phyint *phyints;
extern int num_of_phyints;

/*
 * Functions
 */
extern uint_t		getcurrenttime(void);

extern struct phyint	*phyint_lookup(char *name);
extern struct phyint	*phyint_lookup_on_index(uint_t ifindex);
extern struct phyint	*phyint_create(char *name);
extern int		phyint_init_from_k(struct phyint *pi);
extern void		phyint_delete(struct phyint *pi);
extern uint_t		phyint_timer(struct phyint *pi, uint_t elapsed);
extern void		phyint_print_all(void);
extern int		phyint_get_lla(struct phyint *pi, struct lifreq *lifrp);
extern void		phyint_reach_random(struct phyint *pi,
			    boolean_t set_needed);
extern void		phyint_cleanup(struct phyint *pi);

extern boolean_t	tmptoken_create(struct phyint *pi);
extern void		tmptoken_delete(struct phyint *pi);
extern uint_t		tmptoken_timer(struct phyint *pi, uint_t elapsed);
extern boolean_t	token_equal(struct in6_addr t1, struct in6_addr t2,
			    int bits);

extern struct prefix	*prefix_create(struct phyint *pi, struct in6_addr addr,
			    int addrlen, uint64_t flags);
extern struct prefix	*prefix_lookup_name(struct phyint *pi, char *name);
extern struct prefix	*prefix_lookup_addr_match(struct prefix *pr);
extern struct prefix	*prefix_create_name(struct phyint *pi, char *name);
extern int		prefix_init_from_k(struct prefix *pr);
extern void		prefix_delete(struct prefix *pr);
extern boolean_t	prefix_equal(struct in6_addr p1, struct in6_addr p2,
			    int bits);
extern void		prefix_update_dhcp(struct prefix *pr);
extern void		prefix_update_k(struct prefix *pr);
extern uint_t		prefix_timer(struct prefix *pr, uint_t elapsed);
extern uint_t		adv_prefix_timer(struct adv_prefix *adv_pr,
			    uint_t elapsed);
extern struct prefix	*prefix_lookup_addr(struct phyint *pi,
			    struct in6_addr prefix);

extern struct adv_prefix *adv_prefix_lookup(struct phyint *pi,
			    struct in6_addr addr, int addrlen);
extern struct adv_prefix *adv_prefix_create(struct phyint *pi,
			    struct in6_addr addr, int addrlen);

extern struct router	*router_lookup(struct phyint *pi, struct in6_addr addr);
extern struct router	*router_create(struct phyint *pi, struct in6_addr addr,
			    uint_t lifetime);
extern void		router_update_k(struct router *dr);
extern uint_t		router_timer(struct router *dr, uint_t elapsed);

extern void	check_to_advertise(struct phyint *pi, enum adv_events event);
extern void	check_to_solicit(struct phyint *pi,
		    enum solicit_events event);
extern uint_t	advertise_event(struct phyint *pi, enum adv_events event,
		    uint_t elapsed);
extern uint_t	solicit_event(struct phyint *pi, enum solicit_events event,
		    uint_t elapsed);

extern void	print_route_sol(char *str, struct phyint *pi,
		    struct nd_router_solicit *rs, int len,
		    struct sockaddr_in6 *addr);
extern void	print_route_adv(char *str, struct phyint *pi,
		    struct nd_router_advert *ra, int len,
		    struct sockaddr_in6 *addr);
extern void	print_iflist(struct confvar *confvar);
extern void	print_prefixlist(struct confvar *confvar);

extern void	in_data(struct phyint *pi);

extern void	start_dhcp(struct phyint *pi);

extern void	incoming_ra(struct phyint *pi, struct nd_router_advert *ra,
		    int len, struct sockaddr_in6 *from, boolean_t loopback);

extern boolean_t incoming_prefix_addrconf_process(struct phyint *pi,
		    struct prefix *pr, uchar_t *opt,
		    struct sockaddr_in6 *from, boolean_t loopback,
		    boolean_t new_prefix);

extern void	incoming_prefix_onlink_process(struct prefix *pr,
		    uchar_t *opt);

#ifdef	__cplusplus
}
#endif

#endif	/* _NDPD_TABLES_H */
