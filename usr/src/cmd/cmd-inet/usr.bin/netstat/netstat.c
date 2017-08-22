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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 1990  Mentat Inc.
 * netstat.c 2.2, last change 9/9/91
 * MROUTING Revision 3.5
 * Copyright (c) 2017, Joyent, Inc.
 */

/*
 * simple netstat based on snmp/mib-2 interface to the TCP/IP stack
 *
 * NOTES:
 * 1. A comment "LINTED: (note 1)" appears before certain lines where
 *    lint would have complained, "pointer cast may result in improper
 *    alignment". These are lines where lint had suspected potential
 *    improper alignment of a data structure; in each such situation
 *    we have relied on the kernel guaranteeing proper alignment.
 * 2. Some 'for' loops have been commented as "'for' loop 1", etc
 *    because they have 'continue' or 'break' statements in their
 *    bodies. 'continue' statements have been used inside some loops
 *    where avoiding them would have led to deep levels of indentation.
 *
 * TODO:
 *	Add ability to request subsets from kernel (with level = MIB2_IP;
 *	name = 0 meaning everything for compatibility)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <kstat.h>
#include <assert.h>
#include <locale.h>
#include <synch.h>
#include <thread.h>

#include <sys/types.h>
#include <sys/stream.h>
#include <stropts.h>
#include <sys/strstat.h>
#include <sys/tihdr.h>

#include <sys/socket.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/route.h>

#include <inet/mib2.h>
#include <inet/ip.h>
#include <inet/arp.h>
#include <inet/tcp.h>
#include <netinet/igmp_var.h>
#include <netinet/ip_mroute.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/systeminfo.h>
#include <arpa/inet.h>

#include <netinet/dhcp.h>
#include <dhcpagent_ipc.h>
#include <dhcpagent_util.h>
#include <compat.h>

#include <libtsnet.h>
#include <tsol/label.h>

#include "statcommon.h"

extern void	unixpr(kstat_ctl_t *kc);

#define	STR_EXPAND	4

#define	V4MASK_TO_V6(v4, v6)	((v6)._S6_un._S6_u32[0] = 0xfffffffful, \
				(v6)._S6_un._S6_u32[1] = 0xfffffffful, \
				(v6)._S6_un._S6_u32[2] = 0xfffffffful, \
				(v6)._S6_un._S6_u32[3] = (v4))

#define	IN6_IS_V4MASK(v6)	((v6)._S6_un._S6_u32[0] == 0xfffffffful && \
				(v6)._S6_un._S6_u32[1] == 0xfffffffful && \
				(v6)._S6_un._S6_u32[2] == 0xfffffffful)

/*
 * This is used as a cushion in the buffer allocation directed by SIOCGLIFNUM.
 * Because there's no locking between SIOCGLIFNUM and SIOCGLIFCONF, it's
 * possible for an administrator to plumb new interfaces between those two
 * calls, resulting in the failure of the latter.  This addition makes that
 * less likely.
 */
#define	LIFN_GUARD_VALUE	10

typedef struct mib_item_s {
	struct mib_item_s	*next_item;
	int			group;
	int			mib_id;
	int			length;
	void			*valp;
} mib_item_t;

struct	ifstat {
	uint64_t	ipackets;
	uint64_t	ierrors;
	uint64_t	opackets;
	uint64_t	oerrors;
	uint64_t	collisions;
};

struct iflist {
	struct iflist	*next_if;
	char		ifname[LIFNAMSIZ];
	struct ifstat	tot;
};

static	mib_item_t	*mibget(int sd);
static	void		mibfree(mib_item_t *firstitem);
static	int		mibopen(void);
static void		mib_get_constants(mib_item_t *item);
static mib_item_t	*mib_item_dup(mib_item_t *item);
static mib_item_t	*mib_item_diff(mib_item_t *item1,
    mib_item_t *item2);
static void		mib_item_destroy(mib_item_t **item);

static boolean_t	octetstrmatch(const Octet_t *a, const Octet_t *b);
static char		*octetstr(const Octet_t *op, int code,
			    char *dst, uint_t dstlen);
static char		*pr_addr(uint_t addr,
			    char *dst, uint_t dstlen);
static char		*pr_addrnz(ipaddr_t addr, char *dst, uint_t dstlen);
static char		*pr_addr6(const in6_addr_t *addr,
			    char *dst, uint_t dstlen);
static char		*pr_mask(uint_t addr,
			    char *dst, uint_t dstlen);
static char		*pr_prefix6(const struct in6_addr *addr,
			    uint_t prefixlen, char *dst, uint_t dstlen);
static char		*pr_ap(uint_t addr, uint_t port,
			    char *proto, char *dst, uint_t dstlen);
static char		*pr_ap6(const in6_addr_t *addr, uint_t port,
			    char *proto, char *dst, uint_t dstlen);
static char		*pr_net(uint_t addr, uint_t mask,
			    char *dst, uint_t dstlen);
static char		*pr_netaddr(uint_t addr, uint_t mask,
			    char *dst, uint_t dstlen);
static char		*fmodestr(uint_t fmode);
static char		*portname(uint_t port, char *proto,
			    char *dst, uint_t dstlen);

static const char	*mitcp_state(int code,
			    const mib2_transportMLPEntry_t *attr);
static const char	*miudp_state(int code,
			    const mib2_transportMLPEntry_t *attr);

static void		stat_report(mib_item_t *item);
static void		mrt_stat_report(mib_item_t *item);
static void		arp_report(mib_item_t *item);
static void		ndp_report(mib_item_t *item);
static void		mrt_report(mib_item_t *item);
static void		if_stat_total(struct ifstat *oldstats,
			    struct ifstat *newstats, struct ifstat *sumstats);
static void		if_report(mib_item_t *item, char *ifname,
			    int Iflag_only, boolean_t once_only);
static void		if_report_ip4(mib2_ipAddrEntry_t *ap,
			    char ifname[], char logintname[],
			    struct ifstat *statptr, boolean_t ksp_not_null);
static void		if_report_ip6(mib2_ipv6AddrEntry_t *ap6,
			    char ifname[], char logintname[],
			    struct ifstat *statptr, boolean_t ksp_not_null);
static void		ire_report(const mib_item_t *item);
static void		tcp_report(const mib_item_t *item);
static void		udp_report(const mib_item_t *item);
static void		group_report(mib_item_t *item);
static void		dce_report(mib_item_t *item);
static void		print_ip_stats(mib2_ip_t *ip);
static void		print_icmp_stats(mib2_icmp_t *icmp);
static void		print_ip6_stats(mib2_ipv6IfStatsEntry_t *ip6);
static void		print_icmp6_stats(mib2_ipv6IfIcmpEntry_t *icmp6);
static void		print_sctp_stats(mib2_sctp_t *tcp);
static void		print_tcp_stats(mib2_tcp_t *tcp);
static void		print_udp_stats(mib2_udp_t *udp);
static void		print_rawip_stats(mib2_rawip_t *rawip);
static void		print_igmp_stats(struct igmpstat *igps);
static void		print_mrt_stats(struct mrtstat *mrts);
static void		sctp_report(const mib_item_t *item);
static void		sum_ip6_stats(mib2_ipv6IfStatsEntry_t *ip6,
			    mib2_ipv6IfStatsEntry_t *sum6);
static void		sum_icmp6_stats(mib2_ipv6IfIcmpEntry_t *icmp6,
			    mib2_ipv6IfIcmpEntry_t *sum6);
static void		m_report(void);
static void		dhcp_report(char *);

static	uint64_t	kstat_named_value(kstat_t *, char *);
static	kid_t		safe_kstat_read(kstat_ctl_t *, kstat_t *, void *);
static int		isnum(char *);
static char		*plural(int n);
static char		*pluraly(int n);
static char		*plurales(int n);
static void		process_filter(char *arg);
static char		*ifindex2str(uint_t, char *);
static boolean_t	family_selected(int family);

static void		usage(char *);
static void 		fatal(int errcode, char *str1, ...);

#define	PLURAL(n) plural((int)n)
#define	PLURALY(n) pluraly((int)n)
#define	PLURALES(n) plurales((int)n)
#define	IFLAGMOD(flg, val1, val2)	if (flg == val1) flg = val2
#define	MDIFF(diff, elem2, elem1, member)	(diff)->member = \
	(elem2)->member - (elem1)->member


static	boolean_t	Aflag = B_FALSE;	/* All sockets/ifs/rtng-tbls */
static	boolean_t	Dflag = B_FALSE;	/* DCE info */
static	boolean_t	Iflag = B_FALSE;	/* IP Traffic Interfaces */
static	boolean_t	Mflag = B_FALSE;	/* STREAMS Memory Statistics */
static	boolean_t	Nflag = B_FALSE;	/* Numeric Network Addresses */
static	boolean_t	Rflag = B_FALSE;	/* Routing Tables */
static	boolean_t	RSECflag = B_FALSE;	/* Security attributes */
static	boolean_t	Sflag = B_FALSE;	/* Per-protocol Statistics */
static	boolean_t	Vflag = B_FALSE;	/* Verbose */
static	boolean_t	Pflag = B_FALSE;	/* Net to Media Tables */
static	boolean_t	Gflag = B_FALSE;	/* Multicast group membership */
static	boolean_t	MMflag = B_FALSE;	/* Multicast routing table */
static	boolean_t	DHCPflag = B_FALSE;	/* DHCP statistics */
static	boolean_t	Xflag = B_FALSE;	/* Debug Info */

static	int	v4compat = 0;	/* Compatible printing format for status */

static int	proto = IPPROTO_MAX;	/* all protocols */
kstat_ctl_t	*kc = NULL;

/*
 * Name service timeout detection constants.
 */
static mutex_t ns_lock = ERRORCHECKMUTEX;
static boolean_t ns_active = B_FALSE;	/* Is a lookup ongoing? */
static hrtime_t ns_starttime;		/* Time the lookup started */
static int ns_sleeptime = 2;		/* Time in seconds between checks */
static int ns_warntime = 2;		/* Time in seconds before warning */

/*
 * Sizes of data structures extracted from the base mib.
 * This allows the size of the tables entries to grow while preserving
 * binary compatibility.
 */
static int ipAddrEntrySize;
static int ipRouteEntrySize;
static int ipNetToMediaEntrySize;
static int ipMemberEntrySize;
static int ipGroupSourceEntrySize;
static int ipRouteAttributeSize;
static int vifctlSize;
static int mfcctlSize;

static int ipv6IfStatsEntrySize;
static int ipv6IfIcmpEntrySize;
static int ipv6AddrEntrySize;
static int ipv6RouteEntrySize;
static int ipv6NetToMediaEntrySize;
static int ipv6MemberEntrySize;
static int ipv6GroupSourceEntrySize;

static int ipDestEntrySize;

static int transportMLPSize;
static int tcpConnEntrySize;
static int tcp6ConnEntrySize;
static int udpEntrySize;
static int udp6EntrySize;
static int sctpEntrySize;
static int sctpLocalEntrySize;
static int sctpRemoteEntrySize;

#define	protocol_selected(p)	(proto == IPPROTO_MAX || proto == (p))

/* Machinery used for -f (filter) option */
enum { FK_AF = 0, FK_OUTIF, FK_DST, FK_FLAGS, NFILTERKEYS };

static const char *filter_keys[NFILTERKEYS] = {
	"af", "outif", "dst", "flags"
};

static m_label_t *zone_security_label = NULL;

/* Flags on routes */
#define	FLF_A		0x00000001
#define	FLF_b		0x00000002
#define	FLF_D		0x00000004
#define	FLF_G		0x00000008
#define	FLF_H		0x00000010
#define	FLF_L		0x00000020
#define	FLF_U		0x00000040
#define	FLF_M		0x00000080
#define	FLF_S		0x00000100
#define	FLF_C		0x00000200	/* IRE_IF_CLONE */
#define	FLF_I		0x00000400	/* RTF_INDIRECT */
#define	FLF_R		0x00000800	/* RTF_REJECT */
#define	FLF_B		0x00001000	/* RTF_BLACKHOLE */
#define	FLF_Z		0x00100000	/* RTF_ZONE */

static const char flag_list[] = "AbDGHLUMSCIRBZ";

typedef struct filter_rule filter_t;

struct filter_rule {
	filter_t *f_next;
	union {
		int f_family;
		const char *f_ifname;
		struct {
			struct hostent *f_address;
			in6_addr_t f_mask;
		} a;
		struct {
			uint_t f_flagset;
			uint_t f_flagclear;
		} f;
	} u;
};

/*
 * The user-specified filters are linked into lists separated by
 * keyword (type of filter).  Thus, the matching algorithm is:
 *	For each non-empty filter list
 *		If no filters in the list match
 *			then stop here; route doesn't match
 *	If loop above completes, then route does match and will be
 *	displayed.
 */
static filter_t *filters[NFILTERKEYS];

static uint_t timestamp_fmt = NODATE;

#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"		/* Use this only if it isn't */
#endif

static void
ns_lookup_start(void)
{
	mutex_enter(&ns_lock);
	ns_active = B_TRUE;
	ns_starttime = gethrtime();
	mutex_exit(&ns_lock);
}

static void
ns_lookup_end(void)
{
	mutex_enter(&ns_lock);
	ns_active = B_FALSE;
	mutex_exit(&ns_lock);
}

/*
 * When name services are not functioning, this program appears to hang to the
 * user. To try and give the user a chance of figuring out that this might be
 * the case, we end up warning them and suggest that they may want to use the -n
 * flag.
 */
/* ARGSUSED */
static void *
ns_warning_thr(void *unsued)
{
	for (;;) {
		hrtime_t now;

		(void) sleep(ns_sleeptime);
		now = gethrtime();
		mutex_enter(&ns_lock);
		if (ns_active && now - ns_starttime >= ns_warntime * NANOSEC) {
			(void) fprintf(stderr, "warning: data "
			    "available, but name service lookups are "
			    "taking a while. Use the -n option to "
			    "disable name service lookups.\n");
			mutex_exit(&ns_lock);
			return (NULL);
		}
		mutex_exit(&ns_lock);
	}

	/* LINTED: E_STMT_NOT_REACHED */
	return (NULL);
}


int
main(int argc, char **argv)
{
	char		*name;
	mib_item_t	*item = NULL;
	mib_item_t	*previtem = NULL;
	int		sd = -1;
	char	*ifname = NULL;
	int	interval = 0;	/* Single time by default */
	int	count = -1;	/* Forever */
	int	c;
	int	d;
	/*
	 * Possible values of 'Iflag_only':
	 * -1, no feature-flags;
	 *  0, IFlag and other feature-flags enabled
	 *  1, IFlag is the only feature-flag enabled
	 * : trinary variable, modified using IFLAGMOD()
	 */
	int Iflag_only = -1;
	boolean_t once_only = B_FALSE; /* '-i' with count > 1 */
	extern char	*optarg;
	extern int	optind;
	char *default_ip_str = NULL;

	name = argv[0];

	v4compat = get_compat_flag(&default_ip_str);
	if (v4compat == DEFAULT_PROT_BAD_VALUE)
		fatal(2, "%s: %s: Bad value for %s in %s\n", name,
		    default_ip_str, DEFAULT_IP, INET_DEFAULT_FILE);
	free(default_ip_str);

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "adimnrspMgvxf:P:I:DRT:")) != -1) {
		switch ((char)c) {
		case 'a':		/* all connections */
			Aflag = B_TRUE;
			break;

		case 'd':		/* DCE info */
			Dflag = B_TRUE;
			IFLAGMOD(Iflag_only, 1, 0); /* see macro def'n */
			break;

		case 'i':		/* interface (ill/ipif report) */
			Iflag = B_TRUE;
			IFLAGMOD(Iflag_only, -1, 1); /* '-i' exists */
			break;

		case 'm':		/* streams msg report */
			Mflag = B_TRUE;
			IFLAGMOD(Iflag_only, 1, 0); /* see macro def'n */
			break;

		case 'n':		/* numeric format */
			Nflag = B_TRUE;
			break;

		case 'r':		/* route tables */
			Rflag = B_TRUE;
			IFLAGMOD(Iflag_only, 1, 0); /* see macro def'n */
			break;

		case 'R':		/* security attributes */
			RSECflag = B_TRUE;
			IFLAGMOD(Iflag_only, 1, 0); /* see macro def'n */
			break;

		case 's':		/* per-protocol statistics */
			Sflag = B_TRUE;
			IFLAGMOD(Iflag_only, 1, 0); /* see macro def'n */
			break;

		case 'p':		/* arp/ndp table */
			Pflag = B_TRUE;
			IFLAGMOD(Iflag_only, 1, 0); /* see macro def'n */
			break;

		case 'M':		/* multicast routing tables */
			MMflag = B_TRUE;
			IFLAGMOD(Iflag_only, 1, 0); /* see macro def'n */
			break;

		case 'g':		/* multicast group membership */
			Gflag = B_TRUE;
			IFLAGMOD(Iflag_only, 1, 0); /* see macro def'n */
			break;

		case 'v':		/* verbose output format */
			Vflag = B_TRUE;
			IFLAGMOD(Iflag_only, 1, 0); /* see macro def'n */
			break;

		case 'x':		/* turn on debugging */
			Xflag = B_TRUE;
			break;

		case 'f':
			process_filter(optarg);
			break;

		case 'P':
			if (strcmp(optarg, "ip") == 0) {
				proto = IPPROTO_IP;
			} else if (strcmp(optarg, "ipv6") == 0 ||
			    strcmp(optarg, "ip6") == 0) {
				v4compat = 0;	/* Overridden */
				proto = IPPROTO_IPV6;
			} else if (strcmp(optarg, "icmp") == 0) {
				proto = IPPROTO_ICMP;
			} else if (strcmp(optarg, "icmpv6") == 0 ||
			    strcmp(optarg, "icmp6") == 0) {
				v4compat = 0;	/* Overridden */
				proto = IPPROTO_ICMPV6;
			} else if (strcmp(optarg, "igmp") == 0) {
				proto = IPPROTO_IGMP;
			} else if (strcmp(optarg, "udp") == 0) {
				proto = IPPROTO_UDP;
			} else if (strcmp(optarg, "tcp") == 0) {
				proto = IPPROTO_TCP;
			} else if (strcmp(optarg, "sctp") == 0) {
				proto = IPPROTO_SCTP;
			} else if (strcmp(optarg, "raw") == 0 ||
			    strcmp(optarg, "rawip") == 0) {
				proto = IPPROTO_RAW;
			} else {
				fatal(1, "%s: unknown protocol.\n", optarg);
			}
			break;

		case 'I':
			ifname = optarg;
			Iflag = B_TRUE;
			IFLAGMOD(Iflag_only, -1, 1); /* see macro def'n */
			break;

		case 'D':
			DHCPflag = B_TRUE;
			Iflag_only = 0;
			break;

		case 'T':
			if (optarg) {
				if (*optarg == 'u')
					timestamp_fmt = UDATE;
				else if (*optarg == 'd')
					timestamp_fmt = DDATE;
				else
					usage(name);
			} else {
				usage(name);
			}
			break;

		case '?':
		default:
			usage(name);
		}
	}

	/*
	 * Make sure -R option is set only on a labeled system.
	 */
	if (RSECflag && !is_system_labeled()) {
		(void) fprintf(stderr, "-R set but labeling is not enabled\n");
		usage(name);
	}

	/*
	 * Handle other arguments: find interval, count; the
	 * flags that accept 'interval' and 'count' are OR'd
	 * in the outermost 'if'; more flags may be added as
	 * required
	 */
	if (Iflag || Sflag || Mflag) {
		for (d = optind; d < argc; d++) {
			if (isnum(argv[d])) {
				interval = atoi(argv[d]);
				if (d + 1 < argc &&
				    isnum(argv[d + 1])) {
					count = atoi(argv[d + 1]);
					optind++;
				}
				optind++;
				if (interval == 0 || count == 0)
					usage(name);
				break;
			}
		}
	}
	if (optind < argc) {
		if (Iflag && isnum(argv[optind])) {
			count = atoi(argv[optind]);
			if (count == 0)
				usage(name);
			optind++;
		}
	}
	if (optind < argc) {
		(void) fprintf(stderr,
		    "%s: extra arguments\n", name);
		usage(name);
	}
	if (interval)
		setbuf(stdout, NULL);

	/*
	 * Start up the thread to check for name services warnings.
	 */
	if (thr_create(NULL, 0, ns_warning_thr, NULL,
	    THR_DETACHED | THR_DAEMON, NULL) != 0) {
		fatal(1, "%s: failed to create name services "
		    "thread: %s\n", name, strerror(errno));
	}

	if (DHCPflag) {
		dhcp_report(Iflag ? ifname : NULL);
		exit(0);
	}

	/*
	 * Get this process's security label if the -R switch is set.
	 * We use this label as the current zone's security label.
	 */
	if (RSECflag) {
		zone_security_label = m_label_alloc(MAC_LABEL);
		if (zone_security_label == NULL)
			fatal(errno, "m_label_alloc() failed");
		if (getplabel(zone_security_label) < 0)
			fatal(errno, "getplabel() failed");
	}

	/* Get data structures: priming before iteration */
	if (family_selected(AF_INET) || family_selected(AF_INET6)) {
		sd = mibopen();
		if (sd == -1)
			fatal(1, "can't open mib stream\n");
		if ((item = mibget(sd)) == NULL) {
			(void) close(sd);
			fatal(1, "mibget() failed\n");
		}
		/* Extract constant sizes - need do once only */
		mib_get_constants(item);
	}
	if ((kc = kstat_open()) == NULL) {
		mibfree(item);
		(void) close(sd);
		fail(1, "kstat_open(): can't open /dev/kstat");
	}

	if (interval <= 0) {
		count = 1;
		once_only = B_TRUE;
	}
	/* 'for' loop 1: */
	for (;;) {
		mib_item_t *curritem = NULL; /* only for -[M]s */

		if (timestamp_fmt != NODATE)
			print_timestamp(timestamp_fmt);

		/* netstat: AF_INET[6] behaviour */
		if (family_selected(AF_INET) || family_selected(AF_INET6)) {
			if (Sflag) {
				curritem = mib_item_diff(previtem, item);
				if (curritem == NULL)
					fatal(1, "can't process mib data, "
					    "out of memory\n");
				mib_item_destroy(&previtem);
			}

			if (!(Dflag || Iflag || Rflag || Sflag || Mflag ||
			    MMflag || Pflag || Gflag || DHCPflag)) {
				if (protocol_selected(IPPROTO_UDP))
					udp_report(item);
				if (protocol_selected(IPPROTO_TCP))
					tcp_report(item);
				if (protocol_selected(IPPROTO_SCTP))
					sctp_report(item);
			}
			if (Iflag)
				if_report(item, ifname, Iflag_only, once_only);
			if (Mflag)
				m_report();
			if (Rflag)
				ire_report(item);
			if (Sflag && MMflag) {
				mrt_stat_report(curritem);
			} else {
				if (Sflag)
					stat_report(curritem);
				if (MMflag)
					mrt_report(item);
			}
			if (Gflag)
				group_report(item);
			if (Pflag) {
				if (family_selected(AF_INET))
					arp_report(item);
				if (family_selected(AF_INET6))
					ndp_report(item);
			}
			if (Dflag)
				dce_report(item);
			mib_item_destroy(&curritem);
		}

		/* netstat: AF_UNIX behaviour */
		if (family_selected(AF_UNIX) &&
		    (!(Dflag || Iflag || Rflag || Sflag || Mflag ||
		    MMflag || Pflag || Gflag)))
			unixpr(kc);
		(void) kstat_close(kc);

		/* iteration handling code */
		if (count > 0 && --count == 0)
			break;
		(void) sleep(interval);

		/* re-populating of data structures */
		if (family_selected(AF_INET) || family_selected(AF_INET6)) {
			if (Sflag) {
				/* previtem is a cut-down list */
				previtem = mib_item_dup(item);
				if (previtem == NULL)
					fatal(1, "can't process mib data, "
					    "out of memory\n");
			}
			mibfree(item);
			(void) close(sd);
			if ((sd = mibopen()) == -1)
				fatal(1, "can't open mib stream anymore\n");
			if ((item = mibget(sd)) == NULL) {
				(void) close(sd);
				fatal(1, "mibget() failed\n");
			}
		}
		if ((kc = kstat_open()) == NULL)
			fail(1, "kstat_open(): can't open /dev/kstat");

	} /* 'for' loop 1 ends */
	mibfree(item);
	(void) close(sd);
	if (zone_security_label != NULL)
		m_label_free(zone_security_label);

	return (0);
}


static int
isnum(char *p)
{
	int	len;
	int	i;

	len = strlen(p);
	for (i = 0; i < len; i++)
		if (!isdigit(p[i]))
			return (0);
	return (1);
}


/* --------------------------------- MIBGET -------------------------------- */

static mib_item_t *
mibget(int sd)
{
	/*
	 * buf is an automatic for this function, so the
	 * compiler has complete control over its alignment;
	 * it is assumed this alignment is satisfactory for
	 * it to be casted to certain other struct pointers
	 * here, such as struct T_optmgmt_ack * .
	 */
	uintptr_t		buf[512 / sizeof (uintptr_t)];
	int			flags;
	int			i, j, getcode;
	struct strbuf		ctlbuf, databuf;
	struct T_optmgmt_req	*tor = (struct T_optmgmt_req *)buf;
	struct T_optmgmt_ack	*toa = (struct T_optmgmt_ack *)buf;
	struct T_error_ack	*tea = (struct T_error_ack *)buf;
	struct opthdr		*req;
	mib_item_t		*first_item = NULL;
	mib_item_t		*last_item  = NULL;
	mib_item_t		*temp;

	tor->PRIM_type = T_SVR4_OPTMGMT_REQ;
	tor->OPT_offset = sizeof (struct T_optmgmt_req);
	tor->OPT_length = sizeof (struct opthdr);
	tor->MGMT_flags = T_CURRENT;


	/*
	 * Note: we use the special level value below so that IP will return
	 * us information concerning IRE_MARK_TESTHIDDEN routes.
	 */
	req = (struct opthdr *)&tor[1];
	req->level = EXPER_IP_AND_ALL_IRES;
	req->name  = 0;
	req->len   = 1;

	ctlbuf.buf = (char *)buf;
	ctlbuf.len = tor->OPT_length + tor->OPT_offset;
	flags = 0;
	if (putmsg(sd, &ctlbuf, (struct strbuf *)0, flags) == -1) {
		perror("mibget: putmsg(ctl) failed");
		goto error_exit;
	}

	/*
	 * Each reply consists of a ctl part for one fixed structure
	 * or table, as defined in mib2.h.  The format is a T_OPTMGMT_ACK,
	 * containing an opthdr structure.  level/name identify the entry,
	 * len is the size of the data part of the message.
	 */
	req = (struct opthdr *)&toa[1];
	ctlbuf.maxlen = sizeof (buf);
	j = 1;
	for (;;) {
		flags = 0;
		getcode = getmsg(sd, &ctlbuf, (struct strbuf *)0, &flags);
		if (getcode == -1) {
			perror("mibget getmsg(ctl) failed");
			if (Xflag) {
				(void) fputs("#   level   name    len\n",
				    stderr);
				i = 0;
				for (last_item = first_item; last_item;
				    last_item = last_item->next_item)
					(void) printf("%d  %4d   %5d   %d\n",
					    ++i,
					    last_item->group,
					    last_item->mib_id,
					    last_item->length);
			}
			goto error_exit;
		}
		if (getcode == 0 &&
		    ctlbuf.len >= sizeof (struct T_optmgmt_ack) &&
		    toa->PRIM_type == T_OPTMGMT_ACK &&
		    toa->MGMT_flags == T_SUCCESS &&
		    req->len == 0) {
			if (Xflag)
				(void) printf("mibget getmsg() %d returned "
				    "EOD (level %ld, name %ld)\n",
				    j, req->level, req->name);
			return (first_item);		/* this is EOD msg */
		}

		if (ctlbuf.len >= sizeof (struct T_error_ack) &&
		    tea->PRIM_type == T_ERROR_ACK) {
			(void) fprintf(stderr,
			    "mibget %d gives T_ERROR_ACK: TLI_error = 0x%lx, "
			    "UNIX_error = 0x%lx\n",
			    j, tea->TLI_error, tea->UNIX_error);

			errno = (tea->TLI_error == TSYSERR) ?
			    tea->UNIX_error : EPROTO;
			goto error_exit;
		}

		if (getcode != MOREDATA ||
		    ctlbuf.len < sizeof (struct T_optmgmt_ack) ||
		    toa->PRIM_type != T_OPTMGMT_ACK ||
		    toa->MGMT_flags != T_SUCCESS) {
			(void) printf("mibget getmsg(ctl) %d returned %d, "
			    "ctlbuf.len = %d, PRIM_type = %ld\n",
			    j, getcode, ctlbuf.len, toa->PRIM_type);

			if (toa->PRIM_type == T_OPTMGMT_ACK)
				(void) printf("T_OPTMGMT_ACK: "
				    "MGMT_flags = 0x%lx, req->len = %ld\n",
				    toa->MGMT_flags, req->len);
			errno = ENOMSG;
			goto error_exit;
		}

		temp = (mib_item_t *)malloc(sizeof (mib_item_t));
		if (temp == NULL) {
			perror("mibget malloc failed");
			goto error_exit;
		}
		if (last_item != NULL)
			last_item->next_item = temp;
		else
			first_item = temp;
		last_item = temp;
		last_item->next_item = NULL;
		last_item->group = req->level;
		last_item->mib_id = req->name;
		last_item->length = req->len;
		last_item->valp = malloc((int)req->len);
		if (last_item->valp == NULL)
			goto error_exit;
		if (Xflag)
			(void) printf("msg %d: group = %4d   mib_id = %5d"
			    "length = %d\n",
			    j, last_item->group, last_item->mib_id,
			    last_item->length);

		databuf.maxlen = last_item->length;
		databuf.buf    = (char *)last_item->valp;
		databuf.len    = 0;
		flags = 0;
		getcode = getmsg(sd, (struct strbuf *)0, &databuf, &flags);
		if (getcode == -1) {
			perror("mibget getmsg(data) failed");
			goto error_exit;
		} else if (getcode != 0) {
			(void) printf("mibget getmsg(data) returned %d, "
			    "databuf.maxlen = %d, databuf.len = %d\n",
			    getcode, databuf.maxlen, databuf.len);
			goto error_exit;
		}
		j++;
	}
	/* NOTREACHED */

error_exit:;
	mibfree(first_item);
	return (NULL);
}

/*
 * mibfree: frees a linked list of type (mib_item_t *)
 * returned by mibget(); this is NOT THE SAME AS
 * mib_item_destroy(), so should be used for objects
 * returned by mibget() only
 */
static void
mibfree(mib_item_t *firstitem)
{
	mib_item_t *lastitem;

	while (firstitem != NULL) {
		lastitem = firstitem;
		firstitem = firstitem->next_item;
		if (lastitem->valp != NULL)
			free(lastitem->valp);
		free(lastitem);
	}
}

static int
mibopen(void)
{
	int	sd;

	sd = open("/dev/arp", O_RDWR);
	if (sd == -1) {
		perror("arp open");
		return (-1);
	}
	if (ioctl(sd, I_PUSH, "tcp") == -1) {
		perror("tcp I_PUSH");
		(void) close(sd);
		return (-1);
	}
	if (ioctl(sd, I_PUSH, "udp") == -1) {
		perror("udp I_PUSH");
		(void) close(sd);
		return (-1);
	}
	if (ioctl(sd, I_PUSH, "icmp") == -1) {
		perror("icmp I_PUSH");
		(void) close(sd);
		return (-1);
	}
	return (sd);
}

/*
 * mib_item_dup: returns a clean mib_item_t * linked
 * list, so that for every element item->mib_id is 0;
 * to deallocate this linked list, use mib_item_destroy
 */
static mib_item_t *
mib_item_dup(mib_item_t *item)
{
	int	c = 0;
	mib_item_t *localp;
	mib_item_t *tempp;

	for (tempp = item; tempp; tempp = tempp->next_item)
		if (tempp->mib_id == 0)
			c++;
	tempp = NULL;

	localp = (mib_item_t *)malloc(c * sizeof (mib_item_t));
	if (localp == NULL)
		return (NULL);
	c = 0;
	for (; item; item = item->next_item) {
		if (item->mib_id == 0) {
			/* Replicate item in localp */
			(localp[c]).next_item = NULL;
			(localp[c]).group = item->group;
			(localp[c]).mib_id = item->mib_id;
			(localp[c]).length = item->length;
			(localp[c]).valp = (uintptr_t *)malloc(
			    item->length);
			if ((localp[c]).valp == NULL) {
				mib_item_destroy(&localp);
				return (NULL);
			}
			(void *) memcpy((localp[c]).valp,
			    item->valp,
			    item->length);
			tempp = &(localp[c]);
			if (c > 0)
				(localp[c - 1]).next_item = tempp;
			c++;
		}
	}
	return (localp);
}

/*
 * mib_item_diff: takes two (mib_item_t *) linked lists
 * item1 and item2 and computes the difference between
 * differentiable values in item2 against item1 for every
 * given member of item2; returns an mib_item_t * linked
 * list of diff's, or a copy of item2 if item1 is NULL;
 * will return NULL if system out of memory; works only
 * for item->mib_id == 0
 */
static mib_item_t *
mib_item_diff(mib_item_t *item1, mib_item_t *item2)
{
	int	nitems	= 0; /* no. of items in item2 */
	mib_item_t *tempp2;  /* walking copy of item2 */
	mib_item_t *tempp1;  /* walking copy of item1 */
	mib_item_t *diffp;
	mib_item_t *diffptr; /* walking copy of diffp */
	mib_item_t *prevp = NULL;

	if (item1 == NULL) {
		diffp = mib_item_dup(item2);
		return (diffp);
	}

	for (tempp2 = item2;
	    tempp2;
	    tempp2 = tempp2->next_item) {
		if (tempp2->mib_id == 0)
			switch (tempp2->group) {
			/*
			 * upon adding a case here, the same
			 * must also be added in the next
			 * switch statement, alongwith
			 * appropriate code
			 */
			case MIB2_IP:
			case MIB2_IP6:
			case EXPER_DVMRP:
			case EXPER_IGMP:
			case MIB2_ICMP:
			case MIB2_ICMP6:
			case MIB2_TCP:
			case MIB2_UDP:
			case MIB2_SCTP:
			case EXPER_RAWIP:
				nitems++;
			}
	}
	tempp2 = NULL;
	if (nitems == 0) {
		diffp = mib_item_dup(item2);
		return (diffp);
	}

	diffp = (mib_item_t *)calloc(nitems, sizeof (mib_item_t));
	if (diffp == NULL)
		return (NULL);
	diffptr = diffp;
	/* 'for' loop 1: */
	for (tempp2 = item2; tempp2 != NULL; tempp2 = tempp2->next_item) {
		if (tempp2->mib_id != 0)
			continue; /* 'for' loop 1 */
		/* 'for' loop 2: */
		for (tempp1 = item1; tempp1 != NULL;
		    tempp1 = tempp1->next_item) {
			if (!(tempp1->mib_id == 0 &&
			    tempp1->group == tempp2->group &&
			    tempp1->mib_id == tempp2->mib_id))
				continue; /* 'for' loop 2 */
			/* found comparable data sets */
			if (prevp != NULL)
				prevp->next_item = diffptr;
			switch (tempp2->group) {
			/*
			 * Indenting note: Because of long variable names
			 * in cases MIB2_IP6 and MIB2_ICMP6, their contents
			 * have been indented by one tab space only
			 */
			case MIB2_IP: {
				mib2_ip_t *i2 = (mib2_ip_t *)tempp2->valp;
				mib2_ip_t *i1 = (mib2_ip_t *)tempp1->valp;
				mib2_ip_t *d;

				diffptr->group = tempp2->group;
				diffptr->mib_id = tempp2->mib_id;
				diffptr->length = tempp2->length;
				d = (mib2_ip_t *)calloc(tempp2->length, 1);
				if (d == NULL)
					goto mibdiff_out_of_memory;
				diffptr->valp = d;
				d->ipForwarding = i2->ipForwarding;
				d->ipDefaultTTL = i2->ipDefaultTTL;
				MDIFF(d, i2, i1, ipInReceives);
				MDIFF(d, i2, i1, ipInHdrErrors);
				MDIFF(d, i2, i1, ipInAddrErrors);
				MDIFF(d, i2, i1, ipInCksumErrs);
				MDIFF(d, i2, i1, ipForwDatagrams);
				MDIFF(d, i2, i1, ipForwProhibits);
				MDIFF(d, i2, i1, ipInUnknownProtos);
				MDIFF(d, i2, i1, ipInDiscards);
				MDIFF(d, i2, i1, ipInDelivers);
				MDIFF(d, i2, i1, ipOutRequests);
				MDIFF(d, i2, i1, ipOutDiscards);
				MDIFF(d, i2, i1, ipOutNoRoutes);
				MDIFF(d, i2, i1, ipReasmTimeout);
				MDIFF(d, i2, i1, ipReasmReqds);
				MDIFF(d, i2, i1, ipReasmOKs);
				MDIFF(d, i2, i1, ipReasmFails);
				MDIFF(d, i2, i1, ipReasmDuplicates);
				MDIFF(d, i2, i1, ipReasmPartDups);
				MDIFF(d, i2, i1, ipFragOKs);
				MDIFF(d, i2, i1, ipFragFails);
				MDIFF(d, i2, i1, ipFragCreates);
				MDIFF(d, i2, i1, ipRoutingDiscards);
				MDIFF(d, i2, i1, tcpInErrs);
				MDIFF(d, i2, i1, udpNoPorts);
				MDIFF(d, i2, i1, udpInCksumErrs);
				MDIFF(d, i2, i1, udpInOverflows);
				MDIFF(d, i2, i1, rawipInOverflows);
				MDIFF(d, i2, i1, ipsecInSucceeded);
				MDIFF(d, i2, i1, ipsecInFailed);
				MDIFF(d, i2, i1, ipInIPv6);
				MDIFF(d, i2, i1, ipOutIPv6);
				MDIFF(d, i2, i1, ipOutSwitchIPv6);
				prevp = diffptr++;
				break;
			}
			case MIB2_IP6: {
			mib2_ipv6IfStatsEntry_t *i2;
			mib2_ipv6IfStatsEntry_t *i1;
			mib2_ipv6IfStatsEntry_t *d;

			i2 = (mib2_ipv6IfStatsEntry_t *)tempp2->valp;
			i1 = (mib2_ipv6IfStatsEntry_t *)tempp1->valp;
			diffptr->group = tempp2->group;
			diffptr->mib_id = tempp2->mib_id;
			diffptr->length = tempp2->length;
			d = (mib2_ipv6IfStatsEntry_t *)calloc(
			    tempp2->length, 1);
			if (d == NULL)
				goto mibdiff_out_of_memory;
			diffptr->valp = d;
			d->ipv6Forwarding = i2->ipv6Forwarding;
			d->ipv6DefaultHopLimit =
			    i2->ipv6DefaultHopLimit;

			MDIFF(d, i2, i1, ipv6InReceives);
			MDIFF(d, i2, i1, ipv6InHdrErrors);
			MDIFF(d, i2, i1, ipv6InTooBigErrors);
			MDIFF(d, i2, i1, ipv6InNoRoutes);
			MDIFF(d, i2, i1, ipv6InAddrErrors);
			MDIFF(d, i2, i1, ipv6InUnknownProtos);
			MDIFF(d, i2, i1, ipv6InTruncatedPkts);
			MDIFF(d, i2, i1, ipv6InDiscards);
			MDIFF(d, i2, i1, ipv6InDelivers);
			MDIFF(d, i2, i1, ipv6OutForwDatagrams);
			MDIFF(d, i2, i1, ipv6OutRequests);
			MDIFF(d, i2, i1, ipv6OutDiscards);
			MDIFF(d, i2, i1, ipv6OutNoRoutes);
			MDIFF(d, i2, i1, ipv6OutFragOKs);
			MDIFF(d, i2, i1, ipv6OutFragFails);
			MDIFF(d, i2, i1, ipv6OutFragCreates);
			MDIFF(d, i2, i1, ipv6ReasmReqds);
			MDIFF(d, i2, i1, ipv6ReasmOKs);
			MDIFF(d, i2, i1, ipv6ReasmFails);
			MDIFF(d, i2, i1, ipv6InMcastPkts);
			MDIFF(d, i2, i1, ipv6OutMcastPkts);
			MDIFF(d, i2, i1, ipv6ReasmDuplicates);
			MDIFF(d, i2, i1, ipv6ReasmPartDups);
			MDIFF(d, i2, i1, ipv6ForwProhibits);
			MDIFF(d, i2, i1, udpInCksumErrs);
			MDIFF(d, i2, i1, udpInOverflows);
			MDIFF(d, i2, i1, rawipInOverflows);
			MDIFF(d, i2, i1, ipv6InIPv4);
			MDIFF(d, i2, i1, ipv6OutIPv4);
			MDIFF(d, i2, i1, ipv6OutSwitchIPv4);
			prevp = diffptr++;
			break;
			}
			case EXPER_DVMRP: {
				struct mrtstat *m2;
				struct mrtstat *m1;
				struct mrtstat *d;

				m2 = (struct mrtstat *)tempp2->valp;
				m1 = (struct mrtstat *)tempp1->valp;
				diffptr->group = tempp2->group;
				diffptr->mib_id = tempp2->mib_id;
				diffptr->length = tempp2->length;
				d = (struct mrtstat *)calloc(tempp2->length, 1);
				if (d == NULL)
					goto mibdiff_out_of_memory;
				diffptr->valp = d;
				MDIFF(d, m2, m1, mrts_mfc_hits);
				MDIFF(d, m2, m1, mrts_mfc_misses);
				MDIFF(d, m2, m1, mrts_fwd_in);
				MDIFF(d, m2, m1, mrts_fwd_out);
				d->mrts_upcalls = m2->mrts_upcalls;
				MDIFF(d, m2, m1, mrts_fwd_drop);
				MDIFF(d, m2, m1, mrts_bad_tunnel);
				MDIFF(d, m2, m1, mrts_cant_tunnel);
				MDIFF(d, m2, m1, mrts_wrong_if);
				MDIFF(d, m2, m1, mrts_upq_ovflw);
				MDIFF(d, m2, m1, mrts_cache_cleanups);
				MDIFF(d, m2, m1, mrts_drop_sel);
				MDIFF(d, m2, m1, mrts_q_overflow);
				MDIFF(d, m2, m1, mrts_pkt2large);
				MDIFF(d, m2, m1, mrts_pim_badversion);
				MDIFF(d, m2, m1, mrts_pim_rcv_badcsum);
				MDIFF(d, m2, m1, mrts_pim_badregisters);
				MDIFF(d, m2, m1, mrts_pim_regforwards);
				MDIFF(d, m2, m1, mrts_pim_regsend_drops);
				MDIFF(d, m2, m1, mrts_pim_malformed);
				MDIFF(d, m2, m1, mrts_pim_nomemory);
				prevp = diffptr++;
				break;
			}
			case EXPER_IGMP: {
				struct igmpstat *i2;
				struct igmpstat *i1;
				struct igmpstat *d;

				i2 = (struct igmpstat *)tempp2->valp;
				i1 = (struct igmpstat *)tempp1->valp;
				diffptr->group = tempp2->group;
				diffptr->mib_id = tempp2->mib_id;
				diffptr->length = tempp2->length;
				d = (struct igmpstat *)calloc(
				    tempp2->length, 1);
				if (d == NULL)
					goto mibdiff_out_of_memory;
				diffptr->valp = d;
				MDIFF(d, i2, i1, igps_rcv_total);
				MDIFF(d, i2, i1, igps_rcv_tooshort);
				MDIFF(d, i2, i1, igps_rcv_badsum);
				MDIFF(d, i2, i1, igps_rcv_queries);
				MDIFF(d, i2, i1, igps_rcv_badqueries);
				MDIFF(d, i2, i1, igps_rcv_reports);
				MDIFF(d, i2, i1, igps_rcv_badreports);
				MDIFF(d, i2, i1, igps_rcv_ourreports);
				MDIFF(d, i2, i1, igps_snd_reports);
				prevp = diffptr++;
				break;
			}
			case MIB2_ICMP: {
				mib2_icmp_t *i2;
				mib2_icmp_t *i1;
				mib2_icmp_t *d;

				i2 = (mib2_icmp_t *)tempp2->valp;
				i1 = (mib2_icmp_t *)tempp1->valp;
				diffptr->group = tempp2->group;
				diffptr->mib_id = tempp2->mib_id;
				diffptr->length = tempp2->length;
				d = (mib2_icmp_t *)calloc(tempp2->length, 1);
				if (d == NULL)
					goto mibdiff_out_of_memory;
				diffptr->valp = d;
				MDIFF(d, i2, i1, icmpInMsgs);
				MDIFF(d, i2, i1, icmpInErrors);
				MDIFF(d, i2, i1, icmpInCksumErrs);
				MDIFF(d, i2, i1, icmpInUnknowns);
				MDIFF(d, i2, i1, icmpInDestUnreachs);
				MDIFF(d, i2, i1, icmpInTimeExcds);
				MDIFF(d, i2, i1, icmpInParmProbs);
				MDIFF(d, i2, i1, icmpInSrcQuenchs);
				MDIFF(d, i2, i1, icmpInRedirects);
				MDIFF(d, i2, i1, icmpInBadRedirects);
				MDIFF(d, i2, i1, icmpInEchos);
				MDIFF(d, i2, i1, icmpInEchoReps);
				MDIFF(d, i2, i1, icmpInTimestamps);
				MDIFF(d, i2, i1, icmpInAddrMasks);
				MDIFF(d, i2, i1, icmpInAddrMaskReps);
				MDIFF(d, i2, i1, icmpInFragNeeded);
				MDIFF(d, i2, i1, icmpOutMsgs);
				MDIFF(d, i2, i1, icmpOutDrops);
				MDIFF(d, i2, i1, icmpOutErrors);
				MDIFF(d, i2, i1, icmpOutDestUnreachs);
				MDIFF(d, i2, i1, icmpOutTimeExcds);
				MDIFF(d, i2, i1, icmpOutParmProbs);
				MDIFF(d, i2, i1, icmpOutSrcQuenchs);
				MDIFF(d, i2, i1, icmpOutRedirects);
				MDIFF(d, i2, i1, icmpOutEchos);
				MDIFF(d, i2, i1, icmpOutEchoReps);
				MDIFF(d, i2, i1, icmpOutTimestamps);
				MDIFF(d, i2, i1, icmpOutTimestampReps);
				MDIFF(d, i2, i1, icmpOutAddrMasks);
				MDIFF(d, i2, i1, icmpOutAddrMaskReps);
				MDIFF(d, i2, i1, icmpOutFragNeeded);
				MDIFF(d, i2, i1, icmpInOverflows);
				prevp = diffptr++;
				break;
			}
			case MIB2_ICMP6: {
	mib2_ipv6IfIcmpEntry_t *i2;
	mib2_ipv6IfIcmpEntry_t *i1;
	mib2_ipv6IfIcmpEntry_t *d;

	i2 = (mib2_ipv6IfIcmpEntry_t *)tempp2->valp;
	i1 = (mib2_ipv6IfIcmpEntry_t *)tempp1->valp;
	diffptr->group = tempp2->group;
	diffptr->mib_id = tempp2->mib_id;
	diffptr->length = tempp2->length;
	d = (mib2_ipv6IfIcmpEntry_t *)calloc(tempp2->length, 1);
	if (d == NULL)
		goto mibdiff_out_of_memory;
	diffptr->valp = d;
	MDIFF(d, i2, i1, ipv6IfIcmpInMsgs);
	MDIFF(d, i2, i1, ipv6IfIcmpInErrors);
	MDIFF(d, i2, i1, ipv6IfIcmpInDestUnreachs);
	MDIFF(d, i2, i1, ipv6IfIcmpInAdminProhibs);
	MDIFF(d, i2, i1, ipv6IfIcmpInTimeExcds);
	MDIFF(d, i2, i1, ipv6IfIcmpInParmProblems);
	MDIFF(d, i2, i1, ipv6IfIcmpInPktTooBigs);
	MDIFF(d, i2, i1, ipv6IfIcmpInEchos);
	MDIFF(d, i2, i1, ipv6IfIcmpInEchoReplies);
	MDIFF(d, i2, i1, ipv6IfIcmpInRouterSolicits);
	MDIFF(d, i2, i1, ipv6IfIcmpInRouterAdvertisements);
	MDIFF(d, i2, i1, ipv6IfIcmpInNeighborSolicits);
	MDIFF(d, i2, i1, ipv6IfIcmpInNeighborAdvertisements);
	MDIFF(d, i2, i1, ipv6IfIcmpInRedirects);
	MDIFF(d, i2, i1, ipv6IfIcmpInBadRedirects);
	MDIFF(d, i2, i1, ipv6IfIcmpInGroupMembQueries);
	MDIFF(d, i2, i1, ipv6IfIcmpInGroupMembResponses);
	MDIFF(d, i2, i1, ipv6IfIcmpInGroupMembReductions);
	MDIFF(d, i2, i1, ipv6IfIcmpInOverflows);
	MDIFF(d, i2, i1, ipv6IfIcmpOutMsgs);
	MDIFF(d, i2, i1, ipv6IfIcmpOutErrors);
	MDIFF(d, i2, i1, ipv6IfIcmpOutDestUnreachs);
	MDIFF(d, i2, i1, ipv6IfIcmpOutAdminProhibs);
	MDIFF(d, i2, i1, ipv6IfIcmpOutTimeExcds);
	MDIFF(d, i2, i1, ipv6IfIcmpOutParmProblems);
	MDIFF(d, i2, i1, ipv6IfIcmpOutPktTooBigs);
	MDIFF(d, i2, i1, ipv6IfIcmpOutEchos);
	MDIFF(d, i2, i1, ipv6IfIcmpOutEchoReplies);
	MDIFF(d, i2, i1, ipv6IfIcmpOutRouterSolicits);
	MDIFF(d, i2, i1, ipv6IfIcmpOutRouterAdvertisements);
	MDIFF(d, i2, i1, ipv6IfIcmpOutNeighborSolicits);
	MDIFF(d, i2, i1, ipv6IfIcmpOutNeighborAdvertisements);
	MDIFF(d, i2, i1, ipv6IfIcmpOutRedirects);
	MDIFF(d, i2, i1, ipv6IfIcmpOutGroupMembQueries);
	MDIFF(d, i2, i1, ipv6IfIcmpOutGroupMembResponses);
	MDIFF(d, i2, i1, ipv6IfIcmpOutGroupMembReductions);
	prevp = diffptr++;
	break;
			}
			case MIB2_TCP: {
				mib2_tcp_t *t2;
				mib2_tcp_t *t1;
				mib2_tcp_t *d;

				t2 = (mib2_tcp_t *)tempp2->valp;
				t1 = (mib2_tcp_t *)tempp1->valp;
				diffptr->group = tempp2->group;
				diffptr->mib_id = tempp2->mib_id;
				diffptr->length = tempp2->length;
				d = (mib2_tcp_t *)calloc(tempp2->length, 1);
				if (d == NULL)
					goto mibdiff_out_of_memory;
				diffptr->valp = d;
				d->tcpRtoMin = t2->tcpRtoMin;
				d->tcpRtoMax = t2->tcpRtoMax;
				d->tcpMaxConn = t2->tcpMaxConn;
				MDIFF(d, t2, t1, tcpActiveOpens);
				MDIFF(d, t2, t1, tcpPassiveOpens);
				MDIFF(d, t2, t1, tcpAttemptFails);
				MDIFF(d, t2, t1, tcpEstabResets);
				d->tcpCurrEstab = t2->tcpCurrEstab;
				MDIFF(d, t2, t1, tcpHCOutSegs);
				MDIFF(d, t2, t1, tcpOutDataSegs);
				MDIFF(d, t2, t1, tcpOutDataBytes);
				MDIFF(d, t2, t1, tcpRetransSegs);
				MDIFF(d, t2, t1, tcpRetransBytes);
				MDIFF(d, t2, t1, tcpOutAck);
				MDIFF(d, t2, t1, tcpOutAckDelayed);
				MDIFF(d, t2, t1, tcpOutUrg);
				MDIFF(d, t2, t1, tcpOutWinUpdate);
				MDIFF(d, t2, t1, tcpOutWinProbe);
				MDIFF(d, t2, t1, tcpOutControl);
				MDIFF(d, t2, t1, tcpOutRsts);
				MDIFF(d, t2, t1, tcpOutFastRetrans);
				MDIFF(d, t2, t1, tcpHCInSegs);
				MDIFF(d, t2, t1, tcpInAckSegs);
				MDIFF(d, t2, t1, tcpInAckBytes);
				MDIFF(d, t2, t1, tcpInDupAck);
				MDIFF(d, t2, t1, tcpInAckUnsent);
				MDIFF(d, t2, t1, tcpInDataInorderSegs);
				MDIFF(d, t2, t1, tcpInDataInorderBytes);
				MDIFF(d, t2, t1, tcpInDataUnorderSegs);
				MDIFF(d, t2, t1, tcpInDataUnorderBytes);
				MDIFF(d, t2, t1, tcpInDataDupSegs);
				MDIFF(d, t2, t1, tcpInDataDupBytes);
				MDIFF(d, t2, t1, tcpInDataPartDupSegs);
				MDIFF(d, t2, t1, tcpInDataPartDupBytes);
				MDIFF(d, t2, t1, tcpInDataPastWinSegs);
				MDIFF(d, t2, t1, tcpInDataPastWinBytes);
				MDIFF(d, t2, t1, tcpInWinProbe);
				MDIFF(d, t2, t1, tcpInWinUpdate);
				MDIFF(d, t2, t1, tcpInClosed);
				MDIFF(d, t2, t1, tcpRttNoUpdate);
				MDIFF(d, t2, t1, tcpRttUpdate);
				MDIFF(d, t2, t1, tcpTimRetrans);
				MDIFF(d, t2, t1, tcpTimRetransDrop);
				MDIFF(d, t2, t1, tcpTimKeepalive);
				MDIFF(d, t2, t1, tcpTimKeepaliveProbe);
				MDIFF(d, t2, t1, tcpTimKeepaliveDrop);
				MDIFF(d, t2, t1, tcpListenDrop);
				MDIFF(d, t2, t1, tcpListenDropQ0);
				MDIFF(d, t2, t1, tcpHalfOpenDrop);
				MDIFF(d, t2, t1, tcpOutSackRetransSegs);
				prevp = diffptr++;
				break;
			}
			case MIB2_UDP: {
				mib2_udp_t *u2;
				mib2_udp_t *u1;
				mib2_udp_t *d;

				u2 = (mib2_udp_t *)tempp2->valp;
				u1 = (mib2_udp_t *)tempp1->valp;
				diffptr->group = tempp2->group;
				diffptr->mib_id = tempp2->mib_id;
				diffptr->length = tempp2->length;
				d = (mib2_udp_t *)calloc(tempp2->length, 1);
				if (d == NULL)
					goto mibdiff_out_of_memory;
				diffptr->valp = d;
				MDIFF(d, u2, u1, udpHCInDatagrams);
				MDIFF(d, u2, u1, udpInErrors);
				MDIFF(d, u2, u1, udpHCOutDatagrams);
				MDIFF(d, u2, u1, udpOutErrors);
				prevp = diffptr++;
				break;
			}
			case MIB2_SCTP: {
				mib2_sctp_t *s2;
				mib2_sctp_t *s1;
				mib2_sctp_t *d;

				s2 = (mib2_sctp_t *)tempp2->valp;
				s1 = (mib2_sctp_t *)tempp1->valp;
				diffptr->group = tempp2->group;
				diffptr->mib_id = tempp2->mib_id;
				diffptr->length = tempp2->length;
				d = (mib2_sctp_t *)calloc(tempp2->length, 1);
				if (d == NULL)
					goto mibdiff_out_of_memory;
				diffptr->valp = d;
				d->sctpRtoAlgorithm = s2->sctpRtoAlgorithm;
				d->sctpRtoMin = s2->sctpRtoMin;
				d->sctpRtoMax = s2->sctpRtoMax;
				d->sctpRtoInitial = s2->sctpRtoInitial;
				d->sctpMaxAssocs = s2->sctpMaxAssocs;
				d->sctpValCookieLife = s2->sctpValCookieLife;
				d->sctpMaxInitRetr = s2->sctpMaxInitRetr;
				d->sctpCurrEstab = s2->sctpCurrEstab;
				MDIFF(d, s2, s1, sctpActiveEstab);
				MDIFF(d, s2, s1, sctpPassiveEstab);
				MDIFF(d, s2, s1, sctpAborted);
				MDIFF(d, s2, s1, sctpShutdowns);
				MDIFF(d, s2, s1, sctpOutOfBlue);
				MDIFF(d, s2, s1, sctpChecksumError);
				MDIFF(d, s2, s1, sctpOutCtrlChunks);
				MDIFF(d, s2, s1, sctpOutOrderChunks);
				MDIFF(d, s2, s1, sctpOutUnorderChunks);
				MDIFF(d, s2, s1, sctpRetransChunks);
				MDIFF(d, s2, s1, sctpOutAck);
				MDIFF(d, s2, s1, sctpOutAckDelayed);
				MDIFF(d, s2, s1, sctpOutWinUpdate);
				MDIFF(d, s2, s1, sctpOutFastRetrans);
				MDIFF(d, s2, s1, sctpOutWinProbe);
				MDIFF(d, s2, s1, sctpInCtrlChunks);
				MDIFF(d, s2, s1, sctpInOrderChunks);
				MDIFF(d, s2, s1, sctpInUnorderChunks);
				MDIFF(d, s2, s1, sctpInAck);
				MDIFF(d, s2, s1, sctpInDupAck);
				MDIFF(d, s2, s1, sctpInAckUnsent);
				MDIFF(d, s2, s1, sctpFragUsrMsgs);
				MDIFF(d, s2, s1, sctpReasmUsrMsgs);
				MDIFF(d, s2, s1, sctpOutSCTPPkts);
				MDIFF(d, s2, s1, sctpInSCTPPkts);
				MDIFF(d, s2, s1, sctpInInvalidCookie);
				MDIFF(d, s2, s1, sctpTimRetrans);
				MDIFF(d, s2, s1, sctpTimRetransDrop);
				MDIFF(d, s2, s1, sctpTimHeartBeatProbe);
				MDIFF(d, s2, s1, sctpTimHeartBeatDrop);
				MDIFF(d, s2, s1, sctpListenDrop);
				MDIFF(d, s2, s1, sctpInClosed);
				prevp = diffptr++;
				break;
			}
			case EXPER_RAWIP: {
				mib2_rawip_t *r2;
				mib2_rawip_t *r1;
				mib2_rawip_t *d;

				r2 = (mib2_rawip_t *)tempp2->valp;
				r1 = (mib2_rawip_t *)tempp1->valp;
				diffptr->group = tempp2->group;
				diffptr->mib_id = tempp2->mib_id;
				diffptr->length = tempp2->length;
				d = (mib2_rawip_t *)calloc(tempp2->length, 1);
				if (d == NULL)
					goto mibdiff_out_of_memory;
				diffptr->valp = d;
				MDIFF(d, r2, r1, rawipInDatagrams);
				MDIFF(d, r2, r1, rawipInErrors);
				MDIFF(d, r2, r1, rawipInCksumErrs);
				MDIFF(d, r2, r1, rawipOutDatagrams);
				MDIFF(d, r2, r1, rawipOutErrors);
				prevp = diffptr++;
				break;
			}
			/*
			 * there are more "group" types but they aren't
			 * required for the -s and -Ms options
			 */
			}
		} /* 'for' loop 2 ends */
		tempp1 = NULL;
	} /* 'for' loop 1 ends */
	tempp2 = NULL;
	diffptr--;
	diffptr->next_item = NULL;
	return (diffp);

mibdiff_out_of_memory:;
	mib_item_destroy(&diffp);
	return (NULL);
}

/*
 * mib_item_destroy: cleans up a mib_item_t *
 * that was created by calling mib_item_dup or
 * mib_item_diff
 */
static void
mib_item_destroy(mib_item_t **itemp)
{
	int	nitems = 0;
	int	c = 0;
	mib_item_t *tempp;

	if (itemp == NULL || *itemp == NULL)
		return;

	for (tempp = *itemp; tempp != NULL; tempp = tempp->next_item)
		if (tempp->mib_id == 0)
			nitems++;
		else
			return;	/* cannot destroy! */

	if (nitems == 0)
		return;		/* cannot destroy! */

	for (c = nitems - 1; c >= 0; c--) {
		if ((itemp[0][c]).valp != NULL)
			free((itemp[0][c]).valp);
	}
	free(*itemp);

	*itemp = NULL;
}

/* Compare two Octet_ts.  Return B_TRUE if they match, B_FALSE if not. */
static boolean_t
octetstrmatch(const Octet_t *a, const Octet_t *b)
{
	if (a == NULL || b == NULL)
		return (B_FALSE);

	if (a->o_length != b->o_length)
		return (B_FALSE);

	return (memcmp(a->o_bytes, b->o_bytes, a->o_length) == 0);
}

/* If octetstr() changes make an appropriate change to STR_EXPAND */
static char *
octetstr(const Octet_t *op, int code, char *dst, uint_t dstlen)
{
	int	i;
	char	*cp;

	cp = dst;
	if (op) {
		for (i = 0; i < op->o_length; i++) {
			switch (code) {
			case 'd':
				if (cp - dst + 4 > dstlen) {
					*cp = '\0';
					return (dst);
				}
				(void) snprintf(cp, 5, "%d.",
				    0xff & op->o_bytes[i]);
				cp = strchr(cp, '\0');
				break;
			case 'a':
				if (cp - dst + 1 > dstlen) {
					*cp = '\0';
					return (dst);
				}
				*cp++ = op->o_bytes[i];
				break;
			case 'h':
			default:
				if (cp - dst + 3 > dstlen) {
					*cp = '\0';
					return (dst);
				}
				(void) snprintf(cp, 4, "%02x:",
				    0xff & op->o_bytes[i]);
				cp += 3;
				break;
			}
		}
	}
	if (code != 'a' && cp != dst)
		cp--;
	*cp = '\0';
	return (dst);
}

static const char *
mitcp_state(int state, const mib2_transportMLPEntry_t *attr)
{
	static char tcpsbuf[50];
	const char *cp;

	switch (state) {
	case TCPS_CLOSED:
		cp = "CLOSED";
		break;
	case TCPS_IDLE:
		cp = "IDLE";
		break;
	case TCPS_BOUND:
		cp = "BOUND";
		break;
	case TCPS_LISTEN:
		cp = "LISTEN";
		break;
	case TCPS_SYN_SENT:
		cp = "SYN_SENT";
		break;
	case TCPS_SYN_RCVD:
		cp = "SYN_RCVD";
		break;
	case TCPS_ESTABLISHED:
		cp = "ESTABLISHED";
		break;
	case TCPS_CLOSE_WAIT:
		cp = "CLOSE_WAIT";
		break;
	case TCPS_FIN_WAIT_1:
		cp = "FIN_WAIT_1";
		break;
	case TCPS_CLOSING:
		cp = "CLOSING";
		break;
	case TCPS_LAST_ACK:
		cp = "LAST_ACK";
		break;
	case TCPS_FIN_WAIT_2:
		cp = "FIN_WAIT_2";
		break;
	case TCPS_TIME_WAIT:
		cp = "TIME_WAIT";
		break;
	default:
		(void) snprintf(tcpsbuf, sizeof (tcpsbuf),
		    "UnknownState(%d)", state);
		cp = tcpsbuf;
		break;
	}

	if (RSECflag && attr != NULL && attr->tme_flags != 0) {
		if (cp != tcpsbuf) {
			(void) strlcpy(tcpsbuf, cp, sizeof (tcpsbuf));
			cp = tcpsbuf;
		}
		if (attr->tme_flags & MIB2_TMEF_PRIVATE)
			(void) strlcat(tcpsbuf, " P", sizeof (tcpsbuf));
		if (attr->tme_flags & MIB2_TMEF_SHARED)
			(void) strlcat(tcpsbuf, " S", sizeof (tcpsbuf));
	}

	return (cp);
}

static const char *
miudp_state(int state, const mib2_transportMLPEntry_t *attr)
{
	static char udpsbuf[50];
	const char *cp;

	switch (state) {
	case MIB2_UDP_unbound:
		cp = "Unbound";
		break;
	case MIB2_UDP_idle:
		cp = "Idle";
		break;
	case MIB2_UDP_connected:
		cp = "Connected";
		break;
	default:
		(void) snprintf(udpsbuf, sizeof (udpsbuf),
		    "Unknown State(%d)", state);
		cp = udpsbuf;
		break;
	}

	if (RSECflag && attr != NULL && attr->tme_flags != 0) {
		if (cp != udpsbuf) {
			(void) strlcpy(udpsbuf, cp, sizeof (udpsbuf));
			cp = udpsbuf;
		}
		if (attr->tme_flags & MIB2_TMEF_PRIVATE)
			(void) strlcat(udpsbuf, " P", sizeof (udpsbuf));
		if (attr->tme_flags & MIB2_TMEF_SHARED)
			(void) strlcat(udpsbuf, " S", sizeof (udpsbuf));
	}

	return (cp);
}

static int odd;

static void
prval_init(void)
{
	odd = 0;
}

static void
prval(char *str, Counter val)
{
	(void) printf("\t%-20s=%6u", str, val);
	if (odd++ & 1)
		(void) putchar('\n');
}

static void
prval64(char *str, Counter64 val)
{
	(void) printf("\t%-20s=%6llu", str, val);
	if (odd++ & 1)
		(void) putchar('\n');
}

static void
pr_int_val(char *str, int val)
{
	(void) printf("\t%-20s=%6d", str, val);
	if (odd++ & 1)
		(void) putchar('\n');
}

static void
pr_sctp_rtoalgo(char *str, int val)
{
	(void) printf("\t%-20s=", str);
	switch (val) {
		case MIB2_SCTP_RTOALGO_OTHER:
			(void) printf("%6.6s", "other");
			break;

		case MIB2_SCTP_RTOALGO_VANJ:
			(void) printf("%6.6s", "vanj");
			break;

		default:
			(void) printf("%6d", val);
			break;
	}
	if (odd++ & 1)
		(void) putchar('\n');
}

static void
prval_end(void)
{
	if (odd++ & 1)
		(void) putchar('\n');
}

/* Extract constant sizes */
static void
mib_get_constants(mib_item_t *item)
{
	/* 'for' loop 1: */
	for (; item; item = item->next_item) {
		if (item->mib_id != 0)
			continue; /* 'for' loop 1 */

		switch (item->group) {
		case MIB2_IP: {
			mib2_ip_t	*ip = (mib2_ip_t *)item->valp;

			ipAddrEntrySize = ip->ipAddrEntrySize;
			ipRouteEntrySize = ip->ipRouteEntrySize;
			ipNetToMediaEntrySize = ip->ipNetToMediaEntrySize;
			ipMemberEntrySize = ip->ipMemberEntrySize;
			ipGroupSourceEntrySize = ip->ipGroupSourceEntrySize;
			ipRouteAttributeSize = ip->ipRouteAttributeSize;
			transportMLPSize = ip->transportMLPSize;
			ipDestEntrySize = ip->ipDestEntrySize;
			assert(IS_P2ALIGNED(ipAddrEntrySize,
			    sizeof (mib2_ipAddrEntry_t *)));
			assert(IS_P2ALIGNED(ipRouteEntrySize,
			    sizeof (mib2_ipRouteEntry_t *)));
			assert(IS_P2ALIGNED(ipNetToMediaEntrySize,
			    sizeof (mib2_ipNetToMediaEntry_t *)));
			assert(IS_P2ALIGNED(ipMemberEntrySize,
			    sizeof (ip_member_t *)));
			assert(IS_P2ALIGNED(ipGroupSourceEntrySize,
			    sizeof (ip_grpsrc_t *)));
			assert(IS_P2ALIGNED(ipRouteAttributeSize,
			    sizeof (mib2_ipAttributeEntry_t *)));
			assert(IS_P2ALIGNED(transportMLPSize,
			    sizeof (mib2_transportMLPEntry_t *)));
			break;
		}
		case EXPER_DVMRP: {
			struct mrtstat	*mrts = (struct mrtstat *)item->valp;

			vifctlSize = mrts->mrts_vifctlSize;
			mfcctlSize = mrts->mrts_mfcctlSize;
			assert(IS_P2ALIGNED(vifctlSize,
			    sizeof (struct vifclt *)));
			assert(IS_P2ALIGNED(mfcctlSize,
			    sizeof (struct mfcctl *)));
			break;
		}
		case MIB2_IP6: {
			mib2_ipv6IfStatsEntry_t *ip6;
			/* Just use the first entry */

			ip6 = (mib2_ipv6IfStatsEntry_t *)item->valp;
			ipv6IfStatsEntrySize = ip6->ipv6IfStatsEntrySize;
			ipv6AddrEntrySize = ip6->ipv6AddrEntrySize;
			ipv6RouteEntrySize = ip6->ipv6RouteEntrySize;
			ipv6NetToMediaEntrySize = ip6->ipv6NetToMediaEntrySize;
			ipv6MemberEntrySize = ip6->ipv6MemberEntrySize;
			ipv6GroupSourceEntrySize =
			    ip6->ipv6GroupSourceEntrySize;
			assert(IS_P2ALIGNED(ipv6IfStatsEntrySize,
			    sizeof (mib2_ipv6IfStatsEntry_t *)));
			assert(IS_P2ALIGNED(ipv6AddrEntrySize,
			    sizeof (mib2_ipv6AddrEntry_t *)));
			assert(IS_P2ALIGNED(ipv6RouteEntrySize,
			    sizeof (mib2_ipv6RouteEntry_t *)));
			assert(IS_P2ALIGNED(ipv6NetToMediaEntrySize,
			    sizeof (mib2_ipv6NetToMediaEntry_t *)));
			assert(IS_P2ALIGNED(ipv6MemberEntrySize,
			    sizeof (ipv6_member_t *)));
			assert(IS_P2ALIGNED(ipv6GroupSourceEntrySize,
			    sizeof (ipv6_grpsrc_t *)));
			break;
		}
		case MIB2_ICMP6: {
			mib2_ipv6IfIcmpEntry_t *icmp6;
			/* Just use the first entry */

			icmp6 = (mib2_ipv6IfIcmpEntry_t *)item->valp;
			ipv6IfIcmpEntrySize = icmp6->ipv6IfIcmpEntrySize;
			assert(IS_P2ALIGNED(ipv6IfIcmpEntrySize,
			    sizeof (mib2_ipv6IfIcmpEntry_t *)));
			break;
		}
		case MIB2_TCP: {
			mib2_tcp_t	*tcp = (mib2_tcp_t *)item->valp;

			tcpConnEntrySize = tcp->tcpConnTableSize;
			tcp6ConnEntrySize = tcp->tcp6ConnTableSize;
			assert(IS_P2ALIGNED(tcpConnEntrySize,
			    sizeof (mib2_tcpConnEntry_t *)));
			assert(IS_P2ALIGNED(tcp6ConnEntrySize,
			    sizeof (mib2_tcp6ConnEntry_t *)));
			break;
		}
		case MIB2_UDP: {
			mib2_udp_t	*udp = (mib2_udp_t *)item->valp;

			udpEntrySize = udp->udpEntrySize;
			udp6EntrySize = udp->udp6EntrySize;
			assert(IS_P2ALIGNED(udpEntrySize,
			    sizeof (mib2_udpEntry_t *)));
			assert(IS_P2ALIGNED(udp6EntrySize,
			    sizeof (mib2_udp6Entry_t *)));
			break;
		}
		case MIB2_SCTP: {
			mib2_sctp_t	*sctp = (mib2_sctp_t *)item->valp;

			sctpEntrySize = sctp->sctpEntrySize;
			sctpLocalEntrySize = sctp->sctpLocalEntrySize;
			sctpRemoteEntrySize = sctp->sctpRemoteEntrySize;
			break;
		}
		}
	} /* 'for' loop 1 ends */

	if (Xflag) {
		(void) puts("mib_get_constants:");
		(void) printf("\tipv6IfStatsEntrySize %d\n",
		    ipv6IfStatsEntrySize);
		(void) printf("\tipAddrEntrySize %d\n", ipAddrEntrySize);
		(void) printf("\tipRouteEntrySize %d\n", ipRouteEntrySize);
		(void) printf("\tipNetToMediaEntrySize %d\n",
		    ipNetToMediaEntrySize);
		(void) printf("\tipMemberEntrySize %d\n", ipMemberEntrySize);
		(void) printf("\tipRouteAttributeSize %d\n",
		    ipRouteAttributeSize);
		(void) printf("\tvifctlSize %d\n", vifctlSize);
		(void) printf("\tmfcctlSize %d\n", mfcctlSize);

		(void) printf("\tipv6AddrEntrySize %d\n", ipv6AddrEntrySize);
		(void) printf("\tipv6RouteEntrySize %d\n", ipv6RouteEntrySize);
		(void) printf("\tipv6NetToMediaEntrySize %d\n",
		    ipv6NetToMediaEntrySize);
		(void) printf("\tipv6MemberEntrySize %d\n",
		    ipv6MemberEntrySize);
		(void) printf("\tipv6IfIcmpEntrySize %d\n",
		    ipv6IfIcmpEntrySize);
		(void) printf("\tipDestEntrySize %d\n", ipDestEntrySize);
		(void) printf("\ttransportMLPSize %d\n", transportMLPSize);
		(void) printf("\ttcpConnEntrySize %d\n", tcpConnEntrySize);
		(void) printf("\ttcp6ConnEntrySize %d\n", tcp6ConnEntrySize);
		(void) printf("\tudpEntrySize %d\n", udpEntrySize);
		(void) printf("\tudp6EntrySize %d\n", udp6EntrySize);
		(void) printf("\tsctpEntrySize %d\n", sctpEntrySize);
		(void) printf("\tsctpLocalEntrySize %d\n", sctpLocalEntrySize);
		(void) printf("\tsctpRemoteEntrySize %d\n",
		    sctpRemoteEntrySize);
	}
}


/* ----------------------------- STAT_REPORT ------------------------------- */

static void
stat_report(mib_item_t *item)
{
	int	jtemp = 0;
	char	ifname[LIFNAMSIZ + 1];

	/* 'for' loop 1: */
	for (; item; item = item->next_item) {
		if (Xflag) {
			(void) printf("\n--- Entry %d ---\n", ++jtemp);
			(void) printf("Group = %d, mib_id = %d, "
			    "length = %d, valp = 0x%p\n",
			    item->group, item->mib_id,
			    item->length, item->valp);
		}
		if (item->mib_id != 0)
			continue; /* 'for' loop 1 */

		switch (item->group) {
		case MIB2_IP: {
			mib2_ip_t	*ip = (mib2_ip_t *)item->valp;

			if (protocol_selected(IPPROTO_IP) &&
			    family_selected(AF_INET)) {
				(void) fputs(v4compat ? "\nIP" : "\nIPv4",
				    stdout);
				print_ip_stats(ip);
			}
			break;
		}
		case MIB2_ICMP: {
			mib2_icmp_t	*icmp =
			    (mib2_icmp_t *)item->valp;

			if (protocol_selected(IPPROTO_ICMP) &&
			    family_selected(AF_INET)) {
				(void) fputs(v4compat ? "\nICMP" : "\nICMPv4",
				    stdout);
				print_icmp_stats(icmp);
			}
			break;
		}
		case MIB2_IP6: {
			mib2_ipv6IfStatsEntry_t *ip6;
			mib2_ipv6IfStatsEntry_t sum6;

			if (!(protocol_selected(IPPROTO_IPV6)) ||
			    !(family_selected(AF_INET6)))
				break;
			bzero(&sum6, sizeof (sum6));
			/* 'for' loop 2a: */
			for (ip6 = (mib2_ipv6IfStatsEntry_t *)item->valp;
			    (char *)ip6 < (char *)item->valp + item->length;
			    /* LINTED: (note 1) */
			    ip6 = (mib2_ipv6IfStatsEntry_t *)((char *)ip6 +
			    ipv6IfStatsEntrySize)) {
				if (ip6->ipv6IfIndex == 0) {
					/*
					 * The "unknown interface" ip6
					 * mib. Just add to the sum.
					 */
					sum_ip6_stats(ip6, &sum6);
					continue; /* 'for' loop 2a */
				}
				if (Aflag) {
					(void) printf("\nIPv6 for %s\n",
					    ifindex2str(ip6->ipv6IfIndex,
					    ifname));
					print_ip6_stats(ip6);
				}
				sum_ip6_stats(ip6, &sum6);
			} /* 'for' loop 2a ends */
			(void) fputs("\nIPv6", stdout);
			print_ip6_stats(&sum6);
			break;
		}
		case MIB2_ICMP6: {
			mib2_ipv6IfIcmpEntry_t *icmp6;
			mib2_ipv6IfIcmpEntry_t sum6;

			if (!(protocol_selected(IPPROTO_ICMPV6)) ||
			    !(family_selected(AF_INET6)))
				break;
			bzero(&sum6, sizeof (sum6));
			/* 'for' loop 2b: */
			for (icmp6 = (mib2_ipv6IfIcmpEntry_t *)item->valp;
			    (char *)icmp6 < (char *)item->valp + item->length;
			    icmp6 = (void *)((char *)icmp6 +
			    ipv6IfIcmpEntrySize)) {
				if (icmp6->ipv6IfIcmpIfIndex == 0) {
					/*
					 * The "unknown interface" icmp6
					 * mib. Just add to the sum.
					 */
					sum_icmp6_stats(icmp6, &sum6);
					continue; /* 'for' loop 2b: */
				}
				if (Aflag) {
					(void) printf("\nICMPv6 for %s\n",
					    ifindex2str(
					    icmp6->ipv6IfIcmpIfIndex, ifname));
					print_icmp6_stats(icmp6);
				}
				sum_icmp6_stats(icmp6, &sum6);
			} /* 'for' loop 2b ends */
			(void) fputs("\nICMPv6", stdout);
			print_icmp6_stats(&sum6);
			break;
		}
		case MIB2_TCP: {
			mib2_tcp_t	*tcp = (mib2_tcp_t *)item->valp;

			if (protocol_selected(IPPROTO_TCP) &&
			    (family_selected(AF_INET) ||
			    family_selected(AF_INET6))) {
				(void) fputs("\nTCP", stdout);
				print_tcp_stats(tcp);
			}
			break;
		}
		case MIB2_UDP: {
			mib2_udp_t	*udp = (mib2_udp_t *)item->valp;

			if (protocol_selected(IPPROTO_UDP) &&
			    (family_selected(AF_INET) ||
			    family_selected(AF_INET6))) {
				(void) fputs("\nUDP", stdout);
				print_udp_stats(udp);
			}
			break;
		}
		case MIB2_SCTP: {
			mib2_sctp_t	*sctp = (mib2_sctp_t *)item->valp;

			if (protocol_selected(IPPROTO_SCTP) &&
			    (family_selected(AF_INET) ||
			    family_selected(AF_INET6))) {
				(void) fputs("\nSCTP", stdout);
				print_sctp_stats(sctp);
			}
			break;
		}
		case EXPER_RAWIP: {
			mib2_rawip_t	*rawip =
			    (mib2_rawip_t *)item->valp;

			if (protocol_selected(IPPROTO_RAW) &&
			    (family_selected(AF_INET) ||
			    family_selected(AF_INET6))) {
				(void) fputs("\nRAWIP", stdout);
				print_rawip_stats(rawip);
			}
			break;
		}
		case EXPER_IGMP: {
			struct igmpstat	*igps =
			    (struct igmpstat *)item->valp;

			if (protocol_selected(IPPROTO_IGMP) &&
			    (family_selected(AF_INET))) {
				(void) fputs("\nIGMP:\n", stdout);
				print_igmp_stats(igps);
			}
			break;
		}
		}
	} /* 'for' loop 1 ends */
	(void) putchar('\n');
	(void) fflush(stdout);
}

static void
print_ip_stats(mib2_ip_t *ip)
{
	prval_init();
	pr_int_val("ipForwarding",	ip->ipForwarding);
	pr_int_val("ipDefaultTTL",	ip->ipDefaultTTL);
	prval("ipInReceives",		ip->ipInReceives);
	prval("ipInHdrErrors",		ip->ipInHdrErrors);
	prval("ipInAddrErrors",		ip->ipInAddrErrors);
	prval("ipInCksumErrs",		ip->ipInCksumErrs);
	prval("ipForwDatagrams",	ip->ipForwDatagrams);
	prval("ipForwProhibits",	ip->ipForwProhibits);
	prval("ipInUnknownProtos",	ip->ipInUnknownProtos);
	prval("ipInDiscards",		ip->ipInDiscards);
	prval("ipInDelivers",		ip->ipInDelivers);
	prval("ipOutRequests",		ip->ipOutRequests);
	prval("ipOutDiscards",		ip->ipOutDiscards);
	prval("ipOutNoRoutes",		ip->ipOutNoRoutes);
	pr_int_val("ipReasmTimeout",	ip->ipReasmTimeout);
	prval("ipReasmReqds",		ip->ipReasmReqds);
	prval("ipReasmOKs",		ip->ipReasmOKs);
	prval("ipReasmFails",		ip->ipReasmFails);
	prval("ipReasmDuplicates",	ip->ipReasmDuplicates);
	prval("ipReasmPartDups",	ip->ipReasmPartDups);
	prval("ipFragOKs",		ip->ipFragOKs);
	prval("ipFragFails",		ip->ipFragFails);
	prval("ipFragCreates",		ip->ipFragCreates);
	prval("ipRoutingDiscards",	ip->ipRoutingDiscards);

	prval("tcpInErrs",		ip->tcpInErrs);
	prval("udpNoPorts",		ip->udpNoPorts);
	prval("udpInCksumErrs",		ip->udpInCksumErrs);
	prval("udpInOverflows",		ip->udpInOverflows);
	prval("rawipInOverflows",	ip->rawipInOverflows);
	prval("ipsecInSucceeded",	ip->ipsecInSucceeded);
	prval("ipsecInFailed",		ip->ipsecInFailed);
	prval("ipInIPv6",		ip->ipInIPv6);
	prval("ipOutIPv6",		ip->ipOutIPv6);
	prval("ipOutSwitchIPv6",	ip->ipOutSwitchIPv6);
	prval_end();
}

static void
print_icmp_stats(mib2_icmp_t *icmp)
{
	prval_init();
	prval("icmpInMsgs",		icmp->icmpInMsgs);
	prval("icmpInErrors",		icmp->icmpInErrors);
	prval("icmpInCksumErrs",	icmp->icmpInCksumErrs);
	prval("icmpInUnknowns",		icmp->icmpInUnknowns);
	prval("icmpInDestUnreachs",	icmp->icmpInDestUnreachs);
	prval("icmpInTimeExcds",	icmp->icmpInTimeExcds);
	prval("icmpInParmProbs",	icmp->icmpInParmProbs);
	prval("icmpInSrcQuenchs",	icmp->icmpInSrcQuenchs);
	prval("icmpInRedirects",	icmp->icmpInRedirects);
	prval("icmpInBadRedirects",	icmp->icmpInBadRedirects);
	prval("icmpInEchos",		icmp->icmpInEchos);
	prval("icmpInEchoReps",		icmp->icmpInEchoReps);
	prval("icmpInTimestamps",	icmp->icmpInTimestamps);
	prval("icmpInTimestampReps",	icmp->icmpInTimestampReps);
	prval("icmpInAddrMasks",	icmp->icmpInAddrMasks);
	prval("icmpInAddrMaskReps",	icmp->icmpInAddrMaskReps);
	prval("icmpInFragNeeded",	icmp->icmpInFragNeeded);
	prval("icmpOutMsgs",		icmp->icmpOutMsgs);
	prval("icmpOutDrops",		icmp->icmpOutDrops);
	prval("icmpOutErrors",		icmp->icmpOutErrors);
	prval("icmpOutDestUnreachs",	icmp->icmpOutDestUnreachs);
	prval("icmpOutTimeExcds",	icmp->icmpOutTimeExcds);
	prval("icmpOutParmProbs",	icmp->icmpOutParmProbs);
	prval("icmpOutSrcQuenchs",	icmp->icmpOutSrcQuenchs);
	prval("icmpOutRedirects",	icmp->icmpOutRedirects);
	prval("icmpOutEchos",		icmp->icmpOutEchos);
	prval("icmpOutEchoReps",	icmp->icmpOutEchoReps);
	prval("icmpOutTimestamps",	icmp->icmpOutTimestamps);
	prval("icmpOutTimestampReps",	icmp->icmpOutTimestampReps);
	prval("icmpOutAddrMasks",	icmp->icmpOutAddrMasks);
	prval("icmpOutAddrMaskReps",	icmp->icmpOutAddrMaskReps);
	prval("icmpOutFragNeeded",	icmp->icmpOutFragNeeded);
	prval("icmpInOverflows",	icmp->icmpInOverflows);
	prval_end();
}

static void
print_ip6_stats(mib2_ipv6IfStatsEntry_t *ip6)
{
	prval_init();
	prval("ipv6Forwarding",		ip6->ipv6Forwarding);
	prval("ipv6DefaultHopLimit",	ip6->ipv6DefaultHopLimit);

	prval("ipv6InReceives",		ip6->ipv6InReceives);
	prval("ipv6InHdrErrors",	ip6->ipv6InHdrErrors);
	prval("ipv6InTooBigErrors",	ip6->ipv6InTooBigErrors);
	prval("ipv6InNoRoutes",		ip6->ipv6InNoRoutes);
	prval("ipv6InAddrErrors",	ip6->ipv6InAddrErrors);
	prval("ipv6InUnknownProtos",	ip6->ipv6InUnknownProtos);
	prval("ipv6InTruncatedPkts",	ip6->ipv6InTruncatedPkts);
	prval("ipv6InDiscards",		ip6->ipv6InDiscards);
	prval("ipv6InDelivers",		ip6->ipv6InDelivers);
	prval("ipv6OutForwDatagrams",	ip6->ipv6OutForwDatagrams);
	prval("ipv6OutRequests",	ip6->ipv6OutRequests);
	prval("ipv6OutDiscards",	ip6->ipv6OutDiscards);
	prval("ipv6OutNoRoutes",	ip6->ipv6OutNoRoutes);
	prval("ipv6OutFragOKs",		ip6->ipv6OutFragOKs);
	prval("ipv6OutFragFails",	ip6->ipv6OutFragFails);
	prval("ipv6OutFragCreates",	ip6->ipv6OutFragCreates);
	prval("ipv6ReasmReqds",		ip6->ipv6ReasmReqds);
	prval("ipv6ReasmOKs",		ip6->ipv6ReasmOKs);
	prval("ipv6ReasmFails",		ip6->ipv6ReasmFails);
	prval("ipv6InMcastPkts",	ip6->ipv6InMcastPkts);
	prval("ipv6OutMcastPkts",	ip6->ipv6OutMcastPkts);
	prval("ipv6ReasmDuplicates",	ip6->ipv6ReasmDuplicates);
	prval("ipv6ReasmPartDups",	ip6->ipv6ReasmPartDups);
	prval("ipv6ForwProhibits",	ip6->ipv6ForwProhibits);
	prval("udpInCksumErrs",		ip6->udpInCksumErrs);
	prval("udpInOverflows",		ip6->udpInOverflows);
	prval("rawipInOverflows",	ip6->rawipInOverflows);
	prval("ipv6InIPv4",		ip6->ipv6InIPv4);
	prval("ipv6OutIPv4",		ip6->ipv6OutIPv4);
	prval("ipv6OutSwitchIPv4",	ip6->ipv6OutSwitchIPv4);
	prval_end();
}

static void
print_icmp6_stats(mib2_ipv6IfIcmpEntry_t *icmp6)
{
	prval_init();
	prval("icmp6InMsgs",		icmp6->ipv6IfIcmpInMsgs);
	prval("icmp6InErrors",		icmp6->ipv6IfIcmpInErrors);
	prval("icmp6InDestUnreachs",	icmp6->ipv6IfIcmpInDestUnreachs);
	prval("icmp6InAdminProhibs",	icmp6->ipv6IfIcmpInAdminProhibs);
	prval("icmp6InTimeExcds",	icmp6->ipv6IfIcmpInTimeExcds);
	prval("icmp6InParmProblems",	icmp6->ipv6IfIcmpInParmProblems);
	prval("icmp6InPktTooBigs",	icmp6->ipv6IfIcmpInPktTooBigs);
	prval("icmp6InEchos",		icmp6->ipv6IfIcmpInEchos);
	prval("icmp6InEchoReplies",	icmp6->ipv6IfIcmpInEchoReplies);
	prval("icmp6InRouterSols",	icmp6->ipv6IfIcmpInRouterSolicits);
	prval("icmp6InRouterAds",
	    icmp6->ipv6IfIcmpInRouterAdvertisements);
	prval("icmp6InNeighborSols",	icmp6->ipv6IfIcmpInNeighborSolicits);
	prval("icmp6InNeighborAds",
	    icmp6->ipv6IfIcmpInNeighborAdvertisements);
	prval("icmp6InRedirects",	icmp6->ipv6IfIcmpInRedirects);
	prval("icmp6InBadRedirects",	icmp6->ipv6IfIcmpInBadRedirects);
	prval("icmp6InGroupQueries",	icmp6->ipv6IfIcmpInGroupMembQueries);
	prval("icmp6InGroupResps",	icmp6->ipv6IfIcmpInGroupMembResponses);
	prval("icmp6InGroupReds",	icmp6->ipv6IfIcmpInGroupMembReductions);
	prval("icmp6InOverflows",	icmp6->ipv6IfIcmpInOverflows);
	prval_end();
	prval_init();
	prval("icmp6OutMsgs",		icmp6->ipv6IfIcmpOutMsgs);
	prval("icmp6OutErrors",		icmp6->ipv6IfIcmpOutErrors);
	prval("icmp6OutDestUnreachs",	icmp6->ipv6IfIcmpOutDestUnreachs);
	prval("icmp6OutAdminProhibs",	icmp6->ipv6IfIcmpOutAdminProhibs);
	prval("icmp6OutTimeExcds",	icmp6->ipv6IfIcmpOutTimeExcds);
	prval("icmp6OutParmProblems",	icmp6->ipv6IfIcmpOutParmProblems);
	prval("icmp6OutPktTooBigs",	icmp6->ipv6IfIcmpOutPktTooBigs);
	prval("icmp6OutEchos",		icmp6->ipv6IfIcmpOutEchos);
	prval("icmp6OutEchoReplies",	icmp6->ipv6IfIcmpOutEchoReplies);
	prval("icmp6OutRouterSols",	icmp6->ipv6IfIcmpOutRouterSolicits);
	prval("icmp6OutRouterAds",
	    icmp6->ipv6IfIcmpOutRouterAdvertisements);
	prval("icmp6OutNeighborSols",	icmp6->ipv6IfIcmpOutNeighborSolicits);
	prval("icmp6OutNeighborAds",
	    icmp6->ipv6IfIcmpOutNeighborAdvertisements);
	prval("icmp6OutRedirects",	icmp6->ipv6IfIcmpOutRedirects);
	prval("icmp6OutGroupQueries",	icmp6->ipv6IfIcmpOutGroupMembQueries);
	prval("icmp6OutGroupResps",
	    icmp6->ipv6IfIcmpOutGroupMembResponses);
	prval("icmp6OutGroupReds",
	    icmp6->ipv6IfIcmpOutGroupMembReductions);
	prval_end();
}

static void
print_sctp_stats(mib2_sctp_t *sctp)
{
	prval_init();
	pr_sctp_rtoalgo("sctpRtoAlgorithm", sctp->sctpRtoAlgorithm);
	prval("sctpRtoMin",		sctp->sctpRtoMin);
	prval("sctpRtoMax",		sctp->sctpRtoMax);
	prval("sctpRtoInitial",		sctp->sctpRtoInitial);
	pr_int_val("sctpMaxAssocs",	sctp->sctpMaxAssocs);
	prval("sctpValCookieLife",	sctp->sctpValCookieLife);
	prval("sctpMaxInitRetr",	sctp->sctpMaxInitRetr);
	prval("sctpCurrEstab",		sctp->sctpCurrEstab);
	prval("sctpActiveEstab",	sctp->sctpActiveEstab);
	prval("sctpPassiveEstab",	sctp->sctpPassiveEstab);
	prval("sctpAborted",		sctp->sctpAborted);
	prval("sctpShutdowns",		sctp->sctpShutdowns);
	prval("sctpOutOfBlue",		sctp->sctpOutOfBlue);
	prval("sctpChecksumError",	sctp->sctpChecksumError);
	prval64("sctpOutCtrlChunks",	sctp->sctpOutCtrlChunks);
	prval64("sctpOutOrderChunks",	sctp->sctpOutOrderChunks);
	prval64("sctpOutUnorderChunks",	sctp->sctpOutUnorderChunks);
	prval64("sctpRetransChunks",	sctp->sctpRetransChunks);
	prval("sctpOutAck",		sctp->sctpOutAck);
	prval("sctpOutAckDelayed",	sctp->sctpOutAckDelayed);
	prval("sctpOutWinUpdate",	sctp->sctpOutWinUpdate);
	prval("sctpOutFastRetrans",	sctp->sctpOutFastRetrans);
	prval("sctpOutWinProbe",	sctp->sctpOutWinProbe);
	prval64("sctpInCtrlChunks",	sctp->sctpInCtrlChunks);
	prval64("sctpInOrderChunks",	sctp->sctpInOrderChunks);
	prval64("sctpInUnorderChunks",	sctp->sctpInUnorderChunks);
	prval("sctpInAck",		sctp->sctpInAck);
	prval("sctpInDupAck",		sctp->sctpInDupAck);
	prval("sctpInAckUnsent",	sctp->sctpInAckUnsent);
	prval64("sctpFragUsrMsgs",	sctp->sctpFragUsrMsgs);
	prval64("sctpReasmUsrMsgs",	sctp->sctpReasmUsrMsgs);
	prval64("sctpOutSCTPPkts",	sctp->sctpOutSCTPPkts);
	prval64("sctpInSCTPPkts",	sctp->sctpInSCTPPkts);
	prval("sctpInInvalidCookie",	sctp->sctpInInvalidCookie);
	prval("sctpTimRetrans",		sctp->sctpTimRetrans);
	prval("sctpTimRetransDrop",	sctp->sctpTimRetransDrop);
	prval("sctpTimHearBeatProbe",	sctp->sctpTimHeartBeatProbe);
	prval("sctpTimHearBeatDrop",	sctp->sctpTimHeartBeatDrop);
	prval("sctpListenDrop",		sctp->sctpListenDrop);
	prval("sctpInClosed",		sctp->sctpInClosed);
	prval_end();
}

static void
print_tcp_stats(mib2_tcp_t *tcp)
{
	prval_init();
	pr_int_val("tcpRtoAlgorithm",	tcp->tcpRtoAlgorithm);
	pr_int_val("tcpRtoMin",		tcp->tcpRtoMin);
	pr_int_val("tcpRtoMax",		tcp->tcpRtoMax);
	pr_int_val("tcpMaxConn",	tcp->tcpMaxConn);
	prval("tcpActiveOpens",		tcp->tcpActiveOpens);
	prval("tcpPassiveOpens",	tcp->tcpPassiveOpens);
	prval("tcpAttemptFails",	tcp->tcpAttemptFails);
	prval("tcpEstabResets",		tcp->tcpEstabResets);
	prval("tcpCurrEstab",		tcp->tcpCurrEstab);
	prval64("tcpOutSegs",		tcp->tcpHCOutSegs);
	prval("tcpOutDataSegs",		tcp->tcpOutDataSegs);
	prval("tcpOutDataBytes",	tcp->tcpOutDataBytes);
	prval("tcpRetransSegs",		tcp->tcpRetransSegs);
	prval("tcpRetransBytes",	tcp->tcpRetransBytes);
	prval("tcpOutAck",		tcp->tcpOutAck);
	prval("tcpOutAckDelayed",	tcp->tcpOutAckDelayed);
	prval("tcpOutUrg",		tcp->tcpOutUrg);
	prval("tcpOutWinUpdate",	tcp->tcpOutWinUpdate);
	prval("tcpOutWinProbe",		tcp->tcpOutWinProbe);
	prval("tcpOutControl",		tcp->tcpOutControl);
	prval("tcpOutRsts",		tcp->tcpOutRsts);
	prval("tcpOutFastRetrans",	tcp->tcpOutFastRetrans);
	prval64("tcpInSegs",		tcp->tcpHCInSegs);
	prval_end();
	prval("tcpInAckSegs",		tcp->tcpInAckSegs);
	prval("tcpInAckBytes",		tcp->tcpInAckBytes);
	prval("tcpInDupAck",		tcp->tcpInDupAck);
	prval("tcpInAckUnsent",		tcp->tcpInAckUnsent);
	prval("tcpInInorderSegs",	tcp->tcpInDataInorderSegs);
	prval("tcpInInorderBytes",	tcp->tcpInDataInorderBytes);
	prval("tcpInUnorderSegs",	tcp->tcpInDataUnorderSegs);
	prval("tcpInUnorderBytes",	tcp->tcpInDataUnorderBytes);
	prval("tcpInDupSegs",		tcp->tcpInDataDupSegs);
	prval("tcpInDupBytes",		tcp->tcpInDataDupBytes);
	prval("tcpInPartDupSegs",	tcp->tcpInDataPartDupSegs);
	prval("tcpInPartDupBytes",	tcp->tcpInDataPartDupBytes);
	prval("tcpInPastWinSegs",	tcp->tcpInDataPastWinSegs);
	prval("tcpInPastWinBytes",	tcp->tcpInDataPastWinBytes);
	prval("tcpInWinProbe",		tcp->tcpInWinProbe);
	prval("tcpInWinUpdate",		tcp->tcpInWinUpdate);
	prval("tcpInClosed",		tcp->tcpInClosed);
	prval("tcpRttNoUpdate",		tcp->tcpRttNoUpdate);
	prval("tcpRttUpdate",		tcp->tcpRttUpdate);
	prval("tcpTimRetrans",		tcp->tcpTimRetrans);
	prval("tcpTimRetransDrop",	tcp->tcpTimRetransDrop);
	prval("tcpTimKeepalive",	tcp->tcpTimKeepalive);
	prval("tcpTimKeepaliveProbe",	tcp->tcpTimKeepaliveProbe);
	prval("tcpTimKeepaliveDrop",	tcp->tcpTimKeepaliveDrop);
	prval("tcpListenDrop",		tcp->tcpListenDrop);
	prval("tcpListenDropQ0",	tcp->tcpListenDropQ0);
	prval("tcpHalfOpenDrop",	tcp->tcpHalfOpenDrop);
	prval("tcpOutSackRetrans",	tcp->tcpOutSackRetransSegs);
	prval_end();

}

static void
print_udp_stats(mib2_udp_t *udp)
{
	prval_init();
	prval64("udpInDatagrams",	udp->udpHCInDatagrams);
	prval("udpInErrors",		udp->udpInErrors);
	prval64("udpOutDatagrams",	udp->udpHCOutDatagrams);
	prval("udpOutErrors",		udp->udpOutErrors);
	prval_end();
}

static void
print_rawip_stats(mib2_rawip_t *rawip)
{
	prval_init();
	prval("rawipInDatagrams",	rawip->rawipInDatagrams);
	prval("rawipInErrors",		rawip->rawipInErrors);
	prval("rawipInCksumErrs",	rawip->rawipInCksumErrs);
	prval("rawipOutDatagrams",	rawip->rawipOutDatagrams);
	prval("rawipOutErrors",		rawip->rawipOutErrors);
	prval_end();
}

void
print_igmp_stats(struct igmpstat *igps)
{
	(void) printf(" %10u message%s received\n",
	    igps->igps_rcv_total, PLURAL(igps->igps_rcv_total));
	(void) printf(" %10u message%s received with too few bytes\n",
	    igps->igps_rcv_tooshort, PLURAL(igps->igps_rcv_tooshort));
	(void) printf(" %10u message%s received with bad checksum\n",
	    igps->igps_rcv_badsum, PLURAL(igps->igps_rcv_badsum));
	(void) printf(" %10u membership quer%s received\n",
	    igps->igps_rcv_queries, PLURALY(igps->igps_rcv_queries));
	(void) printf(" %10u membership quer%s received with invalid "
	    "field(s)\n",
	    igps->igps_rcv_badqueries, PLURALY(igps->igps_rcv_badqueries));
	(void) printf(" %10u membership report%s received\n",
	    igps->igps_rcv_reports, PLURAL(igps->igps_rcv_reports));
	(void) printf(" %10u membership report%s received with invalid "
	    "field(s)\n",
	    igps->igps_rcv_badreports, PLURAL(igps->igps_rcv_badreports));
	(void) printf(" %10u membership report%s received for groups to "
	    "which we belong\n",
	    igps->igps_rcv_ourreports, PLURAL(igps->igps_rcv_ourreports));
	(void) printf(" %10u membership report%s sent\n",
	    igps->igps_snd_reports, PLURAL(igps->igps_snd_reports));
}

static void
print_mrt_stats(struct mrtstat *mrts)
{
	(void) puts("DVMRP multicast routing:");
	(void) printf(" %10u hit%s - kernel forwarding cache hits\n",
	    mrts->mrts_mfc_hits, PLURAL(mrts->mrts_mfc_hits));
	(void) printf(" %10u miss%s - kernel forwarding cache misses\n",
	    mrts->mrts_mfc_misses, PLURALES(mrts->mrts_mfc_misses));
	(void) printf(" %10u packet%s potentially forwarded\n",
	    mrts->mrts_fwd_in, PLURAL(mrts->mrts_fwd_in));
	(void) printf(" %10u packet%s actually sent out\n",
	    mrts->mrts_fwd_out, PLURAL(mrts->mrts_fwd_out));
	(void) printf(" %10u upcall%s - upcalls made to mrouted\n",
	    mrts->mrts_upcalls, PLURAL(mrts->mrts_upcalls));
	(void) printf(" %10u packet%s not sent out due to lack of resources\n",
	    mrts->mrts_fwd_drop, PLURAL(mrts->mrts_fwd_drop));
	(void) printf(" %10u datagram%s with malformed tunnel options\n",
	    mrts->mrts_bad_tunnel, PLURAL(mrts->mrts_bad_tunnel));
	(void) printf(" %10u datagram%s with no room for tunnel options\n",
	    mrts->mrts_cant_tunnel, PLURAL(mrts->mrts_cant_tunnel));
	(void) printf(" %10u datagram%s arrived on wrong interface\n",
	    mrts->mrts_wrong_if, PLURAL(mrts->mrts_wrong_if));
	(void) printf(" %10u datagram%s dropped due to upcall Q overflow\n",
	    mrts->mrts_upq_ovflw, PLURAL(mrts->mrts_upq_ovflw));
	(void) printf(" %10u datagram%s cleaned up by the cache\n",
	    mrts->mrts_cache_cleanups, PLURAL(mrts->mrts_cache_cleanups));
	(void) printf(" %10u datagram%s dropped selectively by ratelimiter\n",
	    mrts->mrts_drop_sel, PLURAL(mrts->mrts_drop_sel));
	(void) printf(" %10u datagram%s dropped - bucket Q overflow\n",
	    mrts->mrts_q_overflow, PLURAL(mrts->mrts_q_overflow));
	(void) printf(" %10u datagram%s dropped - larger than bkt size\n",
	    mrts->mrts_pkt2large, PLURAL(mrts->mrts_pkt2large));
	(void) printf("\nPIM multicast routing:\n");
	(void) printf(" %10u datagram%s dropped - bad version number\n",
	    mrts->mrts_pim_badversion, PLURAL(mrts->mrts_pim_badversion));
	(void) printf(" %10u datagram%s dropped - bad checksum\n",
	    mrts->mrts_pim_rcv_badcsum, PLURAL(mrts->mrts_pim_rcv_badcsum));
	(void) printf(" %10u datagram%s dropped - bad register packets\n",
	    mrts->mrts_pim_badregisters, PLURAL(mrts->mrts_pim_badregisters));
	(void) printf(
	    " %10u datagram%s potentially forwarded - register packets\n",
	    mrts->mrts_pim_regforwards, PLURAL(mrts->mrts_pim_regforwards));
	(void) printf(" %10u datagram%s dropped - register send drops\n",
	    mrts->mrts_pim_regsend_drops, PLURAL(mrts->mrts_pim_regsend_drops));
	(void) printf(" %10u datagram%s dropped - packet malformed\n",
	    mrts->mrts_pim_malformed, PLURAL(mrts->mrts_pim_malformed));
	(void) printf(" %10u datagram%s dropped - no memory to forward\n",
	    mrts->mrts_pim_nomemory, PLURAL(mrts->mrts_pim_nomemory));
}

static void
sum_ip6_stats(mib2_ipv6IfStatsEntry_t *ip6, mib2_ipv6IfStatsEntry_t *sum6)
{
	/* First few are not additive */
	sum6->ipv6Forwarding = ip6->ipv6Forwarding;
	sum6->ipv6DefaultHopLimit = ip6->ipv6DefaultHopLimit;

	sum6->ipv6InReceives += ip6->ipv6InReceives;
	sum6->ipv6InHdrErrors += ip6->ipv6InHdrErrors;
	sum6->ipv6InTooBigErrors += ip6->ipv6InTooBigErrors;
	sum6->ipv6InNoRoutes += ip6->ipv6InNoRoutes;
	sum6->ipv6InAddrErrors += ip6->ipv6InAddrErrors;
	sum6->ipv6InUnknownProtos += ip6->ipv6InUnknownProtos;
	sum6->ipv6InTruncatedPkts += ip6->ipv6InTruncatedPkts;
	sum6->ipv6InDiscards += ip6->ipv6InDiscards;
	sum6->ipv6InDelivers += ip6->ipv6InDelivers;
	sum6->ipv6OutForwDatagrams += ip6->ipv6OutForwDatagrams;
	sum6->ipv6OutRequests += ip6->ipv6OutRequests;
	sum6->ipv6OutDiscards += ip6->ipv6OutDiscards;
	sum6->ipv6OutFragOKs += ip6->ipv6OutFragOKs;
	sum6->ipv6OutFragFails += ip6->ipv6OutFragFails;
	sum6->ipv6OutFragCreates += ip6->ipv6OutFragCreates;
	sum6->ipv6ReasmReqds += ip6->ipv6ReasmReqds;
	sum6->ipv6ReasmOKs += ip6->ipv6ReasmOKs;
	sum6->ipv6ReasmFails += ip6->ipv6ReasmFails;
	sum6->ipv6InMcastPkts += ip6->ipv6InMcastPkts;
	sum6->ipv6OutMcastPkts += ip6->ipv6OutMcastPkts;
	sum6->ipv6OutNoRoutes += ip6->ipv6OutNoRoutes;
	sum6->ipv6ReasmDuplicates += ip6->ipv6ReasmDuplicates;
	sum6->ipv6ReasmPartDups += ip6->ipv6ReasmPartDups;
	sum6->ipv6ForwProhibits += ip6->ipv6ForwProhibits;
	sum6->udpInCksumErrs += ip6->udpInCksumErrs;
	sum6->udpInOverflows += ip6->udpInOverflows;
	sum6->rawipInOverflows += ip6->rawipInOverflows;
}

static void
sum_icmp6_stats(mib2_ipv6IfIcmpEntry_t *icmp6, mib2_ipv6IfIcmpEntry_t *sum6)
{
	sum6->ipv6IfIcmpInMsgs += icmp6->ipv6IfIcmpInMsgs;
	sum6->ipv6IfIcmpInErrors += icmp6->ipv6IfIcmpInErrors;
	sum6->ipv6IfIcmpInDestUnreachs += icmp6->ipv6IfIcmpInDestUnreachs;
	sum6->ipv6IfIcmpInAdminProhibs += icmp6->ipv6IfIcmpInAdminProhibs;
	sum6->ipv6IfIcmpInTimeExcds += icmp6->ipv6IfIcmpInTimeExcds;
	sum6->ipv6IfIcmpInParmProblems += icmp6->ipv6IfIcmpInParmProblems;
	sum6->ipv6IfIcmpInPktTooBigs += icmp6->ipv6IfIcmpInPktTooBigs;
	sum6->ipv6IfIcmpInEchos += icmp6->ipv6IfIcmpInEchos;
	sum6->ipv6IfIcmpInEchoReplies += icmp6->ipv6IfIcmpInEchoReplies;
	sum6->ipv6IfIcmpInRouterSolicits += icmp6->ipv6IfIcmpInRouterSolicits;
	sum6->ipv6IfIcmpInRouterAdvertisements +=
	    icmp6->ipv6IfIcmpInRouterAdvertisements;
	sum6->ipv6IfIcmpInNeighborSolicits +=
	    icmp6->ipv6IfIcmpInNeighborSolicits;
	sum6->ipv6IfIcmpInNeighborAdvertisements +=
	    icmp6->ipv6IfIcmpInNeighborAdvertisements;
	sum6->ipv6IfIcmpInRedirects += icmp6->ipv6IfIcmpInRedirects;
	sum6->ipv6IfIcmpInGroupMembQueries +=
	    icmp6->ipv6IfIcmpInGroupMembQueries;
	sum6->ipv6IfIcmpInGroupMembResponses +=
	    icmp6->ipv6IfIcmpInGroupMembResponses;
	sum6->ipv6IfIcmpInGroupMembReductions +=
	    icmp6->ipv6IfIcmpInGroupMembReductions;
	sum6->ipv6IfIcmpOutMsgs += icmp6->ipv6IfIcmpOutMsgs;
	sum6->ipv6IfIcmpOutErrors += icmp6->ipv6IfIcmpOutErrors;
	sum6->ipv6IfIcmpOutDestUnreachs += icmp6->ipv6IfIcmpOutDestUnreachs;
	sum6->ipv6IfIcmpOutAdminProhibs += icmp6->ipv6IfIcmpOutAdminProhibs;
	sum6->ipv6IfIcmpOutTimeExcds += icmp6->ipv6IfIcmpOutTimeExcds;
	sum6->ipv6IfIcmpOutParmProblems += icmp6->ipv6IfIcmpOutParmProblems;
	sum6->ipv6IfIcmpOutPktTooBigs += icmp6->ipv6IfIcmpOutPktTooBigs;
	sum6->ipv6IfIcmpOutEchos += icmp6->ipv6IfIcmpOutEchos;
	sum6->ipv6IfIcmpOutEchoReplies += icmp6->ipv6IfIcmpOutEchoReplies;
	sum6->ipv6IfIcmpOutRouterSolicits +=
	    icmp6->ipv6IfIcmpOutRouterSolicits;
	sum6->ipv6IfIcmpOutRouterAdvertisements +=
	    icmp6->ipv6IfIcmpOutRouterAdvertisements;
	sum6->ipv6IfIcmpOutNeighborSolicits +=
	    icmp6->ipv6IfIcmpOutNeighborSolicits;
	sum6->ipv6IfIcmpOutNeighborAdvertisements +=
	    icmp6->ipv6IfIcmpOutNeighborAdvertisements;
	sum6->ipv6IfIcmpOutRedirects += icmp6->ipv6IfIcmpOutRedirects;
	sum6->ipv6IfIcmpOutGroupMembQueries +=
	    icmp6->ipv6IfIcmpOutGroupMembQueries;
	sum6->ipv6IfIcmpOutGroupMembResponses +=
	    icmp6->ipv6IfIcmpOutGroupMembResponses;
	sum6->ipv6IfIcmpOutGroupMembReductions +=
	    icmp6->ipv6IfIcmpOutGroupMembReductions;
	sum6->ipv6IfIcmpInOverflows += icmp6->ipv6IfIcmpInOverflows;
}

/* ----------------------------- MRT_STAT_REPORT --------------------------- */

static void
mrt_stat_report(mib_item_t *curritem)
{
	int	jtemp = 0;
	mib_item_t *tempitem;

	if (!(family_selected(AF_INET)))
		return;

	(void) putchar('\n');
	/* 'for' loop 1: */
	for (tempitem = curritem;
	    tempitem;
	    tempitem = tempitem->next_item) {
		if (Xflag) {
			(void) printf("\n--- Entry %d ---\n", ++jtemp);
			(void) printf("Group = %d, mib_id = %d, "
			    "length = %d, valp = 0x%p\n",
			    tempitem->group, tempitem->mib_id,
			    tempitem->length, tempitem->valp);
		}

		if (tempitem->mib_id == 0) {
			switch (tempitem->group) {
			case EXPER_DVMRP: {
				struct mrtstat	*mrts;
				mrts = (struct mrtstat *)tempitem->valp;

				if (!(family_selected(AF_INET)))
					continue; /* 'for' loop 1 */

				print_mrt_stats(mrts);
				break;
			}
			}
		}
	} /* 'for' loop 1 ends */
	(void) putchar('\n');
	(void) fflush(stdout);
}

/*
 * if_stat_total() - Computes totals for interface statistics
 *                   and returns result by updating sumstats.
 */
static void
if_stat_total(struct ifstat *oldstats, struct ifstat *newstats,
    struct ifstat *sumstats)
{
	sumstats->ipackets += newstats->ipackets - oldstats->ipackets;
	sumstats->opackets += newstats->opackets - oldstats->opackets;
	sumstats->ierrors += newstats->ierrors - oldstats->ierrors;
	sumstats->oerrors += newstats->oerrors - oldstats->oerrors;
	sumstats->collisions += newstats->collisions - oldstats->collisions;
}

/* --------------------- IF_REPORT (netstat -i)  -------------------------- */

static struct	ifstat	zerostat = {
	0LL, 0LL, 0LL, 0LL, 0LL
};

static void
if_report(mib_item_t *item, char *matchname,
    int Iflag_only, boolean_t once_only)
{
	static boolean_t	reentry = B_FALSE;
	boolean_t		alreadydone = B_FALSE;
	int			jtemp = 0;
	uint32_t		ifindex_v4 = 0;
	uint32_t		ifindex_v6 = 0;
	boolean_t		first_header = B_TRUE;

	/* 'for' loop 1: */
	for (; item; item = item->next_item) {
		if (Xflag) {
			(void) printf("\n--- Entry %d ---\n", ++jtemp);
			(void) printf("Group = %d, mib_id = %d, "
			    "length = %d, valp = 0x%p\n",
			    item->group, item->mib_id, item->length,
			    item->valp);
		}

		switch (item->group) {
		case MIB2_IP:
		if (item->mib_id != MIB2_IP_ADDR ||
		    !family_selected(AF_INET))
			continue; /* 'for' loop 1 */
		{
			static struct ifstat	old = {0L, 0L, 0L, 0L, 0L};
			static struct ifstat	new = {0L, 0L, 0L, 0L, 0L};
			struct ifstat		sum;
			struct iflist		*newlist = NULL;
			static struct iflist	*oldlist = NULL;
			kstat_t	 *ksp;

			if (once_only) {
				char    ifname[LIFNAMSIZ + 1];
				char    logintname[LIFNAMSIZ + 1];
				mib2_ipAddrEntry_t *ap;
				struct ifstat	stat = {0L, 0L, 0L, 0L, 0L};
				boolean_t	first = B_TRUE;
				uint32_t	new_ifindex;

				if (Xflag)
					(void) printf("if_report: %d items\n",
					    (item->length)
					    / sizeof (mib2_ipAddrEntry_t));

				/* 'for' loop 2a: */
				for (ap = (mib2_ipAddrEntry_t *)item->valp;
				    (char *)ap < (char *)item->valp
				    + item->length;
				    ap++) {
					(void) octetstr(&ap->ipAdEntIfIndex,
					    'a', logintname,
					    sizeof (logintname));
					(void) strcpy(ifname, logintname);
					(void) strtok(ifname, ":");
					if (matchname != NULL &&
					    strcmp(matchname, ifname) != 0 &&
					    strcmp(matchname, logintname) != 0)
						continue; /* 'for' loop 2a */
					new_ifindex =
					    if_nametoindex(logintname);
					/*
					 * First lookup the "link" kstats in
					 * case the link is renamed. Then
					 * fallback to the legacy kstats for
					 * those non-GLDv3 links.
					 */
					if (new_ifindex != ifindex_v4 &&
					    (((ksp = kstat_lookup(kc, "link", 0,
					    ifname)) != NULL) ||
					    ((ksp = kstat_lookup(kc, NULL, -1,
					    ifname)) != NULL))) {
						(void) safe_kstat_read(kc, ksp,
						    NULL);
						stat.ipackets =
						    kstat_named_value(ksp,
						    "ipackets");
						stat.ierrors =
						    kstat_named_value(ksp,
						    "ierrors");
						stat.opackets =
						    kstat_named_value(ksp,
						    "opackets");
						stat.oerrors =
						    kstat_named_value(ksp,
						    "oerrors");
						stat.collisions =
						    kstat_named_value(ksp,
						    "collisions");
						if (first) {
							if (!first_header)
							(void) putchar('\n');
							first_header = B_FALSE;
						(void) printf(
						    "%-5.5s %-5.5s%-13.13s "
						    "%-14.14s %-6.6s %-5.5s "
						    "%-6.6s %-5.5s %-6.6s "
						    "%-6.6s\n",
						    "Name", "Mtu", "Net/Dest",
						    "Address", "Ipkts",
						    "Ierrs", "Opkts", "Oerrs",
						    "Collis", "Queue");

						first = B_FALSE;
						}
						if_report_ip4(ap, ifname,
						    logintname, &stat, B_TRUE);
						ifindex_v4 = new_ifindex;
					} else {
						if_report_ip4(ap, ifname,
						    logintname, &stat, B_FALSE);
					}
				} /* 'for' loop 2a ends */
			} else if (!alreadydone) {
				char    ifname[LIFNAMSIZ + 1];
				char    buf[LIFNAMSIZ + 1];
				mib2_ipAddrEntry_t *ap;
				struct ifstat   t;
				struct iflist	*tlp = NULL;
				struct iflist	**nextnew = &newlist;
				struct iflist	*walkold;
				struct iflist	*cleanlist;
				boolean_t	found_if = B_FALSE;

				alreadydone = B_TRUE; /* ignore other case */

				/*
				 * Check if there is anything to do.
				 */
				if (item->length <
				    sizeof (mib2_ipAddrEntry_t)) {
					fail(0, "No compatible interfaces");
				}

				/*
				 * 'for' loop 2b: find the "right" entry:
				 * If an interface name to match has been
				 * supplied then try and find it, otherwise
				 * match the first non-loopback interface found.
				 * Use lo0 if all else fails.
				 */
				for (ap = (mib2_ipAddrEntry_t *)item->valp;
				    (char *)ap < (char *)item->valp
				    + item->length;
				    ap++) {
					(void) octetstr(&ap->ipAdEntIfIndex,
					    'a', ifname, sizeof (ifname));
					(void) strtok(ifname, ":");

					if (matchname) {
						if (strcmp(matchname,
						    ifname) == 0) {
							/* 'for' loop 2b */
							found_if = B_TRUE;
							break;
						}
					} else if (strcmp(ifname, "lo0") != 0)
						break; /* 'for' loop 2b */
				} /* 'for' loop 2b ends */

				if (matchname == NULL) {
					matchname = ifname;
				} else {
					if (!found_if)
						fail(0, "-I: %s no such "
						    "interface.", matchname);
				}

				if (Iflag_only == 0 || !reentry) {
					(void) printf("    input   %-6.6s    "
					    "output	",
					    matchname);
					(void) printf("   input  (Total)    "
					"output\n");
					(void) printf("%-7.7s %-5.5s %-7.7s "
					    "%-5.5s %-6.6s ",
					    "packets", "errs", "packets",
					    "errs", "colls");
					(void) printf("%-7.7s %-5.5s %-7.7s "
					    "%-5.5s %-6.6s\n",
					    "packets", "errs", "packets",
					    "errs", "colls");
				}

				sum = zerostat;

				/* 'for' loop 2c: */
				for (ap = (mib2_ipAddrEntry_t *)item->valp;
				    (char *)ap < (char *)item->valp
				    + item->length;
				    ap++) {
					(void) octetstr(&ap->ipAdEntIfIndex,
					    'a', buf, sizeof (buf));
					(void) strtok(buf, ":");

					/*
					 * We have reduced the IP interface
					 * name, which could have been a
					 * logical, down to a name suitable
					 * for use with kstats.
					 * We treat this name as unique and
					 * only collate statistics for it once
					 * per pass. This is to avoid falsely
					 * amplifying these statistics by the
					 * the number of logical instances.
					 */
					if ((tlp != NULL) &&
					    ((strcmp(buf, tlp->ifname) == 0))) {
						continue;
					}

					/*
					 * First lookup the "link" kstats in
					 * case the link is renamed. Then
					 * fallback to the legacy kstats for
					 * those non-GLDv3 links.
					 */
					if (((ksp = kstat_lookup(kc, "link",
					    0, buf)) != NULL ||
					    (ksp = kstat_lookup(kc, NULL, -1,
					    buf)) != NULL) && (ksp->ks_type ==
					    KSTAT_TYPE_NAMED)) {
						(void) safe_kstat_read(kc, ksp,
						    NULL);
					}

					t.ipackets = kstat_named_value(ksp,
					    "ipackets");
					t.ierrors = kstat_named_value(ksp,
					    "ierrors");
					t.opackets = kstat_named_value(ksp,
					    "opackets");
					t.oerrors = kstat_named_value(ksp,
					    "oerrors");
					t.collisions = kstat_named_value(ksp,
					    "collisions");

					if (strcmp(buf, matchname) == 0)
						new = t;

					/* Build the interface list */

					tlp = malloc(sizeof (struct iflist));
					(void) strlcpy(tlp->ifname, buf,
					    sizeof (tlp->ifname));
					tlp->tot = t;
					*nextnew = tlp;
					nextnew = &tlp->next_if;

					/*
					 * First time through.
					 * Just add up the interface stats.
					 */

					if (oldlist == NULL) {
						if_stat_total(&zerostat,
						    &t, &sum);
						continue;
					}

					/*
					 * Walk old list for the interface.
					 *
					 * If found, add difference to total.
					 *
					 * If not, an interface has been plumbed
					 * up.  In this case, we will simply
					 * ignore the new interface until the
					 * next interval; as there's no easy way
					 * to acquire statistics between time
					 * of the plumb and the next interval
					 * boundary.  This results in inaccurate
					 * total values for current interval.
					 *
					 * Note the case when an interface is
					 * unplumbed; as similar problems exist.
					 * The unplumbed interface is not in the
					 * current list, and there's no easy way
					 * to account for the statistics between
					 * the previous interval and time of the
					 * unplumb.  Therefore, we (in a sense)
					 * ignore the removed interface by only
					 * involving "current" interfaces when
					 * computing the total statistics.
					 * Unfortunately, this also results in
					 * inaccurate values for interval total.
					 */

					for (walkold = oldlist;
					    walkold != NULL;
					    walkold = walkold->next_if) {
						if (strcmp(walkold->ifname,
						    buf) == 0) {
							if_stat_total(
							    &walkold->tot,
							    &t, &sum);
							break;
						}
					}

				} /* 'for' loop 2c ends */

				*nextnew = NULL;

				(void) printf("%-7llu %-5llu %-7llu "
				    "%-5llu %-6llu ",
				    new.ipackets - old.ipackets,
				    new.ierrors - old.ierrors,
				    new.opackets - old.opackets,
				    new.oerrors - old.oerrors,
				    new.collisions - old.collisions);

				(void) printf("%-7llu %-5llu %-7llu "
				    "%-5llu %-6llu\n", sum.ipackets,
				    sum.ierrors, sum.opackets,
				    sum.oerrors, sum.collisions);

				/*
				 * Tidy things up once finished.
				 */

				old = new;
				cleanlist = oldlist;
				oldlist = newlist;
				while (cleanlist != NULL) {
					tlp = cleanlist->next_if;
					free(cleanlist);
					cleanlist = tlp;
				}
			}
			break;
		}
		case MIB2_IP6:
		if (item->mib_id != MIB2_IP6_ADDR ||
		    !family_selected(AF_INET6))
			continue; /* 'for' loop 1 */
		{
			static struct ifstat	old6 = {0L, 0L, 0L, 0L, 0L};
			static struct ifstat	new6 = {0L, 0L, 0L, 0L, 0L};
			struct ifstat		sum6;
			struct iflist		*newlist6 = NULL;
			static struct iflist	*oldlist6 = NULL;
			kstat_t	 *ksp;

			if (once_only) {
				char    ifname[LIFNAMSIZ + 1];
				char    logintname[LIFNAMSIZ + 1];
				mib2_ipv6AddrEntry_t *ap6;
				struct ifstat	stat = {0L, 0L, 0L, 0L, 0L};
				boolean_t	first = B_TRUE;
				uint32_t	new_ifindex;

				if (Xflag)
					(void) printf("if_report: %d items\n",
					    (item->length)
					    / sizeof (mib2_ipv6AddrEntry_t));
				/* 'for' loop 2d: */
				for (ap6 = (mib2_ipv6AddrEntry_t *)item->valp;
				    (char *)ap6 < (char *)item->valp
				    + item->length;
				    ap6++) {
					(void) octetstr(&ap6->ipv6AddrIfIndex,
					    'a', logintname,
					    sizeof (logintname));
					(void) strcpy(ifname, logintname);
					(void) strtok(ifname, ":");
					if (matchname != NULL &&
					    strcmp(matchname, ifname) != 0 &&
					    strcmp(matchname, logintname) != 0)
						continue; /* 'for' loop 2d */
					new_ifindex =
					    if_nametoindex(logintname);

					/*
					 * First lookup the "link" kstats in
					 * case the link is renamed. Then
					 * fallback to the legacy kstats for
					 * those non-GLDv3 links.
					 */
					if (new_ifindex != ifindex_v6 &&
					    ((ksp = kstat_lookup(kc, "link", 0,
					    ifname)) != NULL ||
					    (ksp = kstat_lookup(kc, NULL, -1,
					    ifname)) != NULL)) {
						(void) safe_kstat_read(kc, ksp,
						    NULL);
						stat.ipackets =
						    kstat_named_value(ksp,
						    "ipackets");
						stat.ierrors =
						    kstat_named_value(ksp,
						    "ierrors");
						stat.opackets =
						    kstat_named_value(ksp,
						    "opackets");
						stat.oerrors =
						    kstat_named_value(ksp,
						    "oerrors");
						stat.collisions =
						    kstat_named_value(ksp,
						    "collisions");
						if (first) {
							if (!first_header)
							(void) putchar('\n');
							first_header = B_FALSE;
							(void) printf(
							    "%-5.5s %-5.5s%"
							    "-27.27s %-27.27s "
							    "%-6.6s %-5.5s "
							    "%-6.6s %-5.5s "
							    "%-6.6s\n",
							    "Name", "Mtu",
							    "Net/Dest",
							    "Address", "Ipkts",
							    "Ierrs", "Opkts",
							    "Oerrs", "Collis");
							first = B_FALSE;
						}
						if_report_ip6(ap6, ifname,
						    logintname, &stat, B_TRUE);
						ifindex_v6 = new_ifindex;
					} else {
						if_report_ip6(ap6, ifname,
						    logintname, &stat, B_FALSE);
					}
				} /* 'for' loop 2d ends */
			} else if (!alreadydone) {
				char    ifname[LIFNAMSIZ + 1];
				char    buf[IFNAMSIZ + 1];
				mib2_ipv6AddrEntry_t *ap6;
				struct ifstat   t;
				struct iflist	*tlp = NULL;
				struct iflist	**nextnew = &newlist6;
				struct iflist	*walkold;
				struct iflist	*cleanlist;
				boolean_t	found_if = B_FALSE;

				alreadydone = B_TRUE; /* ignore other case */

				/*
				 * Check if there is anything to do.
				 */
				if (item->length <
				    sizeof (mib2_ipv6AddrEntry_t)) {
					fail(0, "No compatible interfaces");
				}

				/*
				 * 'for' loop 2e: find the "right" entry:
				 * If an interface name to match has been
				 * supplied then try and find it, otherwise
				 * match the first non-loopback interface found.
				 * Use lo0 if all else fails.
				 */
				for (ap6 = (mib2_ipv6AddrEntry_t *)item->valp;
				    (char *)ap6 < (char *)item->valp
				    + item->length;
				    ap6++) {
					(void) octetstr(&ap6->ipv6AddrIfIndex,
					    'a', ifname, sizeof (ifname));
					(void) strtok(ifname, ":");

					if (matchname) {
						if (strcmp(matchname,
						    ifname) == 0) {
							/* 'for' loop 2e */
							found_if = B_TRUE;
							break;
						}
					} else if (strcmp(ifname, "lo0") != 0)
						break; /* 'for' loop 2e */
				} /* 'for' loop 2e ends */

				if (matchname == NULL) {
					matchname = ifname;
				} else {
					if (!found_if)
						fail(0, "-I: %s no such "
						    "interface.", matchname);
				}

				if (Iflag_only == 0 || !reentry) {
					(void) printf(
					    "    input   %-6.6s"
					    "    output	",
					    matchname);
					(void) printf("   input  (Total)"
					    "    output\n");
					(void) printf("%-7.7s %-5.5s %-7.7s "
					    "%-5.5s %-6.6s ",
					    "packets", "errs", "packets",
					    "errs", "colls");
					(void) printf("%-7.7s %-5.5s %-7.7s "
					    "%-5.5s %-6.6s\n",
					    "packets", "errs", "packets",
					    "errs", "colls");
				}

				sum6 = zerostat;

				/* 'for' loop 2f: */
				for (ap6 = (mib2_ipv6AddrEntry_t *)item->valp;
				    (char *)ap6 < (char *)item->valp
				    + item->length;
				    ap6++) {
					(void) octetstr(&ap6->ipv6AddrIfIndex,
					    'a', buf, sizeof (buf));
					(void) strtok(buf, ":");

					/*
					 * We have reduced the IP interface
					 * name, which could have been a
					 * logical, down to a name suitable
					 * for use with kstats.
					 * We treat this name as unique and
					 * only collate statistics for it once
					 * per pass. This is to avoid falsely
					 * amplifying these statistics by the
					 * the number of logical instances.
					 */

					if ((tlp != NULL) &&
					    ((strcmp(buf, tlp->ifname) == 0))) {
						continue;
					}

					/*
					 * First lookup the "link" kstats in
					 * case the link is renamed. Then
					 * fallback to the legacy kstats for
					 * those non-GLDv3 links.
					 */
					if (((ksp = kstat_lookup(kc, "link",
					    0, buf)) != NULL ||
					    (ksp = kstat_lookup(kc, NULL, -1,
					    buf)) != NULL) && (ksp->ks_type ==
					    KSTAT_TYPE_NAMED)) {
						(void) safe_kstat_read(kc,
						    ksp, NULL);
					}

					t.ipackets = kstat_named_value(ksp,
					    "ipackets");
					t.ierrors = kstat_named_value(ksp,
					    "ierrors");
					t.opackets = kstat_named_value(ksp,
					    "opackets");
					t.oerrors = kstat_named_value(ksp,
					    "oerrors");
					t.collisions = kstat_named_value(ksp,
					    "collisions");

					if (strcmp(buf, matchname) == 0)
						new6 = t;

					/* Build the interface list */

					tlp = malloc(sizeof (struct iflist));
					(void) strlcpy(tlp->ifname, buf,
					    sizeof (tlp->ifname));
					tlp->tot = t;
					*nextnew = tlp;
					nextnew = &tlp->next_if;

					/*
					 * First time through.
					 * Just add up the interface stats.
					 */

					if (oldlist6 == NULL) {
						if_stat_total(&zerostat,
						    &t, &sum6);
						continue;
					}

					/*
					 * Walk old list for the interface.
					 *
					 * If found, add difference to total.
					 *
					 * If not, an interface has been plumbed
					 * up.  In this case, we will simply
					 * ignore the new interface until the
					 * next interval; as there's no easy way
					 * to acquire statistics between time
					 * of the plumb and the next interval
					 * boundary.  This results in inaccurate
					 * total values for current interval.
					 *
					 * Note the case when an interface is
					 * unplumbed; as similar problems exist.
					 * The unplumbed interface is not in the
					 * current list, and there's no easy way
					 * to account for the statistics between
					 * the previous interval and time of the
					 * unplumb.  Therefore, we (in a sense)
					 * ignore the removed interface by only
					 * involving "current" interfaces when
					 * computing the total statistics.
					 * Unfortunately, this also results in
					 * inaccurate values for interval total.
					 */

					for (walkold = oldlist6;
					    walkold != NULL;
					    walkold = walkold->next_if) {
						if (strcmp(walkold->ifname,
						    buf) == 0) {
							if_stat_total(
							    &walkold->tot,
							    &t, &sum6);
							break;
						}
					}

				} /* 'for' loop 2f ends */

				*nextnew = NULL;

				(void) printf("%-7llu %-5llu %-7llu "
				    "%-5llu %-6llu ",
				    new6.ipackets - old6.ipackets,
				    new6.ierrors - old6.ierrors,
				    new6.opackets - old6.opackets,
				    new6.oerrors - old6.oerrors,
				    new6.collisions - old6.collisions);

				(void) printf("%-7llu %-5llu %-7llu "
				    "%-5llu %-6llu\n", sum6.ipackets,
				    sum6.ierrors, sum6.opackets,
				    sum6.oerrors, sum6.collisions);

				/*
				 * Tidy things up once finished.
				 */

				old6 = new6;
				cleanlist = oldlist6;
				oldlist6 = newlist6;
				while (cleanlist != NULL) {
					tlp = cleanlist->next_if;
					free(cleanlist);
					cleanlist = tlp;
				}
			}
			break;
		}
		}
		(void) fflush(stdout);
	} /* 'for' loop 1 ends */
	if ((Iflag_only == 0) && (!once_only))
		(void) putchar('\n');
	reentry = B_TRUE;
}

static void
if_report_ip4(mib2_ipAddrEntry_t *ap,
    char ifname[], char logintname[], struct ifstat *statptr,
    boolean_t ksp_not_null)
{

	char abuf[MAXHOSTNAMELEN + 1];
	char dstbuf[MAXHOSTNAMELEN + 1];

	if (ksp_not_null) {
		(void) printf("%-5s %-4u ",
		    ifname, ap->ipAdEntInfo.ae_mtu);
		if (ap->ipAdEntInfo.ae_flags & IFF_POINTOPOINT)
			(void) pr_addr(ap->ipAdEntInfo.ae_pp_dst_addr,
			    abuf, sizeof (abuf));
		else
			(void) pr_netaddr(ap->ipAdEntAddr,
			    ap->ipAdEntNetMask, abuf, sizeof (abuf));
		(void) printf("%-13s %-14s %-6llu %-5llu %-6llu %-5llu "
		    "%-6llu %-6llu\n",
		    abuf, pr_addr(ap->ipAdEntAddr, dstbuf, sizeof (dstbuf)),
		    statptr->ipackets, statptr->ierrors,
		    statptr->opackets, statptr->oerrors,
		    statptr->collisions, 0LL);
	}
	/*
	 * Print logical interface info if Aflag set (including logical unit 0)
	 */
	if (Aflag) {
		*statptr = zerostat;
		statptr->ipackets = ap->ipAdEntInfo.ae_ibcnt;
		statptr->opackets = ap->ipAdEntInfo.ae_obcnt;

		(void) printf("%-5s %-4u ", logintname, ap->ipAdEntInfo.ae_mtu);
		if (ap->ipAdEntInfo.ae_flags & IFF_POINTOPOINT)
			(void) pr_addr(ap->ipAdEntInfo.ae_pp_dst_addr, abuf,
			    sizeof (abuf));
		else
			(void) pr_netaddr(ap->ipAdEntAddr, ap->ipAdEntNetMask,
			    abuf, sizeof (abuf));

		(void) printf("%-13s %-14s %-6llu %-5s %-6s "
		    "%-5s %-6s %-6llu\n", abuf,
		    pr_addr(ap->ipAdEntAddr, dstbuf, sizeof (dstbuf)),
		    statptr->ipackets, "N/A", "N/A", "N/A", "N/A",
		    0LL);
	}
}

static void
if_report_ip6(mib2_ipv6AddrEntry_t *ap6,
    char ifname[], char logintname[], struct ifstat *statptr,
    boolean_t ksp_not_null)
{

	char abuf[MAXHOSTNAMELEN + 1];
	char dstbuf[MAXHOSTNAMELEN + 1];

	if (ksp_not_null) {
		(void) printf("%-5s %-4u ", ifname, ap6->ipv6AddrInfo.ae_mtu);
		if (ap6->ipv6AddrInfo.ae_flags &
		    IFF_POINTOPOINT) {
			(void) pr_addr6(&ap6->ipv6AddrInfo.ae_pp_dst_addr,
			    abuf, sizeof (abuf));
		} else {
			(void) pr_prefix6(&ap6->ipv6AddrAddress,
			    ap6->ipv6AddrPfxLength, abuf,
			    sizeof (abuf));
		}
		(void) printf("%-27s %-27s %-6llu %-5llu "
		    "%-6llu %-5llu %-6llu\n",
		    abuf, pr_addr6(&ap6->ipv6AddrAddress, dstbuf,
		    sizeof (dstbuf)),
		    statptr->ipackets, statptr->ierrors, statptr->opackets,
		    statptr->oerrors, statptr->collisions);
	}
	/*
	 * Print logical interface info if Aflag set (including logical unit 0)
	 */
	if (Aflag) {
		*statptr = zerostat;
		statptr->ipackets = ap6->ipv6AddrInfo.ae_ibcnt;
		statptr->opackets = ap6->ipv6AddrInfo.ae_obcnt;

		(void) printf("%-5s %-4u ", logintname,
		    ap6->ipv6AddrInfo.ae_mtu);
		if (ap6->ipv6AddrInfo.ae_flags & IFF_POINTOPOINT)
			(void) pr_addr6(&ap6->ipv6AddrInfo.ae_pp_dst_addr,
			    abuf, sizeof (abuf));
		else
			(void) pr_prefix6(&ap6->ipv6AddrAddress,
			    ap6->ipv6AddrPfxLength, abuf, sizeof (abuf));
		(void) printf("%-27s %-27s %-6llu %-5s %-6s %-5s %-6s\n",
		    abuf, pr_addr6(&ap6->ipv6AddrAddress, dstbuf,
		    sizeof (dstbuf)),
		    statptr->ipackets, "N/A", "N/A", "N/A", "N/A");
	}
}

/* --------------------- DHCP_REPORT  (netstat -D) ------------------------- */

static boolean_t
dhcp_do_ipc(dhcp_ipc_type_t type, const char *ifname, boolean_t printed_one)
{
	dhcp_ipc_request_t	*request;
	dhcp_ipc_reply_t	*reply;
	int			error;

	request = dhcp_ipc_alloc_request(type, ifname, NULL, 0, DHCP_TYPE_NONE);
	if (request == NULL)
		fail(0, "dhcp_do_ipc: out of memory");

	error = dhcp_ipc_make_request(request, &reply, DHCP_IPC_WAIT_DEFAULT);
	if (error != 0) {
		free(request);
		fail(0, "dhcp_do_ipc: %s", dhcp_ipc_strerror(error));
	}

	free(request);
	error = reply->return_code;
	if (error == DHCP_IPC_E_UNKIF) {
		free(reply);
		return (printed_one);
	}
	if (error != 0) {
		free(reply);
		fail(0, "dhcp_do_ipc: %s", dhcp_ipc_strerror(error));
	}

	if (timestamp_fmt != NODATE)
		print_timestamp(timestamp_fmt);

	if (!printed_one)
		(void) printf("%s", dhcp_status_hdr_string());

	(void) printf("%s", dhcp_status_reply_to_string(reply));
	free(reply);
	return (B_TRUE);
}

/*
 * dhcp_walk_interfaces: walk the list of interfaces for a given address
 * family (af).  For each, print out the DHCP status using dhcp_do_ipc.
 */
static boolean_t
dhcp_walk_interfaces(int af, boolean_t printed_one)
{
	struct lifnum	lifn;
	struct lifconf	lifc;
	int		n_ifs, i, sock_fd;

	sock_fd = socket(af, SOCK_DGRAM, 0);
	if (sock_fd == -1)
		return (printed_one);

	/*
	 * SIOCGLIFNUM is just an estimate.  If the ioctl fails, we don't care;
	 * just drive on and use SIOCGLIFCONF with increasing buffer sizes, as
	 * is traditional.
	 */
	(void) memset(&lifn, 0, sizeof (lifn));
	lifn.lifn_family = af;
	lifn.lifn_flags = LIFC_ALLZONES | LIFC_NOXMIT | LIFC_UNDER_IPMP;
	if (ioctl(sock_fd, SIOCGLIFNUM, &lifn) == -1)
		n_ifs = LIFN_GUARD_VALUE;
	else
		n_ifs = lifn.lifn_count + LIFN_GUARD_VALUE;

	(void) memset(&lifc, 0, sizeof (lifc));
	lifc.lifc_family = af;
	lifc.lifc_flags = lifn.lifn_flags;
	lifc.lifc_len = n_ifs * sizeof (struct lifreq);
	lifc.lifc_buf = malloc(lifc.lifc_len);
	if (lifc.lifc_buf != NULL) {

		if (ioctl(sock_fd, SIOCGLIFCONF, &lifc) == -1) {
			(void) close(sock_fd);
			free(lifc.lifc_buf);
			return (NULL);
		}

		n_ifs = lifc.lifc_len / sizeof (struct lifreq);

		for (i = 0; i < n_ifs; i++) {
			printed_one = dhcp_do_ipc(DHCP_STATUS |
			    (af == AF_INET6 ? DHCP_V6 : 0),
			    lifc.lifc_req[i].lifr_name, printed_one);
		}
	}
	(void) close(sock_fd);
	free(lifc.lifc_buf);
	return (printed_one);
}

static void
dhcp_report(char *ifname)
{
	boolean_t printed_one;

	if (!family_selected(AF_INET) && !family_selected(AF_INET6))
		return;

	printed_one = B_FALSE;
	if (ifname != NULL) {
		if (family_selected(AF_INET)) {
			printed_one = dhcp_do_ipc(DHCP_STATUS, ifname,
			    printed_one);
		}
		if (family_selected(AF_INET6)) {
			printed_one = dhcp_do_ipc(DHCP_STATUS | DHCP_V6,
			    ifname, printed_one);
		}
		if (!printed_one) {
			fail(0, "%s: %s", ifname,
			    dhcp_ipc_strerror(DHCP_IPC_E_UNKIF));
		}
	} else {
		if (family_selected(AF_INET)) {
			printed_one = dhcp_walk_interfaces(AF_INET,
			    printed_one);
		}
		if (family_selected(AF_INET6))
			(void) dhcp_walk_interfaces(AF_INET6, printed_one);
	}
}

/* --------------------- GROUP_REPORT (netstat -g) ------------------------- */

static void
group_report(mib_item_t *item)
{
	mib_item_t	*v4grp = NULL, *v4src = NULL;
	mib_item_t	*v6grp = NULL, *v6src = NULL;
	int		jtemp = 0;
	char		ifname[LIFNAMSIZ + 1];
	char		abuf[MAXHOSTNAMELEN + 1];
	ip_member_t	*ipmp;
	ip_grpsrc_t	*ips;
	ipv6_member_t	*ipmp6;
	ipv6_grpsrc_t	*ips6;
	boolean_t	first, first_src;

	/* 'for' loop 1: */
	for (; item; item = item->next_item) {
		if (Xflag) {
			(void) printf("\n--- Entry %d ---\n", ++jtemp);
			(void) printf("Group = %d, mib_id = %d, "
			    "length = %d, valp = 0x%p\n",
			    item->group, item->mib_id, item->length,
			    item->valp);
		}
		if (item->group == MIB2_IP && family_selected(AF_INET)) {
			switch (item->mib_id) {
			case EXPER_IP_GROUP_MEMBERSHIP:
				v4grp = item;
				if (Xflag)
					(void) printf("item is v4grp info\n");
				break;
			case EXPER_IP_GROUP_SOURCES:
				v4src = item;
				if (Xflag)
					(void) printf("item is v4src info\n");
				break;
			default:
				continue;
			}
			continue;
		}
		if (item->group == MIB2_IP6 && family_selected(AF_INET6)) {
			switch (item->mib_id) {
			case EXPER_IP6_GROUP_MEMBERSHIP:
				v6grp = item;
				if (Xflag)
					(void) printf("item is v6grp info\n");
				break;
			case EXPER_IP6_GROUP_SOURCES:
				v6src = item;
				if (Xflag)
					(void) printf("item is v6src info\n");
				break;
			default:
				continue;
			}
		}
	}

	if (family_selected(AF_INET) && v4grp != NULL) {
		if (Xflag)
			(void) printf("%u records for ipGroupMember:\n",
			    v4grp->length / sizeof (ip_member_t));

		first = B_TRUE;
		for (ipmp = (ip_member_t *)v4grp->valp;
		    (char *)ipmp < (char *)v4grp->valp + v4grp->length;
		    /* LINTED: (note 1) */
		    ipmp = (ip_member_t *)((char *)ipmp + ipMemberEntrySize)) {
			if (first) {
				(void) puts(v4compat ?
				    "Group Memberships" :
				    "Group Memberships: IPv4");
				(void) puts("Interface "
				    "Group                RefCnt");
				(void) puts("--------- "
				    "-------------------- ------");
				first = B_FALSE;
			}

			(void) printf("%-9s %-20s %6u\n",
			    octetstr(&ipmp->ipGroupMemberIfIndex, 'a',
			    ifname, sizeof (ifname)),
			    pr_addr(ipmp->ipGroupMemberAddress,
			    abuf, sizeof (abuf)),
			    ipmp->ipGroupMemberRefCnt);


			if (!Vflag || v4src == NULL)
				continue;

			if (Xflag)
				(void) printf("scanning %u ipGroupSource "
				    "records...\n",
				    v4src->length/sizeof (ip_grpsrc_t));

			first_src = B_TRUE;
			for (ips = (ip_grpsrc_t *)v4src->valp;
			    (char *)ips < (char *)v4src->valp + v4src->length;
			    /* LINTED: (note 1) */
			    ips = (ip_grpsrc_t *)((char *)ips +
			    ipGroupSourceEntrySize)) {
				/*
				 * We assume that all source addrs for a given
				 * interface/group pair are contiguous, so on
				 * the first non-match after we've found at
				 * least one, we bail.
				 */
				if ((ipmp->ipGroupMemberAddress !=
				    ips->ipGroupSourceGroup) ||
				    (!octetstrmatch(&ipmp->ipGroupMemberIfIndex,
				    &ips->ipGroupSourceIfIndex))) {
					if (first_src)
						continue;
					else
						break;
				}
				if (first_src) {
					(void) printf("\t%s:    %s\n",
					    fmodestr(
					    ipmp->ipGroupMemberFilterMode),
					    pr_addr(ips->ipGroupSourceAddress,
					    abuf, sizeof (abuf)));
					first_src = B_FALSE;
					continue;
				}

				(void) printf("\t            %s\n",
				    pr_addr(ips->ipGroupSourceAddress, abuf,
				    sizeof (abuf)));
			}
		}
		(void) putchar('\n');
	}

	if (family_selected(AF_INET6) && v6grp != NULL) {
		if (Xflag)
			(void) printf("%u records for ipv6GroupMember:\n",
			    v6grp->length / sizeof (ipv6_member_t));

		first = B_TRUE;
		for (ipmp6 = (ipv6_member_t *)v6grp->valp;
		    (char *)ipmp6 < (char *)v6grp->valp + v6grp->length;
		    /* LINTED: (note 1) */
		    ipmp6 = (ipv6_member_t *)((char *)ipmp6 +
		    ipv6MemberEntrySize)) {
			if (first) {
				(void) puts("Group Memberships: "
				    "IPv6");
				(void) puts(" If       "
				    "Group                   RefCnt");
				(void) puts("----- "
				    "--------------------------- ------");
				first = B_FALSE;
			}

			(void) printf("%-5s %-27s %5u\n",
			    ifindex2str(ipmp6->ipv6GroupMemberIfIndex, ifname),
			    pr_addr6(&ipmp6->ipv6GroupMemberAddress,
			    abuf, sizeof (abuf)),
			    ipmp6->ipv6GroupMemberRefCnt);

			if (!Vflag || v6src == NULL)
				continue;

			if (Xflag)
				(void) printf("scanning %u ipv6GroupSource "
				    "records...\n",
				    v6src->length/sizeof (ipv6_grpsrc_t));

			first_src = B_TRUE;
			for (ips6 = (ipv6_grpsrc_t *)v6src->valp;
			    (char *)ips6 < (char *)v6src->valp + v6src->length;
			    /* LINTED: (note 1) */
			    ips6 = (ipv6_grpsrc_t *)((char *)ips6 +
			    ipv6GroupSourceEntrySize)) {
				/* same assumption as in the v4 case above */
				if ((ipmp6->ipv6GroupMemberIfIndex !=
				    ips6->ipv6GroupSourceIfIndex) ||
				    (!IN6_ARE_ADDR_EQUAL(
				    &ipmp6->ipv6GroupMemberAddress,
				    &ips6->ipv6GroupSourceGroup))) {
					if (first_src)
						continue;
					else
						break;
				}
				if (first_src) {
					(void) printf("\t%s:    %s\n",
					    fmodestr(
					    ipmp6->ipv6GroupMemberFilterMode),
					    pr_addr6(
					    &ips6->ipv6GroupSourceAddress,
					    abuf, sizeof (abuf)));
					first_src = B_FALSE;
					continue;
				}

				(void) printf("\t            %s\n",
				    pr_addr6(&ips6->ipv6GroupSourceAddress,
				    abuf, sizeof (abuf)));
			}
		}
		(void) putchar('\n');
	}

	(void) putchar('\n');
	(void) fflush(stdout);
}

/* --------------------- DCE_REPORT (netstat -d) ------------------------- */

#define	FLBUFSIZE	8

/* Assumes flbuf is at least 5 characters; callers use FLBUFSIZE */
static char *
dceflags2str(uint32_t flags, char *flbuf)
{
	char *str = flbuf;

	if (flags & DCEF_DEFAULT)
		*str++ = 'D';
	if (flags & DCEF_PMTU)
		*str++ = 'P';
	if (flags & DCEF_UINFO)
		*str++ = 'U';
	if (flags & DCEF_TOO_SMALL_PMTU)
		*str++ = 'S';
	*str++ = '\0';
	return (flbuf);
}

static void
dce_report(mib_item_t *item)
{
	mib_item_t	*v4dce = NULL;
	mib_item_t	*v6dce = NULL;
	int		jtemp = 0;
	char		ifname[LIFNAMSIZ + 1];
	char		abuf[MAXHOSTNAMELEN + 1];
	char		flbuf[FLBUFSIZE];
	boolean_t	first;
	dest_cache_entry_t *dce;

	/* 'for' loop 1: */
	for (; item; item = item->next_item) {
		if (Xflag) {
			(void) printf("\n--- Entry %d ---\n", ++jtemp);
			(void) printf("Group = %d, mib_id = %d, "
			    "length = %d, valp = 0x%p\n",
			    item->group, item->mib_id, item->length,
			    item->valp);
		}
		if (item->group == MIB2_IP && family_selected(AF_INET) &&
		    item->mib_id == EXPER_IP_DCE) {
			v4dce = item;
			if (Xflag)
				(void) printf("item is v4dce info\n");
		}
		if (item->group == MIB2_IP6 && family_selected(AF_INET6) &&
		    item->mib_id == EXPER_IP_DCE) {
			v6dce = item;
			if (Xflag)
				(void) printf("item is v6dce info\n");
		}
	}

	if (family_selected(AF_INET) && v4dce != NULL) {
		if (Xflag)
			(void) printf("%u records for DestCacheEntry:\n",
			    v4dce->length / ipDestEntrySize);

		first = B_TRUE;
		for (dce = (dest_cache_entry_t *)v4dce->valp;
		    (char *)dce < (char *)v4dce->valp + v4dce->length;
		    /* LINTED: (note 1) */
		    dce = (dest_cache_entry_t *)((char *)dce +
		    ipDestEntrySize)) {
			if (first) {
				(void) putchar('\n');
				(void) puts("Destination Cache Entries: IPv4");
				(void) puts(
				    "Address               PMTU   Age  Flags");
				(void) puts(
				    "-------------------- ------ ----- -----");
				first = B_FALSE;
			}

			(void) printf("%-20s %6u %5u %-5s\n",
			    pr_addr(dce->DestIpv4Address, abuf, sizeof (abuf)),
			    dce->DestPmtu, dce->DestAge,
			    dceflags2str(dce->DestFlags, flbuf));
		}
	}

	if (family_selected(AF_INET6) && v6dce != NULL) {
		if (Xflag)
			(void) printf("%u records for DestCacheEntry:\n",
			    v6dce->length / ipDestEntrySize);

		first = B_TRUE;
		for (dce = (dest_cache_entry_t *)v6dce->valp;
		    (char *)dce < (char *)v6dce->valp + v6dce->length;
		    /* LINTED: (note 1) */
		    dce = (dest_cache_entry_t *)((char *)dce +
		    ipDestEntrySize)) {
			if (first) {
				(void) putchar('\n');
				(void) puts("Destination Cache Entries: IPv6");
				(void) puts(
				    "Address                      PMTU  "
				    " Age Flags If ");
				(void) puts(
				    "--------------------------- ------ "
				    "----- ----- ---");
				first = B_FALSE;
			}

			(void) printf("%-27s %6u %5u %-5s %s\n",
			    pr_addr6(&dce->DestIpv6Address, abuf,
			    sizeof (abuf)),
			    dce->DestPmtu, dce->DestAge,
			    dceflags2str(dce->DestFlags, flbuf),
			    dce->DestIfindex == 0 ? "" :
			    ifindex2str(dce->DestIfindex, ifname));
		}
	}
	(void) fflush(stdout);
}

/* --------------------- ARP_REPORT (netstat -p) -------------------------- */

static void
arp_report(mib_item_t *item)
{
	int		jtemp = 0;
	char		ifname[LIFNAMSIZ + 1];
	char		abuf[MAXHOSTNAMELEN + 1];
	char		maskbuf[STR_EXPAND * OCTET_LENGTH + 1];
	char		flbuf[32];	/* ACE_F_ flags */
	char		xbuf[STR_EXPAND * OCTET_LENGTH + 1];
	mib2_ipNetToMediaEntry_t	*np;
	int		flags;
	boolean_t	first;

	if (!(family_selected(AF_INET)))
		return;

	/* 'for' loop 1: */
	for (; item; item = item->next_item) {
		if (Xflag) {
			(void) printf("\n--- Entry %d ---\n", ++jtemp);
			(void) printf("Group = %d, mib_id = %d, "
			    "length = %d, valp = 0x%p\n",
			    item->group, item->mib_id, item->length,
			    item->valp);
		}
		if (!(item->group == MIB2_IP && item->mib_id == MIB2_IP_MEDIA))
			continue; /* 'for' loop 1 */

		if (Xflag)
			(void) printf("%u records for "
			    "ipNetToMediaEntryTable:\n",
			    item->length/sizeof (mib2_ipNetToMediaEntry_t));

		first = B_TRUE;
		/* 'for' loop 2: */
		for (np = (mib2_ipNetToMediaEntry_t *)item->valp;
		    (char *)np < (char *)item->valp + item->length;
		    /* LINTED: (note 1) */
		    np = (mib2_ipNetToMediaEntry_t *)((char *)np +
		    ipNetToMediaEntrySize)) {
			if (first) {
				(void) puts(v4compat ?
				    "Net to Media Table" :
				    "Net to Media Table: IPv4");
				(void) puts("Device "
				    "  IP Address               Mask      "
				    "Flags      Phys Addr");
				(void) puts("------ "
				    "-------------------- --------------- "
				    "-------- ---------------");
				first = B_FALSE;
			}

			flbuf[0] = '\0';
			flags = np->ipNetToMediaInfo.ntm_flags;
			/*
			 * Note that not all flags are possible at the same
			 * time.  Patterns: SPLAy DUo
			 */
			if (flags & ACE_F_PERMANENT)
				(void) strcat(flbuf, "S");
			if (flags & ACE_F_PUBLISH)
				(void) strcat(flbuf, "P");
			if (flags & ACE_F_DYING)
				(void) strcat(flbuf, "D");
			if (!(flags & ACE_F_RESOLVED))
				(void) strcat(flbuf, "U");
			if (flags & ACE_F_MAPPING)
				(void) strcat(flbuf, "M");
			if (flags & ACE_F_MYADDR)
				(void) strcat(flbuf, "L");
			if (flags & ACE_F_UNVERIFIED)
				(void) strcat(flbuf, "d");
			if (flags & ACE_F_AUTHORITY)
				(void) strcat(flbuf, "A");
			if (flags & ACE_F_OLD)
				(void) strcat(flbuf, "o");
			if (flags & ACE_F_DELAYED)
				(void) strcat(flbuf, "y");
			(void) printf("%-6s %-20s %-15s %-8s %s\n",
			    octetstr(&np->ipNetToMediaIfIndex, 'a',
			    ifname, sizeof (ifname)),
			    pr_addr(np->ipNetToMediaNetAddress,
			    abuf, sizeof (abuf)),
			    octetstr(&np->ipNetToMediaInfo.ntm_mask, 'd',
			    maskbuf, sizeof (maskbuf)),
			    flbuf,
			    octetstr(&np->ipNetToMediaPhysAddress, 'h',
			    xbuf, sizeof (xbuf)));
		} /* 'for' loop 2 ends */
	} /* 'for' loop 1 ends */
	(void) fflush(stdout);
}

/* --------------------- NDP_REPORT (netstat -p) -------------------------- */

static void
ndp_report(mib_item_t *item)
{
	int		jtemp = 0;
	char		abuf[MAXHOSTNAMELEN + 1];
	char		*state;
	char		*type;
	char		xbuf[STR_EXPAND * OCTET_LENGTH + 1];
	mib2_ipv6NetToMediaEntry_t	*np6;
	char		ifname[LIFNAMSIZ + 1];
	boolean_t	first;

	if (!(family_selected(AF_INET6)))
		return;

	/* 'for' loop 1: */
	for (; item; item = item->next_item) {
		if (Xflag) {
			(void) printf("\n--- Entry %d ---\n", ++jtemp);
			(void) printf("Group = %d, mib_id = %d, "
			    "length = %d, valp = 0x%p\n",
			    item->group, item->mib_id, item->length,
			    item->valp);
		}
		if (!(item->group == MIB2_IP6 &&
		    item->mib_id == MIB2_IP6_MEDIA))
			continue; /* 'for' loop 1 */

		first = B_TRUE;
		/* 'for' loop 2: */
		for (np6 = (mib2_ipv6NetToMediaEntry_t *)item->valp;
		    (char *)np6 < (char *)item->valp + item->length;
		    /* LINTED: (note 1) */
		    np6 = (mib2_ipv6NetToMediaEntry_t *)((char *)np6 +
		    ipv6NetToMediaEntrySize)) {
			if (first) {
				(void) puts("\nNet to Media Table: IPv6");
				(void) puts(" If   Physical Address   "
				    " Type      State      Destination/Mask");
				(void) puts("----- -----------------  "
				    "------- ------------ "
				    "---------------------------");
				first = B_FALSE;
			}

			switch (np6->ipv6NetToMediaState) {
			case ND_INCOMPLETE:
				state = "INCOMPLETE";
				break;
			case ND_REACHABLE:
				state = "REACHABLE";
				break;
			case ND_STALE:
				state = "STALE";
				break;
			case ND_DELAY:
				state = "DELAY";
				break;
			case ND_PROBE:
				state = "PROBE";
				break;
			case ND_UNREACHABLE:
				state = "UNREACHABLE";
				break;
			default:
				state = "UNKNOWN";
			}

			switch (np6->ipv6NetToMediaType) {
			case 1:
				type = "other";
				break;
			case 2:
				type = "dynamic";
				break;
			case 3:
				type = "static";
				break;
			case 4:
				type = "local";
				break;
			}
			(void) printf("%-5s %-17s  %-7s %-12s %-27s\n",
			    ifindex2str(np6->ipv6NetToMediaIfIndex, ifname),
			    octetstr(&np6->ipv6NetToMediaPhysAddress, 'h',
			    xbuf, sizeof (xbuf)),
			    type,
			    state,
			    pr_addr6(&np6->ipv6NetToMediaNetAddress,
			    abuf, sizeof (abuf)));
		} /* 'for' loop 2 ends */
	} /* 'for' loop 1 ends */
	(void) putchar('\n');
	(void) fflush(stdout);
}

/* ------------------------- ire_report (netstat -r) ------------------------ */

typedef struct sec_attr_list_s {
	struct sec_attr_list_s *sal_next;
	const mib2_ipAttributeEntry_t *sal_attr;
} sec_attr_list_t;

static boolean_t ire_report_item_v4(const mib2_ipRouteEntry_t *, boolean_t,
    const sec_attr_list_t *);
static boolean_t ire_report_item_v6(const mib2_ipv6RouteEntry_t *, boolean_t,
    const sec_attr_list_t *);
static const char *pr_secattr(const sec_attr_list_t *);

static void
ire_report(const mib_item_t *item)
{
	int			jtemp = 0;
	boolean_t		print_hdr_once_v4 = B_TRUE;
	boolean_t		print_hdr_once_v6 = B_TRUE;
	mib2_ipRouteEntry_t	*rp;
	mib2_ipv6RouteEntry_t	*rp6;
	sec_attr_list_t		**v4_attrs, **v4a;
	sec_attr_list_t		**v6_attrs, **v6a;
	sec_attr_list_t		*all_attrs, *aptr;
	const mib_item_t	*iptr;
	int			ipv4_route_count, ipv6_route_count;
	int			route_attrs_count;

	/*
	 * Preparation pass: the kernel returns separate entries for IP routing
	 * table entries and security attributes.  We loop through the
	 * attributes first and link them into lists.
	 */
	ipv4_route_count = ipv6_route_count = route_attrs_count = 0;
	for (iptr = item; iptr != NULL; iptr = iptr->next_item) {
		if (iptr->group == MIB2_IP6 && iptr->mib_id == MIB2_IP6_ROUTE)
			ipv6_route_count += iptr->length / ipv6RouteEntrySize;
		if (iptr->group == MIB2_IP && iptr->mib_id == MIB2_IP_ROUTE)
			ipv4_route_count += iptr->length / ipRouteEntrySize;
		if ((iptr->group == MIB2_IP || iptr->group == MIB2_IP6) &&
		    iptr->mib_id == EXPER_IP_RTATTR)
			route_attrs_count += iptr->length /
			    ipRouteAttributeSize;
	}
	v4_attrs = v6_attrs = NULL;
	all_attrs = NULL;
	if (family_selected(AF_INET) && ipv4_route_count > 0) {
		v4_attrs = calloc(ipv4_route_count, sizeof (*v4_attrs));
		if (v4_attrs == NULL) {
			perror("ire_report calloc v4_attrs failed");
			return;
		}
	}
	if (family_selected(AF_INET6) && ipv6_route_count > 0) {
		v6_attrs = calloc(ipv6_route_count, sizeof (*v6_attrs));
		if (v6_attrs == NULL) {
			perror("ire_report calloc v6_attrs failed");
			goto ire_report_done;
		}
	}
	if (route_attrs_count > 0) {
		all_attrs = malloc(route_attrs_count * sizeof (*all_attrs));
		if (all_attrs == NULL) {
			perror("ire_report malloc all_attrs failed");
			goto ire_report_done;
		}
	}
	aptr = all_attrs;
	for (iptr = item; iptr != NULL; iptr = iptr->next_item) {
		mib2_ipAttributeEntry_t *iae;
		sec_attr_list_t **alp;

		if (v4_attrs != NULL && iptr->group == MIB2_IP &&
		    iptr->mib_id == EXPER_IP_RTATTR) {
			alp = v4_attrs;
		} else if (v6_attrs != NULL && iptr->group == MIB2_IP6 &&
		    iptr->mib_id == EXPER_IP_RTATTR) {
			alp = v6_attrs;
		} else {
			continue;
		}
		for (iae = iptr->valp;
		    (char *)iae < (char *)iptr->valp + iptr->length;
		    /* LINTED: (note 1) */
		    iae = (mib2_ipAttributeEntry_t *)((char *)iae +
		    ipRouteAttributeSize)) {
			aptr->sal_next = alp[iae->iae_routeidx];
			aptr->sal_attr = iae;
			alp[iae->iae_routeidx] = aptr++;
		}
	}

	/* 'for' loop 1: */
	v4a = v4_attrs;
	v6a = v6_attrs;
	for (; item != NULL; item = item->next_item) {
		if (Xflag) {
			(void) printf("\n--- Entry %d ---\n", ++jtemp);
			(void) printf("Group = %d, mib_id = %d, "
			    "length = %d, valp = 0x%p\n",
			    item->group, item->mib_id,
			    item->length, item->valp);
		}
		if (!((item->group == MIB2_IP &&
		    item->mib_id == MIB2_IP_ROUTE) ||
		    (item->group == MIB2_IP6 &&
		    item->mib_id == MIB2_IP6_ROUTE)))
			continue; /* 'for' loop 1 */

		if (item->group == MIB2_IP && !family_selected(AF_INET))
			continue; /* 'for' loop 1 */
		else if (item->group == MIB2_IP6 && !family_selected(AF_INET6))
			continue; /* 'for' loop 1 */

		if (Xflag) {
			if (item->group == MIB2_IP) {
				(void) printf("%u records for "
				    "ipRouteEntryTable:\n",
				    item->length/sizeof (mib2_ipRouteEntry_t));
			} else {
				(void) printf("%u records for "
				    "ipv6RouteEntryTable:\n",
				    item->length/
				    sizeof (mib2_ipv6RouteEntry_t));
			}
		}

		if (item->group == MIB2_IP) {
			for (rp = (mib2_ipRouteEntry_t *)item->valp;
			    (char *)rp < (char *)item->valp + item->length;
			    /* LINTED: (note 1) */
			    rp = (mib2_ipRouteEntry_t *)((char *)rp +
			    ipRouteEntrySize)) {
				aptr = v4a == NULL ? NULL : *v4a++;
				print_hdr_once_v4 = ire_report_item_v4(rp,
				    print_hdr_once_v4, aptr);
			}
		} else {
			for (rp6 = (mib2_ipv6RouteEntry_t *)item->valp;
			    (char *)rp6 < (char *)item->valp + item->length;
			    /* LINTED: (note 1) */
			    rp6 = (mib2_ipv6RouteEntry_t *)((char *)rp6 +
			    ipv6RouteEntrySize)) {
				aptr = v6a == NULL ? NULL : *v6a++;
				print_hdr_once_v6 = ire_report_item_v6(rp6,
				    print_hdr_once_v6, aptr);
			}
		}
	} /* 'for' loop 1 ends */
	(void) fflush(stdout);
ire_report_done:
	if (v4_attrs != NULL)
		free(v4_attrs);
	if (v6_attrs != NULL)
		free(v6_attrs);
	if (all_attrs != NULL)
		free(all_attrs);
}

/*
 * Match a user-supplied device name.  We do this by string because
 * the MIB2 interface gives us interface name strings rather than
 * ifIndex numbers.  The "none" rule matches only routes with no
 * interface.  The "any" rule matches routes with any non-blank
 * interface.  A base name ("hme0") matches all aliases as well
 * ("hme0:1").
 */
static boolean_t
dev_name_match(const DeviceName *devnam, const char *ifname)
{
	int iflen;

	if (ifname == NULL)
		return (devnam->o_length == 0);		/* "none" */
	if (*ifname == '\0')
		return (devnam->o_length != 0);		/* "any" */
	iflen = strlen(ifname);
	/* The check for ':' here supports interface aliases. */
	if (iflen > devnam->o_length ||
	    (iflen < devnam->o_length && devnam->o_bytes[iflen] != ':'))
		return (B_FALSE);
	return (strncmp(ifname, devnam->o_bytes, iflen) == 0);
}

/*
 * Match a user-supplied IP address list.  The "any" rule matches any
 * non-zero address.  The "none" rule matches only the zero address.
 * IPv6 addresses supplied by the user are ignored.  If the user
 * supplies a subnet mask, then match routes that are at least that
 * specific (use the user's mask).  If the user supplies only an
 * address, then select any routes that would match (use the route's
 * mask).
 */
static boolean_t
v4_addr_match(IpAddress addr, IpAddress mask, const filter_t *fp)
{
	char **app;
	char *aptr;
	in_addr_t faddr, fmask;

	if (fp->u.a.f_address == NULL) {
		if (IN6_IS_ADDR_UNSPECIFIED(&fp->u.a.f_mask))
			return (addr != INADDR_ANY);	/* "any" */
		else
			return (addr == INADDR_ANY);	/* "none" */
	}
	if (!IN6_IS_V4MASK(fp->u.a.f_mask))
		return (B_FALSE);
	IN6_V4MAPPED_TO_IPADDR(&fp->u.a.f_mask, fmask);
	if (fmask != IP_HOST_MASK) {
		if (fmask > mask)
			return (B_FALSE);
		mask = fmask;
	}
	for (app = fp->u.a.f_address->h_addr_list; (aptr = *app) != NULL; app++)
		/* LINTED: (note 1) */
		if (IN6_IS_ADDR_V4MAPPED((in6_addr_t *)aptr)) {
			/* LINTED: (note 1) */
			IN6_V4MAPPED_TO_IPADDR((in6_addr_t *)aptr, faddr);
			if (((faddr ^ addr) & mask) == 0)
				return (B_TRUE);
		}
	return (B_FALSE);
}

/*
 * Run through the filter list for an IPv4 MIB2 route entry.  If all
 * filters of a given type fail to match, then the route is filtered
 * out (not displayed).  If no filter is given or at least one filter
 * of each type matches, then display the route.
 */
static boolean_t
ire_filter_match_v4(const mib2_ipRouteEntry_t *rp, uint_t flag_b)
{
	filter_t *fp;
	int idx;

	/* 'for' loop 1: */
	for (idx = 0; idx < NFILTERKEYS; idx++)
		if ((fp = filters[idx]) != NULL) {
			/* 'for' loop 2: */
			for (; fp != NULL; fp = fp->f_next) {
				switch (idx) {
				case FK_AF:
					if (fp->u.f_family != AF_INET)
						continue; /* 'for' loop 2 */
					break;
				case FK_OUTIF:
					if (!dev_name_match(&rp->ipRouteIfIndex,
					    fp->u.f_ifname))
						continue; /* 'for' loop 2 */
					break;
				case FK_DST:
					if (!v4_addr_match(rp->ipRouteDest,
					    rp->ipRouteMask, fp))
						continue; /* 'for' loop 2 */
					break;
				case FK_FLAGS:
					if ((flag_b & fp->u.f.f_flagset) !=
					    fp->u.f.f_flagset ||
					    (flag_b & fp->u.f.f_flagclear))
						continue; /* 'for' loop 2 */
					break;
				}
				break;
			} /* 'for' loop 2 ends */
			if (fp == NULL)
				return (B_FALSE);
		}
	/* 'for' loop 1 ends */
	return (B_TRUE);
}

/*
 * Given an IPv4 MIB2 route entry, form the list of flags for the
 * route.
 */
static uint_t
form_v4_route_flags(const mib2_ipRouteEntry_t *rp, char *flags)
{
	uint_t flag_b;

	flag_b = FLF_U;
	(void) strcpy(flags, "U");
	/* RTF_INDIRECT wins over RTF_GATEWAY - don't display both */
	if (rp->ipRouteInfo.re_flags & RTF_INDIRECT) {
		(void) strcat(flags, "I");
		flag_b |= FLF_I;
	} else if (rp->ipRouteInfo.re_ire_type & IRE_OFFLINK) {
		(void) strcat(flags, "G");
		flag_b |= FLF_G;
	}
	/* IRE_IF_CLONE wins over RTF_HOST - don't display both */
	if (rp->ipRouteInfo.re_ire_type & IRE_IF_CLONE) {
		(void) strcat(flags, "C");
		flag_b |= FLF_C;
	} else if (rp->ipRouteMask == IP_HOST_MASK) {
		(void) strcat(flags, "H");
		flag_b |= FLF_H;
	}
	if (rp->ipRouteInfo.re_flags & RTF_DYNAMIC) {
		(void) strcat(flags, "D");
		flag_b |= FLF_D;
	}
	if (rp->ipRouteInfo.re_ire_type == IRE_BROADCAST) {	/* Broadcast */
		(void) strcat(flags, "b");
		flag_b |= FLF_b;
	}
	if (rp->ipRouteInfo.re_ire_type == IRE_LOCAL) {		/* Local */
		(void) strcat(flags, "L");
		flag_b |= FLF_L;
	}
	if (rp->ipRouteInfo.re_flags & RTF_MULTIRT) {
		(void) strcat(flags, "M");			/* Multiroute */
		flag_b |= FLF_M;
	}
	if (rp->ipRouteInfo.re_flags & RTF_SETSRC) {
		(void) strcat(flags, "S");			/* Setsrc */
		flag_b |= FLF_S;
	}
	if (rp->ipRouteInfo.re_flags & RTF_REJECT) {
		(void) strcat(flags, "R");
		flag_b |= FLF_R;
	}
	if (rp->ipRouteInfo.re_flags & RTF_BLACKHOLE) {
		(void) strcat(flags, "B");
		flag_b |= FLF_B;
	}
	if (rp->ipRouteInfo.re_flags & RTF_ZONE) {
		(void) strcat(flags, "Z");
		flag_b |= FLF_Z;
	}
	return (flag_b);
}

static const char ire_hdr_v4[] =
"\n%s Table: IPv4\n";
static const char ire_hdr_v4_compat[] =
"\n%s Table:\n";
static const char ire_hdr_v4_verbose[] =
"  Destination             Mask           Gateway          Device "
" MTU  Ref Flg  Out  In/Fwd %s\n"
"-------------------- --------------- -------------------- ------ "
"----- --- --- ----- ------ %s\n";

static const char ire_hdr_v4_normal[] =
"  Destination           Gateway           Flags  Ref     Use     Interface"
" %s\n-------------------- -------------------- ----- ----- ---------- "
"--------- %s\n";

static boolean_t
ire_report_item_v4(const mib2_ipRouteEntry_t *rp, boolean_t first,
    const sec_attr_list_t *attrs)
{
	char			dstbuf[MAXHOSTNAMELEN + 1];
	char			maskbuf[MAXHOSTNAMELEN + 1];
	char			gwbuf[MAXHOSTNAMELEN + 1];
	char			ifname[LIFNAMSIZ + 1];
	char			flags[10];	/* RTF_ flags */
	uint_t			flag_b;

	if (!(Aflag || (rp->ipRouteInfo.re_ire_type != IRE_IF_CLONE &&
	    rp->ipRouteInfo.re_ire_type != IRE_BROADCAST &&
	    rp->ipRouteInfo.re_ire_type != IRE_MULTICAST &&
	    rp->ipRouteInfo.re_ire_type != IRE_NOROUTE &&
	    rp->ipRouteInfo.re_ire_type != IRE_LOCAL))) {
		return (first);
	}

	flag_b = form_v4_route_flags(rp, flags);

	if (!ire_filter_match_v4(rp, flag_b))
		return (first);

	if (first) {
		(void) printf(v4compat ? ire_hdr_v4_compat : ire_hdr_v4,
		    Vflag ? "IRE" : "Routing");
		(void) printf(Vflag ? ire_hdr_v4_verbose : ire_hdr_v4_normal,
		    RSECflag ? "  Gateway security attributes  " : "",
		    RSECflag ? "-------------------------------" : "");
		first = B_FALSE;
	}

	if (flag_b & FLF_H) {
		(void) pr_addr(rp->ipRouteDest, dstbuf, sizeof (dstbuf));
	} else {
		(void) pr_net(rp->ipRouteDest, rp->ipRouteMask,
		    dstbuf, sizeof (dstbuf));
	}
	if (Vflag) {
		(void) printf("%-20s %-15s %-20s %-6s %5u %3u "
		    "%-4s%6u %6u %s\n",
		    dstbuf,
		    pr_mask(rp->ipRouteMask, maskbuf, sizeof (maskbuf)),
		    pr_addrnz(rp->ipRouteNextHop, gwbuf, sizeof (gwbuf)),
		    octetstr(&rp->ipRouteIfIndex, 'a', ifname, sizeof (ifname)),
		    rp->ipRouteInfo.re_max_frag,
		    rp->ipRouteInfo.re_ref,
		    flags,
		    rp->ipRouteInfo.re_obpkt,
		    rp->ipRouteInfo.re_ibpkt,
		    pr_secattr(attrs));
	} else {
		(void) printf("%-20s %-20s %-5s  %4u %10u %-9s %s\n",
		    dstbuf,
		    pr_addrnz(rp->ipRouteNextHop, gwbuf, sizeof (gwbuf)),
		    flags,
		    rp->ipRouteInfo.re_ref,
		    rp->ipRouteInfo.re_obpkt + rp->ipRouteInfo.re_ibpkt,
		    octetstr(&rp->ipRouteIfIndex, 'a',
		    ifname, sizeof (ifname)),
		    pr_secattr(attrs));
	}
	return (first);
}

/*
 * Match a user-supplied IP address list against an IPv6 route entry.
 * If the user specified "any," then any non-zero address matches.  If
 * the user specified "none," then only the zero address matches.  If
 * the user specified a subnet mask length, then use that in matching
 * routes (select routes that are at least as specific).  If the user
 * specified only an address, then use the route's mask (select routes
 * that would match that address).  IPv4 addresses are ignored.
 */
static boolean_t
v6_addr_match(const Ip6Address *addr, int masklen, const filter_t *fp)
{
	const uint8_t *ucp;
	int fmasklen;
	int i;
	char **app;
	const uint8_t *aptr;

	if (fp->u.a.f_address == NULL) {
		if (IN6_IS_ADDR_UNSPECIFIED(&fp->u.a.f_mask))	/* any */
			return (!IN6_IS_ADDR_UNSPECIFIED(addr));
		return (IN6_IS_ADDR_UNSPECIFIED(addr));		/* "none" */
	}
	fmasklen = 0;
	/* 'for' loop 1a: */
	for (ucp = fp->u.a.f_mask.s6_addr;
	    ucp < fp->u.a.f_mask.s6_addr + sizeof (fp->u.a.f_mask.s6_addr);
	    ucp++) {
		if (*ucp != 0xff) {
			if (*ucp != 0)
				fmasklen += 9 - ffs(*ucp);
			break; /* 'for' loop 1a */
		}
		fmasklen += 8;
	} /* 'for' loop 1a ends */
	if (fmasklen != IPV6_ABITS) {
		if (fmasklen > masklen)
			return (B_FALSE);
		masklen = fmasklen;
	}
	/* 'for' loop 1b: */
	for (app = fp->u.a.f_address->h_addr_list;
	    (aptr = (uint8_t *)*app) != NULL; app++) {
		/* LINTED: (note 1) */
		if (IN6_IS_ADDR_V4MAPPED((in6_addr_t *)aptr))
			continue; /* 'for' loop 1b */
		ucp = addr->s6_addr;
		for (i = masklen; i >= 8; i -= 8)
			if (*ucp++ != *aptr++)
				break; /* 'for' loop 1b */
		if (i == 0 ||
		    (i < 8 && ((*ucp ^ *aptr) & ~(0xff >> i)) == 0))
			return (B_TRUE);
	} /* 'for' loop 1b ends */
	return (B_FALSE);
}

/*
 * Run through the filter list for an IPv6 MIB2 IRE.  For a given
 * type, if there's at least one filter and all filters of that type
 * fail to match, then the route doesn't match and isn't displayed.
 * If at least one matches, or none are specified, for each of the
 * types, then the route is selected and displayed.
 */
static boolean_t
ire_filter_match_v6(const mib2_ipv6RouteEntry_t *rp6, uint_t flag_b)
{
	filter_t *fp;
	int idx;

	/* 'for' loop 1: */
	for (idx = 0; idx < NFILTERKEYS; idx++)
		if ((fp = filters[idx]) != NULL) {
			/* 'for' loop 2: */
			for (; fp != NULL; fp = fp->f_next) {
				switch (idx) {
				case FK_AF:
					if (fp->u.f_family != AF_INET6)
						/* 'for' loop 2 */
						continue;
					break;
				case FK_OUTIF:
					if (!dev_name_match(&rp6->
					    ipv6RouteIfIndex, fp->u.f_ifname))
						/* 'for' loop 2 */
						continue;
					break;
				case FK_DST:
					if (!v6_addr_match(&rp6->ipv6RouteDest,
					    rp6->ipv6RoutePfxLength, fp))
						/* 'for' loop 2 */
						continue;
					break;
				case FK_FLAGS:
					if ((flag_b & fp->u.f.f_flagset) !=
					    fp->u.f.f_flagset ||
					    (flag_b & fp->u.f.f_flagclear))
						/* 'for' loop 2 */
						continue;
					break;
				}
				break;
			} /* 'for' loop 2 ends */
			if (fp == NULL)
				return (B_FALSE);
		}
	/* 'for' loop 1 ends */
	return (B_TRUE);
}

/*
 * Given an IPv6 MIB2 route entry, form the list of flags for the
 * route.
 */
static uint_t
form_v6_route_flags(const mib2_ipv6RouteEntry_t *rp6, char *flags)
{
	uint_t flag_b;

	flag_b = FLF_U;
	(void) strcpy(flags, "U");
	/* RTF_INDIRECT wins over RTF_GATEWAY - don't display both */
	if (rp6->ipv6RouteInfo.re_flags & RTF_INDIRECT) {
		(void) strcat(flags, "I");
		flag_b |= FLF_I;
	} else if (rp6->ipv6RouteInfo.re_ire_type & IRE_OFFLINK) {
		(void) strcat(flags, "G");
		flag_b |= FLF_G;
	}

	/* IRE_IF_CLONE wins over RTF_HOST - don't display both */
	if (rp6->ipv6RouteInfo.re_ire_type & IRE_IF_CLONE) {
		(void) strcat(flags, "C");
		flag_b |= FLF_C;
	} else if (rp6->ipv6RoutePfxLength == IPV6_ABITS) {
		(void) strcat(flags, "H");
		flag_b |= FLF_H;
	}

	if (rp6->ipv6RouteInfo.re_flags & RTF_DYNAMIC) {
		(void) strcat(flags, "D");
		flag_b |= FLF_D;
	}
	if (rp6->ipv6RouteInfo.re_ire_type == IRE_LOCAL) {	/* Local */
		(void) strcat(flags, "L");
		flag_b |= FLF_L;
	}
	if (rp6->ipv6RouteInfo.re_flags & RTF_MULTIRT) {
		(void) strcat(flags, "M");			/* Multiroute */
		flag_b |= FLF_M;
	}
	if (rp6->ipv6RouteInfo.re_flags & RTF_SETSRC) {
		(void) strcat(flags, "S");			/* Setsrc */
		flag_b |= FLF_S;
	}
	if (rp6->ipv6RouteInfo.re_flags & RTF_REJECT) {
		(void) strcat(flags, "R");
		flag_b |= FLF_R;
	}
	if (rp6->ipv6RouteInfo.re_flags & RTF_BLACKHOLE) {
		(void) strcat(flags, "B");
		flag_b |= FLF_B;
	}
	if (rp6->ipv6RouteInfo.re_flags & RTF_ZONE) {
		(void) strcat(flags, "Z");
		flag_b |= FLF_Z;
	}
	return (flag_b);
}

static const char ire_hdr_v6[] =
"\n%s Table: IPv6\n";
static const char ire_hdr_v6_verbose[] =
"  Destination/Mask            Gateway                    If    MTU  "
"Ref Flags  Out   In/Fwd %s\n"
"--------------------------- --------------------------- ----- ----- "
"--- ----- ------ ------ %s\n";
static const char ire_hdr_v6_normal[] =
"  Destination/Mask            Gateway                   Flags Ref   Use  "
"  If   %s\n"
"--------------------------- --------------------------- ----- --- ------- "
"----- %s\n";

static boolean_t
ire_report_item_v6(const mib2_ipv6RouteEntry_t *rp6, boolean_t first,
    const sec_attr_list_t *attrs)
{
	char			dstbuf[MAXHOSTNAMELEN + 1];
	char			gwbuf[MAXHOSTNAMELEN + 1];
	char			ifname[LIFNAMSIZ + 1];
	char			flags[10];	/* RTF_ flags */
	uint_t			flag_b;

	if (!(Aflag || (rp6->ipv6RouteInfo.re_ire_type != IRE_IF_CLONE &&
	    rp6->ipv6RouteInfo.re_ire_type != IRE_MULTICAST &&
	    rp6->ipv6RouteInfo.re_ire_type != IRE_NOROUTE &&
	    rp6->ipv6RouteInfo.re_ire_type != IRE_LOCAL))) {
		return (first);
	}

	flag_b = form_v6_route_flags(rp6, flags);

	if (!ire_filter_match_v6(rp6, flag_b))
		return (first);

	if (first) {
		(void) printf(ire_hdr_v6, Vflag ? "IRE" : "Routing");
		(void) printf(Vflag ? ire_hdr_v6_verbose : ire_hdr_v6_normal,
		    RSECflag ? "  Gateway security attributes  " : "",
		    RSECflag ? "-------------------------------" : "");
		first = B_FALSE;
	}

	if (Vflag) {
		(void) printf("%-27s %-27s %-5s %5u %3u "
		    "%-5s %6u %6u %s\n",
		    pr_prefix6(&rp6->ipv6RouteDest,
		    rp6->ipv6RoutePfxLength, dstbuf, sizeof (dstbuf)),
		    IN6_IS_ADDR_UNSPECIFIED(&rp6->ipv6RouteNextHop) ?
		    "    --" :
		    pr_addr6(&rp6->ipv6RouteNextHop, gwbuf, sizeof (gwbuf)),
		    octetstr(&rp6->ipv6RouteIfIndex, 'a',
		    ifname, sizeof (ifname)),
		    rp6->ipv6RouteInfo.re_max_frag,
		    rp6->ipv6RouteInfo.re_ref,
		    flags,
		    rp6->ipv6RouteInfo.re_obpkt,
		    rp6->ipv6RouteInfo.re_ibpkt,
		    pr_secattr(attrs));
	} else {
		(void) printf("%-27s %-27s %-5s %3u %7u %-5s %s\n",
		    pr_prefix6(&rp6->ipv6RouteDest,
		    rp6->ipv6RoutePfxLength, dstbuf, sizeof (dstbuf)),
		    IN6_IS_ADDR_UNSPECIFIED(&rp6->ipv6RouteNextHop) ?
		    "    --" :
		    pr_addr6(&rp6->ipv6RouteNextHop, gwbuf, sizeof (gwbuf)),
		    flags,
		    rp6->ipv6RouteInfo.re_ref,
		    rp6->ipv6RouteInfo.re_obpkt + rp6->ipv6RouteInfo.re_ibpkt,
		    octetstr(&rp6->ipv6RouteIfIndex, 'a',
		    ifname, sizeof (ifname)),
		    pr_secattr(attrs));
	}
	return (first);
}

/*
 * Common attribute-gathering routine for all transports.
 */
static mib2_transportMLPEntry_t **
gather_attrs(const mib_item_t *item, int group, int mib_id, int esize)
{
	int transport_count = 0;
	const mib_item_t *iptr;
	mib2_transportMLPEntry_t **attrs, *tme;

	for (iptr = item; iptr != NULL; iptr = iptr->next_item) {
		if (iptr->group == group && iptr->mib_id == mib_id)
			transport_count += iptr->length / esize;
	}
	if (transport_count <= 0)
		return (NULL);
	attrs = calloc(transport_count, sizeof (*attrs));
	if (attrs == NULL) {
		perror("gather_attrs calloc failed");
		return (NULL);
	}
	for (iptr = item; iptr != NULL; iptr = iptr->next_item) {
		if (iptr->group == group && iptr->mib_id == EXPER_XPORT_MLP) {
			for (tme = iptr->valp;
			    (char *)tme < (char *)iptr->valp + iptr->length;
			    /* LINTED: (note 1) */
			    tme = (mib2_transportMLPEntry_t *)((char *)tme +
			    transportMLPSize)) {
				attrs[tme->tme_connidx] = tme;
			}
		}
	}
	return (attrs);
}

static void
print_transport_label(const mib2_transportMLPEntry_t *attr)
{
	if (!RSECflag || attr == NULL ||
	    !(attr->tme_flags & MIB2_TMEF_IS_LABELED))
		return;

	if (bisinvalid(&attr->tme_label)) {
		(void) printf("   INVALID\n");
	} else if (!blequal(&attr->tme_label, zone_security_label)) {
		char *sl_str;

		sl_str = sl_to_str(&attr->tme_label);
		(void) printf("   %s\n", sl_str);
		free(sl_str);
	}
}

/* ------------------------------ TCP_REPORT------------------------------- */

static const char tcp_hdr_v4[] =
"\nTCP: IPv4\n";
static const char tcp_hdr_v4_compat[] =
"\nTCP\n";
static const char tcp_hdr_v4_verbose[] =
"Local/Remote Address Swind  Snext     Suna   Rwind  Rnext     Rack   "
" Rto   Mss     State\n"
"-------------------- ----- -------- -------- ----- -------- -------- "
"----- ----- -----------\n";
static const char tcp_hdr_v4_normal[] =
"   Local Address        Remote Address    Swind Send-Q Rwind Recv-Q "
"   State\n"
"-------------------- -------------------- ----- ------ ----- ------ "
"-----------\n";

static const char tcp_hdr_v6[] =
"\nTCP: IPv6\n";
static const char tcp_hdr_v6_verbose[] =
"Local/Remote Address              Swind  Snext     Suna   Rwind  Rnext   "
"  Rack    Rto   Mss    State      If\n"
"--------------------------------- ----- -------- -------- ----- -------- "
"-------- ----- ----- ----------- -----\n";
static const char tcp_hdr_v6_normal[] =
"   Local Address                     Remote Address                 "
"Swind Send-Q Rwind Recv-Q   State      If\n"
"--------------------------------- --------------------------------- "
"----- ------ ----- ------ ----------- -----\n";

static boolean_t tcp_report_item_v4(const mib2_tcpConnEntry_t *,
    boolean_t first, const mib2_transportMLPEntry_t *);
static boolean_t tcp_report_item_v6(const mib2_tcp6ConnEntry_t *,
    boolean_t first, const mib2_transportMLPEntry_t *);

static void
tcp_report(const mib_item_t *item)
{
	int			jtemp = 0;
	boolean_t		print_hdr_once_v4 = B_TRUE;
	boolean_t		print_hdr_once_v6 = B_TRUE;
	mib2_tcpConnEntry_t	*tp;
	mib2_tcp6ConnEntry_t	*tp6;
	mib2_transportMLPEntry_t **v4_attrs, **v6_attrs;
	mib2_transportMLPEntry_t **v4a, **v6a;
	mib2_transportMLPEntry_t *aptr;

	if (!protocol_selected(IPPROTO_TCP))
		return;

	/*
	 * Preparation pass: the kernel returns separate entries for TCP
	 * connection table entries and Multilevel Port attributes.  We loop
	 * through the attributes first and set up an array for each address
	 * family.
	 */
	v4_attrs = family_selected(AF_INET) && RSECflag ?
	    gather_attrs(item, MIB2_TCP, MIB2_TCP_CONN, tcpConnEntrySize) :
	    NULL;
	v6_attrs = family_selected(AF_INET6) && RSECflag ?
	    gather_attrs(item, MIB2_TCP6, MIB2_TCP6_CONN, tcp6ConnEntrySize) :
	    NULL;

	/* 'for' loop 1: */
	v4a = v4_attrs;
	v6a = v6_attrs;
	for (; item != NULL; item = item->next_item) {
		if (Xflag) {
			(void) printf("\n--- Entry %d ---\n", ++jtemp);
			(void) printf("Group = %d, mib_id = %d, "
			    "length = %d, valp = 0x%p\n",
			    item->group, item->mib_id,
			    item->length, item->valp);
		}

		if (!((item->group == MIB2_TCP &&
		    item->mib_id == MIB2_TCP_CONN) ||
		    (item->group == MIB2_TCP6 &&
		    item->mib_id == MIB2_TCP6_CONN)))
			continue; /* 'for' loop 1 */

		if (item->group == MIB2_TCP && !family_selected(AF_INET))
			continue; /* 'for' loop 1 */
		else if (item->group == MIB2_TCP6 && !family_selected(AF_INET6))
			continue; /* 'for' loop 1 */

		if (item->group == MIB2_TCP) {
			for (tp = (mib2_tcpConnEntry_t *)item->valp;
			    (char *)tp < (char *)item->valp + item->length;
			    /* LINTED: (note 1) */
			    tp = (mib2_tcpConnEntry_t *)((char *)tp +
			    tcpConnEntrySize)) {
				aptr = v4a == NULL ? NULL : *v4a++;
				print_hdr_once_v4 = tcp_report_item_v4(tp,
				    print_hdr_once_v4, aptr);
			}
		} else {
			for (tp6 = (mib2_tcp6ConnEntry_t *)item->valp;
			    (char *)tp6 < (char *)item->valp + item->length;
			    /* LINTED: (note 1) */
			    tp6 = (mib2_tcp6ConnEntry_t *)((char *)tp6 +
			    tcp6ConnEntrySize)) {
				aptr = v6a == NULL ? NULL : *v6a++;
				print_hdr_once_v6 = tcp_report_item_v6(tp6,
				    print_hdr_once_v6, aptr);
			}
		}
	} /* 'for' loop 1 ends */
	(void) fflush(stdout);

	if (v4_attrs != NULL)
		free(v4_attrs);
	if (v6_attrs != NULL)
		free(v6_attrs);
}

static boolean_t
tcp_report_item_v4(const mib2_tcpConnEntry_t *tp, boolean_t first,
    const mib2_transportMLPEntry_t *attr)
{
	/*
	 * lname and fname below are for the hostname as well as the portname
	 * There is no limit on portname length so we assume MAXHOSTNAMELEN
	 * as the limit
	 */
	char	lname[MAXHOSTNAMELEN + MAXHOSTNAMELEN + 1];
	char	fname[MAXHOSTNAMELEN + MAXHOSTNAMELEN + 1];

	if (!(Aflag || tp->tcpConnEntryInfo.ce_state >= TCPS_ESTABLISHED))
		return (first); /* Nothing to print */

	if (first) {
		(void) printf(v4compat ? tcp_hdr_v4_compat : tcp_hdr_v4);
		(void) printf(Vflag ? tcp_hdr_v4_verbose : tcp_hdr_v4_normal);
	}

	if (Vflag) {
		(void) printf("%-20s\n%-20s %5u %08x %08x %5u %08x %08x "
		    "%5u %5u %s\n",
		    pr_ap(tp->tcpConnLocalAddress,
		    tp->tcpConnLocalPort, "tcp", lname, sizeof (lname)),
		    pr_ap(tp->tcpConnRemAddress,
		    tp->tcpConnRemPort, "tcp", fname, sizeof (fname)),
		    tp->tcpConnEntryInfo.ce_swnd,
		    tp->tcpConnEntryInfo.ce_snxt,
		    tp->tcpConnEntryInfo.ce_suna,
		    tp->tcpConnEntryInfo.ce_rwnd,
		    tp->tcpConnEntryInfo.ce_rnxt,
		    tp->tcpConnEntryInfo.ce_rack,
		    tp->tcpConnEntryInfo.ce_rto,
		    tp->tcpConnEntryInfo.ce_mss,
		    mitcp_state(tp->tcpConnEntryInfo.ce_state, attr));
	} else {
		int sq = (int)tp->tcpConnEntryInfo.ce_snxt -
		    (int)tp->tcpConnEntryInfo.ce_suna - 1;
		int rq = (int)tp->tcpConnEntryInfo.ce_rnxt -
		    (int)tp->tcpConnEntryInfo.ce_rack;

		(void) printf("%-20s %-20s %5u %6d %5u %6d %s\n",
		    pr_ap(tp->tcpConnLocalAddress,
		    tp->tcpConnLocalPort, "tcp", lname, sizeof (lname)),
		    pr_ap(tp->tcpConnRemAddress,
		    tp->tcpConnRemPort, "tcp", fname, sizeof (fname)),
		    tp->tcpConnEntryInfo.ce_swnd,
		    (sq >= 0) ? sq : 0,
		    tp->tcpConnEntryInfo.ce_rwnd,
		    (rq >= 0) ? rq : 0,
		    mitcp_state(tp->tcpConnEntryInfo.ce_state, attr));
	}

	print_transport_label(attr);

	return (B_FALSE);
}

static boolean_t
tcp_report_item_v6(const mib2_tcp6ConnEntry_t *tp6, boolean_t first,
    const mib2_transportMLPEntry_t *attr)
{
	/*
	 * lname and fname below are for the hostname as well as the portname
	 * There is no limit on portname length so we assume MAXHOSTNAMELEN
	 * as the limit
	 */
	char	lname[MAXHOSTNAMELEN + MAXHOSTNAMELEN + 1];
	char	fname[MAXHOSTNAMELEN + MAXHOSTNAMELEN + 1];
	char	ifname[LIFNAMSIZ + 1];
	char	*ifnamep;

	if (!(Aflag || tp6->tcp6ConnEntryInfo.ce_state >= TCPS_ESTABLISHED))
		return (first); /* Nothing to print */

	if (first) {
		(void) printf(tcp_hdr_v6);
		(void) printf(Vflag ? tcp_hdr_v6_verbose : tcp_hdr_v6_normal);
	}

	ifnamep = (tp6->tcp6ConnIfIndex != 0) ?
	    if_indextoname(tp6->tcp6ConnIfIndex, ifname) : NULL;
	if (ifnamep == NULL)
		ifnamep = "";

	if (Vflag) {
		(void) printf("%-33s\n%-33s %5u %08x %08x %5u %08x %08x "
		    "%5u %5u %-11s %s\n",
		    pr_ap6(&tp6->tcp6ConnLocalAddress,
		    tp6->tcp6ConnLocalPort, "tcp", lname, sizeof (lname)),
		    pr_ap6(&tp6->tcp6ConnRemAddress,
		    tp6->tcp6ConnRemPort, "tcp", fname, sizeof (fname)),
		    tp6->tcp6ConnEntryInfo.ce_swnd,
		    tp6->tcp6ConnEntryInfo.ce_snxt,
		    tp6->tcp6ConnEntryInfo.ce_suna,
		    tp6->tcp6ConnEntryInfo.ce_rwnd,
		    tp6->tcp6ConnEntryInfo.ce_rnxt,
		    tp6->tcp6ConnEntryInfo.ce_rack,
		    tp6->tcp6ConnEntryInfo.ce_rto,
		    tp6->tcp6ConnEntryInfo.ce_mss,
		    mitcp_state(tp6->tcp6ConnEntryInfo.ce_state, attr),
		    ifnamep);
	} else {
		int sq = (int)tp6->tcp6ConnEntryInfo.ce_snxt -
		    (int)tp6->tcp6ConnEntryInfo.ce_suna - 1;
		int rq = (int)tp6->tcp6ConnEntryInfo.ce_rnxt -
		    (int)tp6->tcp6ConnEntryInfo.ce_rack;

		(void) printf("%-33s %-33s %5u %6d %5u %6d %-11s %s\n",
		    pr_ap6(&tp6->tcp6ConnLocalAddress,
		    tp6->tcp6ConnLocalPort, "tcp", lname, sizeof (lname)),
		    pr_ap6(&tp6->tcp6ConnRemAddress,
		    tp6->tcp6ConnRemPort, "tcp", fname, sizeof (fname)),
		    tp6->tcp6ConnEntryInfo.ce_swnd,
		    (sq >= 0) ? sq : 0,
		    tp6->tcp6ConnEntryInfo.ce_rwnd,
		    (rq >= 0) ? rq : 0,
		    mitcp_state(tp6->tcp6ConnEntryInfo.ce_state, attr),
		    ifnamep);
	}

	print_transport_label(attr);

	return (B_FALSE);
}

/* ------------------------------- UDP_REPORT------------------------------- */

static boolean_t udp_report_item_v4(const mib2_udpEntry_t *ude,
    boolean_t first, const mib2_transportMLPEntry_t *attr);
static boolean_t udp_report_item_v6(const mib2_udp6Entry_t *ude6,
    boolean_t first, const mib2_transportMLPEntry_t *attr);

static const char udp_hdr_v4[] =
"   Local Address        Remote Address      State\n"
"-------------------- -------------------- ----------\n";

static const char udp_hdr_v6[] =
"   Local Address                     Remote Address                 "
"  State      If\n"
"--------------------------------- --------------------------------- "
"---------- -----\n";

static void
udp_report(const mib_item_t *item)
{
	int			jtemp = 0;
	boolean_t		print_hdr_once_v4 = B_TRUE;
	boolean_t		print_hdr_once_v6 = B_TRUE;
	mib2_udpEntry_t		*ude;
	mib2_udp6Entry_t	*ude6;
	mib2_transportMLPEntry_t **v4_attrs, **v6_attrs;
	mib2_transportMLPEntry_t **v4a, **v6a;
	mib2_transportMLPEntry_t *aptr;

	if (!protocol_selected(IPPROTO_UDP))
		return;

	/*
	 * Preparation pass: the kernel returns separate entries for UDP
	 * connection table entries and Multilevel Port attributes.  We loop
	 * through the attributes first and set up an array for each address
	 * family.
	 */
	v4_attrs = family_selected(AF_INET) && RSECflag ?
	    gather_attrs(item, MIB2_UDP, MIB2_UDP_ENTRY, udpEntrySize) : NULL;
	v6_attrs = family_selected(AF_INET6) && RSECflag ?
	    gather_attrs(item, MIB2_UDP6, MIB2_UDP6_ENTRY, udp6EntrySize) :
	    NULL;

	v4a = v4_attrs;
	v6a = v6_attrs;
	/* 'for' loop 1: */
	for (; item; item = item->next_item) {
		if (Xflag) {
			(void) printf("\n--- Entry %d ---\n", ++jtemp);
			(void) printf("Group = %d, mib_id = %d, "
			    "length = %d, valp = 0x%p\n",
			    item->group, item->mib_id,
			    item->length, item->valp);
		}
		if (!((item->group == MIB2_UDP &&
		    item->mib_id == MIB2_UDP_ENTRY) ||
		    (item->group == MIB2_UDP6 &&
		    item->mib_id == MIB2_UDP6_ENTRY)))
			continue; /* 'for' loop 1 */

		if (item->group == MIB2_UDP && !family_selected(AF_INET))
			continue; /* 'for' loop 1 */
		else if (item->group == MIB2_UDP6 && !family_selected(AF_INET6))
			continue; /* 'for' loop 1 */

		/*	xxx.xxx.xxx.xxx,pppp  sss... */
		if (item->group == MIB2_UDP) {
			for (ude = (mib2_udpEntry_t *)item->valp;
			    (char *)ude < (char *)item->valp + item->length;
			    /* LINTED: (note 1) */
			    ude = (mib2_udpEntry_t *)((char *)ude +
			    udpEntrySize)) {
				aptr = v4a == NULL ? NULL : *v4a++;
				print_hdr_once_v4 = udp_report_item_v4(ude,
				    print_hdr_once_v4, aptr);
			}
		} else {
			for (ude6 = (mib2_udp6Entry_t *)item->valp;
			    (char *)ude6 < (char *)item->valp + item->length;
			    /* LINTED: (note 1) */
			    ude6 = (mib2_udp6Entry_t *)((char *)ude6 +
			    udp6EntrySize)) {
				aptr = v6a == NULL ? NULL : *v6a++;
				print_hdr_once_v6 = udp_report_item_v6(ude6,
				    print_hdr_once_v6, aptr);
			}
		}
	} /* 'for' loop 1 ends */
	(void) fflush(stdout);

	if (v4_attrs != NULL)
		free(v4_attrs);
	if (v6_attrs != NULL)
		free(v6_attrs);
}

static boolean_t
udp_report_item_v4(const mib2_udpEntry_t *ude, boolean_t first,
    const mib2_transportMLPEntry_t *attr)
{
	char	lname[MAXHOSTNAMELEN + MAXHOSTNAMELEN + 1];
			/* hostname + portname */

	if (!(Aflag || ude->udpEntryInfo.ue_state >= MIB2_UDP_connected))
		return (first); /* Nothing to print */

	if (first) {
		(void) printf(v4compat ? "\nUDP\n" : "\nUDP: IPv4\n");
		(void) printf(udp_hdr_v4);
		first = B_FALSE;
	}

	(void) printf("%-20s ",
	    pr_ap(ude->udpLocalAddress, ude->udpLocalPort, "udp",
	    lname, sizeof (lname)));
	(void) printf("%-20s %s\n",
	    ude->udpEntryInfo.ue_state == MIB2_UDP_connected ?
	    pr_ap(ude->udpEntryInfo.ue_RemoteAddress,
	    ude->udpEntryInfo.ue_RemotePort, "udp", lname, sizeof (lname)) :
	    "",
	    miudp_state(ude->udpEntryInfo.ue_state, attr));

	print_transport_label(attr);

	return (first);
}

static boolean_t
udp_report_item_v6(const mib2_udp6Entry_t *ude6, boolean_t first,
    const mib2_transportMLPEntry_t *attr)
{
	char	lname[MAXHOSTNAMELEN + MAXHOSTNAMELEN + 1];
			/* hostname + portname */
	char	ifname[LIFNAMSIZ + 1];
	const char *ifnamep;

	if (!(Aflag || ude6->udp6EntryInfo.ue_state >= MIB2_UDP_connected))
		return (first); /* Nothing to print */

	if (first) {
		(void) printf("\nUDP: IPv6\n");
		(void) printf(udp_hdr_v6);
		first = B_FALSE;
	}

	ifnamep = (ude6->udp6IfIndex != 0) ?
	    if_indextoname(ude6->udp6IfIndex, ifname) : NULL;

	(void) printf("%-33s ",
	    pr_ap6(&ude6->udp6LocalAddress,
	    ude6->udp6LocalPort, "udp", lname, sizeof (lname)));
	(void) printf("%-33s %-10s %s\n",
	    ude6->udp6EntryInfo.ue_state == MIB2_UDP_connected ?
	    pr_ap6(&ude6->udp6EntryInfo.ue_RemoteAddress,
	    ude6->udp6EntryInfo.ue_RemotePort, "udp", lname, sizeof (lname)) :
	    "",
	    miudp_state(ude6->udp6EntryInfo.ue_state, attr),
	    ifnamep == NULL ? "" : ifnamep);

	print_transport_label(attr);

	return (first);
}

/* ------------------------------ SCTP_REPORT------------------------------- */

static const char sctp_hdr[] =
"\nSCTP:";
static const char sctp_hdr_normal[] =
"        Local Address                   Remote Address          "
"Swind  Send-Q Rwind  Recv-Q StrsI/O  State\n"
"------------------------------- ------------------------------- "
"------ ------ ------ ------ ------- -----------";

static const char *
nssctp_state(int state, const mib2_transportMLPEntry_t *attr)
{
	static char sctpsbuf[50];
	const char *cp;

	switch (state) {
	case MIB2_SCTP_closed:
		cp = "CLOSED";
		break;
	case MIB2_SCTP_cookieWait:
		cp = "COOKIE_WAIT";
		break;
	case MIB2_SCTP_cookieEchoed:
		cp = "COOKIE_ECHOED";
		break;
	case MIB2_SCTP_established:
		cp = "ESTABLISHED";
		break;
	case MIB2_SCTP_shutdownPending:
		cp = "SHUTDOWN_PENDING";
		break;
	case MIB2_SCTP_shutdownSent:
		cp = "SHUTDOWN_SENT";
		break;
	case MIB2_SCTP_shutdownReceived:
		cp = "SHUTDOWN_RECEIVED";
		break;
	case MIB2_SCTP_shutdownAckSent:
		cp = "SHUTDOWN_ACK_SENT";
		break;
	case MIB2_SCTP_listen:
		cp = "LISTEN";
		break;
	default:
		(void) snprintf(sctpsbuf, sizeof (sctpsbuf),
		    "UNKNOWN STATE(%d)", state);
		cp = sctpsbuf;
		break;
	}

	if (RSECflag && attr != NULL && attr->tme_flags != 0) {
		if (cp != sctpsbuf) {
			(void) strlcpy(sctpsbuf, cp, sizeof (sctpsbuf));
			cp = sctpsbuf;
		}
		if (attr->tme_flags & MIB2_TMEF_PRIVATE)
			(void) strlcat(sctpsbuf, " P", sizeof (sctpsbuf));
		if (attr->tme_flags & MIB2_TMEF_SHARED)
			(void) strlcat(sctpsbuf, " S", sizeof (sctpsbuf));
	}

	return (cp);
}

static const mib2_sctpConnRemoteEntry_t *
sctp_getnext_rem(const mib_item_t **itemp,
    const mib2_sctpConnRemoteEntry_t *current, uint32_t associd)
{
	const mib_item_t *item = *itemp;
	const mib2_sctpConnRemoteEntry_t	*sre;

	for (; item != NULL; item = item->next_item, current = NULL) {
		if (!(item->group == MIB2_SCTP &&
		    item->mib_id == MIB2_SCTP_CONN_REMOTE)) {
			continue;
		}

		if (current != NULL) {
			/* LINTED: (note 1) */
			sre = (const mib2_sctpConnRemoteEntry_t *)
			    ((const char *)current + sctpRemoteEntrySize);
		} else {
			sre = item->valp;
		}
		for (; (char *)sre < (char *)item->valp + item->length;
		    /* LINTED: (note 1) */
		    sre = (const mib2_sctpConnRemoteEntry_t *)
		    ((const char *)sre + sctpRemoteEntrySize)) {
			if (sre->sctpAssocId != associd) {
				continue;
			}
			*itemp = item;
			return (sre);
		}
	}
	*itemp = NULL;
	return (NULL);
}

static const mib2_sctpConnLocalEntry_t *
sctp_getnext_local(const mib_item_t **itemp,
    const mib2_sctpConnLocalEntry_t *current, uint32_t associd)
{
	const mib_item_t *item = *itemp;
	const mib2_sctpConnLocalEntry_t	*sle;

	for (; item != NULL; item = item->next_item, current = NULL) {
		if (!(item->group == MIB2_SCTP &&
		    item->mib_id == MIB2_SCTP_CONN_LOCAL)) {
			continue;
		}

		if (current != NULL) {
			/* LINTED: (note 1) */
			sle = (const mib2_sctpConnLocalEntry_t *)
			    ((const char *)current + sctpLocalEntrySize);
		} else {
			sle = item->valp;
		}
		for (; (char *)sle < (char *)item->valp + item->length;
		    /* LINTED: (note 1) */
		    sle = (const mib2_sctpConnLocalEntry_t *)
		    ((const char *)sle + sctpLocalEntrySize)) {
			if (sle->sctpAssocId != associd) {
				continue;
			}
			*itemp = item;
			return (sle);
		}
	}
	*itemp = NULL;
	return (NULL);
}

static void
sctp_pr_addr(int type, char *name, int namelen, const in6_addr_t *addr,
    int port)
{
	ipaddr_t	v4addr;
	in6_addr_t	v6addr;

	/*
	 * Address is either a v4 mapped or v6 addr. If
	 * it's a v4 mapped, convert to v4 before
	 * displaying.
	 */
	switch (type) {
	case MIB2_SCTP_ADDR_V4:
		/* v4 */
		v6addr = *addr;

		IN6_V4MAPPED_TO_IPADDR(&v6addr, v4addr);
		if (port > 0) {
			(void) pr_ap(v4addr, port, "sctp", name, namelen);
		} else {
			(void) pr_addr(v4addr, name, namelen);
		}
		break;

	case MIB2_SCTP_ADDR_V6:
		/* v6 */
		if (port > 0) {
			(void) pr_ap6(addr, port, "sctp", name, namelen);
		} else {
			(void) pr_addr6(addr, name, namelen);
		}
		break;

	default:
		(void) snprintf(name, namelen, "<unknown addr type>");
		break;
	}
}

static void
sctp_conn_report_item(const mib_item_t *head, const mib2_sctpConnEntry_t *sp,
    const mib2_transportMLPEntry_t *attr)
{
	char		lname[MAXHOSTNAMELEN + MAXHOSTNAMELEN + 1];
	char		fname[MAXHOSTNAMELEN + MAXHOSTNAMELEN + 1];
	const mib2_sctpConnRemoteEntry_t	*sre = NULL;
	const mib2_sctpConnLocalEntry_t	*sle = NULL;
	const mib_item_t *local = head;
	const mib_item_t *remote = head;
	uint32_t	id = sp->sctpAssocId;
	boolean_t	printfirst = B_TRUE;

	sctp_pr_addr(sp->sctpAssocRemPrimAddrType, fname, sizeof (fname),
	    &sp->sctpAssocRemPrimAddr, sp->sctpAssocRemPort);
	sctp_pr_addr(sp->sctpAssocRemPrimAddrType, lname, sizeof (lname),
	    &sp->sctpAssocLocPrimAddr, sp->sctpAssocLocalPort);

	(void) printf("%-31s %-31s %6u %6d %6u %6d %3d/%-3d %s\n",
	    lname, fname,
	    sp->sctpConnEntryInfo.ce_swnd,
	    sp->sctpConnEntryInfo.ce_sendq,
	    sp->sctpConnEntryInfo.ce_rwnd,
	    sp->sctpConnEntryInfo.ce_recvq,
	    sp->sctpAssocInStreams, sp->sctpAssocOutStreams,
	    nssctp_state(sp->sctpAssocState, attr));

	print_transport_label(attr);

	if (!Vflag) {
		return;
	}

	/* Print remote addresses/local addresses on following lines */
	while ((sre = sctp_getnext_rem(&remote, sre, id)) != NULL) {
		if (!IN6_ARE_ADDR_EQUAL(&sre->sctpAssocRemAddr,
		    &sp->sctpAssocRemPrimAddr)) {
			if (printfirst == B_TRUE) {
				(void) fputs("\t<Remote: ", stdout);
				printfirst = B_FALSE;
			} else {
				(void) fputs(", ", stdout);
			}
			sctp_pr_addr(sre->sctpAssocRemAddrType, fname,
			    sizeof (fname), &sre->sctpAssocRemAddr, -1);
			if (sre->sctpAssocRemAddrActive == MIB2_SCTP_ACTIVE) {
				(void) fputs(fname, stdout);
			} else {
				(void) printf("(%s)", fname);
			}
		}
	}
	if (printfirst == B_FALSE) {
		(void) puts(">");
		printfirst = B_TRUE;
	}
	while ((sle = sctp_getnext_local(&local, sle, id)) != NULL) {
		if (!IN6_ARE_ADDR_EQUAL(&sle->sctpAssocLocalAddr,
		    &sp->sctpAssocLocPrimAddr)) {
			if (printfirst == B_TRUE) {
				(void) fputs("\t<Local: ", stdout);
				printfirst = B_FALSE;
			} else {
				(void) fputs(", ", stdout);
			}
			sctp_pr_addr(sle->sctpAssocLocalAddrType, lname,
			    sizeof (lname), &sle->sctpAssocLocalAddr, -1);
			(void) fputs(lname, stdout);
		}
	}
	if (printfirst == B_FALSE) {
		(void) puts(">");
	}
}

static void
sctp_report(const mib_item_t *item)
{
	const mib_item_t		*head;
	const mib2_sctpConnEntry_t	*sp;
	boolean_t		first = B_TRUE;
	mib2_transportMLPEntry_t **attrs, **aptr;
	mib2_transportMLPEntry_t *attr;

	/*
	 * Preparation pass: the kernel returns separate entries for SCTP
	 * connection table entries and Multilevel Port attributes.  We loop
	 * through the attributes first and set up an array for each address
	 * family.
	 */
	attrs = RSECflag ?
	    gather_attrs(item, MIB2_SCTP, MIB2_SCTP_CONN, sctpEntrySize) :
	    NULL;

	aptr = attrs;
	head = item;
	for (; item != NULL; item = item->next_item) {

		if (!(item->group == MIB2_SCTP &&
		    item->mib_id == MIB2_SCTP_CONN))
			continue;

		for (sp = item->valp;
		    (char *)sp < (char *)item->valp + item->length;
		    /* LINTED: (note 1) */
		    sp = (mib2_sctpConnEntry_t *)((char *)sp + sctpEntrySize)) {
			attr = aptr == NULL ? NULL : *aptr++;
			if (Aflag ||
			    sp->sctpAssocState >= MIB2_SCTP_established) {
				if (first == B_TRUE) {
					(void) puts(sctp_hdr);
					(void) puts(sctp_hdr_normal);
					first = B_FALSE;
				}
				sctp_conn_report_item(head, sp, attr);
			}
		}
	}
	if (attrs != NULL)
		free(attrs);
}

static char *
plural(int n)
{
	return (n != 1 ? "s" : "");
}

static char *
pluraly(int n)
{
	return (n != 1 ? "ies" : "y");
}

static char *
plurales(int n)
{
	return (n != 1 ? "es" : "");
}

static char *
pktscale(int n)
{
	static char buf[6];
	char t;

	if (n < 1024) {
		t = ' ';
	} else if (n < 1024 * 1024) {
		t = 'k';
		n /= 1024;
	} else if (n < 1024 * 1024 * 1024) {
		t = 'm';
		n /= 1024 * 1024;
	} else {
		t = 'g';
		n /= 1024 * 1024 * 1024;
	}

	(void) snprintf(buf, sizeof (buf), "%4u%c", n, t);
	return (buf);
}

/* --------------------- mrt_report (netstat -m) -------------------------- */

static void
mrt_report(mib_item_t *item)
{
	int		jtemp = 0;
	struct vifctl	*vip;
	vifi_t		vifi;
	struct mfcctl	*mfccp;
	int		numvifs = 0;
	int		nmfc = 0;
	char		abuf[MAXHOSTNAMELEN + 1];

	if (!(family_selected(AF_INET)))
		return;

	/* 'for' loop 1: */
	for (; item; item = item->next_item) {
		if (Xflag) {
			(void) printf("\n--- Entry %d ---\n", ++jtemp);
			(void) printf("Group = %d, mib_id = %d, "
			    "length = %d, valp = 0x%p\n",
			    item->group, item->mib_id, item->length,
			    item->valp);
		}
		if (item->group != EXPER_DVMRP)
			continue; /* 'for' loop 1 */

		switch (item->mib_id) {

		case EXPER_DVMRP_VIF:
			if (Xflag)
				(void) printf("%u records for ipVifTable:\n",
				    item->length/sizeof (struct vifctl));
			if (item->length/sizeof (struct vifctl) == 0) {
				(void) puts("\nVirtual Interface Table is "
				    "empty");
				break;
			}

			(void) puts("\nVirtual Interface Table\n"
			    " Vif Threshold Rate_Limit Local-Address"
			    "   Remote-Address     Pkt_in   Pkt_out");

			/* 'for' loop 2: */
			for (vip = (struct vifctl *)item->valp;
			    (char *)vip < (char *)item->valp + item->length;
			    /* LINTED: (note 1) */
			    vip = (struct vifctl *)((char *)vip +
			    vifctlSize)) {
				if (vip->vifc_lcl_addr.s_addr == 0)
					continue; /* 'for' loop 2 */
				/* numvifs = vip->vifc_vifi; */

				numvifs++;
				(void) printf("  %2u       %3u       "
				    "%4u %-15.15s",
				    vip->vifc_vifi,
				    vip->vifc_threshold,
				    vip->vifc_rate_limit,
				    pr_addr(vip->vifc_lcl_addr.s_addr,
				    abuf, sizeof (abuf)));
				(void) printf(" %-15.15s  %8u  %8u\n",
				    (vip->vifc_flags & VIFF_TUNNEL) ?
				    pr_addr(vip->vifc_rmt_addr.s_addr,
				    abuf, sizeof (abuf)) : "",
				    vip->vifc_pkt_in,
				    vip->vifc_pkt_out);
			} /* 'for' loop 2 ends */

			(void) printf("Numvifs: %d\n", numvifs);
			break;

		case EXPER_DVMRP_MRT:
			if (Xflag)
				(void) printf("%u records for ipMfcTable:\n",
				    item->length/sizeof (struct vifctl));
			if (item->length/sizeof (struct vifctl) == 0) {
				(void) puts("\nMulticast Forwarding Cache is "
				    "empty");
				break;
			}

			(void) puts("\nMulticast Forwarding Cache\n"
			    "  Origin-Subnet                 Mcastgroup      "
			    "# Pkts  In-Vif  Out-vifs/Forw-ttl");

			for (mfccp = (struct mfcctl *)item->valp;
			    (char *)mfccp < (char *)item->valp + item->length;
			    /* LINTED: (note 1) */
			    mfccp = (struct mfcctl *)((char *)mfccp +
			    mfcctlSize)) {

				nmfc++;
				(void) printf("  %-30.15s",
				    pr_addr(mfccp->mfcc_origin.s_addr,
				    abuf, sizeof (abuf)));
				(void) printf("%-15.15s  %6s  %3u    ",
				    pr_net(mfccp->mfcc_mcastgrp.s_addr,
				    mfccp->mfcc_mcastgrp.s_addr,
				    abuf, sizeof (abuf)),
				    pktscale((int)mfccp->mfcc_pkt_cnt),
				    mfccp->mfcc_parent);

				for (vifi = 0; vifi < MAXVIFS; ++vifi) {
					if (mfccp->mfcc_ttls[vifi]) {
						(void) printf("      %u (%u)",
						    vifi,
						    mfccp->mfcc_ttls[vifi]);
					}

				}
				(void) putchar('\n');
			}
			(void) printf("\nTotal no. of entries in cache: %d\n",
			    nmfc);
			break;
		}
	} /* 'for' loop 1 ends */
	(void) putchar('\n');
	(void) fflush(stdout);
}

/*
 * Get the stats for the cache named 'name'.  If prefix != 0, then
 * interpret the name as a prefix, and sum up stats for all caches
 * named 'name*'.
 */
static void
kmem_cache_stats(char *title, char *name, int prefix, int64_t *total_bytes)
{
	int len;
	int alloc;
	int64_t total_alloc = 0;
	int alloc_fail, total_alloc_fail = 0;
	int buf_size = 0;
	int buf_avail;
	int buf_total;
	int buf_max, total_buf_max = 0;
	int buf_inuse, total_buf_inuse = 0;
	kstat_t *ksp;
	char buf[256];

	len = prefix ? strlen(name) : 256;

	/* 'for' loop 1: */
	for (ksp = kc->kc_chain; ksp != NULL; ksp = ksp->ks_next) {

		if (strcmp(ksp->ks_class, "kmem_cache") != 0)
			continue; /* 'for' loop 1 */

		/*
		 * Hack alert: because of the way streams messages are
		 * allocated, every constructed free dblk has an associated
		 * mblk.  From the allocator's viewpoint those mblks are
		 * allocated (because they haven't been freed), but from
		 * our viewpoint they're actually free (because they're
		 * not currently in use).  To account for this caching
		 * effect we subtract the total constructed free dblks
		 * from the total allocated mblks to derive mblks in use.
		 */
		if (strcmp(name, "streams_mblk") == 0 &&
		    strncmp(ksp->ks_name, "streams_dblk", 12) == 0) {
			(void) safe_kstat_read(kc, ksp, NULL);
			total_buf_inuse -=
			    kstat_named_value(ksp, "buf_constructed");
			continue; /* 'for' loop 1 */
		}

		if (strncmp(ksp->ks_name, name, len) != 0)
			continue; /* 'for' loop 1 */

		(void) safe_kstat_read(kc, ksp, NULL);

		alloc		= kstat_named_value(ksp, "alloc");
		alloc_fail	= kstat_named_value(ksp, "alloc_fail");
		buf_size	= kstat_named_value(ksp, "buf_size");
		buf_avail	= kstat_named_value(ksp, "buf_avail");
		buf_total	= kstat_named_value(ksp, "buf_total");
		buf_max		= kstat_named_value(ksp, "buf_max");
		buf_inuse	= buf_total - buf_avail;

		if (Vflag && prefix) {
			(void) snprintf(buf, sizeof (buf), "%s%s", title,
			    ksp->ks_name + len);
			(void) printf("    %-18s %6u %9u %11u %11u\n",
			    buf, buf_inuse, buf_max, alloc, alloc_fail);
		}

		total_alloc		+= alloc;
		total_alloc_fail	+= alloc_fail;
		total_buf_max		+= buf_max;
		total_buf_inuse		+= buf_inuse;
		*total_bytes		+= (int64_t)buf_inuse * buf_size;
	} /* 'for' loop 1 ends */

	if (buf_size == 0) {
		(void) printf("%-22s [couldn't find statistics for %s]\n",
		    title, name);
		return;
	}

	if (Vflag && prefix)
		(void) snprintf(buf, sizeof (buf), "%s_total", title);
	else
		(void) snprintf(buf, sizeof (buf), "%s", title);

	(void) printf("%-22s %6d %9d %11lld %11d\n", buf,
	    total_buf_inuse, total_buf_max, total_alloc, total_alloc_fail);
}

static void
m_report(void)
{
	int64_t total_bytes = 0;

	(void) puts("streams allocation:");
	(void) printf("%63s\n", "cumulative  allocation");
	(void) printf("%63s\n",
	    "current   maximum       total    failures");

	kmem_cache_stats("streams",
	    "stream_head_cache", 0, &total_bytes);
	kmem_cache_stats("queues", "queue_cache", 0, &total_bytes);
	kmem_cache_stats("mblk", "streams_mblk", 0, &total_bytes);
	kmem_cache_stats("dblk", "streams_dblk", 1, &total_bytes);
	kmem_cache_stats("linkblk", "linkinfo_cache", 0, &total_bytes);
	kmem_cache_stats("syncq", "syncq_cache", 0, &total_bytes);
	kmem_cache_stats("qband", "qband_cache", 0, &total_bytes);

	(void) printf("\n%lld Kbytes allocated for streams data\n",
	    total_bytes / 1024);

	(void) putchar('\n');
	(void) fflush(stdout);
}

/* --------------------------------- */

/*
 * Print an IPv4 address. Remove the matching part of the domain name
 * from the returned name.
 */
static char *
pr_addr(uint_t addr, char *dst, uint_t dstlen)
{
	char			*cp;
	struct hostent		*hp = NULL;
	static char		domain[MAXHOSTNAMELEN + 1];
	static boolean_t	first = B_TRUE;
	int			error_num;

	if (first) {
		first = B_FALSE;
		if (sysinfo(SI_HOSTNAME, domain, MAXHOSTNAMELEN) != -1 &&
		    (cp = strchr(domain, '.'))) {
			(void) strncpy(domain, cp + 1, sizeof (domain));
		} else
			domain[0] = 0;
	}
	cp = NULL;
	if (!Nflag) {
		ns_lookup_start();
		hp = getipnodebyaddr((char *)&addr, sizeof (uint_t), AF_INET,
		    &error_num);
		ns_lookup_end();
		if (hp) {
			if ((cp = strchr(hp->h_name, '.')) != NULL &&
			    strcasecmp(cp + 1, domain) == 0)
				*cp = 0;
			cp = hp->h_name;
		}
	}
	if (cp != NULL) {
		(void) strncpy(dst, cp, dstlen);
		dst[dstlen - 1] = 0;
	} else {
		(void) inet_ntop(AF_INET, (char *)&addr, dst, dstlen);
	}
	if (hp != NULL)
		freehostent(hp);
	return (dst);
}

/*
 * Print a non-zero IPv4 address.  Print "    --" if the address is zero.
 */
static char *
pr_addrnz(ipaddr_t addr, char *dst, uint_t dstlen)
{
	if (addr == INADDR_ANY) {
		(void) strlcpy(dst, "    --", dstlen);
		return (dst);
	}
	return (pr_addr(addr, dst, dstlen));
}

/*
 * Print an IPv6 address. Remove the matching part of the domain name
 * from the returned name.
 */
static char *
pr_addr6(const struct in6_addr *addr, char *dst, uint_t dstlen)
{
	char			*cp;
	struct hostent		*hp = NULL;
	static char		domain[MAXHOSTNAMELEN + 1];
	static boolean_t	first = B_TRUE;
	int			error_num;

	if (first) {
		first = B_FALSE;
		if (sysinfo(SI_HOSTNAME, domain, MAXHOSTNAMELEN) != -1 &&
		    (cp = strchr(domain, '.'))) {
			(void) strncpy(domain, cp + 1, sizeof (domain));
		} else
			domain[0] = 0;
	}
	cp = NULL;
	if (!Nflag) {
		ns_lookup_start();
		hp = getipnodebyaddr((char *)addr,
		    sizeof (struct in6_addr), AF_INET6, &error_num);
		ns_lookup_end();
		if (hp) {
			if ((cp = strchr(hp->h_name, '.')) != NULL &&
			    strcasecmp(cp + 1, domain) == 0)
				*cp = 0;
			cp = hp->h_name;
		}
	}
	if (cp != NULL) {
		(void) strncpy(dst, cp, dstlen);
		dst[dstlen - 1] = 0;
	} else {
		(void) inet_ntop(AF_INET6, (void *)addr, dst, dstlen);
	}
	if (hp != NULL)
		freehostent(hp);
	return (dst);
}

/* For IPv4 masks */
static char *
pr_mask(uint_t addr, char *dst, uint_t dstlen)
{
	uint8_t	*ip_addr = (uint8_t *)&addr;

	(void) snprintf(dst, dstlen, "%d.%d.%d.%d",
	    ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
	return (dst);
}

/*
 * For ipv6 masks format is : dest/mask
 * Does not print /128 to save space in printout. H flag carries this notion.
 */
static char *
pr_prefix6(const struct in6_addr *addr, uint_t prefixlen, char *dst,
    uint_t dstlen)
{
	char *cp;

	if (IN6_IS_ADDR_UNSPECIFIED(addr) && prefixlen == 0) {
		(void) strncpy(dst, "default", dstlen);
		dst[dstlen - 1] = 0;
		return (dst);
	}

	(void) pr_addr6(addr, dst, dstlen);
	if (prefixlen != IPV6_ABITS) {
		/* How much room is left? */
		cp = strchr(dst, '\0');
		if (dst + dstlen > cp) {
			dstlen -= (cp - dst);
			(void) snprintf(cp, dstlen, "/%d", prefixlen);
		}
	}
	return (dst);
}

/* Print IPv4 address and port */
static char *
pr_ap(uint_t addr, uint_t port, char *proto,
    char *dst, uint_t dstlen)
{
	char *cp;

	if (addr == INADDR_ANY) {
		(void) strncpy(dst, "      *", dstlen);
		dst[dstlen - 1] = 0;
	} else {
		(void) pr_addr(addr, dst, dstlen);
	}
	/* How much room is left? */
	cp = strchr(dst, '\0');
	if (dst + dstlen > cp + 1) {
		*cp++ = '.';
		dstlen -= (cp - dst);
		dstlen--;
		(void) portname(port, proto, cp, dstlen);
	}
	return (dst);
}

/* Print IPv6 address and port */
static char *
pr_ap6(const in6_addr_t *addr, uint_t port, char *proto,
    char *dst, uint_t dstlen)
{
	char *cp;

	if (IN6_IS_ADDR_UNSPECIFIED(addr)) {
		(void) strncpy(dst, "      *", dstlen);
		dst[dstlen - 1] = 0;
	} else {
		(void) pr_addr6(addr, dst, dstlen);
	}
	/* How much room is left? */
	cp = strchr(dst, '\0');
	if (dst + dstlen + 1 > cp) {
		*cp++ = '.';
		dstlen -= (cp - dst);
		dstlen--;
		(void) portname(port, proto, cp, dstlen);
	}
	return (dst);
}

/*
 * Return the name of the network whose address is given. The address is
 * assumed to be that of a net or subnet, not a host.
 */
static char *
pr_net(uint_t addr, uint_t mask, char *dst, uint_t dstlen)
{
	char		*cp = NULL;
	struct netent	*np = NULL;
	struct hostent	*hp = NULL;
	uint_t		net;
	int		subnetshift;
	int		error_num;

	if (addr == INADDR_ANY && mask == INADDR_ANY) {
		(void) strncpy(dst, "default", dstlen);
		dst[dstlen - 1] = 0;
		return (dst);
	}

	if (!Nflag && addr) {
		if (mask == 0) {
			if (IN_CLASSA(addr)) {
				mask = (uint_t)IN_CLASSA_NET;
				subnetshift = 8;
			} else if (IN_CLASSB(addr)) {
				mask = (uint_t)IN_CLASSB_NET;
				subnetshift = 8;
			} else {
				mask = (uint_t)IN_CLASSC_NET;
				subnetshift = 4;
			}
			/*
			 * If there are more bits than the standard mask
			 * would suggest, subnets must be in use. Guess at
			 * the subnet mask, assuming reasonable width subnet
			 * fields.
			 */
			while (addr & ~mask)
				/* compiler doesn't sign extend! */
				mask = (mask | ((int)mask >> subnetshift));
		}
		net = addr & mask;
		while ((mask & 1) == 0)
			mask >>= 1, net >>= 1;
		ns_lookup_start();
		np = getnetbyaddr(net, AF_INET);
		ns_lookup_end();
		if (np && np->n_net == net)
			cp = np->n_name;
		else {
			/*
			 * Look for subnets in hosts map.
			 */
			ns_lookup_start();
			hp = getipnodebyaddr((char *)&addr, sizeof (uint_t),
			    AF_INET, &error_num);
			ns_lookup_end();
			if (hp)
				cp = hp->h_name;
		}
	}
	if (cp != NULL) {
		(void) strncpy(dst, cp, dstlen);
		dst[dstlen - 1] = 0;
	} else {
		(void) inet_ntop(AF_INET, (char *)&addr, dst, dstlen);
	}
	if (hp != NULL)
		freehostent(hp);
	return (dst);
}

/*
 * Return the name of the network whose address is given.
 * The address is assumed to be a host address.
 */
static char *
pr_netaddr(uint_t addr, uint_t mask, char *dst, uint_t dstlen)
{
	char		*cp = NULL;
	struct netent	*np = NULL;
	struct hostent	*hp = NULL;
	uint_t		net;
	uint_t		netshifted;
	int		subnetshift;
	struct in_addr in;
	int		error_num;
	uint_t		nbo_addr = addr;	/* network byte order */

	addr = ntohl(addr);
	mask = ntohl(mask);
	if (addr == INADDR_ANY && mask == INADDR_ANY) {
		(void) strncpy(dst, "default", dstlen);
		dst[dstlen - 1] = 0;
		return (dst);
	}

	/* Figure out network portion of address (with host portion = 0) */
	if (addr) {
		/* Try figuring out mask if unknown (all 0s). */
		if (mask == 0) {
			if (IN_CLASSA(addr)) {
				mask = (uint_t)IN_CLASSA_NET;
				subnetshift = 8;
			} else if (IN_CLASSB(addr)) {
				mask = (uint_t)IN_CLASSB_NET;
				subnetshift = 8;
			} else {
				mask = (uint_t)IN_CLASSC_NET;
				subnetshift = 4;
			}
			/*
			 * If there are more bits than the standard mask
			 * would suggest, subnets must be in use. Guess at
			 * the subnet mask, assuming reasonable width subnet
			 * fields.
			 */
			while (addr & ~mask)
				/* compiler doesn't sign extend! */
				mask = (mask | ((int)mask >> subnetshift));
		}
		net = netshifted = addr & mask;
		while ((mask & 1) == 0)
			mask >>= 1, netshifted >>= 1;
	}
	else
		net = netshifted = 0;

	/* Try looking up name unless -n was specified. */
	if (!Nflag) {
		ns_lookup_start();
		np = getnetbyaddr(netshifted, AF_INET);
		ns_lookup_end();
		if (np && np->n_net == netshifted)
			cp = np->n_name;
		else {
			/*
			 * Look for subnets in hosts map.
			 */
			ns_lookup_start();
			hp = getipnodebyaddr((char *)&nbo_addr, sizeof (uint_t),
			    AF_INET, &error_num);
			ns_lookup_end();
			if (hp)
				cp = hp->h_name;
		}

		if (cp != NULL) {
			(void) strncpy(dst, cp, dstlen);
			dst[dstlen - 1] = 0;
			if (hp != NULL)
				freehostent(hp);
			return (dst);
		}
		/*
		 * No name found for net: fallthru and return in decimal
		 * dot notation.
		 */
	}

	in.s_addr = htonl(net);
	(void) inet_ntop(AF_INET, (char *)&in, dst, dstlen);
	if (hp != NULL)
		freehostent(hp);
	return (dst);
}

/*
 * Return the filter mode as a string:
 *	1 => "INCLUDE"
 *	2 => "EXCLUDE"
 *	otherwise "<unknown>"
 */
static char *
fmodestr(uint_t fmode)
{
	switch (fmode) {
	case 1:
		return ("INCLUDE");
	case 2:
		return ("EXCLUDE");
	default:
		return ("<unknown>");
	}
}

#define	MAX_STRING_SIZE	256

static const char *
pr_secattr(const sec_attr_list_t *attrs)
{
	int i;
	char buf[MAX_STRING_SIZE + 1], *cp;
	static char *sbuf;
	static size_t sbuf_len;
	struct rtsa_s rtsa;
	const sec_attr_list_t *aptr;

	if (!RSECflag || attrs == NULL)
		return ("");

	for (aptr = attrs, i = 1; aptr != NULL; aptr = aptr->sal_next)
		i += MAX_STRING_SIZE;
	if (i > sbuf_len) {
		cp = realloc(sbuf, i);
		if (cp == NULL) {
			perror("realloc security attribute buffer");
			return ("");
		}
		sbuf_len = i;
		sbuf = cp;
	}

	cp = sbuf;
	while (attrs != NULL) {
		const mib2_ipAttributeEntry_t *iae = attrs->sal_attr;

		/* note: effectively hard-coded in rtsa_keyword */
		rtsa.rtsa_mask = RTSA_CIPSO | RTSA_SLRANGE | RTSA_DOI;
		rtsa.rtsa_slrange = iae->iae_slrange;
		rtsa.rtsa_doi = iae->iae_doi;

		(void) snprintf(cp, MAX_STRING_SIZE,
		    "<%s>%s ", rtsa_to_str(&rtsa, buf, sizeof (buf)),
		    attrs->sal_next == NULL ? "" : ",");
		cp += strlen(cp);
		attrs = attrs->sal_next;
	}
	*cp = '\0';

	return (sbuf);
}

/*
 * Pretty print a port number. If the Nflag was
 * specified, use numbers instead of names.
 */
static char *
portname(uint_t port, char *proto, char *dst, uint_t dstlen)
{
	struct servent *sp = NULL;

	if (!Nflag && port) {
		ns_lookup_start();
		sp = getservbyport(htons(port), proto);
		ns_lookup_end();
	}
	if (sp || port == 0)
		(void) snprintf(dst, dstlen, "%.*s", MAXHOSTNAMELEN,
		    sp ? sp->s_name : "*");
	else
		(void) snprintf(dst, dstlen, "%d", port);
	dst[dstlen - 1] = 0;
	return (dst);
}

/*PRINTFLIKE2*/
void
fail(int do_perror, char *message, ...)
{
	va_list args;

	va_start(args, message);
	(void) fputs("netstat: ", stderr);
	(void) vfprintf(stderr, message, args);
	va_end(args);
	if (do_perror)
		(void) fprintf(stderr, ": %s", strerror(errno));
	(void) fputc('\n', stderr);
	exit(2);
}

/*
 * Return value of named statistic for given kstat_named kstat;
 * return 0LL if named statistic is not in list (use "ll" as a
 * type qualifier when printing 64-bit int's with printf() )
 */
static uint64_t
kstat_named_value(kstat_t *ksp, char *name)
{
	kstat_named_t *knp;
	uint64_t value;

	if (ksp == NULL)
		return (0LL);

	knp = kstat_data_lookup(ksp, name);
	if (knp == NULL)
		return (0LL);

	switch (knp->data_type) {
	case KSTAT_DATA_INT32:
	case KSTAT_DATA_UINT32:
		value = (uint64_t)(knp->value.ui32);
		break;
	case KSTAT_DATA_INT64:
	case KSTAT_DATA_UINT64:
		value = knp->value.ui64;
		break;
	default:
		value = 0LL;
		break;
	}

	return (value);
}

kid_t
safe_kstat_read(kstat_ctl_t *kc, kstat_t *ksp, void *data)
{
	kid_t kstat_chain_id = kstat_read(kc, ksp, data);

	if (kstat_chain_id == -1)
		fail(1, "kstat_read(%p, '%s') failed", (void *)kc,
		    ksp->ks_name);
	return (kstat_chain_id);
}

/*
 * Parse a list of IRE flag characters into a bit field.
 */
static uint_t
flag_bits(const char *arg)
{
	const char *cp;
	uint_t val;

	if (*arg == '\0')
		fatal(1, "missing flag list\n");

	val = 0;
	while (*arg != '\0') {
		if ((cp = strchr(flag_list, *arg)) == NULL)
			fatal(1, "%c: illegal flag\n", *arg);
		val |= 1 << (cp - flag_list);
		arg++;
	}
	return (val);
}

/*
 * Handle -f argument.  Validate input format, sort by keyword, and
 * save off digested results.
 */
static void
process_filter(char *arg)
{
	int idx;
	int klen = 0;
	char *cp, *cp2;
	int val;
	filter_t *newf;
	struct hostent *hp;
	int error_num;
	uint8_t *ucp;
	int maxv;

	/* Look up the keyword first */
	if (strchr(arg, ':') == NULL) {
		idx = FK_AF;
	} else {
		for (idx = 0; idx < NFILTERKEYS; idx++) {
			klen = strlen(filter_keys[idx]);
			if (strncmp(filter_keys[idx], arg, klen) == 0 &&
			    arg[klen] == ':')
				break;
		}
		if (idx >= NFILTERKEYS)
			fatal(1, "%s: unknown filter keyword\n", arg);

		/* Advance past keyword and separator. */
		arg += klen + 1;
	}

	if ((newf = malloc(sizeof (*newf))) == NULL) {
		perror("filter");
		exit(1);
	}
	switch (idx) {
	case FK_AF:
		if (strcmp(arg, "inet") == 0) {
			newf->u.f_family = AF_INET;
		} else if (strcmp(arg, "inet6") == 0) {
			newf->u.f_family = AF_INET6;
		} else if (strcmp(arg, "unix") == 0) {
			newf->u.f_family = AF_UNIX;
		} else {
			newf->u.f_family = strtol(arg, &cp, 0);
			if (arg == cp || *cp != '\0')
				fatal(1, "%s: unknown address family.\n", arg);
		}
		break;

	case FK_OUTIF:
		if (strcmp(arg, "none") == 0) {
			newf->u.f_ifname = NULL;
			break;
		}
		if (strcmp(arg, "any") == 0) {
			newf->u.f_ifname = "";
			break;
		}
		val = strtol(arg, &cp, 0);
		if (val <= 0 || arg == cp || cp[0] != '\0') {
			if ((val = if_nametoindex(arg)) == 0) {
				perror(arg);
				exit(1);
			}
		}
		newf->u.f_ifname = arg;
		break;

	case FK_DST:
		V4MASK_TO_V6(IP_HOST_MASK, newf->u.a.f_mask);
		if (strcmp(arg, "any") == 0) {
			/* Special semantics; any address *but* zero */
			newf->u.a.f_address = NULL;
			(void) memset(&newf->u.a.f_mask, 0,
			    sizeof (newf->u.a.f_mask));
			break;
		}
		if (strcmp(arg, "none") == 0) {
			newf->u.a.f_address = NULL;
			break;
		}
		if ((cp = strrchr(arg, '/')) != NULL)
			*cp++ = '\0';
		hp = getipnodebyname(arg, AF_INET6, AI_V4MAPPED|AI_ALL,
		    &error_num);
		if (hp == NULL)
			fatal(1, "%s: invalid or unknown host address\n", arg);
		newf->u.a.f_address = hp;
		if (cp == NULL) {
			V4MASK_TO_V6(IP_HOST_MASK, newf->u.a.f_mask);
		} else {
			val = strtol(cp, &cp2, 0);
			if (cp != cp2 && cp2[0] == '\0') {
				/*
				 * If decode as "/n" works, then translate
				 * into a mask.
				 */
				if (hp->h_addr_list[0] != NULL &&
				    /* LINTED: (note 1) */
				    IN6_IS_ADDR_V4MAPPED((in6_addr_t *)
				    hp->h_addr_list[0])) {
					maxv = IP_ABITS;
				} else {
					maxv = IPV6_ABITS;
				}
				if (val < 0 || val >= maxv)
					fatal(1, "%d: not in range 0 to %d\n",
					    val, maxv - 1);
				if (maxv == IP_ABITS)
					val += IPV6_ABITS - IP_ABITS;
				ucp = newf->u.a.f_mask.s6_addr;
				while (val >= 8)
					*ucp++ = 0xff, val -= 8;
				*ucp++ = (0xff << (8 - val)) & 0xff;
				while (ucp < newf->u.a.f_mask.s6_addr +
				    sizeof (newf->u.a.f_mask.s6_addr))
					*ucp++ = 0;
				/* Otherwise, try as numeric address */
			} else if (inet_pton(AF_INET6,
			    cp, &newf->u.a.f_mask) <= 0) {
				fatal(1, "%s: illegal mask format\n", cp);
			}
		}
		break;

	case FK_FLAGS:
		if (*arg == '+') {
			newf->u.f.f_flagset = flag_bits(arg + 1);
			newf->u.f.f_flagclear = 0;
		} else if (*arg == '-') {
			newf->u.f.f_flagset = 0;
			newf->u.f.f_flagclear = flag_bits(arg + 1);
		} else {
			newf->u.f.f_flagset = flag_bits(arg);
			newf->u.f.f_flagclear = ~newf->u.f.f_flagset;
		}
		break;

	default:
		assert(0);
	}
	newf->f_next = filters[idx];
	filters[idx] = newf;
}

/* Determine if user wants this address family printed. */
static boolean_t
family_selected(int family)
{
	const filter_t *fp;

	if (v4compat && family == AF_INET6)
		return (B_FALSE);
	if ((fp = filters[FK_AF]) == NULL)
		return (B_TRUE);
	while (fp != NULL) {
		if (fp->u.f_family == family)
			return (B_TRUE);
		fp = fp->f_next;
	}
	return (B_FALSE);
}

/*
 * Convert the interface index to a string using the buffer `ifname', which
 * must be at least LIFNAMSIZ bytes.  We first try to map it to name.  If that
 * fails (e.g., because we're inside a zone and it does not have access to
 * interface for the index in question), just return "if#<num>".
 */
static char *
ifindex2str(uint_t ifindex, char *ifname)
{
	if (if_indextoname(ifindex, ifname) == NULL)
		(void) snprintf(ifname, LIFNAMSIZ, "if#%d", ifindex);

	return (ifname);
}

/*
 * print the usage line
 */
static void
usage(char *cmdname)
{
	(void) fprintf(stderr, "usage: %s [-anv] [-f address_family] "
	    "[-T d|u]\n", cmdname);
	(void) fprintf(stderr, "       %s [-n] [-f address_family] "
	    "[-P protocol] [-T d|u] [-g | -p | -s [interval [count]]]\n",
	    cmdname);
	(void) fprintf(stderr, "       %s -m [-v] [-T d|u] "
	    "[interval [count]]\n", cmdname);
	(void) fprintf(stderr, "       %s -i [-I interface] [-an] "
	    "[-f address_family] [-T d|u] [interval [count]]\n", cmdname);
	(void) fprintf(stderr, "       %s -r [-anv] "
	    "[-f address_family|filter] [-T d|u]\n", cmdname);
	(void) fprintf(stderr, "       %s -M [-ns] [-f address_family] "
	    "[-T d|u]\n", cmdname);
	(void) fprintf(stderr, "       %s -D [-I interface] "
	    "[-f address_family] [-T d|u]\n", cmdname);
	exit(EXIT_FAILURE);
}

/*
 * fatal: print error message to stderr and
 * call exit(errcode)
 */
/*PRINTFLIKE2*/
static void
fatal(int errcode, char *format, ...)
{
	va_list argp;

	if (format == NULL)
		return;

	va_start(argp, format);
	(void) vfprintf(stderr, format, argp);
	va_end(argp);

	exit(errcode);
}
