/*
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/* All Rights Reserved	*/

/* Copyright (c) 1990  Mentat Inc. */
/* Copyright 2018, Joyent, Inc. */

/*
 *
 * Copyright (c) 1983, 1989, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)route.c	8.6 (Berkeley) 4/28/95
 *	@(#)linkaddr.c	8.1 (Berkeley) 6/4/93
 */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/stream.h>
#include <sys/sysmacros.h>
#include <sys/tihdr.h>
#include <sys/types.h>
#include <sys/ccompile.h>

#include <net/if.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <inet/mib2.h>
#include <inet/ip.h>

#include <limits.h>
#include <locale.h>

#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stropts.h>
#include <fcntl.h>
#include <stdarg.h>
#include <assert.h>
#include <strings.h>

#include <libcontract.h>
#include <sys/ctfs.h>
#include <sys/contract/process.h>
#include <sys/wait.h>
#include <libzonecfg.h>
#include <zone.h>

#include <libtsnet.h>
#include <tsol/label.h>

static struct keytab {
	char	*kt_cp;
	int	kt_i;
} keywords[] = {
#define	K_ADD		1
	{"add",		K_ADD},
#define	K_BLACKHOLE	2
	{"blackhole",	K_BLACKHOLE},
#define	K_CHANGE	3
	{"change",	K_CHANGE},
#define	K_CLONING	4
	{"cloning",	K_CLONING},
#define	K_DELETE	5
	{"delete",	K_DELETE},
#define	K_DST		6
	{"dst",		K_DST},
#define	K_EXPIRE	7
	{"expire",	K_EXPIRE},
#define	K_FLUSH		8
	{"flush",	K_FLUSH},
#define	K_GATEWAY	9
	{"gateway",	K_GATEWAY},
#define	K_GET		11
	{"get",		K_GET},
#define	K_HOPCOUNT	12
	{"hopcount",	K_HOPCOUNT},
#define	K_HOST		13
	{"host",	K_HOST},
#define	K_IFA		14
	{"ifa",		K_IFA},
#define	K_IFACE		15
	{"iface",	K_IFACE},
#define	K_IFP		16
	{"ifp",		K_IFP},
#define	K_INET		17
	{"inet",	K_INET},
#define	K_INET6		18
	{"inet6",	K_INET6},
#define	K_INTERFACE	19
	{"interface",	K_INTERFACE},
#define	K_LINK		20
	{"link",	K_LINK},
#define	K_LOCK		21
	{"lock",	K_LOCK},
#define	K_LOCKREST	22
	{"lockrest",	K_LOCKREST},
#define	K_MASK		23
	{"mask",	K_MASK},
#define	K_MONITOR	24
	{"monitor",	K_MONITOR},
#define	K_MTU		25
	{"mtu",		K_MTU},
#define	K_NET		26
	{"net",		K_NET},
#define	K_NETMASK	27
	{"netmask",	K_NETMASK},
#define	K_NOSTATIC	28
	{"nostatic",	K_NOSTATIC},
#define	K_PRIVATE	29
	{"private",	K_PRIVATE},
#define	K_PROTO1	30
	{"proto1",	K_PROTO1},
#define	K_PROTO2	31
	{"proto2",	K_PROTO2},
#define	K_RECVPIPE	32
	{"recvpipe",	K_RECVPIPE},
#define	K_REJECT	33
	{"reject",	K_REJECT},
#define	K_RTT		34
	{"rtt",		K_RTT},
#define	K_RTTVAR	35
	{"rttvar",	K_RTTVAR},
#define	K_SA		36
	{"sa",		K_SA},
#define	K_SENDPIPE	37
	{"sendpipe",	K_SENDPIPE},
#define	K_SSTHRESH	38
	{"ssthresh",	K_SSTHRESH},
#define	K_STATIC	39
	{"static",	K_STATIC},
#define	K_XRESOLVE	40
	{"xresolve",	K_XRESOLVE},
#define	K_MULTIRT	41
	{"multirt",	K_MULTIRT},
#define	K_SETSRC	42
	{"setsrc",	K_SETSRC},
#define	K_SHOW		43
	{"show",	K_SHOW},
#define	K_SECATTR	43
	{"secattr",	K_SECATTR},
#define	K_INDIRECT	44
	{"indirect",	K_INDIRECT},
	{0, 0}
};

/*
 * Size of buffers used to hold command lines from the saved route file as
 * well as error strings.
 */
#define	BUF_SIZE 2048

typedef union sockunion {
	struct	sockaddr sa;
	struct	sockaddr_in sin;
	struct	sockaddr_dl sdl;
	struct	sockaddr_in6 sin6;
} su_t;

/*
 * This structure represents the digested information from parsing arguments
 * to route add, change, delete, and get.
 *
 */
typedef struct rtcmd_irep {
	int ri_cmd;
	int ri_flags;
	int ri_af;
	ulong_t	ri_inits;
	struct rt_metrics ri_metrics;
	int ri_addrs;
	su_t ri_dst;
	char *ri_dest_str;
	su_t ri_src;
	su_t ri_gate;
	struct hostent *ri_gate_hp;
	char *ri_gate_str;
	su_t ri_mask;
	su_t ri_ifa;
	su_t ri_ifp;
	char *ri_ifp_str;
	int ri_rtsa_cnt;	/* number of gateway security attributes */
	struct rtsa_s ri_rtsa;	/* enough space for one attribute */
} rtcmd_irep_t;

typedef struct	mib_item_s {
	struct mib_item_s *next_item;
	long group;
	long mib_id;
	long length;
	intmax_t *valp;
} mib_item_t;

typedef enum {
	ADDR_TYPE_ANY,
	ADDR_TYPE_HOST,
	ADDR_TYPE_NET
} addr_type_t;

typedef enum {
	SEARCH_MODE_NULL,
	SEARCH_MODE_PRINT,
	SEARCH_MODE_DEL
} search_mode_t;

static boolean_t	args_to_rtcmd(rtcmd_irep_t *rcip, char **argv,
    char *cmd_string);
static void		bprintf(FILE *fp, int b, char *s);
static boolean_t	compare_rtcmd(rtcmd_irep_t *srch_rt,
    rtcmd_irep_t *file_rt);
static void		delRouteEntry(mib2_ipRouteEntry_t *rp,
    mib2_ipv6RouteEntry_t *rp6, int seqno);
static void		del_rtcmd_irep(rtcmd_irep_t *rcip);
static void		flushroutes(int argc, char *argv[]);
static boolean_t	getaddr(rtcmd_irep_t *rcip, int which, char *s,
    addr_type_t atype);
static boolean_t	in6_getaddr(char *s, struct sockaddr_in6 *sin6,
    int *plenp, struct hostent **hpp);
static boolean_t	in_getaddr(char *s, struct sockaddr_in *sin,
    int *plenp, int which, struct hostent **hpp, addr_type_t atype,
    rtcmd_irep_t *rcip);
static int		in_getprefixlen(char *addr, int max_plen);
static boolean_t	in_prefixlentomask(int prefixlen, int maxlen,
    uchar_t *mask);
static void		inet_makenetandmask(rtcmd_irep_t *rcip, in_addr_t net,
    struct sockaddr_in *sin);
static in_addr_t	inet_makesubnetmask(in_addr_t addr, in_addr_t mask);
static int		keyword(const char *cp);
static void		link_addr(const char *addr, struct sockaddr_dl *sdl);
static char		*link_ntoa(const struct sockaddr_dl *sdl);
static mib_item_t	*mibget(int sd);
static char		*netname(struct sockaddr *sa);
static int		newroute(char **argv);
static rtcmd_irep_t	*new_rtcmd_irep(void);
static void		pmsg_addrs(const char *cp, size_t len, uint_t addrs);
static void		pmsg_common(const struct rt_msghdr *rtm, size_t len);
static void		print_getmsg(rtcmd_irep_t *req_rt,
    struct rt_msghdr *rtm, int msglen);
static void		print_rtcmd_short(FILE *to, rtcmd_irep_t *rcip,
    boolean_t gw_good, boolean_t to_saved);
static void		print_rtmsg(struct rt_msghdr *rtm, int msglen);
static void		quit(char *s, int err) __NORETURN;
static char		*routename(const struct sockaddr *sa);
static void		rtmonitor(int argc, char *argv[]);
static int		rtmsg(rtcmd_irep_t *rcip);
static int		salen(const struct sockaddr *sa);
static void		save_route(int argc, char **argv, int do_flush);
static void		save_string(char **dst, char *src);
static int		search_rtfile(FILE *fp, FILE *temp_fp, rtcmd_irep_t *rt,
    search_mode_t mode);
static void		set_metric(rtcmd_irep_t *rcip, char *value, int key,
    boolean_t lock);
static int		show_saved_routes(int argc);
static void		sockaddr(char *addr, struct sockaddr *sa);
static void		sodump(su_t *su, char *which);
static void		syntax_arg_missing(char *keyword);
static void		syntax_bad_keyword(char *keyword);
static void		syntax_error(char *err, ...);
static void		usage(char *cp);
static void		write_to_rtfile(FILE *fp, int argc, char **argv);
static void		pmsg_secattr(const char *, size_t, const char *);
static void		do_zone(char *);

static pid_t		pid;
static int		s;
static boolean_t	nflag;
static int		af = AF_INET;
static boolean_t	qflag, tflag;
static boolean_t	verbose;
static boolean_t	debugonly;
static boolean_t	fflag;
static boolean_t	update_table;
static boolean_t	perm_flag;
static boolean_t	early_v6_keyword;
static char		perm_file_sfx[] = "/etc/inet/static_routes";
static char		*perm_file;
static char		temp_file_sfx[] = "/etc/inet/static_routes.tmp";
static char		*temp_file;
static char		*zonename;
static struct in6_addr	in6_host_mask = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
/*
 * WARNING:
 * This next variable indicates whether certain functions exit when an error
 * is detected in the user input.  Currently, exit_on_error is only set false
 * in search_rtfile(), when argument are being parsed.  Only those functions
 * used by search_rtfile() to parse its arguments are designed to work in
 * both modes.  Take particular care in setting this false to ensure that any
 * functions you call that might act on this flag properly return errors when
 * exit_on_error is false.
 */
static int		exit_on_error = B_TRUE;

static struct {
	struct	rt_msghdr m_rtm;
	char	m_space[BUF_SIZE];
} m_rtmsg;

/*
 * Sizes of data structures extracted from the base mib.
 * This allows the size of the tables entries to grow while preserving
 * binary compatibility.
 */
static int ipRouteEntrySize;
static int ipv6RouteEntrySize;

#define	ROUNDUP_LONG(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof (long) - 1))) : sizeof (long))
#define	ADVANCE(x, n) ((x) += ROUNDUP_LONG(salen(n)))
#define	C(x)	((x) & 0xff)

/*
 * return values from in_getprefixlen()
 */
#define	BAD_ADDR	-1	/* prefix is invalid */
#define	NO_PREFIX	-2	/* no prefix was found */

void
usage(char *cp)
{
	if (cp != NULL) {
		(void) fprintf(stderr, gettext("route: botched keyword: %s\n"),
		    cp);
	}
	(void) fprintf(stderr, gettext("usage: route [ -fnpqv ] "
	    "[-z <zone> ] [ -R <root-dir> ] cmd [[ -<qualifers> ] args ]\n"));
	exit(1);
	/* NOTREACHED */
}

/*PRINTFLIKE1*/
void
syntax_error(char *err, ...)
{
	va_list args;

	if (exit_on_error) {
		va_start(args, err);
		(void) vfprintf(stderr, err, args);
		va_end(args);
		exit(1);
	}
	/* NOTREACHED */
}

void
syntax_bad_keyword(char *keyword)
{
	syntax_error(gettext("route: botched keyword: %s\n"), keyword);
}

void
syntax_arg_missing(char *keyword)
{
	syntax_error(gettext("route: argument required following keyword %s\n"),
	    keyword);
}

void
quit(char *s, int sverrno)
{
	(void) fprintf(stderr, "route: ");
	if (s != NULL)
		(void) fprintf(stderr, "%s: ", s);
	(void) fprintf(stderr, "%s\n", strerror(sverrno));
	exit(sverrno);
	/* NOTREACHED */
}

int
main(int argc, char **argv)
{
	extern int optind;
	extern char *optarg;
	int ch;
	int rval;
	size_t size;
	const char *root_dir = NULL;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (argc < 2)
		usage(NULL);

	while ((ch = getopt(argc, argv, "R:nqdtvfpz:")) != EOF) {
		switch (ch) {
		case 'n':
			nflag = B_TRUE;
			break;
		case 'q':
			qflag = B_TRUE;
			break;
		case 'v':
			verbose = B_TRUE;
			break;
		case 't':
			tflag = B_TRUE;
			break;
		case 'd':
			debugonly = B_TRUE;
			break;
		case 'f':
			fflag = B_TRUE;
			break;
		case 'p':
			perm_flag = B_TRUE;
			break;
		case 'R':
			root_dir = optarg;
			break;
		case 'z':
			zonename = optarg;
			break;
		case '?':
		default:
			usage(NULL);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;

	do_zone(zonename);

	pid = getpid();
	if (tflag)
		s = open("/dev/null", O_WRONLY);
	else
		s = socket(PF_ROUTE, SOCK_RAW, 0);
	if (s < 0)
		quit("socket", errno);

	/*
	 * Handle the -p and -R flags.  The -R flag only applies
	 * when the -p flag is set.
	 */
	if (root_dir == NULL) {
		perm_file = perm_file_sfx;
		temp_file = temp_file_sfx;
	} else {
		size = strlen(root_dir) + sizeof (perm_file_sfx);
		perm_file = malloc(size);
		if (perm_file == NULL)
			quit("malloc", errno);
		(void) snprintf(perm_file, size, "%s%s", root_dir,
		    perm_file_sfx);
		size = strlen(root_dir) + sizeof (temp_file_sfx);
		temp_file = malloc(size);
		if (temp_file == NULL)
			quit("malloc", errno);
		(void) snprintf(temp_file, size, "%s%s", root_dir,
		    temp_file_sfx);
	}
	/*
	 * Whether or not to act on the routing table.  The only time the
	 * routing table is not modified is when both -p and -R are present.
	 */
	update_table = (!perm_flag || root_dir == NULL);
	if (tflag)
		perm_flag = 0;

	if (fflag) {
		/*
		 * Accept an address family keyword after the -f.  Since the
		 * default address family is AF_INET, reassign af only for the
		 * other valid address families.
		 */
		if (*argv != NULL) {
			switch (keyword(*argv)) {
			case K_INET6:
				af = AF_INET6;
				early_v6_keyword = B_TRUE;
				/* fallthrough */
			case K_INET:
				/* Skip over the address family parameter. */
				argc--;
				argv++;
				break;
			}
		}
		flushroutes(0, NULL);
	}

	if (*argv != NULL) {
		switch (keyword(*argv)) {
		case K_GET:
		case K_CHANGE:
		case K_ADD:
		case K_DELETE:
			rval = 0;
			if (update_table) {
				rval = newroute(argv);
			}
			if (perm_flag && (rval == 0 || rval == EEXIST ||
			    rval == ESRCH)) {
				save_route(argc, argv, B_FALSE);
				return (0);
			}
			return (rval);
		case K_SHOW:
			if (perm_flag) {
				return (show_saved_routes(argc));
			} else {
				syntax_error(gettext(
				    "route: show command requires -p\n"));
			}
			/* NOTREACHED */
		case K_MONITOR:
			rtmonitor(argc, argv);
			/* NOTREACHED */

		case K_FLUSH:
			flushroutes(argc, argv);
			return (0);
		}
	}
	if (!fflag)
		usage(*argv);
	return (0);
}

/*
 * Purge all entries in the routing tables not
 * associated with network interfaces.
 */
void
flushroutes(int argc, char *argv[])
{
	int seqno;
	int sd;	/* mib stream */
	mib_item_t	*item;
	mib2_ipRouteEntry_t *rp;
	mib2_ipv6RouteEntry_t *rp6;
	int oerrno;
	int off = 0;
	int on = 1;

	if (argc > 1) {
		argv++;
		if (argc == 2 && **argv == '-') {
			/*
			 * The address family (preceded by a dash) may be used
			 * to flush the routes of that particular family.
			 */
			switch (keyword(*argv + 1)) {
			case K_INET:
				af = AF_INET;
				break;
			case K_LINK:
				af = AF_LINK;
				break;
			case K_INET6:
				af = AF_INET6;
				break;
			default:
				usage(*argv);
				/* NOTREACHED */
			}
		} else {
			usage(*argv);
		}
	}
	if (perm_flag) {
		/* This flushes the persistent route file */
		save_route(0, NULL, B_TRUE);
	}
	if (!update_table) {
		return;
	}

	if (setsockopt(s, SOL_SOCKET, SO_USELOOPBACK, (char *)&off,
	    sizeof (off)) < 0)
		quit("setsockopt", errno);

	sd = open("/dev/ip", O_RDWR);
	oerrno = errno;
	if (sd < 0) {
		switch (errno) {
		case EACCES:
			(void) fprintf(stderr,
			    gettext("route: flush: insufficient privileges\n"));
			exit(oerrno);
			/* NOTREACHED */
		default:
			quit(gettext("can't open mib stream"), oerrno);
			/* NOTREACHED */
		}
	}
	if ((item = mibget(sd)) == NULL)
		quit("mibget", errno);
	if (verbose) {
		(void) printf("Examining routing table from "
		    "T_SVR4_OPTMGMT_REQ\n");
	}
	seqno = 0;		/* ??? */
	switch (af) {
	case AF_INET:
		/* Extract ipRouteEntrySize */
		for (; item != NULL; item = item->next_item) {
			if (item->mib_id != 0)
				continue;
			if (item->group == MIB2_IP) {
				ipRouteEntrySize =
				    ((mib2_ip_t *)item->valp)->ipRouteEntrySize;
				assert(IS_P2ALIGNED(ipRouteEntrySize,
				    sizeof (mib2_ipRouteEntry_t *)));
				break;
			}
		}
		if (ipRouteEntrySize == 0) {
			(void) fprintf(stderr,
			    gettext("ipRouteEntrySize can't be determined.\n"));
			exit(1);
		}
		for (; item != NULL; item = item->next_item) {
			/*
			 * skip all the other trash that comes up the mib stream
			 */
			if (item->group != MIB2_IP ||
			    item->mib_id != MIB2_IP_ROUTE)
				continue;
			for (rp = (mib2_ipRouteEntry_t *)item->valp;
			    (char *)rp < (char *)item->valp + item->length;
			    /* LINTED */
			    rp = (mib2_ipRouteEntry_t *)
			    ((char *)rp + ipRouteEntrySize)) {
				delRouteEntry(rp, NULL, seqno);
				seqno++;
			}
			break;
		}
		break;
	case AF_INET6:
		/* Extract ipv6RouteEntrySize */
		for (; item != NULL; item = item->next_item) {
			if (item->mib_id != 0)
				continue;
			if (item->group == MIB2_IP6) {
				ipv6RouteEntrySize =
				    ((mib2_ipv6IfStatsEntry_t *)item->valp)->
				    ipv6RouteEntrySize;
				assert(IS_P2ALIGNED(ipv6RouteEntrySize,
				    sizeof (mib2_ipv6RouteEntry_t *)));
				break;
			}
		}
		if (ipv6RouteEntrySize == 0) {
			(void) fprintf(stderr, gettext(
			    "ipv6RouteEntrySize cannot be determined.\n"));
			exit(1);
		}
		for (; item != NULL; item = item->next_item) {
			/*
			 * skip all the other trash that comes up the mib stream
			 */
			if (item->group != MIB2_IP6 ||
			    item->mib_id != MIB2_IP6_ROUTE)
				continue;
			for (rp6 = (mib2_ipv6RouteEntry_t *)item->valp;
			    (char *)rp6 < (char *)item->valp + item->length;
			    /* LINTED */
			    rp6 = (mib2_ipv6RouteEntry_t *)
			    ((char *)rp6 + ipv6RouteEntrySize)) {
				delRouteEntry(NULL, rp6, seqno);
				seqno++;
			}
			break;
		}
		break;
	}

	if (setsockopt(s, SOL_SOCKET, SO_USELOOPBACK, (char *)&on,
	    sizeof (on)) < 0)
		quit("setsockopt", errno);
}

/*
 * Given the contents of a mib_item_t of id type MIB2_IP_ROUTE or
 * MIB2_IP6_ROUTE, construct and send an RTM_DELETE routing socket message in
 * order to facilitate the flushing of RTF_GATEWAY routes.
 */
static void
delRouteEntry(mib2_ipRouteEntry_t *rp, mib2_ipv6RouteEntry_t *rp6, int seqno)
{
	char *cp;
	int ire_type;
	int rlen;
	struct rt_msghdr *rtm;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	int slen;

	if (rp != NULL)
		ire_type = rp->ipRouteInfo.re_ire_type;
	else
		ire_type = rp6->ipv6RouteInfo.re_ire_type;
	if (ire_type != IRE_DEFAULT &&
	    ire_type != IRE_PREFIX &&
	    ire_type != IRE_HOST &&
	    ire_type != IRE_HOST_REDIRECT)
		return;

	rtm = &m_rtmsg.m_rtm;
	(void) memset(rtm, 0, sizeof (m_rtmsg));
	rtm->rtm_type = RTM_DELETE;
	rtm->rtm_seq = seqno;
	rtm->rtm_flags |= RTF_GATEWAY;
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
	cp = m_rtmsg.m_space;
	if (rp != NULL) {
		slen = sizeof (struct sockaddr_in);
		if (rp->ipRouteMask == IP_HOST_MASK)
			rtm->rtm_flags |= RTF_HOST;
		(void) memset(&sin, 0, slen);
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = rp->ipRouteDest;
		(void) memmove(cp, &sin, slen);
		cp += slen;
		sin.sin_addr.s_addr = rp->ipRouteNextHop;
		(void) memmove(cp, &sin, slen);
		cp += slen;
		sin.sin_addr.s_addr = rp->ipRouteMask;
		(void) memmove(cp, &sin, slen);
		cp += slen;
	} else {
		slen = sizeof (struct sockaddr_in6);
		if (rp6->ipv6RoutePfxLength == IPV6_ABITS)
			rtm->rtm_flags |= RTF_HOST;
		(void) memset(&sin6, 0, slen);
		sin6.sin6_family = AF_INET6;
		sin6.sin6_addr = rp6->ipv6RouteDest;
		(void) memmove(cp, &sin6, slen);
		cp += slen;
		sin6.sin6_addr = rp6->ipv6RouteNextHop;
		(void) memmove(cp, &sin6, slen);
		cp += slen;
		(void) memset(&sin6.sin6_addr, 0, sizeof (sin6.sin6_addr));
		(void) in_prefixlentomask(rp6->ipv6RoutePfxLength, IPV6_ABITS,
		    (uchar_t *)&sin6.sin6_addr.s6_addr);
		(void) memmove(cp, &sin6, slen);
		cp += slen;
	}
	rtm->rtm_msglen = cp - (char *)&m_rtmsg;
	if (debugonly) {
		/*
		 * In debugonly mode, the routing socket message to delete the
		 * current entry is not actually sent.  However if verbose is
		 * also set, the routing socket message that would have been
		 * is printed.
		 */
		if (verbose)
			print_rtmsg(rtm, rtm->rtm_msglen);
		return;
	}

	rlen = write(s, (char *)&m_rtmsg, rtm->rtm_msglen);
	if (rlen < (int)rtm->rtm_msglen) {
		if (rlen < 0) {
			(void) fprintf(stderr,
			    gettext("route: write to routing socket: %s\n"),
			    strerror(errno));
		} else {
			(void) fprintf(stderr, gettext("route: write to "
			    "routing socket got only %d for rlen\n"), rlen);
		}
		return;
	}
	if (qflag) {
		/*
		 * In quiet mode, nothing is printed at all (unless the write()
		 * itself failed.
		 */
		return;
	}
	if (verbose) {
		print_rtmsg(rtm, rlen);
	} else {
		struct sockaddr *sa = (struct sockaddr *)(rtm + 1);

		(void) printf("%-20.20s ",
		    rtm->rtm_flags & RTF_HOST ? routename(sa) :
		    netname(sa));
		/* LINTED */
		sa = (struct sockaddr *)(salen(sa) + (char *)sa);
		(void) printf("%-20.20s ", routename(sa));
		(void) printf("done\n");
	}
}

/*
 * Return the name of the host whose address is given.
 */
char *
routename(const struct sockaddr *sa)
{
	char *cp;
	static char line[MAXHOSTNAMELEN + 1];
	struct hostent *hp = NULL;
	static char domain[MAXHOSTNAMELEN + 1];
	static boolean_t first = B_TRUE;
	struct in_addr in;
	struct in6_addr in6;
	int error_num;
	ushort_t *s;
	ushort_t *slim;

	if (first) {
		first = B_FALSE;
		if (gethostname(domain, MAXHOSTNAMELEN) == 0 &&
		    (cp = strchr(domain, '.')))
			(void) strcpy(domain, cp + 1);
		else
			domain[0] = 0;
	}

	if (salen(sa) == 0) {
		(void) strcpy(line, "default");
		return (line);
	}
	switch (sa->sa_family) {

	case AF_INET:
		/* LINTED */
		in = ((struct sockaddr_in *)sa)->sin_addr;

		cp = NULL;
		if (in.s_addr == INADDR_ANY)
			cp = "default";
		if (cp == NULL && !nflag) {
			hp = gethostbyaddr((char *)&in, sizeof (struct in_addr),
			    AF_INET);
			if (hp != NULL) {
				if (((cp = strchr(hp->h_name, '.')) != NULL) &&
				    (strcmp(cp + 1, domain) == 0))
					*cp = 0;
				cp = hp->h_name;
			}
		}
		if (cp != NULL) {
			(void) strncpy(line, cp, MAXHOSTNAMELEN);
			line[MAXHOSTNAMELEN] = '\0';
		} else {
			in.s_addr = ntohl(in.s_addr);
			(void) sprintf(line, "%u.%u.%u.%u", C(in.s_addr >> 24),
			    C(in.s_addr >> 16), C(in.s_addr >> 8),
			    C(in.s_addr));
		}
		break;

	case AF_LINK:
		return (link_ntoa((struct sockaddr_dl *)sa));

	case AF_INET6:
		/* LINTED */
		in6 = ((struct sockaddr_in6 *)sa)->sin6_addr;

		cp = NULL;
		if (IN6_IS_ADDR_UNSPECIFIED(&in6))
			cp = "default";
		if (cp == NULL && !nflag) {
			hp = getipnodebyaddr((char *)&in6,
			    sizeof (struct in6_addr), AF_INET6, &error_num);
			if (hp != NULL) {
				if (((cp = strchr(hp->h_name, '.')) != NULL) &&
				    (strcmp(cp + 1, domain) == 0))
					*cp = 0;
				cp = hp->h_name;
			}
		}
		if (cp != NULL) {
			(void) strncpy(line, cp, MAXHOSTNAMELEN);
			line[MAXHOSTNAMELEN] = '\0';
		} else {
			(void) inet_ntop(AF_INET6, (void *)&in6, line,
			    INET6_ADDRSTRLEN);
		}
		if (hp != NULL)
			freehostent(hp);

		break;

	default:
		s = (ushort_t *)sa;

		slim = s + ((salen(sa) + 1) >> 1);
		cp = line + sprintf(line, "(%d)", sa->sa_family);

		while (++s < slim) /* start with sa->sa_data */
			cp += sprintf(cp, " %x", *s);
		break;
	}
	return (line);
}

/*
 * Return the name of the network whose address is given.
 * The address is assumed to be that of a net or subnet, not a host.
 */
static char *
netname(struct sockaddr *sa)
{
	char *cp = NULL;
	static char line[MAXHOSTNAMELEN + 1];
	struct netent *np;
	in_addr_t net, mask;
	int subnetshift;
	struct in_addr in;
	ushort_t *s;
	ushort_t *slim;

	switch (sa->sa_family) {

	case AF_INET:
		/* LINTED */
		in = ((struct sockaddr_in *)sa)->sin_addr;

		in.s_addr = ntohl(in.s_addr);
		if (in.s_addr == INADDR_ANY) {
			cp = "default";
		} else if (!nflag) {
			if (IN_CLASSA(in.s_addr)) {
				mask = IN_CLASSA_NET;
				subnetshift = 8;
			} else if (IN_CLASSB(in.s_addr)) {
				mask = IN_CLASSB_NET;
				subnetshift = 8;
			} else {
				mask = IN_CLASSC_NET;
				subnetshift = 4;
			}
			/*
			 * If there are more bits than the standard mask
			 * would suggest, subnets must be in use.
			 * Guess at the subnet mask, assuming reasonable
			 * width subnet fields.
			 */
			while (in.s_addr &~ mask)
				mask = (long)mask >> subnetshift;
			net = in.s_addr & mask;
			while ((mask & 1) == 0)
				mask >>= 1, net >>= 1;
			np = getnetbyaddr(net, AF_INET);
			if (np != NULL)
				cp = np->n_name;
		}
		if (cp != NULL) {
			(void) strncpy(line, cp, MAXHOSTNAMELEN);
			line[MAXHOSTNAMELEN] = '\0';
		} else if ((in.s_addr & 0xffffff) == 0) {
			(void) sprintf(line, "%u", C(in.s_addr >> 24));
		} else if ((in.s_addr & 0xffff) == 0) {
			(void) sprintf(line, "%u.%u", C(in.s_addr >> 24),
			    C(in.s_addr >> 16));
		} else if ((in.s_addr & 0xff) == 0) {
			(void) sprintf(line, "%u.%u.%u", C(in.s_addr >> 24),
			    C(in.s_addr >> 16), C(in.s_addr >> 8));
		} else {
			(void) sprintf(line, "%u.%u.%u.%u", C(in.s_addr >> 24),
			    C(in.s_addr >> 16), C(in.s_addr >> 8),
			    C(in.s_addr));
		}
		break;

	case AF_LINK:
		return (link_ntoa((struct sockaddr_dl *)sa));

	case AF_INET6:
		return (routename(sa));

	default:
		/* LINTED */
		s = (ushort_t *)sa->sa_data;

		slim = s + ((salen(sa) + 1) >> 1);
		cp = line + sprintf(line, "af %d:", sa->sa_family);

		while (s < slim)
			cp += sprintf(cp, " %x", *s++);
		break;
	}
	return (line);
}

/*
 * Initialize a new structure.  Keep in mind that ri_dst_str, ri_gate_str and
 * ri_ifp_str will be freed by det_rtcmd_irep, so they should either be NULL
 * or point to dynamically allocated memory.
 */
rtcmd_irep_t *
new_rtcmd_irep(void)
{
	rtcmd_irep_t *rcip;

	rcip = calloc(1, sizeof (rtcmd_irep_t));
	if (rcip == NULL) {
		quit("calloc", errno);
	}
	rcip->ri_af = af;
	rcip->ri_flags = RTF_STATIC;
	return (rcip);
}

void
del_rtcmd_irep(rtcmd_irep_t *rcip)
{
	free(rcip->ri_dest_str);
	free(rcip->ri_gate_str);
	free(rcip->ri_ifp_str);
	/*
	 * IPv6 host entries come from getipnodebyname, which dynamically
	 * allocates memory.  IPv4 host entries come from gethostbyname, which
	 * returns static memory and cannot be freed with freehostent.
	 */
	if (rcip->ri_gate_hp != NULL &&
	    rcip->ri_gate_hp->h_addrtype == AF_INET6)
		freehostent(rcip->ri_gate_hp);
	free(rcip);
}

void
save_string(char **dst, char *src)
{
	free(*dst);
	*dst = strdup(src);
	if (*dst == NULL) {
		quit("malloc", errno);
	}
}

/*
 * Print the short form summary of a route command.
 * Eg. "add net default: gateway 10.0.0.1"
 * The final newline is not added, allowing the caller to append additional
 * information.
 */
void
print_rtcmd_short(FILE *to, rtcmd_irep_t *rcip, boolean_t gw_good,
    boolean_t to_saved)
{
	char *cmd;
	char obuf[INET6_ADDRSTRLEN];

	switch (rcip->ri_cmd) {
	case RTM_ADD:
		cmd = "add";
		break;
	case RTM_CHANGE:
		cmd = "change";
		break;
	case RTM_DELETE:
		cmd = "delete";
		break;
	case RTM_GET:
		cmd = "get";
		break;
	default:
		assert(0);
	}

	(void) fprintf(to, "%s%s %s %s", cmd,
	    (to_saved) ? " persistent" : "",
	    (rcip->ri_flags & RTF_HOST) ? "host" : "net",
	    (rcip->ri_dest_str == NULL) ? "NULL" : rcip->ri_dest_str);

	if (rcip->ri_gate_str != NULL) {
		switch (rcip->ri_af) {
		case AF_INET:
			if (nflag) {
				(void) fprintf(to, ": gateway %s",
				    inet_ntoa(rcip->ri_gate.sin.sin_addr));
			} else if (gw_good &&
			    rcip->ri_gate_hp != NULL &&
			    rcip->ri_gate_hp->h_addr_list[1] != NULL) {
				/*
				 * Print the actual address used in the case
				 * where there was more than one address
				 * available for the name, and one was used
				 * successfully.
				 */
				(void) fprintf(to, ": gateway %s (%s)",
				    rcip->ri_gate_str,
				    inet_ntoa(rcip->ri_gate.sin.sin_addr));
			} else {
				(void) fprintf(to, ": gateway %s",
				    rcip->ri_gate_str);
			}
			break;
		case AF_INET6:
			if (inet_ntop(AF_INET6,
			    &rcip->ri_gate.sin6.sin6_addr, obuf,
			    INET6_ADDRSTRLEN) != NULL) {
				if (nflag) {
					(void) fprintf(to, ": gateway %s",
					    obuf);
					break;
				}
				if (gw_good &&
				    rcip->ri_gate_hp->h_addr_list[1] != NULL) {
					(void) fprintf(to, ": gateway %s (%s)",
					    rcip->ri_gate_str, obuf);
					break;
				}
			}
			/* FALLTHROUGH */
		default:
			(void) fprintf(to, ": gateway %s",
			    rcip->ri_gate_str);
			break;
		}
	}
}

void
set_metric(rtcmd_irep_t *rcip, char *value, int key, boolean_t lock)
{
	int flag = 0;
	uint_t noval, *valp = &noval;

	switch (key) {
#define	caseof(x, y, z)	\
	case (x): valp = &(rcip->ri_metrics.z); flag = (y); break

	caseof(K_MTU, RTV_MTU, rmx_mtu);
	caseof(K_HOPCOUNT, RTV_HOPCOUNT, rmx_hopcount);
	caseof(K_EXPIRE, RTV_EXPIRE, rmx_expire);
	caseof(K_RECVPIPE, RTV_RPIPE, rmx_recvpipe);
	caseof(K_SENDPIPE, RTV_SPIPE, rmx_sendpipe);
	caseof(K_SSTHRESH, RTV_SSTHRESH, rmx_ssthresh);
	caseof(K_RTT, RTV_RTT, rmx_rtt);
	caseof(K_RTTVAR, RTV_RTTVAR, rmx_rttvar);
#undef	caseof
	}
	rcip->ri_inits |= flag;
	if (lock)
		rcip->ri_metrics.rmx_locks |= flag;
	*valp = atoi(value);
}

/*
 * Parse the options give in argv[], filling in rcip with the results.
 * If cmd_string is non-null, argc and argv are ignored, and cmd_string is
 * tokenized to produce the command line.  Cmd_string is tokenized using
 * strtok, which will overwrite whitespace in the string with nulls.
 *
 * Returns B_TRUE on success and B_FALSE on failure.
 */
boolean_t
args_to_rtcmd(rtcmd_irep_t *rcip, char **argv, char *cmd_string)
{
	const char *ws = "\f\n\r\t\v ";
	char *tok = cmd_string;
	char *keyword_str;
	addr_type_t atype = ADDR_TYPE_ANY;
	boolean_t iflag = B_FALSE;
	boolean_t locknext = B_FALSE;
	boolean_t lockrest = B_FALSE;
	boolean_t dash_keyword;
	int key;
	char *err;

	if (cmd_string == NULL) {
		tok = argv[0];
	} else {
		tok = strtok(cmd_string, ws);
	}

	/*
	 * The command keywords are already fully checked by main() or
	 * search_rtfile().
	 */
	switch (*tok) {
	case 'a':
		rcip->ri_cmd = RTM_ADD;
		break;
	case 'c':
		rcip->ri_cmd = RTM_CHANGE;
		break;
	case 'd':
		rcip->ri_cmd = RTM_DELETE;
		break;
	case 'g':
		rcip->ri_cmd = RTM_GET;
		break;
	default:
		/* NOTREACHED */
		quit(gettext("Internal Error"), EINVAL);
		/* NOTREACHED */
	}

#define	NEXTTOKEN \
	((tok = (cmd_string == NULL ? *++argv : strtok(NULL, ws))) != NULL)

	while (NEXTTOKEN) {
		keyword_str = tok;
		if (*tok == '-') {
			dash_keyword = B_TRUE;
			key = keyword(tok + 1);
		} else {
			dash_keyword = B_FALSE;
			key = keyword(tok);
			if (key != K_HOST && key != K_NET) {
				/* All others must be preceded by '-' */
				key = 0;
			}
		}
		switch (key) {
		case K_HOST:
			if (atype == ADDR_TYPE_NET) {
				syntax_error(gettext("route: -host and -net "
				    "are mutually exclusive\n"));
				return (B_FALSE);
			}
			atype = ADDR_TYPE_HOST;
			break;
		case K_NET:
			if (atype == ADDR_TYPE_HOST) {
				syntax_error(gettext("route: -host and -net "
				    "are mutually exclusive\n"));
				return (B_FALSE);
			}
			atype = ADDR_TYPE_NET;
			break;
		case K_LINK:
			rcip->ri_af = AF_LINK;
			break;
		case K_INET:
			rcip->ri_af = AF_INET;
			break;
		case K_SA:
			rcip->ri_af = PF_ROUTE;
			break;
		case K_INET6:
			rcip->ri_af = AF_INET6;
			break;
		case K_IFACE:
		case K_INTERFACE:
			iflag = B_TRUE;
			/* fallthrough */
		case K_NOSTATIC:
			rcip->ri_flags &= ~RTF_STATIC;
			break;
		case K_LOCK:
			locknext = B_TRUE;
			break;
		case K_LOCKREST:
			lockrest = B_TRUE;
			break;
		case K_REJECT:
			rcip->ri_flags |= RTF_REJECT;
			break;
		case K_BLACKHOLE:
			rcip->ri_flags |= RTF_BLACKHOLE;
			break;
		case K_PROTO1:
			rcip->ri_flags |= RTF_PROTO1;
			break;
		case K_PROTO2:
			rcip->ri_flags |= RTF_PROTO2;
			break;
		case K_CLONING:
			rcip->ri_flags |= RTF_CLONING;
			break;
		case K_XRESOLVE:
			rcip->ri_flags |= RTF_XRESOLVE;
			break;
		case K_STATIC:
			rcip->ri_flags |= RTF_STATIC;
			break;
		case K_IFA:
			if (!NEXTTOKEN) {
				syntax_arg_missing(keyword_str);
				return (B_FALSE);
			}
			if (!getaddr(rcip, RTA_IFA, tok, atype)) {
				return (B_FALSE);
			}
			break;
		case K_IFP:
			if (!NEXTTOKEN) {
				syntax_arg_missing(keyword_str);
				return (B_FALSE);
			}
			if (!getaddr(rcip, RTA_IFP, tok, atype)) {
				return (B_FALSE);
			}
			break;
		case K_GATEWAY:
			if (!NEXTTOKEN) {
				syntax_arg_missing(keyword_str);
				return (B_FALSE);
			}
			if (!getaddr(rcip, RTA_GATEWAY, tok, atype)) {
				return (B_FALSE);
			}
			break;
		case K_DST:
			if (!NEXTTOKEN) {
				syntax_arg_missing(keyword_str);
				return (B_FALSE);
			}
			if (!getaddr(rcip, RTA_DST, tok, atype)) {
				return (B_FALSE);
			}
			break;
		case K_NETMASK:
			if (!NEXTTOKEN) {
				syntax_arg_missing(keyword_str);
				return (B_FALSE);
			}
			if (!getaddr(rcip, RTA_NETMASK, tok, atype)) {
				return (B_FALSE);
			}
			atype = ADDR_TYPE_NET;
			break;
		case K_MTU:
		case K_HOPCOUNT:
		case K_EXPIRE:
		case K_RECVPIPE:
		case K_SENDPIPE:
		case K_SSTHRESH:
		case K_RTT:
		case K_RTTVAR:
			if (!NEXTTOKEN) {
				syntax_arg_missing(keyword_str);
				return (B_FALSE);
			}
			set_metric(rcip, tok, key, locknext || lockrest);
			locknext = B_FALSE;
			break;
		case K_PRIVATE:
			rcip->ri_flags |= RTF_PRIVATE;
			break;
		case K_MULTIRT:
			rcip->ri_flags |= RTF_MULTIRT;
			break;
		case K_SETSRC:
			if (!NEXTTOKEN) {
				syntax_arg_missing(keyword_str);
				return (B_FALSE);
			}
			if (!getaddr(rcip, RTA_SRC, tok, atype)) {
				return (B_FALSE);
			}
			rcip->ri_flags |= RTF_SETSRC;
			break;
		case K_SECATTR:
			if (!NEXTTOKEN) {
				syntax_arg_missing(keyword_str);
				return (B_FALSE);
			}
			if (is_system_labeled()) {
				int err;

				if (rcip->ri_rtsa_cnt >= 1) {
					syntax_error(gettext("route: can't "
					    "specify more than one security "
					    "attribute\n"));
					return (B_FALSE);
				}
				if (!rtsa_keyword(tok, &rcip->ri_rtsa, &err,
				    NULL)) {
					syntax_error(gettext("route: "
					    "bad security attribute: %s\n"),
					    tsol_strerror(err, errno));
					return (B_FALSE);
				}
				rcip->ri_rtsa_cnt++;
			} else {
				syntax_error(gettext("route: "
				    "system is not labeled; cannot specify "
				    "security attributes.\n"));
				return (B_FALSE);
			}
			break;
		case K_INDIRECT:
			rcip->ri_flags |= RTF_INDIRECT;
			break;
		default:
			if (dash_keyword) {
				syntax_bad_keyword(tok + 1);
				return (B_FALSE);
			}
			if ((rcip->ri_addrs & RTA_DST) == 0) {
				if (!getaddr(rcip, RTA_DST, tok, atype)) {
					return (B_FALSE);
				}
			} else if ((rcip->ri_addrs & RTA_GATEWAY) == 0) {
				/*
				 * For the gateway parameter, retrieve the
				 * pointer to the struct hostent so that all
				 * possible addresses can be tried until one
				 * is successful.
				 */
				if (!getaddr(rcip, RTA_GATEWAY, tok, atype)) {
					return (B_FALSE);
				}
			} else {
				ulong_t metric;
				/*
				 * Assume that a regular number is a metric.
				 * Needed for compatibility with old route
				 * command syntax.
				 */
				errno = 0;
				metric = strtoul(tok, &err, 10);
				if (errno == 0 && *err == '\0' &&
				    metric < 0x80000000ul) {
					iflag = (metric == 0);
					if (verbose) {
						(void) printf("old usage of "
						    "trailing number, assuming "
						    "route %s\n", iflag ?
						    "to if" : "via gateway");
					}
					continue;
				}
				if (!getaddr(rcip, RTA_NETMASK, tok, atype)) {
					return (B_FALSE);
				}
			}
		}
	}
#undef NEXTTOKEN

	if ((rcip->ri_addrs & RTA_DST) == 0) {
		syntax_error(gettext("route: destination required\n"));
		return (B_FALSE);
	} else if ((rcip->ri_cmd == RTM_ADD || rcip->ri_cmd == RTM_DELETE) &&
	    (rcip->ri_addrs & RTA_GATEWAY) == 0) {
		syntax_error(gettext(
		    "route: gateway required for add or delete command\n"));
		return (B_FALSE);
	}

	if (!iflag) {
		rcip->ri_flags |= RTF_GATEWAY;
	}

	if (atype != ADDR_TYPE_NET) {
		if (rcip->ri_addrs & RTA_NETMASK) {
			/*
			 * We know the netmask, so we can set the host flag
			 * based on whether the netmask is the host netmask.
			 */
			if (rcip->ri_af == AF_INET &&
			    rcip->ri_mask.sin.sin_addr.s_addr ==
			    IP_HOST_MASK) {
				rcip->ri_flags |= RTF_HOST;
			}
			if (rcip->ri_af == AF_INET6 &&
			    memcmp(&rcip->ri_mask.sin6.sin6_addr,
			    &in6_host_mask,
			    sizeof (struct in6_addr)) == 0) {
				rcip->ri_flags |= RTF_HOST;
			}
		} else {
			/*
			 * If no prefix mask has been saved at this point, it
			 * only makes sense to treat the destination address
			 * as a host address.
			 */
			rcip->ri_flags |= RTF_HOST;
		}
	}
	return (B_TRUE);
}

/*
 * This command always seeks to the end of the file prior to writing.
 */
void
write_to_rtfile(FILE *fp, int argc, char **argv)
{
	char file_line[BUF_SIZE];
	int len;
	int i;

	len = 0;
	if (early_v6_keyword) {
		/*
		 * This flag is set when "inet6" was seen as an
		 * argument to the -f flag.  Normally, when writing
		 * routes to the persistent route file, everything on
		 * the command line after "add" is saved verbatim.
		 * In this case, the arguments after "add" may not be
		 * sufficient, as the ipv6 keyword came before "add",
		 * yet must be present in the persistent route file.
		 */
		len += snprintf(file_line, BUF_SIZE, "-inet6 ");
	}
	for (i = 0; argc > 0 && len < BUF_SIZE; i++, argc--) {
		len += snprintf(&file_line[len], BUF_SIZE - len, "%s ",
		    argv[i]);
	}
	if (len >= BUF_SIZE)
		quit(gettext("Internal Error"), EINVAL);
	file_line[len - 1] = '\n';
	if (fseek(fp, 0, SEEK_END) != 0 ||
	    fputs(file_line, fp) == EOF) {
		quit(gettext("failed to write to route file"),
		    errno);
	}
}

boolean_t
compare_rtcmd(rtcmd_irep_t *srch_rt, rtcmd_irep_t *file_rt)
{
	if (strcmp(srch_rt->ri_dest_str, file_rt->ri_dest_str) != 0 ||
	    memcmp(&srch_rt->ri_mask, &file_rt->ri_mask, sizeof (su_t)) != 0) {
		return (B_FALSE);
	}
	return (srch_rt->ri_gate_str == NULL ||
	    strcmp(srch_rt->ri_gate_str, file_rt->ri_gate_str) == 0);
}

/*
 * Search the route file for routes matching the supplied route.  There are 3
 * modes of operation:
 *    SEARCH_MODE_RET - no side effects.
 *    SEARCH_MODE_PRINT - prints each matching line.
 *    SEARCH_MODE_DEL - copies all valid, non-matching lines to tmp_fp.
 *
 * In all cases, the number of matches is returned.  If rt is NULL, all routes
 * matching the global af value are considered matching.
 */
int
search_rtfile(FILE *fp, FILE *temp_fp, rtcmd_irep_t *rt, search_mode_t mode)
{
	char *tmp_buf;
	int match_cnt;
	boolean_t match;
	char file_line[BUF_SIZE + 4] = "add ";
	rtcmd_irep_t *thisrt;

	match_cnt = 0;

	/*
	 * Leave space at the beginning of file_line for "add ".
	 */
	while (fgets(file_line + 4, BUF_SIZE, fp) != NULL) {

		if (file_line[4] == '#' || file_line[4] == '\n') {
			/* Handle comments and blank lines */
			if (mode == SEARCH_MODE_DEL &&
			    fputs(file_line + 4, temp_fp) == EOF) {
				quit(gettext(
				    "route: failed to write to temp file"),
				    errno);
			}
			continue;
		}
		thisrt = new_rtcmd_irep();
		/*
		 * thisrt->ri_af defaults to whatever address family happens
		 * to be set in the global af, but routes in the persistent
		 * route file must be treated as AF_INET by default.
		 */
		thisrt->ri_af = AF_INET;

		exit_on_error = B_FALSE;
		tmp_buf = strdup(file_line);
		/* args_to_rtcmd() will mangle the string passed. */
		if (!args_to_rtcmd(thisrt, NULL, tmp_buf)) {
			/* There was an error in args_to_rtcmd() or helpers */
			del_rtcmd_irep(thisrt);
			free(tmp_buf);
			continue;
		}
		exit_on_error = B_TRUE;
		free(tmp_buf);

		if (thisrt->ri_gate_str == NULL) {
			del_rtcmd_irep(thisrt);
			continue;
		}
		match = (rt == NULL) ? (thisrt->ri_af == af) :
		    compare_rtcmd(rt, thisrt);

		if (match) match_cnt++;
		if (match && mode == SEARCH_MODE_PRINT) {
			(void) printf("persistent: route %s", file_line);
		}
		if (match && mode == SEARCH_MODE_DEL) {
			thisrt->ri_cmd = RTM_DELETE;
			print_rtcmd_short(stdout, thisrt, B_FALSE, B_TRUE);
			(void) printf("\n");
		}
		del_rtcmd_irep(thisrt);

		if (!match && mode == SEARCH_MODE_DEL &&
		    fputs(file_line + 4, temp_fp) == EOF) {
			quit(gettext("failed to write to temp file"),
			    errno);
		}
	}
	return (match_cnt);
}

/*
 * Perform the route operation given in argv on the persistent route file.
 * If do_flush is set, the persistent route file is flushed of all routes
 * matching the global family, and the arguments are ignored.
 */
void
save_route(int argc, char **argv, int do_flush)
{
	rtcmd_irep_t *rt;
	int perm_fd;
	FILE *perm_fp;
	FILE *temp_fp;
	mode_t fmode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	struct flock lock;
	struct stat st;
	const char commentstr[] =
	    "# File generated by route(1M) - do not edit.\n";

	perm_fd = open(perm_file, O_RDWR | O_CREAT, fmode);
	if (perm_fd == -1 || fstat(perm_fd, &st) == -1)
		quit("failed to open route file", errno);

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;
	if (fcntl(perm_fd, F_SETLK, &lock) != 0) {
		quit(gettext("failed to lock route file"), errno);
		/* NOTREACHED */
	}
	if (st.st_size == 0 &&
	    write(perm_fd, commentstr, sizeof (commentstr) - 1) !=
	    sizeof (commentstr) - 1)
		quit(gettext("failed to open route file"), errno);

	if ((perm_fp = fdopen(perm_fd, "r+")) == NULL) {
		quit(gettext("failed to open route file"), errno);
		/* NOTREACHED */
	}

	if (!do_flush) {
		rt = new_rtcmd_irep();
		(void) args_to_rtcmd(rt, argv, NULL);
	}
	if (do_flush || rt->ri_cmd == RTM_DELETE) {
		if ((temp_fp = fopen(temp_file, "w")) == NULL) {
			quit(gettext("failed to open temp file"), errno);
			/* NOTREACHED */
		}
	}
	if (do_flush) {
		(void) search_rtfile(perm_fp, temp_fp, NULL, SEARCH_MODE_DEL);
		if (fclose(temp_fp) != 0 || rename(temp_file, perm_file) != 0) {
			quit(gettext("failed to update route file"), errno);
			/* NOTREACHED */
		}
		(void) fclose(perm_fp);
		return;
	}

	switch (rt->ri_cmd) {
	case RTM_ADD:
		if (search_rtfile(perm_fp, NULL, rt, SEARCH_MODE_NULL) > 0) {
			/* Route is already in the file */
			print_rtcmd_short(stderr, rt, B_FALSE, B_TRUE);
			(void) fprintf(stderr, ": entry exists\n");
			exit(1);
		}
		write_to_rtfile(perm_fp, argc - 1, argv + 1);
		print_rtcmd_short(stdout, rt, B_FALSE, B_TRUE);
		(void) printf("\n");
		break;

	case RTM_CHANGE:
		syntax_error(
		    gettext("route: change command not supported with -p\n"));
		/* NOTREACHED */

	case RTM_DELETE:
		if (search_rtfile(perm_fp, temp_fp, rt, SEARCH_MODE_DEL) <= 0) {
			/* Route not found */
			print_rtcmd_short(stderr, rt, B_FALSE, B_TRUE);
			(void) fprintf(stderr, gettext(": not in file\n"));
			exit(1);
		}
		if (fclose(temp_fp) != 0 || rename(temp_file, perm_file) != 0) {
			quit(gettext("failed to update route file"), errno);
			/* NOTREACHED */
		}
		break;

	case RTM_GET:
		if (search_rtfile(perm_fp, temp_fp, rt, SEARCH_MODE_PRINT) <=
		    0) {
			print_rtcmd_short(stdout, rt, B_FALSE, B_TRUE);
			(void) printf(gettext(": not in file\n"));
		}
		break;

	default:
		quit(gettext("Internal Error"), EINVAL);
		/* NOTREACHED */
	}

	/*
	 * Closing the file unlocks it.
	 */
	(void) fclose(perm_fp);
}

int
show_saved_routes(int argc)
{
	int perm_fd;
	FILE *perm_fp;
	struct flock lock;
	int count = 0;

	if (argc != 1) {
		syntax_error(gettext("route: invalid arguments for show\n"));
	}

	perm_fd = open(perm_file, O_RDONLY, 0);

	if (perm_fd == -1) {
		if (errno == ENOENT) {
			(void) printf("No persistent routes are defined\n");
			return (0);
		} else {
			quit(gettext("failed to open route file"), errno);
		}
	}
	lock.l_type = F_RDLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;
	if (fcntl(perm_fd, F_SETLK, &lock) != 0) {
		quit(gettext("failed to lock route file"),
		    errno);
		/* NOTREACHED */
	}
	if ((perm_fp = fdopen(perm_fd, "r")) == NULL) {
		quit(gettext("failed to open route file"), errno);
		/* NOTREACHED */
	}
	count += search_rtfile(perm_fp, NULL, NULL, SEARCH_MODE_PRINT);
	(void) fseek(perm_fp, 0, SEEK_SET);
	af = AF_INET6;
	count += search_rtfile(perm_fp, NULL, NULL, SEARCH_MODE_PRINT);

	if (count == 0)
		(void) printf("No persistent routes are defined\n");

	(void) fclose(perm_fp);
	return (0);
}

int
newroute(char **argv)
{
	rtcmd_irep_t *newrt;
	int ret, attempts, oerrno;
	char *err;
	char obuf[INET6_ADDRSTRLEN];
#define	hp (newrt->ri_gate_hp)

	newrt = new_rtcmd_irep();
	(void) args_to_rtcmd(newrt, argv, NULL);

	if (newrt->ri_cmd != RTM_GET && !tflag) {
		/* Don't want to read back our messages */
		(void) shutdown(s, 0);
	}
	if (newrt->ri_addrs & RTA_IFP) {
		newrt->ri_ifp.sdl.sdl_index = if_nametoindex(newrt->ri_ifp_str);
		if (newrt->ri_ifp.sdl.sdl_index == 0) {
			if (errno != ENXIO) {
				quit("if_nametoindex", errno);
			} else {
				(void) fprintf(stderr,
				    gettext("route: %s: no such interface\n"),
				    newrt->ri_ifp_str);
				exit(1);
			}
		}
		newrt->ri_ifp.sdl.sdl_family = AF_LINK;
	}
	for (attempts = 1; ; attempts++) {
		errno = 0;
		if ((ret = rtmsg(newrt)) == 0)
			break;
		if (errno != ENETUNREACH && errno != ESRCH)
			break;
		if ((newrt->ri_addrs & RTA_GATEWAY) && hp != NULL &&
		    hp->h_addr_list[attempts] != NULL) {
			switch (af) {
			case AF_INET:
				(void) memmove(&newrt->ri_gate.sin.sin_addr,
				    hp->h_addr_list[attempts], hp->h_length);
				continue;
			case AF_INET6:
				(void) memmove(&newrt->ri_gate.sin6.sin6_addr,
				    hp->h_addr_list[attempts], hp->h_length);
				continue;
			}
		}
		break;
	}
	oerrno = errno;

	if (newrt->ri_cmd != RTM_GET) {
		print_rtcmd_short(stdout, newrt, (ret == 0), B_FALSE);
		if (ret == 0)
			(void) printf("\n");
	} else if (ret != 0) {
		/*
		 * Note: there is nothing additional to print for get
		 * if ret == 0.
		 */
		if (nflag) {
			switch (newrt->ri_af) {
			case AF_INET:
				(void) printf(" %s",
				    inet_ntoa(newrt->ri_dst.sin.sin_addr));
				break;
			case AF_INET6:
				if (inet_ntop(AF_INET6,
				    (void *)&newrt->ri_dst.sin6.sin6_addr,
				    obuf, INET6_ADDRSTRLEN) != NULL) {
					(void) printf(" %s", obuf);
					break;
				}
				/* FALLTHROUGH */
			default:
				(void) printf("%s", newrt->ri_dest_str);
				break;
			}
		} else {
			(void) printf("%s", newrt->ri_dest_str);
		}
	}

	if (ret != 0) {
		switch (oerrno) {
		case ESRCH:
			err = "not in table";
			break;
		case EBUSY:
			err = "entry in use";
			break;
		case ENOBUFS:
			err = "routing table overflow";
			break;
		case EEXIST:
			err = "entry exists";
			break;
		case EPERM:
			err = "insufficient privileges";
			break;
		default:
			err = strerror(oerrno);
			break;
		}
		(void) printf(": %s\n", err);
	}

	del_rtcmd_irep(newrt);

	return (oerrno);
#undef hp
}


/*
 * Convert a network number to the corresponding IP address.
 * If the RTA_NETMASK hasn't been specified yet set it based
 * on the class of address.
 */
static void
inet_makenetandmask(rtcmd_irep_t *rcip, in_addr_t net, struct sockaddr_in *sin)
{
	in_addr_t addr, mask;

	if (net == 0) {
		mask = addr = 0;
	} else if (net < 128) {
		addr = net << IN_CLASSA_NSHIFT;
		mask = IN_CLASSA_NET;
	} else if (net < 65536) {
		addr = net << IN_CLASSB_NSHIFT;
		mask = IN_CLASSB_NET;
	} else if (net < 16777216L) {
		addr = net << IN_CLASSC_NSHIFT;
		mask = IN_CLASSC_NET;
	} else {
		addr = net;
		if ((addr & IN_CLASSA_HOST) == 0)
			mask =  IN_CLASSA_NET;
		else if ((addr & IN_CLASSB_HOST) == 0)
			mask =  IN_CLASSB_NET;
		else if ((addr & IN_CLASSC_HOST) == 0)
			mask =  IN_CLASSC_NET;
		else {
			if (IN_CLASSA(addr))
				mask =  IN_CLASSA_NET;
			else if (IN_CLASSB(addr))
				mask =  IN_CLASSB_NET;
			else if (IN_CLASSC(addr))
				mask =  IN_CLASSC_NET;
			else
				mask = IP_HOST_MASK;
			mask = inet_makesubnetmask(addr, mask);
		}
	}
	sin->sin_addr.s_addr = htonl(addr);

	/* Class E default mask is 32 */
	if (IN_CLASSE(addr))
		mask = IN_CLASSE_NET;

	if (!(rcip->ri_addrs & RTA_NETMASK)) {
		rcip->ri_addrs |= RTA_NETMASK;
		sin = &rcip->ri_mask.sin;
		sin->sin_addr.s_addr = htonl(mask);
		sin->sin_family = AF_INET;
	}
}

static in_addr_t
inet_makesubnetmask(in_addr_t addr, in_addr_t mask)
{
	int n;
	struct ifconf ifc;
	struct ifreq ifreq;
	struct ifreq *ifr;
	struct sockaddr_in *sin;
	char *buf;
	int numifs;
	size_t bufsize;
	int iosoc;
	in_addr_t if_addr, if_mask;
	in_addr_t if_subnetmask = 0;
	short if_flags;

	if (mask == 0)
		return (0);
	if ((iosoc = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		quit("socket", errno);
	if (ioctl(iosoc, SIOCGIFNUM, (char *)&numifs) < 0)
		quit("ioctl", errno);
	bufsize = numifs * sizeof (struct ifreq);
	buf = malloc(bufsize);
	if (buf == NULL)
		quit("malloc", errno);
	(void) memset(&ifc, 0, sizeof (ifc));
	ifc.ifc_len = bufsize;
	ifc.ifc_buf = buf;
	if (ioctl(iosoc, SIOCGIFCONF, (char *)&ifc) < 0)
		quit("ioctl (get interface configuration)", errno);
	/* Let's check to see if this is maybe a local subnet route. */
	ifr = ifc.ifc_req;
	for (n = ifc.ifc_len / sizeof (struct ifreq); n > 0; n--, ifr++) {
		ifreq = *ifr;
		/* LINTED */
		sin = (struct sockaddr_in *)&ifr->ifr_addr;
		if_addr = ntohl(sin->sin_addr.s_addr);

		if (ioctl(iosoc, SIOCGIFFLAGS, (char *)&ifreq) < 0)
			quit("ioctl (get interface flags)", errno);
		if ((ifreq.ifr_flags & IFF_UP) == 0)
			continue;
		if_flags = ifreq.ifr_flags;

		if (ioctl(iosoc, SIOCGIFNETMASK, (char *)&ifreq) < 0)
			quit("ioctl (get netmask)", errno);
		/* LINTED */
		sin = (struct sockaddr_in *)&ifreq.ifr_addr;
		if_mask = ntohl(sin->sin_addr.s_addr);
		if ((if_addr & mask) == (addr & mask)) {
			/*
			 * Don't trust pt-pt interfaces if there are
			 * other interfaces.
			 */
			if (if_flags & IFF_POINTOPOINT) {
				if_subnetmask = if_mask;
				continue;
			}
			/*
			 * Fine.  Just assume the same net mask as the
			 * directly attached subnet interface is using.
			 */
			return (if_mask);
		}
	}
	if (if_subnetmask != 0)
		return (if_subnetmask);
	return (mask);
}

/*
 * Interpret an argument as a network address of some kind.
 *
 * If the address family is one looked up in getaddr() using one of the
 * getipnodebyX() functions (currently only AF_INET6), then callers should
 * freehostent() the returned "struct hostent" pointer if one was passed in.
 *
 * If exit_on_error is true, this function will cause route to exit on error by
 * calling syntax_error().  Otherwise, it returns B_TRUE on success or B_FALSE
 * on failure.
 */
static boolean_t
getaddr(rtcmd_irep_t *rcip, int which, char *s, addr_type_t atype)
{
	su_t *su;
	struct hostent **hpp;
	struct hostent *hp;
	int masklen;

	if (which == RTA_GATEWAY) {
		hpp = &(rcip->ri_gate_hp);
	} else {
		hpp = &hp;
	}
	*hpp = NULL;

	rcip->ri_addrs |= which;
	switch (which) {
	case RTA_DST:
		save_string(&rcip->ri_dest_str, s);
		su = &rcip->ri_dst;
		su->sa.sa_family = rcip->ri_af;
		break;
	case RTA_GATEWAY:
		save_string(&rcip->ri_gate_str, s);
		su = &rcip->ri_gate;
		su->sa.sa_family = rcip->ri_af;
		break;
	case RTA_NETMASK:
		su = &rcip->ri_mask;
		su->sa.sa_family = rcip->ri_af;
		break;
	case RTA_IFP:
		save_string(&rcip->ri_ifp_str, s);
		return (B_TRUE);
		/*
		 * RTA_SRC has overloaded meaning. It can represent the
		 * src address of incoming or outgoing packets.
		 */
	case RTA_IFA:
		su = &rcip->ri_ifa;
		su->sa.sa_family = rcip->ri_af;
		break;
	case RTA_SRC:
		su = &rcip->ri_src;
		su->sa.sa_family = rcip->ri_af;
		break;
	default:
		/* NOTREACHED */
		quit(gettext("Internal Error"), EINVAL);
		/* NOTREACHED */
	}
	if (strcmp(s, "default") == 0) {
		if (which == RTA_DST) {
			return (getaddr(rcip, RTA_NETMASK, s, ADDR_TYPE_NET));
		}
		if (which == RTA_SRC) {
			return (B_TRUE);
		}
		return (B_TRUE);
	}
	switch (rcip->ri_af) {
	case AF_LINK:
		link_addr(s, &su->sdl);
		return (B_TRUE);
	case PF_ROUTE:
		sockaddr(s, &su->sa);
		return (B_TRUE);
	case AF_INET6:
		switch (which) {
		case RTA_DST:
			if (!in6_getaddr(s, &su->sin6, &masklen, hpp)) {
				return (B_FALSE);
			}
			if (masklen != NO_PREFIX) {
				(void) memset(&rcip->ri_mask.sin6.sin6_addr, 0,
				    sizeof (rcip->ri_mask.sin6.sin6_addr));
				if (!in_prefixlentomask(masklen, IPV6_ABITS,
				    (uchar_t *)&rcip->ri_mask.sin6.sin6_addr)) {
					syntax_error(gettext(
					    "route: bad prefix length: %d\n"),
					    masklen);
					return (B_FALSE);
				}
				rcip->ri_mask.sin6.sin6_family = rcip->ri_af;
				rcip->ri_addrs |= RTA_NETMASK;
			}
			return (B_TRUE);
		case RTA_GATEWAY:
		case RTA_IFA:
		case RTA_SRC:
			return (in6_getaddr(s, &su->sin6, NULL, hpp));
		case RTA_NETMASK:
			syntax_error(
			    gettext("route: -netmask not supported for IPv6: "
			    "use <prefix>/<prefix-length> instead\n"));
			return (B_FALSE);
		default:
			quit(gettext("Internal Error"), EINVAL);
			/* NOTREACHED */
		}
	case AF_INET:
		switch (which) {
		case RTA_DST:
			if (!in_getaddr(s, &su->sin, &masklen, which, hpp,
			    atype, rcip)) {
				return (B_FALSE);
			}
			if (masklen != NO_PREFIX) {
				(void) memset(&rcip->ri_mask.sin.sin_addr, 0,
				    sizeof (rcip->ri_mask.sin.sin_addr));
				if (!in_prefixlentomask(masklen, IP_ABITS,
				    (uchar_t *)&rcip->ri_mask.sin.sin_addr)) {
					syntax_error(gettext(
					    "route: bad prefix length: %d\n"),
					    masklen);
					return (B_FALSE);
				}
				rcip->ri_mask.sin.sin_family = rcip->ri_af;
				rcip->ri_addrs |= RTA_NETMASK;
			}
			return (B_TRUE);
		case RTA_GATEWAY:
		case RTA_IFA:
		case RTA_NETMASK:
		case RTA_SRC:
			return (in_getaddr(s, &su->sin, NULL, which, hpp, atype,
			    rcip));
		default:
			quit(gettext("Internal Error"), EINVAL);
			/* NOTREACHED */
		}
	default:
		quit(gettext("Internal Error"), EINVAL);
		/* NOTREACHED */
	}
	return (B_TRUE);
}

/*
 * Interpret an argument as an IPv4 network address of some kind,
 * returning B_TRUE on success or B_FALSE on failure.
 * This function will cause an exit() on failure if exit_on_failure is set.
 *
 * Note that this tries host interpretation before network interpretation,
 * except when -net has been given and the destination address is being parsed.
 *
 * If the plenp argument is non-NULL, allow <addr>/<n> syntax and
 * pass out <n> in *plenp.
 * If <n> doesn't parse return BAD_ADDR as *plenp.
 * If no /<n> is present return NO_PREFIX as *plenp.
 */
static boolean_t
in_getaddr(char *s, struct sockaddr_in *sin, int *plenp, int which,
    struct hostent **hpp, addr_type_t atype, rtcmd_irep_t *rcip)
{
	struct hostent *hp;
	struct netent *np;
	in_addr_t val;
	char str[BUFSIZ];

	(void) strlcpy(str, s, sizeof (str));

	/*
	 * If plenp is non-NULL, /<n> syntax for netmask is allowed.
	 */
	if (plenp != NULL) {
		char *cp;

		*plenp = in_getprefixlen(str, IP_ABITS);
		if (*plenp == BAD_ADDR)
			return (B_FALSE);
		cp = strchr(str, '/');
		if (cp != NULL)
			*cp = '\0';
	} else if (strchr(str, '/') != NULL) {
		syntax_error(gettext("route: %s: unexpected '/'\n"), str);
		return (B_FALSE);
	}

	(void) memset(sin, 0, sizeof (*sin));
	sin->sin_family = AF_INET;

	/*
	 * Handle 255.255.255.255 as a special case first.
	 */
	if (strcmp(str, "255.255.255.255") == 0) {
		sin->sin_addr.s_addr = INADDR_BROADCAST;
		return (B_TRUE);
	}

	val = inet_addr(str);
	if (val != (in_addr_t)-1) {
		/* Numeric address */
		sin->sin_addr.s_addr = val;
		if (which == RTA_DST) {
			if (atype == ADDR_TYPE_NET ||
			    (atype == ADDR_TYPE_ANY &&
			    inet_lnaof(sin->sin_addr) == INADDR_ANY)) {
				/* This looks like a network address. */
				inet_makenetandmask(rcip, ntohl(val),
				    sin);
			}
		}
		return (B_TRUE);
	}
	/* Host or net name */
	if (which != RTA_DST || atype != ADDR_TYPE_NET) {
		/* A host name is allowed. */
		if ((hp = gethostbyname(str)) != NULL) {
			*hpp = hp;
			(void) memmove(&sin->sin_addr, hp->h_addr,
			    hp->h_length);
			return (B_TRUE);
		}
	}
	if (atype != ADDR_TYPE_HOST) {
		/* A network name is allowed */
		if ((np = getnetbyname(str)) != NULL &&
		    (val = np->n_net) != 0) {
			if (which == RTA_DST) {
				inet_makenetandmask(rcip, val, sin);
			}
			return (B_TRUE);
		}
	}
	syntax_error(gettext("%s: bad value\n"), s);
	return (B_FALSE);
}

/*
 * Interpret an argument as an IPv6 network address of some kind,
 * returning B_TRUE on success or B_FALSE on failure.
 * This function will cause an exit() on failure if exit_on_failure is set.
 *
 * If the last argument is non-NULL allow a <addr>/<n> syntax and
 * pass out <n> in *plenp.
 * If <n> doesn't parse return BAD_ADDR as *plenp.
 * If no /<n> is present return NO_PREFIX as *plenp.
 */
static boolean_t
in6_getaddr(char *s, struct sockaddr_in6 *sin6, int *plenp,
    struct hostent **hpp)
{
	struct hostent *hp;
	char str[BUFSIZ];
	int error_num;

	(void) strlcpy(str, s, sizeof (str));

	/*
	 * If plenp is non-NULL, /<n> syntax for netmask is allowed.
	 */
	if (plenp != NULL) {
		char *cp;

		*plenp = in_getprefixlen(str, IPV6_ABITS);
		if (*plenp == BAD_ADDR)
			return (B_FALSE);
		cp = strchr(str, '/');
		if (cp != NULL)
			*cp = '\0';
	} else if (strchr(str, '/') != NULL) {
		syntax_error(gettext("route: %s: unexpected '/'\n"), str);
		return (B_FALSE);
	}

	(void) memset(sin6, 0, sizeof (struct sockaddr_in6));
	sin6->sin6_family = AF_INET6;

	hp = getipnodebyname(str, AF_INET6, 0, &error_num);
	if (hp != NULL) {
		*hpp = hp;
		(void) memmove(&sin6->sin6_addr, hp->h_addr, hp->h_length);
		return (B_TRUE);
	}
	if (error_num == TRY_AGAIN) {
		/*
		 * This isn't a problem if we aren't going to use the address
		 * right away.
		 */
		if (!exit_on_error) {
			return (B_TRUE);
		}
		syntax_error(gettext("route: %s: bad address (try "
		    "again later)\n"), s);
		return (B_FALSE);
	}
	syntax_error(gettext("route: %s: bad address\n"), s);
	return (B_FALSE);
}

/*
 * Parse <addr>/<n> syntax and return the integer n.
 * If <addr> is missing or <n> is not a valid integer, this function calls
 * syntax_error() and returns BAD_ADDR.
 * if n is not between 0 and max_plen inclusive, this functions calls
 * syntax_error() and returns BAD_ADDR.
 * If /<n> is not present, this function returns NO_PREFIX.
 * The string addr is not modified.
 */
int
in_getprefixlen(char *addr, int max_plen)
{
	int prefixlen;
	char *str, *end;

	str = strchr(addr, '/');
	if (str == addr) {
		syntax_error(gettext("route: %s: unexpected '/'\n"), addr);
		return (BAD_ADDR);
	}
	if (str == NULL)
		return (NO_PREFIX);
	str++;

	errno = 0;
	prefixlen = strtoul(str, &end, 10);
	if (errno != 0 || str == end) {
		syntax_error(gettext("route: bad prefix length %s\n"), str);
		return (BAD_ADDR);
	}
	if (prefixlen > max_plen) {
		syntax_error(gettext("route: prefix length %s out of range\n"),
		    str);
		return (BAD_ADDR);
	}
	return (prefixlen);
}

/*
 * Convert a prefix length to a mask.
 * Returns B_TRUE if ok. B_FALSE otherwise.
 * Assumes the mask array is zeroed by the caller.
 */
boolean_t
in_prefixlentomask(int prefixlen, int maxlen, uchar_t *mask)
{
	if (prefixlen < 0 || prefixlen > maxlen)
		return (B_FALSE);

	while (prefixlen > 0) {
		if (prefixlen >= 8) {
			*mask++ = 0xFF;
			prefixlen -= 8;
			continue;
		}
		*mask |= 1 << (8 - prefixlen);
		prefixlen--;
	}
	return (B_TRUE);
}

void
rtmonitor(int argc, char *argv[])
{
	int n;
	intmax_t msg[2048 / sizeof (intmax_t)];

	if (tflag)
		exit(0);
	verbose = B_TRUE;
	if (argc > 1) {
		argv++;
		if (argc == 2 && **argv == '-') {
			switch (keyword(*argv + 1)) {
			case K_INET:
				af = AF_INET;
				break;
			case K_LINK:
				af = AF_LINK;
				break;
			case K_INET6:
				af = AF_INET6;
				break;
			default:
				usage(*argv);
				/* NOTREACHED */
			}
		} else {
			usage(*argv);
		}
		(void) close(s);
		s = socket(PF_ROUTE, SOCK_RAW, af);
		if (s < 0)
			quit("socket", errno);
	}
	for (;;) {
		n = read(s, msg, sizeof (msg));
		if (n <= 0)
			quit("read", errno);
		(void) printf("got message of size %d\n", n);
		print_rtmsg((struct rt_msghdr *)msg, n);
	}
}

int
rtmsg(rtcmd_irep_t *newrt)
{
	static int seq;
	int rlen;
	char *cp = m_rtmsg.m_space;
	int l;

	errno = 0;
	(void) memset(&m_rtmsg, 0, sizeof (m_rtmsg));

	if (newrt->ri_cmd == RTM_GET) {
		newrt->ri_ifp.sa.sa_family = AF_LINK;
		newrt->ri_addrs |= RTA_IFP;
	}

#define	rtm m_rtmsg.m_rtm
	rtm.rtm_type = newrt->ri_cmd;
	rtm.rtm_flags = newrt->ri_flags;
	rtm.rtm_version = RTM_VERSION;
	rtm.rtm_seq = ++seq;
	rtm.rtm_addrs = newrt->ri_addrs;
	rtm.rtm_rmx = newrt->ri_metrics;
	rtm.rtm_inits = newrt->ri_inits;

#define	NEXTADDR(w, u) \
	if (newrt->ri_addrs & (w)) { \
		l = ROUNDUP_LONG(salen(&u.sa)); \
		(void) memmove(cp, &(u), l); \
		cp += l; \
		if (verbose) \
			sodump(&(u), #u); \
	}
	NEXTADDR(RTA_DST, newrt->ri_dst);
	NEXTADDR(RTA_GATEWAY, newrt->ri_gate);
	NEXTADDR(RTA_NETMASK, newrt->ri_mask);
	NEXTADDR(RTA_IFP, newrt->ri_ifp);
	NEXTADDR(RTA_IFA, newrt->ri_ifa);
	/*
	 * RTA_SRC has overloaded meaning. It can represent the
	 * src address of incoming or outgoing packets.
	 */
	NEXTADDR(RTA_SRC, newrt->ri_src);
#undef	NEXTADDR

	if (newrt->ri_rtsa_cnt > 0) {
		/* LINTED: aligned */
		rtm_ext_t *rtm_ext = (rtm_ext_t *)cp;
		tsol_rtsecattr_t *rtsecattr;

		rtm_ext->rtmex_type = RTMEX_GATEWAY_SECATTR;
		rtm_ext->rtmex_len = TSOL_RTSECATTR_SIZE(1);

		rtsecattr = (tsol_rtsecattr_t *)(rtm_ext + 1);
		rtsecattr->rtsa_cnt = 1;

		bcopy(&newrt->ri_rtsa, rtsecattr->rtsa_attr,
		    sizeof (newrt->ri_rtsa));
		cp = (char *)(rtsecattr->rtsa_attr + 1);
	}

	rtm.rtm_msglen = l = cp - (char *)&m_rtmsg;

	if (verbose)
		print_rtmsg(&rtm, l);
	if (debugonly)
		return (0);
	if ((rlen = write(s, (char *)&m_rtmsg, l)) < 0) {
		switch (errno) {
		case ESRCH:
		case EBUSY:
		case ENOBUFS:
		case EEXIST:
		case ENETUNREACH:
		case EHOSTUNREACH:
		case EPERM:
			break;
		default:
			perror(gettext("writing to routing socket"));
			break;
		}
		return (-1);
	} else if (rlen < (int)rtm.rtm_msglen) {
		(void) fprintf(stderr,
		    gettext("route: write to routing socket got only %d for "
		    "len\n"), rlen);
		return (-1);
	}
	if (newrt->ri_cmd == RTM_GET) {
		do {
			l = read(s, (char *)&m_rtmsg, sizeof (m_rtmsg));
		} while (l > 0 && (rtm.rtm_seq != seq || rtm.rtm_pid != pid));
		if (l < 0) {
			(void) fprintf(stderr,
			    gettext("route: read from routing socket: %s\n"),
			    strerror(errno));
		} else {
			print_getmsg(newrt, &rtm, l);
		}
	}
#undef rtm
	return (0);
}

static char *msgtypes[] = {
	"",
	"RTM_ADD: Add Route",
	"RTM_DELETE: Delete Route",
	"RTM_CHANGE: Change Metrics or flags",
	"RTM_GET: Report Metrics",
	"RTM_LOSING: Kernel Suspects Partitioning",
	"RTM_REDIRECT: Told to use different route",
	"RTM_MISS: Lookup failed on this address",
	"RTM_LOCK: fix specified metrics",
	"RTM_OLDADD: caused by SIOCADDRT",
	"RTM_OLDDEL: caused by SIOCDELRT",
	"RTM_RESOLVE: Route created by cloning",
	"RTM_NEWADDR: address being brought up on iface",
	"RTM_DELADDR: address being brought down on iface",
	"RTM_IFINFO: iface status change",
	"RTM_CHGADDR: address being changed on iface",
	"RTM_FREEADDR: address being removed from iface",
	0,
};

#define	NMSGTYPES (sizeof (msgtypes) / sizeof (msgtypes[0]))

static char metricnames[] =
"\011pksent\010rttvar\7rtt\6ssthresh\5sendpipe\4recvpipe\3expire\2hopcount"
	"\1mtu";
static char routeflags[] =
"\1UP\2GATEWAY\3HOST\4REJECT\5DYNAMIC\6MODIFIED\7DONE\010MASK_PRESENT"
	"\011CLONING\012XRESOLVE\013LLINFO\014STATIC\015BLACKHOLE"
	"\016PRIVATE\017PROTO2\020PROTO1\021MULTIRT\022SETSRC\023INDIRECT"
	"\024KERNEL\025ZONE";
static char ifnetflags[] =
"\1UP\2BROADCAST\3DEBUG\4LOOPBACK\5PTP\6NOTRAILERS\7RUNNING\010NOARP"
	"\011PPROMISC\012ALLMULTI\013INTELLIGENT\014MULTICAST"
	"\015MULTI_BCAST\016UNNUMBERED\017DHCP\020PRIVATE"
	"\021NOXMIT\022NOLOCAL\023DEPRECATED\024ADDRCONF"
	"\025ROUTER\026NONUD\027ANYCAST\030NORTEXCH\031IPv4\032IPv6"
	"\034NOFAILOVER\035FAILED\036STANDBY\037INACTIVE\040OFFLINE"
	"\041XRESOLV\042COS\043PREFERRED\044TEMPORARY\045FIXEDMTU\046VIRTUAL"
	"\047DUPLICATE";
static char addrnames[] =
"\1DST\2GATEWAY\3NETMASK\4GENMASK\5IFP\6IFA\7AUTHOR\010BRD\011SRC";

void
print_rtmsg(struct rt_msghdr *rtm, int msglen)
{
	struct if_msghdr *ifm;
	struct ifa_msghdr *ifam;

	if (!verbose)
		return;
	if (rtm->rtm_version != RTM_VERSION) {
		(void) printf("routing message version %d not understood\n",
		    rtm->rtm_version);
		return;
	}
	if (rtm->rtm_msglen != msglen) {
		(void) printf("message length mismatch, in packet %d, "
		    "returned %d\n",
		    rtm->rtm_msglen, msglen);
		if (msglen > rtm->rtm_msglen)
			msglen = rtm->rtm_msglen;
	}
	/*
	 * Since rtm->rtm_type is unsigned, we'll just check the case of zero
	 * and the upper-bound of (NMSGTYPES - 1).
	 */
	if (rtm->rtm_type == 0 || rtm->rtm_type >= (NMSGTYPES - 1)) {
		(void) printf("routing message type %d not understood\n",
		    rtm->rtm_type);
		return;
	}
	(void) printf("%s: len %d, ", msgtypes[rtm->rtm_type], msglen);
	switch (rtm->rtm_type) {
	case RTM_IFINFO:
		ifm = (struct if_msghdr *)rtm;
		(void) printf("if# %d, flags:", ifm->ifm_index);
		bprintf(stdout, ifm->ifm_flags, ifnetflags);
		pmsg_addrs((const char *)(ifm + 1), msglen - sizeof (*ifm),
		    ifm->ifm_addrs);
		break;
	case RTM_NEWADDR:
	case RTM_DELADDR:
	case RTM_CHGADDR:
	case RTM_FREEADDR:
		ifam = (struct ifa_msghdr *)rtm;
		(void) printf("metric %d, flags:", ifam->ifam_metric);
		bprintf(stdout, ifam->ifam_flags, routeflags);
		pmsg_addrs((const char *)(ifam + 1), msglen - sizeof (*ifam),
		    ifam->ifam_addrs);
		break;
	default:
		(void) printf("pid: %ld, seq %d, errno %d, flags:",
		    rtm->rtm_pid, rtm->rtm_seq, rtm->rtm_errno);
		bprintf(stdout, rtm->rtm_flags, routeflags);
		pmsg_common(rtm, msglen);
		break;
	}
}

void
print_getmsg(rtcmd_irep_t *req_rt, struct rt_msghdr *rtm, int msglen)
{
	struct sockaddr *dst = NULL, *gate = NULL, *mask = NULL, *src = NULL;
	struct sockaddr_dl *ifp = NULL;
	struct sockaddr *sa;
	char *cp;
	int i;

	(void) printf("   route to: %s\n", routename(&req_rt->ri_dst.sa));
	if (rtm->rtm_version != RTM_VERSION) {
		(void) fprintf(stderr,
		    gettext("routing message version %d not understood\n"),
		    rtm->rtm_version);
		return;
	}
	if (rtm->rtm_msglen > (ushort_t)msglen) {
		(void) fprintf(stderr,
		    gettext("message length mismatch, in packet %d, "
		    "returned %d\n"), rtm->rtm_msglen, msglen);
	}
	if (rtm->rtm_errno)  {
		(void) fprintf(stderr, "RTM_GET: %s (errno %d)\n",
		    strerror(rtm->rtm_errno), rtm->rtm_errno);
		return;
	}
	cp = ((char *)(rtm + 1));
	if (rtm->rtm_addrs != 0) {
		for (i = 1; i != 0; i <<= 1) {
			if (i & rtm->rtm_addrs) {
				/* LINTED */
				sa = (struct sockaddr *)cp;
				switch (i) {
				case RTA_DST:
					dst = sa;
					break;
				case RTA_GATEWAY:
					gate = sa;
					break;
				case RTA_NETMASK:
					mask = sa;
					break;
				case RTA_IFP:
					if (sa->sa_family == AF_LINK &&
					    ((struct sockaddr_dl *)sa)->
					    sdl_nlen != 0)
						ifp = (struct sockaddr_dl *)sa;
					break;
				case RTA_SRC:
					src = sa;
					break;
				}
				ADVANCE(cp, sa);
			}
		}
	}
	if (dst != NULL && mask != NULL)
		mask->sa_family = dst->sa_family;	/* XXX */
	if (dst != NULL)
		(void) printf("destination: %s\n", routename(dst));
	if (mask != NULL) {
		boolean_t savenflag = nflag;

		nflag = B_TRUE;
		(void) printf("       mask: %s\n", routename(mask));
		nflag = savenflag;
	}
	if (gate != NULL && rtm->rtm_flags & RTF_GATEWAY)
		(void) printf("    gateway: %s\n", routename(gate));
	if (src != NULL && rtm->rtm_flags & RTF_SETSRC)
		(void) printf("     setsrc: %s\n", routename(src));
	if (ifp != NULL) {
		if (verbose) {
			int i;

			(void) printf("  interface: %.*s index %d address ",
			    ifp->sdl_nlen, ifp->sdl_data, ifp->sdl_index);
			for (i = ifp->sdl_nlen;
			    i < ifp->sdl_nlen + ifp->sdl_alen;
			    i++) {
				(void) printf("%02x ",
				    ifp->sdl_data[i] & 0xFF);
			}
			(void) printf("\n");
		} else {
			(void) printf("  interface: %.*s\n",
			    ifp->sdl_nlen, ifp->sdl_data);
		}
	}
	(void) printf("      flags: ");
	bprintf(stdout, rtm->rtm_flags, routeflags);

#define	lock(f)	((rtm->rtm_rmx.rmx_locks & RTV_ ## f) ? 'L' : ' ')
#define	msec(u)	(((u) + 500) / 1000)		/* usec to msec */

	(void) printf("\n%s\n", " recvpipe  sendpipe  ssthresh    rtt,ms "
	    "rttvar,ms  hopcount      mtu     expire");
	(void) printf("%8d%c ", rtm->rtm_rmx.rmx_recvpipe, lock(RPIPE));
	(void) printf("%8d%c ", rtm->rtm_rmx.rmx_sendpipe, lock(SPIPE));
	(void) printf("%8d%c ", rtm->rtm_rmx.rmx_ssthresh, lock(SSTHRESH));
	(void) printf("%8d%c ", msec(rtm->rtm_rmx.rmx_rtt), lock(RTT));
	(void) printf("%8d%c ", msec(rtm->rtm_rmx.rmx_rttvar), lock(RTTVAR));
	(void) printf("%8d%c ", rtm->rtm_rmx.rmx_hopcount, lock(HOPCOUNT));
	(void) printf("%8d%c ", rtm->rtm_rmx.rmx_mtu, lock(MTU));
	if (rtm->rtm_rmx.rmx_expire)
		rtm->rtm_rmx.rmx_expire -= time(0);
	(void) printf("%8d%c", rtm->rtm_rmx.rmx_expire, lock(EXPIRE));
#undef lock
#undef msec
#define	RTA_IGN	\
	(RTA_DST|RTA_GATEWAY|RTA_NETMASK|RTA_IFP|RTA_IFA|RTA_BRD|RTA_SRC)
	if (verbose) {
		pmsg_common(rtm, msglen);
	} else {
		const char *sptr, *endptr;
		const struct sockaddr *sa;
		uint_t addrs;

		/* Not verbose; just print out the exceptional cases */
		if (rtm->rtm_addrs &~ RTA_IGN) {
			(void) printf("\nsockaddrs: ");
			bprintf(stdout, rtm->rtm_addrs, addrnames);
		}
		sptr = (const char *)(rtm + 1);
		endptr = (const char *)rtm + msglen;
		addrs = rtm->rtm_addrs;
		while (addrs != 0 && sptr + sizeof (*sa) <= endptr) {
			addrs &= addrs - 1;
			/* LINTED */
			sa = (const struct sockaddr *)sptr;
			ADVANCE(sptr, sa);
		}
		if (addrs == 0)
			pmsg_secattr(sptr, endptr - sptr, "    secattr: ");
		(void) putchar('\n');
	}
#undef	RTA_IGN
}

static void
pmsg_common(const struct rt_msghdr *rtm, size_t msglen)
{
	(void) printf("\nlocks: ");
	bprintf(stdout, (int)rtm->rtm_rmx.rmx_locks, metricnames);
	(void) printf(" inits: ");
	bprintf(stdout, (int)rtm->rtm_inits, metricnames);
	pmsg_addrs((const char *)(rtm + 1), msglen - sizeof (*rtm),
	    rtm->rtm_addrs);
}

static void
pmsg_addrs(const char *cp, size_t msglen, uint_t addrs)
{
	const struct sockaddr *sa;
	const char *maxptr;
	int i;

	if (addrs != 0) {
		(void) printf("\nsockaddrs: ");
		bprintf(stdout, addrs, addrnames);
		(void) putchar('\n');
		maxptr = cp + msglen;
		for (i = 1; i != 0 && cp + sizeof (*sa) <= maxptr; i <<= 1) {
			if (i & addrs) {
				/* LINTED */
				sa = (const struct sockaddr *)cp;
				(void) printf(" %s", routename(sa));
				ADVANCE(cp, sa);
			}
		}
		if (i != 0)
			msglen = 0;
		else
			msglen = maxptr - cp;
	}
	pmsg_secattr(cp, msglen, "secattr: ");
	(void) putchar('\n');
	(void) fflush(stdout);
}

void
bprintf(FILE *fp, int b, char *s)
{
	int i;
	boolean_t gotsome = B_FALSE;

	if (b == 0)
		return;
	while ((i = *s++) != 0) {
		if (b & (1 << (i - 1))) {
			if (!gotsome)
				i = '<';
			else
				i = ',';
			(void) putc(i, fp);
			gotsome = B_TRUE;
			for (; (i = *s) > ' '; s++)
				(void) putc(i, fp);
		} else {
			while (*s > ' ')
				s++;
		}
	}
	if (gotsome)
		(void) putc('>', fp);
}

int
keyword(const char *cp)
{
	struct keytab *kt = keywords;

	while (kt->kt_cp && strcmp(kt->kt_cp, cp))
		kt++;
	return (kt->kt_i);
}

void
sodump(su_t *su, char *which)
{
	static char obuf[INET6_ADDRSTRLEN];

	switch (su->sa.sa_family) {
	case AF_LINK:
		(void) printf("%s: link %s; ",
		    which, link_ntoa(&su->sdl));
		break;
	case AF_INET:
		(void) printf("%s: inet %s; ",
		    which, inet_ntoa(su->sin.sin_addr));
		break;
	case AF_INET6:
		if (inet_ntop(AF_INET6, (void *)&su->sin6.sin6_addr, obuf,
		    INET6_ADDRSTRLEN) != NULL) {
			(void) printf("%s: inet6 %s; ", which, obuf);
			break;
		}
		/* FALLTHROUGH */
	default:
		quit(gettext("Internal Error"), EINVAL);
		/* NOTREACHED */
	}
	(void) fflush(stdout);
}

/* States */
#define	VIRGIN	0
#define	GOTONE	1
#define	GOTTWO	2
#define	RESET	3
/* Inputs */
#define	DIGIT	(4*0)
#define	END	(4*1)
#define	DELIM	(4*2)
#define	LETTER	(4*3)

void
sockaddr(char *addr, struct sockaddr *sa)
{
	char *cp = (char *)sa;
	int size = salen(sa);
	char *cplim = cp + size;
	int byte = 0, state = VIRGIN, new;

	(void) memset(cp, 0, size);
	cp++;
	do {
		if ((*addr >= '0') && (*addr <= '9')) {
			new = *addr - '0';
		} else if ((*addr >= 'a') && (*addr <= 'f')) {
			new = *addr - 'a' + 10;
		} else if ((*addr >= 'A') && (*addr <= 'F')) {
			new = *addr - 'A' + 10;
		} else if (*addr == 0) {
			state |= END;
		} else {
			state |= DELIM;
		}
		addr++;
		switch (state /* | INPUT */) {
		case GOTTWO | DIGIT:
			*cp++ = byte;
			/* FALLTHROUGH */
		case VIRGIN | DIGIT:
			state = GOTONE; byte = new; continue;
		case GOTONE | DIGIT:
			state = GOTTWO; byte = new + (byte << 4); continue;
		default: /* | DELIM */
			state = VIRGIN; *cp++ = byte; byte = 0; continue;
		case GOTONE | END:
		case GOTTWO | END:
			*cp++ = byte;
			/* FALLTHROUGH */
		case VIRGIN | END:
			break;
		}
		break;
	} while (cp < cplim);
}

int
salen(const struct sockaddr *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return (sizeof (struct sockaddr_in));
	case AF_LINK:
		return (sizeof (struct sockaddr_dl));
	case AF_INET6:
		return (sizeof (struct sockaddr_in6));
	default:
		return (sizeof (struct sockaddr));
	}
}

void
link_addr(const char *addr, struct sockaddr_dl *sdl)
{
	char *cp = sdl->sdl_data;
	char *cplim = sizeof (struct sockaddr_dl) + (char *)sdl;
	int byte = 0, state = VIRGIN, new;

	(void) memset(sdl, 0, sizeof (struct sockaddr_dl));
	sdl->sdl_family = AF_LINK;
	do {
		state &= ~LETTER;
		if ((*addr >= '0') && (*addr <= '9')) {
			new = *addr - '0';
		} else if ((*addr >= 'a') && (*addr <= 'f')) {
			new = *addr - 'a' + 10;
		} else if ((*addr >= 'A') && (*addr <= 'F')) {
			new = *addr - 'A' + 10;
		} else if (*addr == 0) {
			state |= END;
		} else if (state == VIRGIN &&
		    (((*addr >= 'A') && (*addr <= 'Z')) ||
		    ((*addr >= 'a') && (*addr <= 'z')))) {
			state |= LETTER;
		} else {
			state |= DELIM;
		}
		addr++;
		switch (state /* | INPUT */) {
		case VIRGIN | DIGIT:
		case VIRGIN | LETTER:
			*cp++ = addr[-1];
			continue;
		case VIRGIN | DELIM:
			state = RESET;
			sdl->sdl_nlen = cp - sdl->sdl_data;
			continue;
		case GOTTWO | DIGIT:
			*cp++ = byte;
			/* FALLTHROUGH */
		case RESET | DIGIT:
			state = GOTONE;
			byte = new;
			continue;
		case GOTONE | DIGIT:
			state = GOTTWO;
			byte = new + (byte << 4);
			continue;
		default: /* | DELIM */
			state = RESET;
			*cp++ = byte;
			byte = 0;
			continue;
		case GOTONE | END:
		case GOTTWO | END:
			*cp++ = byte;
			/* FALLTHROUGH */
		case RESET | END:
			break;
		}
		break;
	} while (cp < cplim);
	sdl->sdl_alen = cp - LLADDR(sdl);
}

static char hexlist[] = "0123456789abcdef";

char *
link_ntoa(const struct sockaddr_dl *sdl)
{
	static char obuf[64];
	char *out = obuf;
	int i;
	uchar_t *in = (uchar_t *)LLADDR(sdl);
	uchar_t *inlim = in + sdl->sdl_alen;
	boolean_t firsttime = B_TRUE;

	if (sdl->sdl_nlen) {
		(void) memcpy(obuf, sdl->sdl_data, sdl->sdl_nlen);
		out += sdl->sdl_nlen;
		if (sdl->sdl_alen)
			*out++ = ':';
	}
	while (in < inlim) {
		if (firsttime)
			firsttime = B_FALSE;
		else
			*out++ = '.';
		i = *in++;
		if (i > 0xf) {
			out[1] = hexlist[i & 0xf];
			i >>= 4;
			out[0] = hexlist[i];
			out += 2;
		} else {
			*out++ = hexlist[i];
		}
	}
	*out = 0;
	return (obuf);
}

static mib_item_t *
mibget(int sd)
{
	intmax_t		buf[512 / sizeof (intmax_t)];
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
	req = (struct opthdr *)&tor[1];
	req->level = MIB2_IP;		/* any MIB2_xxx value ok here */
	req->name  = 0;
	req->len   = 0;

	ctlbuf.buf = (char *)buf;
	ctlbuf.len = tor->OPT_length + tor->OPT_offset;
	flags = 0;
	if (putmsg(sd, &ctlbuf, NULL, flags) < 0) {
		perror("mibget: putmsg (ctl)");
		return (NULL);
	}
	/*
	 * each reply consists of a ctl part for one fixed structure
	 * or table, as defined in mib2.h.  The format is a T_OPTMGMT_ACK,
	 * containing an opthdr structure.  level/name identify the entry,
	 * len is the size of the data part of the message.
	 */
	req = (struct opthdr *)&toa[1];
	ctlbuf.maxlen = sizeof (buf);
	for (j = 1; ; j++) {
		flags = 0;
		getcode = getmsg(sd, &ctlbuf, NULL, &flags);
		if (getcode < 0) {
			perror("mibget: getmsg (ctl)");
			if (verbose) {
				(void) fprintf(stderr,
				    "#   level   name    len\n");
				i = 0;
				for (last_item = first_item; last_item != NULL;
				    last_item = last_item->next_item) {
					(void) printf("%d  %4ld   %5ld   %ld\n",
					    ++i, last_item->group,
					    last_item->mib_id,
					    last_item->length);
				}
			}
			break;
		}
		if (getcode == 0 &&
		    ctlbuf.len >= sizeof (struct T_optmgmt_ack) &&
		    toa->PRIM_type == T_OPTMGMT_ACK &&
		    toa->MGMT_flags == T_SUCCESS &&
		    req->len == 0) {
			if (verbose) {
				(void) printf("mibget getmsg() %d returned EOD "
				    "(level %lu, name %lu)\n", j, req->level,
				    req->name);
			}
			return (first_item);		/* this is EOD msg */
		}

		if (ctlbuf.len >= sizeof (struct T_error_ack) &&
		    tea->PRIM_type == T_ERROR_ACK) {
			(void) fprintf(stderr, gettext("mibget %d gives "
			    "T_ERROR_ACK: TLI_error = 0x%lx, UNIX_error = "
			    "0x%lx\n"), j, tea->TLI_error, tea->UNIX_error);
			errno = (tea->TLI_error == TSYSERR) ?
			    tea->UNIX_error : EPROTO;
			break;
		}

		if (getcode != MOREDATA ||
		    ctlbuf.len < sizeof (struct T_optmgmt_ack) ||
		    toa->PRIM_type != T_OPTMGMT_ACK ||
		    toa->MGMT_flags != T_SUCCESS) {
			(void) printf("mibget getmsg(ctl) %d returned %d, "
			    "ctlbuf.len = %d, PRIM_type = %ld\n",
			    j, getcode, ctlbuf.len, toa->PRIM_type);
			if (toa->PRIM_type == T_OPTMGMT_ACK) {
				(void) printf("T_OPTMGMT_ACK: "
				    "MGMT_flags = 0x%lx, req->len = %ld\n",
				    toa->MGMT_flags, req->len);
			}
			errno = ENOMSG;
			break;
		}

		temp = malloc(sizeof (mib_item_t));
		if (temp == NULL) {
			perror("mibget: malloc");
			break;
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
		last_item->valp = malloc(req->len);
		if (verbose) {
			(void) printf("msg %d:  group = %4ld   mib_id = %5ld   "
			    "length = %ld\n",
			    j, last_item->group, last_item->mib_id,
			    last_item->length);
		}

		databuf.maxlen = last_item->length;
		databuf.buf    = (char *)last_item->valp;
		databuf.len    = 0;
		flags = 0;
		getcode = getmsg(sd, NULL, &databuf, &flags);
		if (getcode < 0) {
			perror("mibget: getmsg (data)");
			break;
		} else if (getcode != 0) {
			(void) printf("mibget getmsg(data) returned %d, "
			    "databuf.maxlen = %d, databuf.len = %d\n",
			    getcode, databuf.maxlen, databuf.len);
			break;
		}
	}

	/*
	 * On error, free all the allocated mib_item_t objects.
	 */
	while (first_item != NULL) {
		last_item = first_item;
		first_item = first_item->next_item;
		free(last_item);
	}
	return (NULL);
}

/*
 * print label security attributes for gateways.
 */
static void
pmsg_secattr(const char *sptr, size_t msglen, const char *labelstr)
{
	rtm_ext_t rtm_ext;
	tsol_rtsecattr_t sp;
	struct rtsa_s *rtsa = &sp.rtsa_attr[0];
	const char *endptr;
	char buf[256];
	int i;

	if (!is_system_labeled())
		return;

	endptr = sptr + msglen;

	for (;;) {
		if (sptr + sizeof (rtm_ext_t) + sizeof (sp) > endptr)
			return;

		bcopy(sptr, &rtm_ext, sizeof (rtm_ext));
		sptr += sizeof (rtm_ext);
		if (rtm_ext.rtmex_type == RTMEX_GATEWAY_SECATTR)
			break;
		sptr += rtm_ext.rtmex_len;
	}

	/* bail if this entry is corrupt or overruns buffer length */
	if (rtm_ext.rtmex_len < sizeof (sp) ||
	    sptr + rtm_ext.rtmex_len > endptr)
		return;

	/* run up just to the end of this extension */
	endptr = sptr + rtm_ext.rtmex_len;

	bcopy(sptr, &sp, sizeof (sp));
	sptr += sizeof (sp);

	if (sptr + (sp.rtsa_cnt - 1) * sizeof (*rtsa) != endptr)
		return;

	for (i = 0; i < sp.rtsa_cnt; i++) {
		if (i > 0) {
			/* first element is part of sp initalized above */
			bcopy(sptr, rtsa, sizeof (*rtsa));
			sptr += sizeof (*rtsa);
		}
		(void) printf("\n%s%s", labelstr, rtsa_to_str(rtsa, buf,
		    sizeof (buf)));
	}
}

static void
do_zone(char *name)
{
	zoneid_t zoneid;
	zone_state_t st;
	int fd, status, rc = 0;
	pid_t pid;

	if (name == NULL)
		return;

	if (getzoneid() != GLOBAL_ZONEID) {
		(void) fprintf(stderr,
		    "route: -z can only be specified from the global zone\n");
		exit(EXIT_FAILURE);
	}

	if (strcmp(name, GLOBAL_ZONENAME) == 0)
		return;

	if (zone_get_state(name, &st) != Z_OK)
		quit("unable to get zone state", errno);

	if (st != ZONE_STATE_RUNNING) {
		(void) fprintf(stderr, "route: zone must be running\n");
		exit(EXIT_FAILURE);
	}

	if ((zoneid = getzoneidbyname(name)) == -1)
		quit("cannot determine zone id", errno);

	if ((fd = open64(CTFS_ROOT "/process/template", O_RDWR)) == -1)
		quit("cannot open ctfs template", errno);

	/*
	 * zone_enter() does not allow contracts to straddle zones, so we must
	 * create a new, though largely unused contract.  Once we fork, the
	 * child is the only member of the new contract, so it can perform a
	 * zone_enter().
	 */
	rc |= ct_tmpl_set_critical(fd, 0);
	rc |= ct_tmpl_set_informative(fd, 0);
	rc |= ct_pr_tmpl_set_fatal(fd, CT_PR_EV_HWERR);
	rc |= ct_pr_tmpl_set_param(fd, CT_PR_PGRPONLY | CT_PR_REGENT);
	if (rc || ct_tmpl_activate(fd)) {
		(void) close(fd);
		quit("could not create contract", errno);
	}

	switch (pid = fork1()) {
	case 0:
		(void) ct_tmpl_clear(fd);
		(void) close(fd);
		if (zone_enter(zoneid) == -1)
			quit("could not enter zone", errno);
		return;

	case -1:
		quit("fork1 failed", errno);

	default:
		(void) ct_tmpl_clear(fd);
		(void) close(fd);
		if (waitpid(pid, &status, 0) < 0)
			quit("waitpid failed", errno);

		exit(WEXITSTATUS(status));
	}

}
