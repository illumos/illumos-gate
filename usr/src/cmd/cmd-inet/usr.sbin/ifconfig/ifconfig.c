/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "defs.h"
#include "strings.h"
#include "ifconfig.h"
#include <compat.h>
#include <libdlpi.h>
#include <inet/ip.h>

#define	LOOPBACK_IF	"lo0"
#define	NONE_STR	"none"
#define	ARP_MOD_NAME	"arp"
#define	TUN_NAME	"tun"
#define	ATUN_NAME	"atun"
#define	TUN6TO4_NAME	"6to4tun"

typedef struct if_flags {
	uint64_t iff_value;
	char	*iff_name;
} if_flags_t;

static if_flags_t	if_flags_tbl[] = {
	{ IFF_UP,		"UP" },
	{ IFF_BROADCAST,	"BROADCAST" },
	{ IFF_DEBUG,		"DEBUG" },
	{ IFF_LOOPBACK,		"LOOPBACK" },
	{ IFF_POINTOPOINT,	"POINTOPOINT" },
	{ IFF_NOTRAILERS,	"NOTRAILERS" },
	{ IFF_RUNNING,		"RUNNING" },
	{ IFF_NOARP,		"NOARP" },
	{ IFF_PROMISC,		"PROMISC" },
	{ IFF_ALLMULTI,		"ALLMULTI" },
	{ IFF_INTELLIGENT,	"INTELLIGENT" },
	{ IFF_MULTICAST,	"MULTICAST" },
	{ IFF_MULTI_BCAST,	"MULTI_BCAST" },
	{ IFF_UNNUMBERED,	"UNNUMBERED" },
	{ IFF_DHCPRUNNING,	"DHCP" },
	{ IFF_PRIVATE,		"PRIVATE" },
	{ IFF_NOXMIT,		"NOXMIT" },
	{ IFF_NOLOCAL,		"NOLOCAL" },
	{ IFF_DEPRECATED,	"DEPRECATED" },
	{ IFF_ADDRCONF,		"ADDRCONF" },
	{ IFF_ROUTER,		"ROUTER" },
	{ IFF_NONUD,		"NONUD" },
	{ IFF_ANYCAST,		"ANYCAST" },
	{ IFF_NORTEXCH,		"NORTEXCH" },
	{ IFF_IPV4,		"IPv4" },
	{ IFF_IPV6,		"IPv6" },
	{ IFF_NOFAILOVER,	"NOFAILOVER" },
	{ IFF_FAILED,		"FAILED" },
	{ IFF_STANDBY,		"STANDBY" },
	{ IFF_INACTIVE,		"INACTIVE" },
	{ IFF_OFFLINE,		"OFFLINE" },
	{ IFF_XRESOLV,		"XRESOLV" },
	{ IFF_COS_ENABLED,	"CoS" },
	{ IFF_PREFERRED,	"PREFERRED" },
	{ IFF_TEMPORARY,	"TEMPORARY" },
	{ IFF_FIXEDMTU,		"FIXEDMTU" },
	{ IFF_VIRTUAL,		"VIRTUAL" },
	{ IFF_DUPLICATE,	"DUPLICATE" }
};

static struct	lifreq lifr;
/* current interface name a particular function is accessing */
static char	name[LIFNAMSIZ];
/* foreach interface saved name */
static char	origname[LIFNAMSIZ];
static char savedname[LIFNAMSIZ];	/* For addif */
static int	setaddr;

/*
 * Make sure the algorithm variables hold more than the sizeof an algorithm
 * in PF_KEY.  (For now, more than a uint8_t.)  The NO_***_?ALG indicates that
 * there was no algorithm requested, and in the ipsec_req that service should
 * be disabled.  (E.g. if ah_aalg remains NO_AH_AALG, then AH will be
 * disabled on that tunnel.)
 */
#define	NO_AH_AALG 256
#define	NO_ESP_AALG 256
#define	NO_ESP_EALG 256

/*
 * iface_t
 * used by setifether to create a list of interfaces to mark
 * down-up when changing the ethernet address of an interface
 */
typedef struct iface {
	struct lifreq lifr;
	struct iface *next;	/* pointer to the next list element */
} iface_t;

static	iface_t	*logifs = NULL; /* list of logical interfaces */
static 	iface_t	*phyif	= NULL;	/* physical interface */

int	s;
int	af = AF_INET;	/* default address family */
int	debug = 0;
int	all = 0;	/* setifdhcp() needs to know this */
int	verbose = 0;
int	v4compat = 0;	/* Compatible printing format */

/*
 * Function prototypes for command functions.
 */
static int	addif(char *arg, int64_t param);
static int	inetplumb(char *arg, int64_t param);
static int	inetunplumb(char *arg, int64_t param);
static int	removeif(char *arg, int64_t param);
static int	setdebugflag(char *arg, int64_t param);
static int	setifaddr(char *arg, int64_t param);
static int	setifbroadaddr(char *arg, int64_t param);
static int	setifdstaddr(char *arg, int64_t param);
static int	setifether(char *arg, int64_t param);
static int	setifflags(char *arg, int64_t param);
static int	setifindex(char *arg, int64_t param);
static int	setifmetric(char *arg, int64_t param);
static int	setifmtu(char *arg, int64_t param);
static int	setifnetmask(char *arg, int64_t param);
static int	setifprefixlen(char *arg, int64_t param);
static int	setifrevarp(char *arg, int64_t param);
static int	setifsubnet(char *arg, int64_t param);
static int	setiftdst(char *arg, int64_t param);
static int	setiftoken(char *arg, int64_t param);
static int	setiftsrc(char *arg, int64_t param);
static int	setverboseflag(char *arg, int64_t param);
static int	set_tun_ah_alg(char *arg, int64_t param);
static int	set_tun_esp_auth_alg(char *arg, int64_t param);
static int	set_tun_esp_encr_alg(char *arg, int64_t param);
static int	modlist(char *arg, int64_t param);
static int	modinsert(char *arg, int64_t param);
static int	modremove(char *arg, int64_t param);
static int	setifgroupname(char *arg, int64_t param);
static int	configinfo(char *arg, int64_t param);
static void	print_config_flags(uint64_t flags);
static void	print_flags(uint64_t flags);
static void	print_ifether(char *ifname);
static int	set_tun_encap_limit(char *arg, int64_t param);
static int	clr_tun_encap_limit(char *arg, int64_t param);
static int	set_tun_hop_limit(char *arg, int64_t param);
static int	setzone(char *arg, int64_t param);
static int	setallzones(char *arg, int64_t param);
static int	setifsrc(char *arg, int64_t param);

/*
 * Address family specific function prototypes.
 */
static void	in_getaddr(char *s, struct sockaddr *saddr, int *plenp);
static void	in_status(int force, uint64_t flags);
static void	in_configinfo(int force, uint64_t flags);
static void	in6_getaddr(char *s, struct sockaddr *saddr, int *plenp);
static void	in6_status(int force, uint64_t flags);
static void	in6_configinfo(int force, uint64_t flags);

/*
 * Misc support functions
 */
static boolean_t	ni_entry(const char *, void *);
static void	foreachinterface(void (*func)(), int argc, char *argv[],
		    int af, int64_t onflags, int64_t offflags,
		    int64_t lifc_flags);
static void	ifconfig(int argc, char *argv[], int af, struct lifreq *lifrp);
static boolean_t	in_getmask(struct sockaddr_in *saddr,
			    boolean_t addr_set);
static int	in_getprefixlen(char *addr, boolean_t slash, int plen);
static boolean_t	in_prefixlentomask(int prefixlen, int maxlen,
			    uchar_t *mask);
static int	settaddr(char *, int (*)(icfg_handle_t,
			    const struct sockaddr *, socklen_t));
static void	status(void);
static void	ifstatus(const char *);
static void	usage(void);
static int	strioctl(int s, int cmd, char *buf, int buflen);
static int	setifdhcp(const char *caller, const char *ifname,
		    int argc, char *argv[]);
static int	ip_domux2fd(int *, int *, int *, int *, int *);
static int	ip_plink(int, int, int, int, int);
static int	modop(char *arg, char op);
static void	selectifs(int argc, char *argv[], int af,
			struct lifreq *lifrp);
static int	updownifs(iface_t *ifs, int up);
static int	find_all_global_interfaces(struct lifconf *lifcp, char **buf,
		    int64_t lifc_flags);
static int	find_all_zone_interfaces(struct lifconf *lifcp, char **buf,
		    int64_t lifc_flags);

#define	max(a, b)	((a) < (b) ? (b) : (a))

/*
 * DHCP_EXIT_IF_FAILURE indicates that the operation failed, but if there
 * are more interfaces to act on (i.e., ifconfig was invoked with -a), keep
 * on going rather than exit with an error.
 */

#define	DHCP_EXIT_IF_FAILURE	-1

#define	NEXTARG		0xffffff	/* command takes an argument */
#define	OPTARG		0xfffffe 	/* command takes an optional argument */
#define	AF_ANY		(-1)

/* Refer to the comments in ifconfig() on the netmask "hack" */
#define	NETMASK_CMD	"netmask"
struct sockaddr_storage	g_netmask;
enum { G_NETMASK_NIL, G_NETMASK_PENDING, G_NETMASK_SET }
    g_netmask_set = G_NETMASK_NIL;

struct	cmd {
	char		*c_name;
	int64_t		c_parameter;	/* NEXTARG means next argv */
	int		(*c_func)(char *, int64_t);
	int		c_abortonfail;	/* don't continue parsing args */
					/* for the current interface */
	int	c_af;			/* address family restrictions */
} cmds[] = {
	{ "up",		IFF_UP,		setifflags,	0,	AF_ANY },
	{ "down",	-IFF_UP,	setifflags,	0,	AF_ANY },
	{ "trailers",	-IFF_NOTRAILERS, setifflags,	0,	AF_ANY },
	{ "-trailers",	IFF_NOTRAILERS,	setifflags,	0,	AF_ANY },
	{ "arp",	-IFF_NOARP,	setifflags,	0,	AF_INET },
	{ "-arp",	IFF_NOARP,	setifflags,	0,	AF_INET },
	{ "router",	IFF_ROUTER,	setifflags,	0,	AF_ANY },
	{ "-router",	-IFF_ROUTER,	setifflags,	0,	AF_ANY },
	{ "private",	IFF_PRIVATE,	setifflags,	0,	AF_ANY },
	{ "-private",	-IFF_PRIVATE,	setifflags,	0,	AF_ANY },
	{ "xmit",	-IFF_NOXMIT,	setifflags,	0,	AF_ANY },
	{ "-xmit",	IFF_NOXMIT,	setifflags,	0,	AF_ANY },
	{ "-nud",	IFF_NONUD,	setifflags,	0,	AF_INET6 },
	{ "nud",	-IFF_NONUD,	setifflags,	0,	AF_INET6 },
	{ "anycast",	IFF_ANYCAST,	setifflags,	0,	AF_ANY },
	{ "-anycast",	-IFF_ANYCAST,	setifflags,	0,	AF_ANY },
	{ "local",	-IFF_NOLOCAL,	setifflags,	0,	AF_ANY },
	{ "-local",	IFF_NOLOCAL,	setifflags,	0,	AF_ANY },
	{ "deprecated",	IFF_DEPRECATED,	setifflags,	0,	AF_ANY },
	{ "-deprecated", -IFF_DEPRECATED, setifflags,	0,	AF_ANY },
	{ "preferred",	IFF_PREFERRED,	setifflags,	0,	AF_INET6 },
	{ "-preferred",	-IFF_PREFERRED,	setifflags,	0,	AF_INET6 },
	{ "debug",	0,		setdebugflag,	0,	AF_ANY },
	{ "verbose",	0,		setverboseflag,	0,	AF_ANY },
	{ NETMASK_CMD,	NEXTARG,	setifnetmask,	0,	AF_INET },
	{ "metric",	NEXTARG,	setifmetric,	0,	AF_ANY },
	{ "mtu",	NEXTARG,	setifmtu,	0,	AF_ANY },
	{ "index",	NEXTARG,	setifindex,	0,	AF_ANY },
	{ "broadcast",	NEXTARG,	setifbroadaddr,	0,	AF_INET },
	{ "auto-revarp", 0,		setifrevarp,	1,	AF_INET },
	{ "plumb",	0,		inetplumb,	1,	AF_ANY },
	{ "unplumb",	0,		inetunplumb,	0,	AF_ANY },
	{ "subnet",	NEXTARG,	setifsubnet,	0,	AF_ANY },
	{ "token",	NEXTARG,	setiftoken,	0,	AF_INET6 },
	{ "tsrc",	NEXTARG,	setiftsrc,	0,	AF_ANY },
	{ "tdst",	NEXTARG,	setiftdst,	0,	AF_ANY },
	{ "encr_auth_algs", NEXTARG,	set_tun_esp_auth_alg, 0, AF_ANY },
	{ "encr_algs",	NEXTARG,	set_tun_esp_encr_alg, 0, AF_ANY },
	{ "auth_algs",	NEXTARG,	set_tun_ah_alg,	0,	AF_ANY },
	{ "addif",	NEXTARG,	addif,		1,	AF_ANY },
	{ "removeif",	NEXTARG,	removeif,	1,	AF_ANY },
	{ "modlist",	0,		modlist,	1,	AF_ANY },
	{ "modinsert",	NEXTARG,	modinsert,	1,	AF_ANY },
	{ "modremove",	NEXTARG,	modremove,	1,	AF_ANY },
	{ "failover",	-IFF_NOFAILOVER, setifflags,	1,	AF_ANY },
	{ "-failover",	IFF_NOFAILOVER, setifflags,	1,	AF_ANY },
	{ "standby",	IFF_STANDBY,	setifflags,	1,	AF_ANY },
	{ "-standby",	-IFF_STANDBY,	setifflags,	1,	AF_ANY },
	{ "failed",	IFF_FAILED,	setifflags,	1,	AF_ANY },
	{ "-failed",	-IFF_FAILED,	setifflags,	1,	AF_ANY },
	{ "group",	NEXTARG,	setifgroupname,	1,	AF_ANY },
	{ "configinfo",	0,		configinfo,	1,	AF_ANY },
	{ "encaplimit",	NEXTARG,	set_tun_encap_limit,	0, AF_ANY },
	{ "-encaplimit", 0,		clr_tun_encap_limit,	0, AF_ANY },
	{ "thoplimit",	NEXTARG,	set_tun_hop_limit,	0, AF_ANY },
	{ "set",	NEXTARG,	setifaddr,	0,	AF_ANY },
	{ "destination", NEXTARG,	setifdstaddr,	0,	AF_ANY },
	{ "zone",	NEXTARG,	setzone,	0,	AF_ANY },
	{ "-zone",	0,		setzone,	0,	AF_ANY },
	{ "all-zones",	0,		setallzones,	0,	AF_ANY },
	{ "ether",	OPTARG,		setifether,	0,	AF_ANY },
	{ "usesrc",	NEXTARG,	setifsrc,	0,	AF_ANY },

	/*
	 * NOTE: any additions to this table must also be applied to ifparse
	 *	(usr/src/cmd/cmd-inet/sbin/ifparse/ifparse.c)
	 */

	{ 0,		0,		setifaddr,	0,	AF_ANY },
	{ 0,		0,		setifdstaddr,	0,	AF_ANY },
	{ 0,		0,		0,		0,	0 },
};


typedef struct if_config_cmd {
	uint64_t	iff_flag;
	char		*iff_name;
} if_config_cmd_t;

static if_config_cmd_t	if_config_cmd_tbl[] = {
	{ IFF_UP,		"up" },
	{ IFF_NOTRAILERS,	"-trailers" },
	{ IFF_PRIVATE,		"private" },
	{ IFF_NOXMIT,		"-xmit" },
	{ IFF_ANYCAST,		"anycast" },
	{ IFF_NOLOCAL,		"-local" },
	{ IFF_DEPRECATED,	"deprecated" },
	{ IFF_NOFAILOVER,	"-failover" },
	{ IFF_STANDBY,		"standby" },
	{ IFF_FAILED,		"failed" },
	{ IFF_PREFERRED,	"preferred" },
	{ 0,			0 },
};

typedef struct ni {
	char		ni_name[LIFNAMSIZ];
	struct ni	*ni_next;
} ni_t;

static ni_t	*ni_list = NULL;
static int	num_ni = 0;

/* End defines and structure definitions for ifconfig -a plumb */

/* Known address families */
struct afswtch {
	char *af_name;
	short af_af;
	void (*af_status)();
	void (*af_getaddr)();
	void (*af_configinfo)();
} afs[] = {
	{ "inet", AF_INET, in_status, in_getaddr, in_configinfo },
	{ "inet6", AF_INET6, in6_status, in6_getaddr, in6_configinfo },
	{ 0, 0,	0, 0, 0 }
};

#define	SOCKET_AF(af)	(((af) == AF_UNSPEC) ? AF_INET : (af))

struct afswtch *afp;	/* the address family being set or asked about */

int
main(int argc, char *argv[])
{
	/* Include IFF_NOXMIT, IFF_TEMPORARY and all zone interfaces */
	int64_t lifc_flags = LIFC_NOXMIT | LIFC_TEMPORARY | LIFC_ALLZONES;
	char *default_ip_str;

	if (argc < 2) {
		usage();
		exit(1);
	}
	argc--, argv++;
	if (strlen(*argv) > sizeof (name) - 1) {
		(void) fprintf(stderr, "%s: interface name too long\n", *argv);
		exit(1);
	}
	(void) strncpy(name, *argv, sizeof (name));
	name[sizeof (name) - 1] = '\0';
	(void) strncpy(origname, name, sizeof (origname));	/* For addif */
	default_ip_str = NULL;
	v4compat = get_compat_flag(&default_ip_str);
	if (v4compat == DEFAULT_PROT_BAD_VALUE) {
		(void) fprintf(stderr,
		    "ifconfig: %s: Bad value for %s in %s\n", default_ip_str,
		    DEFAULT_IP, INET_DEFAULT_FILE);
		free(default_ip_str);
		exit(2);
	}
	free(default_ip_str);
	argc--, argv++;
	if (argc > 0) {
		struct afswtch *myafp;

		for (myafp = afp = afs; myafp->af_name; myafp++) {
			if (strcmp(myafp->af_name, *argv) == 0) {
				afp = myafp; argc--; argv++;
				break;
			}
		}
		af = lifr.lifr_addr.ss_family = afp->af_af;
		if (af == AF_INET6) {
			v4compat = 0;
		}
	}

	s = socket(SOCKET_AF(af), SOCK_DGRAM, 0);
	if (s < 0) {
		Perror0_exit("socket");
	}

	/*
	 * Special interface names is any combination of these flags.
	 * Note that due to the ifconfig syntax they have to be combined
	 * as a single '-' option.
	 *	-a	All interfaces
	 *	-u	"up" interfaces
	 *	-d	"down" interfaces
	 *	-D	Interfaces not controlled by DHCP
	 *	-4	IPv4 interfaces
	 *	-6	IPv6 interfaces
	 *	-X	Turn on debug (not documented)
	 *	-v	Turn on verbose
	 *	-Z	Only interfaces in caller's zone
	 */

	if (name[0] == '-') {
		/* One or more options */
		int64_t onflags = 0;
		int64_t offflags = 0;
		int c;
		char *av[2] = { "ifconfig", name };

		while ((c = getopt(2, av, "audDXZ46v")) != -1) {
			switch ((char)c) {
			case 'a':
				all = 1;
				break;
			case 'u':
				onflags |= IFF_UP;
				break;
			case 'd':
				offflags |= IFF_UP;
				break;
			case 'D':
				offflags |= IFF_DHCPRUNNING;
				break;
			case 'X':
				debug += 3;
				break;
			case 'Z':
				lifc_flags &= ~LIFC_ALLZONES;
				break;
			case '4':
				/*
				 * -4 is not a compatable flag, therefore
				 * we assume they want v4compat turned off
				 */
				v4compat = 0;
				onflags |= IFF_IPV4;
				break;
			case '6':
				/*
				 * If they want IPv6, well then we'll assume
				 * they don't want IPv4 compat
				 */
				v4compat = 0;
				onflags |= IFF_IPV6;
				break;
			case 'v':
				verbose = 1;
				break;
			case '?':
				usage();
				exit(1);
			}
		}
		if (!all) {
			(void) fprintf(stderr,
			    "ifconfig: %s: no such interface\n", name);
			exit(1);
		}
		foreachinterface(ifconfig, argc, argv, af, onflags, offflags,
		    lifc_flags);
	} else {
		ifconfig(argc, argv, af, (struct lifreq *)NULL);
	}
	return (0);
}

/*
 * For each interface, call (*func)(argc, argv, af, lifrp).
 * Only call function if onflags and offflags are set or clear, respectively,
 * in the interfaces flags field.
 */
static void
foreachinterface(void (*func)(), int argc, char *argv[], int af,
    int64_t onflags, int64_t offflags, int64_t lifc_flags)
{
	int n;
	char *buf;
	struct lifnum lifn;
	struct lifconf lifc;
	struct lifreq *lifrp;
	struct lifreq lifrl;	/* Local lifreq struct */
	int numifs;
	unsigned bufsize;
	int plumball = 0;
	int save_af = af;

	buf = NULL;
	/*
	 * Special case:
	 * ifconfig -a plumb should find all network interfaces
	 * in the machine for the global zone.
	 * For non-global zones, only find the assigned interfaces.
	 * Also, there is no need to  SIOCGLIF* ioctls, since
	 * those interfaces have already been plumbed
	 */
	if (argc > 0 && (strcmp(*argv, "plumb") == 0)) {
		if (getzoneid() == GLOBAL_ZONEID) {
			if (find_all_global_interfaces(&lifc, &buf,
			    lifc_flags) != 0)
				return;
		} else {
			if (find_all_zone_interfaces(&lifc, &buf,
			    lifc_flags) != 0)
				return;
		}
		if (lifc.lifc_len == 0)
			return;
		plumball = 1;
	} else {
		lifn.lifn_family = AF_UNSPEC;
		lifn.lifn_flags = lifc_flags;
		if (ioctl(s, SIOCGLIFNUM, (char *)&lifn) < 0) {
			Perror0_exit("Could not determine number"
			    " of interfaces");
		}
		numifs = lifn.lifn_count;
		if (debug)
			(void) printf("ifconfig: %d interfaces\n",  numifs);

		bufsize = numifs * sizeof (struct lifreq);
		if ((buf = malloc(bufsize)) == NULL) {
			Perror0("out of memory\n");
			(void) close(s);
			return;
		}

		lifc.lifc_family = AF_UNSPEC;
		lifc.lifc_flags = lifc_flags;
		lifc.lifc_len = bufsize;
		lifc.lifc_buf = buf;

		if (ioctl(s, SIOCGLIFCONF, (char *)&lifc) < 0) {
			Perror0("SIOCGLIFCONF");
			(void) close(s);
			free(buf);
			return;
		}
	}

	lifrp = lifc.lifc_req;
	for (n = lifc.lifc_len / sizeof (struct lifreq); n > 0; n--, lifrp++) {

		if (!plumball) {
			/*
			 * We must close and recreate the socket each time
			 * since we don't know what type of socket it is now
			 * (each status function may change it).
			 */

			(void) close(s);

			af = lifrp->lifr_addr.ss_family;
			s = socket(SOCKET_AF(af), SOCK_DGRAM, 0);
			if (s == -1) {
				/*
				 * Perror0() assumes the name to be in the
				 * globally defined lifreq structure.
				 */
				(void) strncpy(lifr.lifr_name,
				    lifrp->lifr_name, sizeof (lifr.lifr_name));
				Perror0_exit("socket");
			}
		}

		/*
		 * Only service interfaces that match the on and off
		 * flags masks.
		 */
		if (onflags || offflags) {
			(void) memset(&lifrl, 0, sizeof (lifrl));
			(void) strncpy(lifrl.lifr_name, lifrp->lifr_name,
			    sizeof (lifrl.lifr_name));
			if (ioctl(s, SIOCGLIFFLAGS, (caddr_t)&lifrl) < 0) {
				/*
				 * Perror0() assumes the name to be in the
				 * globally defined lifreq structure.
				 */
				(void) strncpy(lifr.lifr_name,
				    lifrp->lifr_name, sizeof (lifr.lifr_name));
				Perror0_exit("foreachinterface: SIOCGLIFFLAGS");
			}
			if ((lifrl.lifr_flags & onflags) != onflags)
				continue;
			if ((~lifrl.lifr_flags & offflags) != offflags)
				continue;
		}

		if (!plumball) {
			(void) strncpy(lifrl.lifr_name, lifrp->lifr_name,
			    sizeof (lifrl.lifr_name));
			if (ioctl(s, SIOCGLIFADDR, (caddr_t)&lifrl) < 0) {
				/*
				 * Perror0() assumes the name to be in the
				 * globally defined lifreq structure.
				 */
				(void) strncpy(lifr.lifr_name,
				    lifrp->lifr_name, sizeof (lifr.lifr_name));
				Perror0("foreachinterface: SIOCGLIFADDR");
				continue;
			}
			if (lifrl.lifr_addr.ss_family != af) {
				/* Switch address family */
				af = lifrl.lifr_addr.ss_family;
				(void) close(s);

				s = socket(SOCKET_AF(af), SOCK_DGRAM, 0);
				if (s == -1) {
					/*
					 * Perror0() assumes the name to be in
					 * the globally defined lifreq
					 * structure.
					 */
					(void) strncpy(lifr.lifr_name,
					    lifrp->lifr_name,
					    sizeof (lifr.lifr_name));
					Perror0_exit("socket");
				}
			}
		}

		/*
		 * Reset global state
		 * setaddr: Used by parser to tear apart source and dest
		 * name and origname contain the name of the 'current'
		 * interface.
		 */
		setaddr = 0;
		(void) strncpy(name, lifrp->lifr_name, sizeof (name));
		(void) strncpy(origname, name, sizeof (origname));

		(*func)(argc, argv, save_af, lifrp);
		/* the func could have overwritten origname, so restore */
		(void) strncpy(name, origname, sizeof (name));
	}
	if (buf != NULL)
		free(buf);
}

static void
tun_reality_check(void)
{
	struct iftun_req treq;
	ipsec_req_t *ipsr;

	(void) strncpy(treq.ifta_lifr_name, name, sizeof (treq.ifta_lifr_name));
	if (strchr(name, ':') != NULL) {
		/* Return, we don't need to check. */
		return;
	}
	if (ioctl(s, SIOCGTUNPARAM, (caddr_t)&treq) < 0 ||
	    (treq.ifta_flags & IFTUN_SECURITY) == 0) {
		/*
		 * Either not a tunnel (the SIOCGTUNPARAM fails on
		 * non-tunnels), or the security flag is not set.  Either
		 * way, return.
		 */
		return;
	}

	ipsr = (ipsec_req_t *)&treq.ifta_secinfo;

	if (ipsr->ipsr_esp_req != 0 &&
	    ipsr->ipsr_esp_auth_alg == SADB_AALG_NONE &&
	    ipsr->ipsr_ah_req == 0)
		(void) fprintf(stderr, "ifconfig: WARNING - tunnel with "
		    "only ESP and potentially no authentication.\n");
}

/*
 * for the specified interface call (*func)(argc, argv, af, lifrp).
 */

static void
ifconfig(int argc, char *argv[], int af, struct lifreq *lifrp)
{
	static boolean_t scan_netmask = _B_FALSE;
	int ret;

	if (argc == 0) {
		status();
		return;
	}

	if (strcmp(*argv, "auto-dhcp") == 0 || strcmp(*argv, "dhcp") == 0) {
		/*
		 * Some errors are ignored in the case where more than one
		 * interface is being operated on.
		 */
		ret = setifdhcp("ifconfig", name, argc, argv);
		if (ret == DHCP_EXIT_IF_FAILURE) {
			if (!all)
				exit(DHCP_EXIT_FAILURE);
		} else if (ret != DHCP_EXIT_SUCCESS) {
			exit(ret);
		}
		return;
	}

	/*
	 * The following is a "hack" to get around the existing interface
	 * setting mechanism.  Currently, each interface attribute,
	 * such as address, netmask, broadcast, ... is set separately.  But
	 * sometimes two or more attributes must be set together.  For
	 * example, setting an address without a netmask does not make sense.
	 * Yet they can be set separately for IPv4 address using the current
	 * ifconfig(1M) syntax.  The kernel then "infers" the correct netmask
	 * using the deprecated "IP address classes."  This is simply not
	 * correct.
	 *
	 * The "hack" below is to go thru the whole command list looking for
	 * the netmask command first.  Then use this netmask to set the
	 * address.  This does not provide an extensible way to accommodate
	 * future need for setting more than one attributes together.
	 *
	 * Note that if the "netmask" command argument is a "+", we need
	 * to save this info and do the query after we know the address to
	 * be set.  The reason is that if "addif" is used, the working
	 * interface name will be changed later when the logical interface
	 * is created.  In in_getmask(), if an address is not provided,
	 * it will use the working interface's address to do the query.
	 * It will be wrong now as we don't know the logical interface's name.
	 *
	 * ifconfig(1M) is too overloaded and the code is so convoluted
	 * that it is "safer" not to re-architect the code to fix the above
	 * issue, hence this "hack."  We may be better off to have a new
	 * command with better syntax for configuring network interface
	 * parameters...
	 */
	if (!scan_netmask && afp->af_af == AF_INET) {
		int	largc;
		char	**largv;

		/* Only go thru the command list once to find the netmask. */
		scan_netmask = _B_TRUE;

		/*
		 * Currently, if multiple netmask commands are specified, the
		 * last one will be used as the final netmask.  So we need
		 * to scan the whole list to preserve this behavior.
		 */
		for (largc = argc, largv = argv; largc > 0; largc--, largv++) {
			if (strcmp(*largv, NETMASK_CMD) == 0) {
				if (--largc == 0)
					break;
				largv++;
				if (strcmp(*largv, "+") == 0) {
					g_netmask_set = G_NETMASK_PENDING;
				} else {
					in_getaddr(*largv, (struct sockaddr *)
					    &g_netmask, NULL);
					g_netmask_set = G_NETMASK_SET;
				}
				/* Continue the scan. */
			}
		}
	}

	while (argc > 0) {
		struct cmd *p;
		boolean_t found_cmd;

		if (debug)
			(void) printf("ifconfig: argv %s\n", *argv);

		found_cmd = _B_FALSE;
		for (p = cmds; p->c_func; p++) {
			if (p->c_name) {
				if (strcmp(*argv, p->c_name) == 0) {
					/*
					 * indicate that the command was
					 * found and check to see if
					 * the address family is valid
					 */
					found_cmd = _B_TRUE;
					if (p->c_af == AF_ANY ||
					    af == p->c_af)
						break;
				}
			} else {
				if (p->c_af == AF_ANY ||
				    af == p->c_af)
					break;
			}
		}
		/*
		 * If we found the keyword, but the address family
		 * did not match spit out an error
		 */
		if (found_cmd && p->c_name == 0) {
			(void) fprintf(stderr, "ifconfig: Operation %s not"
			    " supported for %s\n", *argv, afp->af_name);
			exit(1);
		}
		/*
		 * else (no keyword found), we assume it's an address
		 * of some sort
		 */
		if (p->c_name == 0 && setaddr)
			p++;	/* got src, do dst */
		if (p->c_func) {
			if (p->c_af == AF_INET6) {
				v4compat = 0;
			}
			if (p->c_parameter == NEXTARG ||
			    p->c_parameter == OPTARG) {
				argc--, argv++;
				if (argc == 0 && p->c_parameter == NEXTARG) {
					(void) fprintf(stderr,
					    "ifconfig: no argument for %s\n",
					    p->c_name);
					exit(1);
				}
			}
			/*
			 *	Call the function if:
			 *
			 *		there's no address family
			 *		restriction
			 *	OR
			 *		we don't know the address yet
			 *		(because we were called from
			 *		main)
			 *	OR
			 *		there is a restriction AND
			 *		the address families match
			 */
			if ((p->c_af == AF_ANY)	||
			    (lifrp == (struct lifreq *)NULL) ||
			    (lifrp->lifr_addr.ss_family == p->c_af)) {
				ret = (*p->c_func)(*argv, p->c_parameter);
				/*
				 *	If c_func failed and we should
				 *	abort processing for this
				 *	interface on failure, return
				 *	now rather than going on to
				 *	process other commands for
				 *	the same interface.
				 */
				if (ret != 0 && p->c_abortonfail)
					return;
			}
		}
		argc--, argv++;
	}

	/* Check to see if there's a security hole in the tunnel setup. */
	tun_reality_check();
}

/* ARGSUSED */
static int
setdebugflag(char *val, int64_t arg)
{
	debug++;
	return (0);
}

/* ARGSUSED */
static int
setverboseflag(char *val, int64_t arg)
{
	verbose++;
	return (0);
}

/*
 * This function fills in the given lifreq's lifr_addr field based on
 * g_netmask_set.
 */
static void
set_mask_lifreq(struct lifreq *lifr, struct sockaddr_storage *addr,
    struct sockaddr_storage *mask)
{
	assert(addr != NULL);
	assert(mask != NULL);

	switch (g_netmask_set) {
	case G_NETMASK_SET:
		lifr->lifr_addr = g_netmask;
		break;

	case G_NETMASK_PENDING:
		/*
		 * "+" is used as the argument to "netmask" command.  Query
		 * the database on the correct netmask based on the address to
		 * be set.
		 */
		assert(afp->af_af == AF_INET);
		g_netmask = *addr;
		if (!in_getmask((struct sockaddr_in *)&g_netmask, _B_TRUE)) {
			lifr->lifr_addr = *mask;
			g_netmask_set = G_NETMASK_NIL;
		} else {
			lifr->lifr_addr = g_netmask;
			g_netmask_set = G_NETMASK_SET;
		}
		break;

	case G_NETMASK_NIL:
	default:
		lifr->lifr_addr = *mask;
		break;
	}
}

/*
 * Set the interface address. Handles <addr>, <addr>/<n> as well as /<n>
 * syntax for setting the address, the address plus netmask, and just
 * the netmask respectively.
 */
/* ARGSUSED */
static int
setifaddr(char *addr, int64_t param)
{
	int prefixlen = 0;
	struct	sockaddr_storage laddr;
	struct	sockaddr_storage netmask;
	struct	sockaddr_in6 *sin6;
	struct	sockaddr_in *sin;
	struct	sockaddr_storage sav_netmask;

	if (addr[0] == '/')
		return (setifprefixlen(addr, 0));

	(*afp->af_getaddr)(addr, (struct sockaddr *)&laddr, &prefixlen);

	(void) memset(&netmask, 0, sizeof (netmask));
	netmask.ss_family = afp->af_af;
	switch (prefixlen) {
	case NO_PREFIX:
		/* Nothing there - ok */
		break;
	case BAD_ADDR:
		(void) fprintf(stderr, "ifconfig: Bad prefix length in %s\n",
		    addr);
		exit(1);
	default:
		if (afp->af_af == AF_INET6) {
			sin6 = (struct sockaddr_in6 *)&netmask;
			if (!in_prefixlentomask(prefixlen, IPV6_ABITS,
			    (uchar_t *)&sin6->sin6_addr)) {
				(void) fprintf(stderr, "ifconfig: "
				    "Bad prefix length: %d\n",
				    prefixlen);
				exit(1);
			}
		} else {
			sin = (struct sockaddr_in *)&netmask;
			if (!in_prefixlentomask(prefixlen, IP_ABITS,
			    (uchar_t *)&sin->sin_addr)) {
				(void) fprintf(stderr, "ifconfig: "
				    "Bad prefix length: %d\n",
				    prefixlen);
				exit(1);
			}
		}
		/*
		 * Just in case of funny setting of both prefix and netmask,
		 * prefix should override the netmask command.
		 */
		g_netmask_set = G_NETMASK_NIL;
		break;
	}
	/* Tell parser that an address was set */
	setaddr++;
	/* save copy of netmask to restore in case of error */
	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCGLIFNETMASK, (caddr_t)&lifr) < 0)
		Perror0_exit("SIOCGLIFNETMASK");
	sav_netmask = lifr.lifr_addr;

	/*
	 * If setting the address and not the mask, clear any existing mask
	 * and the kernel will then assign the default (netmask has been set
	 * to 0 in this case).  If setting both (either by using a prefix or
	 * using the netmask command), set the mask first, so the address will
	 * be interpreted correctly.
	 */
	set_mask_lifreq(&lifr, &laddr, &netmask);
	if (ioctl(s, SIOCSLIFNETMASK, (caddr_t)&lifr) < 0)
		Perror0_exit("SIOCSLIFNETMASK");

	if (debug) {
		char abuf[INET6_ADDRSTRLEN];
		void *addr = (afp->af_af == AF_INET) ?
		    (void *)&((struct sockaddr_in *)&laddr)->sin_addr :
		    (void *)&((struct sockaddr_in6 *)&laddr)->sin6_addr;

		(void) printf("Setting %s af %d addr %s\n",
		    lifr.lifr_name, afp->af_af,
		    inet_ntop(afp->af_af, addr, abuf, sizeof (abuf)));
	}
	lifr.lifr_addr = laddr;
	lifr.lifr_addr.ss_family = afp->af_af;
	if (ioctl(s, SIOCSLIFADDR, (caddr_t)&lifr) < 0) {
		/*
		 * Restore the netmask
		 */
		int saverr = errno;

		(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
		lifr.lifr_addr = sav_netmask;
		(void) ioctl(s, SIOCSLIFNETMASK, (caddr_t)&lifr);
		errno = saverr;
		Perror0_exit("SIOCSLIFADDR");
	}

	return (0);
}

/*
 * The following functions are stolen from the ipseckey(1m) program.
 * Perhaps they should be somewhere common, but for now, we just maintain
 * two versions.  We do this because of the different semantics for which
 * algorithms we select ("requested" for ifconfig vs. "actual" for key).
 */

static ulong_t
parsenum(char *num)
{
	ulong_t rc;
	char *end = NULL;

	errno = 0;
	rc = strtoul(num, &end, 0);
	if (errno != 0 || end == num || *end != '\0') {
		rc = (ulong_t)-1;
	}

	return (rc);
}

/*
 * Parse and reverse parse possible algorithm values, include numbers.
 * Mostly stolen from ipseckey.c. See the comments above parsenum() for why
 * this isn't common to ipseckey.c.
 *
 * NOTE: Static buffer in this function for the return value.  Since ifconfig
 *	 isn't multithreaded, this isn't a huge problem.
 */

#define	NBUF_SIZE 20	/* Enough to print a large integer. */

static char *
rparsealg(uint8_t alg_value, int proto_num)
{
	struct ipsecalgent *alg;
	static char numprint[128];	/* Enough to hold an algorithm name. */

	/* Special-case 0 to return "<any-none>" */
	if (alg_value == 0)
		return ("<any-none>");

	alg = getipsecalgbynum(alg_value, proto_num, NULL);
	if (alg != NULL) {
		(void) strlcpy(numprint, alg->a_names[0], sizeof (numprint));
		freeipsecalgent(alg);
	} else {
		(void) snprintf(numprint, sizeof (numprint), "%d", alg_value);
	}

	return (numprint);
}

static uint_t
parsealg(char *algname, int proto_num)
{
	struct ipsecalgent *alg;
	ulong_t invalue;

	if (algname == NULL) {
		(void) fprintf(stderr, "ifconfig: Unexpected end of command "
		    "line.\n");
		exit(1);
	}

	/*
	 * Special-case "none". Use strcasecmp because its length is
	 * bound.
	 */
	if (strcasecmp("none", algname) == 0) {
		return ((proto_num == IPSEC_PROTO_ESP) ?
		    NO_ESP_EALG : NO_ESP_AALG);
	}

	alg = getipsecalgbyname(algname, proto_num, NULL);
	if (alg != NULL) {
		invalue = alg->a_alg_num;
		freeipsecalgent(alg);
		return ((uint_t)invalue);
	}

	/*
	 * Since algorithms can be loaded during kernel run-time, check for
	 * numeric algorithm values too.
	 */
	invalue = parsenum(algname);
	if ((invalue & (ulong_t)0xff) == invalue)
		return ((uint_t)invalue);

	(void) fprintf(stderr, "ifconfig: %s algorithm type %s unknown.\n",
	    (proto_num == IPSEC_PROTO_ESP) ?
	    "Encryption" : "Authentication", algname);
	exit(1);
	/* NOTREACHED */
}

/*
 * Actual ifconfig functions to set tunnel security properties.
 */

enum ipsec_alg_type { ESP_ENCR_ALG = 1, ESP_AUTH_ALG, AH_AUTH_ALG };

boolean_t first_set_tun = _B_TRUE;
boolean_t encr_alg_set = _B_FALSE;

static int
set_tun_algs(int which_alg, int alg)
{
	struct iftun_req treq;
	ipsec_req_t *ipsr;

	(void) strncpy(treq.ifta_lifr_name, name, sizeof (treq.ifta_lifr_name));
	if (strchr(name, ':') != NULL) {
		errno = EPERM;
		Perror0_exit("Tunnel params on logical interfaces");
	}
	if (ioctl(s, SIOCGTUNPARAM, (caddr_t)&treq) < 0) {
		if (errno == EOPNOTSUPP || errno == EINVAL)
			Perror0_exit("Not a tunnel");
		else Perror0_exit("SIOCGTUNPARAM");
	}

	ipsr = (ipsec_req_t *)&treq.ifta_secinfo;

	if (treq.ifta_vers != IFTUN_VERSION) {
		(void) fprintf(stderr,
		    "Kernel tunnel secinfo version mismatch.\n");
		exit(1);
	}

	/*
	 * If I'm just starting off this ifconfig, I want a clean slate,
	 * otherwise, I've captured the current tunnel security settings.
	 * In the case of continuation, I merely add to the settings.
	 */
	if (first_set_tun) {
		first_set_tun = _B_FALSE;
		(void) memset(ipsr, 0, sizeof (*ipsr));
	}

	treq.ifta_flags = IFTUN_SECURITY;

	switch (which_alg) {
	case ESP_ENCR_ALG:
		if (alg == NO_ESP_EALG) {
			if (ipsr->ipsr_esp_auth_alg == SADB_AALG_NONE)
				ipsr->ipsr_esp_req = 0;
			ipsr->ipsr_esp_alg = SADB_EALG_NONE;
		} else {
			encr_alg_set = _B_TRUE;
			ipsr->ipsr_esp_req =
			    IPSEC_PREF_REQUIRED | IPSEC_PREF_UNIQUE;
			ipsr->ipsr_esp_alg = alg;
		}
		break;
	case ESP_AUTH_ALG:
		if (alg == NO_ESP_AALG) {
			if (ipsr->ipsr_esp_alg == SADB_EALG_NONE ||
			    ipsr->ipsr_esp_alg == SADB_EALG_NULL)
				ipsr->ipsr_esp_req = 0;
			ipsr->ipsr_esp_auth_alg = SADB_AALG_NONE;
		} else {
			ipsr->ipsr_esp_req =
			    IPSEC_PREF_REQUIRED | IPSEC_PREF_UNIQUE;
			ipsr->ipsr_esp_auth_alg = alg;

			/* Let the user specify NULL encryption implicitly. */
			if (ipsr->ipsr_esp_alg == SADB_EALG_NONE &&
			    !encr_alg_set)
				ipsr->ipsr_esp_alg = SADB_EALG_NULL;
		}
		break;
	case AH_AUTH_ALG:
		if (alg == NO_AH_AALG) {
			ipsr->ipsr_ah_req = 0;
			ipsr->ipsr_auth_alg = SADB_AALG_NONE;
		} else {
			ipsr->ipsr_ah_req =
			    IPSEC_PREF_REQUIRED | IPSEC_PREF_UNIQUE;
			ipsr->ipsr_auth_alg = alg;
		}
		break;
		/* Will never hit DEFAULT */
	}

	if (ioctl(s, SIOCSTUNPARAM, (caddr_t)&treq) < 0) {
		Perror2_exit("set tunnel security properties",
		    treq.ifta_lifr_name);
	}

	return (0);
}

/* ARGSUSED */
static int
set_tun_esp_encr_alg(char *addr, int64_t param)
{
	return (set_tun_algs(ESP_ENCR_ALG,
	    parsealg(addr, IPSEC_PROTO_ESP)));
}

/* ARGSUSED */
static int
set_tun_esp_auth_alg(char *addr, int64_t param)
{
	return (set_tun_algs(ESP_AUTH_ALG,
	    parsealg(addr, IPSEC_PROTO_AH)));
}

/* ARGSUSED */
static int
set_tun_ah_alg(char *addr, int64_t param)
{
	return (set_tun_algs(AH_AUTH_ALG,
	    parsealg(addr, IPSEC_PROTO_AH)));
}

/* ARGSUSED */
static int
setifrevarp(char *arg, int64_t param)
{
	struct sockaddr_in	laddr;

	if (afp->af_af == AF_INET6) {
		(void) fprintf(stderr,
		    "ifconfig: revarp not possible on IPv6 interface %s\n",
		    name);
		exit(1);
	}
	if (doifrevarp(name, &laddr)) {
		(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
		laddr.sin_family = AF_INET;
		(void) memcpy(&lifr.lifr_addr, &laddr, sizeof (laddr));
		if (ioctl(s, SIOCSLIFADDR, (caddr_t)&lifr) < 0)
			Perror0_exit("SIOCSLIFADDR");
	}
	return (0);
}

/* ARGSUSED */
static int
setifsubnet(char *addr, int64_t param)
{
	int prefixlen = 0;
	struct	sockaddr_storage subnet;

	(*afp->af_getaddr)(addr, &subnet, &prefixlen);

	switch (prefixlen) {
	case NO_PREFIX:
		(void) fprintf(stderr,
		    "ifconfig: Missing prefix length in subnet %s\n", addr);
		exit(1);
		/* NOTREACHED */
	case BAD_ADDR:
		(void) fprintf(stderr,
		    "ifconfig: Bad prefix length in %s\n", addr);
		exit(1);
	default:
		break;
	}

	lifr.lifr_addr = subnet;
	lifr.lifr_addrlen = prefixlen;
	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCSLIFSUBNET, (caddr_t)&lifr) < 0)
		Perror0_exit("SIOCSLIFSUBNET");

	return (0);
}

/* ARGSUSED */
static int
setifnetmask(char *addr, int64_t param)
{
	struct sockaddr_in netmask;

	assert(afp->af_af != AF_INET6);

	if (strcmp(addr, "+") == 0) {
		if (!in_getmask(&netmask, _B_FALSE))
			return (0);
		(void) printf("Setting netmask of %s to %s\n", name,
		    inet_ntoa(netmask.sin_addr));
	} else {
		in_getaddr(addr, (struct sockaddr *)&netmask, NULL);
	}
	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	(void) memcpy(&lifr.lifr_addr, &netmask, sizeof (netmask));
	if (ioctl(s, SIOCSLIFNETMASK, (caddr_t)&lifr) < 0)
		Perror0_exit("SIOCSLIFNETMASK");
	return (0);
}

/*
 * Parse '/<n>' as a netmask.
 */
/* ARGSUSED */
static int
setifprefixlen(char *addr, int64_t param)
{
	int prefixlen;
	int af = afp->af_af;

	prefixlen = in_getprefixlen(addr, _B_TRUE,
	    (af == AF_INET) ? IP_ABITS : IPV6_ABITS);
	if (prefixlen < 0) {
		(void) fprintf(stderr,
		    "ifconfig: Bad prefix length in %s\n", addr);
		exit(1);
	}
	(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));
	lifr.lifr_addr.ss_family = af;
	if (af == AF_INET6) {
		struct sockaddr_in6 *sin6;

		sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;
		if (!in_prefixlentomask(prefixlen, IPV6_ABITS,
		    (uchar_t *)&sin6->sin6_addr)) {
			(void) fprintf(stderr, "ifconfig: "
			    "Bad prefix length: %d\n",
			    prefixlen);
			exit(1);
		}
	} else if (af == AF_INET) {
		struct sockaddr_in *sin;

		sin = (struct sockaddr_in *)&lifr.lifr_addr;
		if (!in_prefixlentomask(prefixlen, IP_ABITS,
		    (uchar_t *)&sin->sin_addr)) {
			(void) fprintf(stderr, "ifconfig: "
			    "Bad prefix length: %d\n",
			    prefixlen);
			exit(1);
		}
	} else {
		(void) fprintf(stderr, "ifconfig: setting prefix only supported"
		    " for address family inet or inet6\n");
		exit(1);
	}
	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCSLIFNETMASK, (caddr_t)&lifr) < 0)
		Perror0_exit("SIOCSLIFNETMASK");
	return (0);
}

/* ARGSUSED */
static int
setifbroadaddr(char *addr, int64_t param)
{
	struct	sockaddr_in broadaddr;

	assert(afp->af_af != AF_INET6);

	if (strcmp(addr, "+") == 0) {
		/*
		 * This doesn't set the broadcast address at all. Rather, it
		 * gets, then sets the interface's address, relying on the fact
		 * that resetting the address will reset the broadcast address.
		 */
		(void) strncpy(lifr.lifr_name, name,
		    sizeof (lifr.lifr_name));
		if (ioctl(s, SIOCGLIFADDR, (caddr_t)&lifr) < 0) {
			if (errno != EADDRNOTAVAIL)
				Perror0_exit("SIOCGLIFADDR");
			return (0);
		}
		if (ioctl(s, SIOCSLIFADDR, (caddr_t)&lifr) < 0)
			Perror0_exit("SIOCGLIFADDR");

		return (0);
	}
	in_getaddr(addr, (struct sockaddr *)&broadaddr, NULL);

	(void) memcpy(&lifr.lifr_addr, &broadaddr, sizeof (broadaddr));
	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCSLIFBRDADDR, (caddr_t)&lifr) < 0)
		Perror0_exit("SIOCSLIFBRDADDR");
	return (0);
}

/*
 * set interface destination address
 */
/* ARGSUSED */
static int
setifdstaddr(char *addr, int64_t param)
{
	(*afp->af_getaddr)(addr, (struct sockaddr *)&lifr.lifr_addr, NULL);
	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCSLIFDSTADDR, (caddr_t)&lifr) < 0)
		Perror0_exit("setifdstaddr: SIOCSLIFDSTADDR");
	return (0);
}

/* ARGSUSED */
static int
setifflags(char *val, int64_t value)
{
	int phyintlen, origphyintlen;

	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCGLIFFLAGS, (caddr_t)&lifr) < 0)
		Perror0_exit("setifflags: SIOCGLIFFLAGS");

	if (value == IFF_NOFAILOVER) {
		/*
		 * Fail if '-failover' is set after a prior addif created the
		 * alias on a different interface. This can happen when the
		 * interface is part of an IPMP group.
		 */
		phyintlen = strcspn(name, ":");
		origphyintlen = strcspn(origname, ":");
		if (phyintlen != origphyintlen ||
		    strncmp(name, origname, phyintlen) != 0) {
			(void) fprintf(stderr, "ifconfig: can't set -failover "
			    "on failed/standby/offlined interface %s\n",
			    origname);
			exit(1);
		}
	}

	if (value < 0) {
		value = -value;
		lifr.lifr_flags &= ~value;
		if ((value & IFF_UP) && (lifr.lifr_flags & IFF_DUPLICATE)) {
			/*
			 * If the user is trying to mark an interface with a
			 * duplicate address as "down," then fetch the address
			 * and set it.  This will cause IP to clear the
			 * IFF_DUPLICATE flag and stop the automatic recovery
			 * timer.
			 */
			value = lifr.lifr_flags;
			if (ioctl(s, SIOCGLIFADDR, (caddr_t)&lifr) >= 0)
				(void) ioctl(s, SIOCSLIFADDR, (caddr_t)&lifr);
			lifr.lifr_flags = value;
		}
	} else {
		lifr.lifr_flags |= value;
	}
	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCSLIFFLAGS, (caddr_t)&lifr) < 0) {
		Perror0_exit("setifflags: SIOCSLIFFLAGS");
	}
	return (0);
}

/* ARGSUSED */
static int
setifmetric(char *val, int64_t param)
{
	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	lifr.lifr_metric = atoi(val);
	if (ioctl(s, SIOCSLIFMETRIC, (caddr_t)&lifr) < 0)
		Perror0_exit("setifmetric: SIOCSLIFMETRIC");
	return (0);
}

/* ARGSUSED */
static int
setifmtu(char *val, int64_t param)
{
	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	lifr.lifr_mtu = atoi(val);
	if (ioctl(s, SIOCSLIFMTU, (caddr_t)&lifr) < 0)
		Perror0_exit("setifmtu: SIOCSLIFMTU");
	return (0);
}

/* ARGSUSED */
static int
setifindex(char *val, int64_t param)
{
	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	lifr.lifr_index = atoi(val);
	if (ioctl(s, SIOCSLIFINDEX, (caddr_t)&lifr) < 0)
		Perror0_exit("setifindex: SIOCSLIFINDEX");
	return (0);
}

/* ARGSUSED */
static int
setifether(char *addr, int64_t param)
{
	uchar_t	*ea;
	iface_t	*current;
	int	maclen;

	if (addr == NULL) {
		ifstatus(name);
		print_ifether(name);
		return (0);
	}

	phyif = NULL;
	logifs = NULL;

	/*
	 * if the IP interface in the arguments is a logical
	 * interface, exit with an error now.
	 */
	if (strchr(name, ':') != NULL) {
		(void) fprintf(stderr, "ifconfig: cannot change"
		    " ethernet address of a logical interface\n");
		exit(1);
	}

	ea = _link_aton(addr, &maclen);
	if (ea == NULL) {
		if (maclen == -1)
			(void) fprintf(stderr,
			    "ifconfig: %s: bad address\n", addr);
		else
			(void) fprintf(stderr, "ifconfig: malloc() failed\n");
		exit(1);
	}

	(void) strncpy(savedname, name, sizeof (savedname));

	/*
	 * Call selectifs only for the IP interfaces that are ipv4.
	 * offflags == IFF_IPV6 because you should not change the
	 *		Ethernet address of an ipv6 interface
	 */
	foreachinterface(selectifs, 0, (char **)NULL, 0, 0, IFF_IPV6, 0);

	/* If physical interface not found, exit now */
	if (phyif == NULL) {
		(void) fprintf(stderr,
		    "ifconfig: interface %s not found\n", savedname);
		exit(1);
	}

	/* Restore */
	(void) strncpy(name, savedname, sizeof (name));
	(void) strncpy(origname, savedname, sizeof (origname));
	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));

	/*
	 * close and reopen the socket
	 * we don't know which type of socket we have now
	 */
	(void) close(s);
	s = socket(SOCKET_AF(AF_UNSPEC), SOCK_DGRAM, 0);
	if (s < 0) {
		Perror0_exit("socket");
	}

	/*
	 * mark down the logical interfaces first,
	 * and then the physical interface
	 */
	if (updownifs(logifs, 0) < 0 || updownifs(phyif, 0) < 0) {
		Perror0_exit("mark down interface failed");
	}

	/*
	 * Change the physical address
	 */
	if (dlpi_set_address(savedname, ea, maclen) == -1) {
		(void) fprintf(stderr,
		    "ifconfig: failed setting mac address on %s\n",
		    savedname);
	}

	/*
	 * if any interfaces were marked down before changing the
	 * ethernet address, put them up again.
	 * First the physical interface, then the logical ones.
	 */
	if (updownifs(phyif, 1) < 0 || updownifs(logifs, 1) < 0) {
		Perror0_exit("mark down interface failed");
	}

	/* Free the memory allocated by selectifs */
	free(phyif);
	for (current = logifs; current != NULL; current = logifs) {
		logifs = logifs->next;
		free(current);
	}

	return (0);
}

/*
 * Print an interface's Ethernet address, if it has one.
 */
static void
print_ifether(char *ifname)
{
	int		protocol;
	icfg_if_t	interface;
	icfg_handle_t	handle;
	int		fd;

	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1 || ioctl(fd, SIOCGLIFFLAGS, &lifr) == -1) {
		/*
		 * It's possible the interface is only configured for
		 * IPv6; check again with AF_INET6.
		 */
		(void) close(fd);
		fd = socket(AF_INET6, SOCK_DGRAM, 0);
		if (fd == -1 || ioctl(fd, SIOCGLIFFLAGS, &lifr) == -1) {
			(void) close(fd);
			return;
		}
	}
	(void) close(fd);

	/* Virtual interfaces don't have MAC addresses */
	if (lifr.lifr_flags & IFF_VIRTUAL)
		return;

	/*
	 * We must be careful to set if_protocol based on the current
	 * properties of the interface.  For instance, if "ip.tun0" is
	 * configured only as an IPv6 tunnel, then if_protocol must be
	 * set to AF_INET6 or icfg_get_tunnel_lower() will fail and
	 * we will falsely conclude that it's not a tunnel.
	 */
	interface.if_protocol = AF_INET;
	if (lifr.lifr_flags & IFF_IPV6)
		interface.if_protocol = AF_INET6;

	(void) strncpy(interface.if_name, ifname, sizeof (interface.if_name));

	if (icfg_open(&handle, &interface) == ICFG_SUCCESS) {
		if (icfg_get_tunnel_lower(handle, &protocol) == ICFG_SUCCESS) {
			/* Tunnel op succeeded -- it's a tunnel so skip */
			icfg_close(handle);
			return;
		}
		icfg_close(handle);
	}

	dlpi_print_address(ifname);
}

/*
 * static void selectifs(int argc, char *argv[], int af, struct lifreq *rp)
 *
 * Called inside setifether() to create a list of interfaces to
 * mark down/up when changing the Ethernet address.
 * If the current interface is the physical interface passed
 * as an argument to ifconfig, update phyif.
 * If the current interface is a logical interface associated
 * to the physical interface, add it to the logifs list.
 */
/* ARGSUSED */
static void
selectifs(int argc, char *argv[], int af, struct lifreq *rp)
{
	char		*colonp;
	int		length;
	iface_t		*current;

	/*
	 *  savedname=	name of the IP interface to which you want to
	 *		change ethernet address
	 *  name=	name of the current IP interface
	 */
	colonp = strchr(name, ':');
	if (colonp == NULL)
		length = max(strlen(savedname), strlen(name));
	else
		length = max(strlen(savedname), colonp - name);
	if (strncmp(savedname, name, length) == 0) {
		(void) strcpy(lifr.lifr_name, name);
		if (ioctl(s, SIOCGLIFFLAGS, &lifr) < 0) {
			Perror0("selectifs: SIOCGLIFFLAGS");
			return;
		}

		if ((current = malloc(sizeof (iface_t))) == NULL) {
			Perror0_exit("selectifs: malloc failed\n");
		}

		if (colonp == NULL) {
			/* this is the physical interface */
			phyif = current;
			bcopy(&lifr, &phyif->lifr, sizeof (struct lifreq));
			phyif->next = NULL;
		} else {
			/* this is a logical interface */
			bcopy(&lifr, &current->lifr, sizeof (struct lifreq));
			current->next = logifs;
			logifs = current;
		}
	}
}

/*
 * static int updownifs(iface_t *ifs, int up)
 *
 * It takes in input a list of IP interfaces (ifs)
 * and a flag (up).
 * It marks each interface in the list down (up = 0)
 * or up (up > 0). This is done ONLY if the IP
 * interface was originally up.
 *
 * Return values:
 *  0 = everything OK
 * -1 = problem
 */
static int
updownifs(iface_t *ifs, int up)
{
	iface_t *current;
	int	ret = 0;
	int 	save_errno;
	char	savename[LIFNAMSIZ];
	uint64_t orig_flags;

	for (current = ifs; current != NULL; current = current->next) {
		if (current->lifr.lifr_flags & IFF_UP) {
			orig_flags = current->lifr.lifr_flags;
			if (!up)
				current->lifr.lifr_flags &= ~IFF_UP;
			if (ioctl(s, SIOCSLIFFLAGS, &current->lifr) < 0) {
				save_errno = errno;
				(void) strcpy(savename,
				    current->lifr.lifr_name);
				ret = -1;
			}
			if (!up) /* restore the original flags */
				current->lifr.lifr_flags = orig_flags;
		}
	}

	if (ret == -1) {
		(void) strcpy(lifr.lifr_name, savename);
		errno = save_errno;
	}
	return (ret);
}

/*
 * static int find_all_global_interfaces(struct lifconf *lifcp, char **buf,
 *     int64_t lifc_flags)
 *
 * It finds all data links for the global zone.
 *
 * It takes in input a pointer to struct lifconf to receive interfaces
 * informations, a **char to hold allocated buffer, and a lifc_flags.
 *
 * Return values:
 *  0 = everything OK
 * -1 = problem
 */
static int
find_all_global_interfaces(struct lifconf *lifcp, char **buf,
    int64_t lifc_flags)
{
	unsigned bufsize;
	int n;
	ni_t *nip;
	struct lifreq *lifrp;

	(void) dlpi_walk(ni_entry, NULL, 0);

	/*
	 * Now, translate the linked list into
	 * a struct lifreq buffer
	 */
	if (num_ni == 0) {
		lifcp->lifc_family = AF_UNSPEC;
		lifcp->lifc_flags = lifc_flags;
		lifcp->lifc_len = 0;
		lifcp->lifc_buf = NULL;
		return (0);
	}

	bufsize = num_ni * sizeof (struct lifreq);
	if ((*buf = malloc(bufsize)) == NULL)
		Perror0_exit("find_all_interfaces: malloc failed");

	lifcp->lifc_family = AF_UNSPEC;
	lifcp->lifc_flags = lifc_flags;
	lifcp->lifc_len = bufsize;
	lifcp->lifc_buf = *buf;

	for (n = 0, lifrp = lifcp->lifc_req; n < num_ni; n++, lifrp++) {
		nip = ni_list;
		(void) strncpy(lifrp->lifr_name, nip->ni_name,
		    sizeof (lifr.lifr_name));
		ni_list = nip->ni_next;
		free(nip);
	}
	return (0);
}

/*
 * static int find_all_zone_interfaces(struct lifconf *lifcp, char **buf,
 *     int64_t lifc_flags)
 *
 * It finds all interfaces for an exclusive-IP zone, that is all the interfaces
 * assigned to it.
 *
 * It takes in input a pointer to struct lifconf to receive interfaces
 * informations, a **char to hold allocated buffer, and a lifc_flags.
 *
 * Return values:
 *  0 = everything OK
 * -1 = problem
 */
static int
find_all_zone_interfaces(struct lifconf *lifcp, char **buf, int64_t lifc_flags)
{
	zoneid_t zoneid;
	unsigned bufsize;
	char *dlnames, *ptr;
	struct lifreq *lifrp;
	int num_ni_saved, i;

	zoneid = getzoneid();

	num_ni = 0;
	if (zone_list_datalink(zoneid, &num_ni, NULL) != 0)
		Perror0_exit("find_all_interfaces: list interfaces failed");
again:
	/* this zone doesn't have any data-links */
	if (num_ni == 0) {
		lifcp->lifc_family = AF_UNSPEC;
		lifcp->lifc_flags = lifc_flags;
		lifcp->lifc_len = 0;
		lifcp->lifc_buf = NULL;
		return (0);
	}

	dlnames = malloc(num_ni * LIFNAMSIZ);
	if (dlnames == NULL)
		Perror0_exit("find_all_interfaces: out of memory");
	num_ni_saved = num_ni;

	if (zone_list_datalink(zoneid, &num_ni, dlnames) != 0)
		Perror0_exit("find_all_interfaces: list interfaces failed");

	if (num_ni_saved < num_ni) {
		/* list increased, try again */
		free(dlnames);
		goto again;
	}

	/* this zone doesn't have any data-links now */
	if (num_ni == 0) {
		free(dlnames);
		lifcp->lifc_family = AF_UNSPEC;
		lifcp->lifc_flags = lifc_flags;
		lifcp->lifc_len = 0;
		lifcp->lifc_buf = NULL;
		return (0);
	}

	bufsize = num_ni * sizeof (struct lifreq);
	if ((*buf = malloc(bufsize)) == NULL) {
		free(dlnames);
		Perror0_exit("find_all_interfaces: malloc failed");
	}

	lifrp = (struct lifreq *)*buf;
	ptr = dlnames;
	for (i = 0; i < num_ni; i++) {
		if (strlcpy(lifrp->lifr_name, ptr, LIFNAMSIZ) >=
		    LIFNAMSIZ)
			Perror0_exit("find_all_interfaces: overflow");
		ptr += LIFNAMSIZ;
		lifrp++;
	}

	free(dlnames);
	lifcp->lifc_family = AF_UNSPEC;
	lifcp->lifc_flags = lifc_flags;
	lifcp->lifc_len = bufsize;
	lifcp->lifc_buf = *buf;
	return (0);
}

/*
 * Create the next unused logical interface using the original name
 * and assign the address (and mask if '/<n>' is part of the address).
 * Use the new logical interface for subsequent subcommands by updating
 * the name variable.
 *
 * This allows syntax like:
 *	ifconfig le0 addif 109.106.86.130 netmask + up \
 *	addif 109.106.86.131 netmask + up
 */
/* ARGSUSED */
static int
addif(char *str, int64_t param)
{
	int prefixlen = 0;
	struct sockaddr_storage laddr;
	struct sockaddr_storage mask;

	(void) strncpy(name, origname, sizeof (name));

	if (strchr(name, ':') != NULL) {
		(void) fprintf(stderr,
		    "ifconfig: addif: bad physical interface name %s\n",
		    name);
		exit(1);
	}

	/*
	 * clear so parser will interpret next address as source followed
	 * by possible dest
	 */
	setaddr = 0;
	(*afp->af_getaddr)(str, (struct sockaddr *)&laddr, &prefixlen);

	switch (prefixlen) {
	case NO_PREFIX:
		/* Nothing there - ok */
		break;
	case BAD_ADDR:
		(void) fprintf(stderr,
		    "ifconfig: Bad prefix length in %s\n", str);
		exit(1);
	default:
		(void) memset(&mask, 0, sizeof (mask));
		mask.ss_family = afp->af_af;
		if (afp->af_af == AF_INET6) {
			struct sockaddr_in6 *sin6;
			sin6 = (struct sockaddr_in6 *)&mask;
			if (!in_prefixlentomask(prefixlen, IPV6_ABITS,
			    (uchar_t *)&sin6->sin6_addr)) {
				(void) fprintf(stderr, "ifconfig: "
				    "Bad prefix length: %d\n",
				    prefixlen);
				exit(1);
			}
		} else {
			struct sockaddr_in *sin;

			sin = (struct sockaddr_in *)&mask;
			if (!in_prefixlentomask(prefixlen, IP_ABITS,
			    (uchar_t *)&sin->sin_addr)) {
				(void) fprintf(stderr, "ifconfig: "
				    "Bad prefix length: %d\n",
				    prefixlen);
				exit(1);
			}
		}
		g_netmask_set = G_NETMASK_NIL;
		break;
	}

	/*
	 * This is a "hack" to get around the problem of SIOCLIFADDIF.  The
	 * problem is that this ioctl does not include the netmask when
	 * adding a logical interface.  This is the same problem described
	 * in the ifconfig() comments.  To get around this problem, we first
	 * add the logical interface with a 0 address.  After that, we set
	 * the netmask if provided.  Finally we set the interface address.
	 */
	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));

	/* Note: no need to do DAD here since the interface isn't up yet. */

	if (ioctl(s, SIOCLIFADDIF, (caddr_t)&lifr) < 0)
		Perror0_exit("addif: SIOCLIFADDIF");

	(void) printf("Created new logical interface %s\n",
	    lifr.lifr_name);
	(void) strncpy(name, lifr.lifr_name, sizeof (name));

	/*
	 * Check and see if any "netmask" command is used and perform the
	 * necessary operation.
	 */
	set_mask_lifreq(&lifr, &laddr, &mask);
	/*
	 * Only set the netmask if "netmask" command is used or a prefix is
	 * provided.
	 */
	if (g_netmask_set == G_NETMASK_SET || prefixlen >= 0) {
		if (ioctl(s, SIOCSLIFNETMASK, (caddr_t)&lifr) < 0)
			Perror0_exit("addif: SIOCSLIFNETMASK");
	}

	/* Finally, we set the interface address. */
	lifr.lifr_addr = laddr;
	if (ioctl(s, SIOCSLIFADDR, (caddr_t)&lifr) < 0)
		Perror0_exit("SIOCSLIFADDR");

	/*
	 * let parser know we got a source.
	 * Next address, if given, should be dest
	 */
	setaddr++;
	return (0);
}

/*
 * Remove a logical interface based on its IP address. Unlike addif
 * there is no '/<n>' here.
 * Verifies that the interface is down before it is removed.
 */
/* ARGSUSED */
static int
removeif(char *str, int64_t param)
{
	struct sockaddr_storage laddr;

	if (strchr(name, ':') != NULL) {
		(void) fprintf(stderr,
		    "ifconfig: removeif: bad physical interface name %s\n",
		    name);
		exit(1);
	}

	(*afp->af_getaddr)(str, &laddr, NULL);
	lifr.lifr_addr = laddr;

	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCLIFREMOVEIF, (caddr_t)&lifr) < 0) {
		if (errno == EBUSY) {
			/* This can only happen if ipif_id = 0 */
			(void) fprintf(stderr,
			    "ifconfig: removeif: can't remove interface: %s\n",
			    name);
			exit(1);
		}
		Perror0_exit("removeif: SIOCLIFREMOVEIF");
	}
	return (0);
}

/*
 * Set the address token for IPv6.
 */
/* ARGSUSED */
static int
setiftoken(char *addr, int64_t param)
{
	int prefixlen = 0;
	struct sockaddr_in6 token;

	in6_getaddr(addr, (struct sockaddr *)&token, &prefixlen);
	switch (prefixlen) {
	case NO_PREFIX:
		(void) fprintf(stderr,
		    "ifconfig: Missing prefix length in subnet %s\n", addr);
		exit(1);
		/* NOTREACHED */
	case BAD_ADDR:
		(void) fprintf(stderr,
		    "ifconfig: Bad prefix length in %s\n", addr);
		exit(1);
	default:
		break;
	}
	(void) memcpy(&lifr.lifr_addr, &token, sizeof (token));
	lifr.lifr_addrlen = prefixlen;
	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCSLIFTOKEN, (caddr_t)&lifr) < 0)  {
		Perror0_exit("setiftoken: SIOCSLIFTOKEN");
	}
	return (0);
}

/*
 * Return value: 0 on success, -1 on failure.
 */
static int
connect_to_mpathd(int family)
{
	int s;
	struct sockaddr_storage ss;
	struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
	struct in6_addr loopback_addr = IN6ADDR_LOOPBACK_INIT;
	int addrlen;
	int ret;
	int on;

	s = socket(family, SOCK_STREAM, 0);
	if (s < 0) {
		Perror0_exit("connect_to_mpathd: socket");
	}
	(void) bzero((char *)&ss, sizeof (ss));
	ss.ss_family = family;
	/*
	 * Need to bind to a privileged port. For non-root, this
	 * will fail. in.mpathd verifies that only commands coming
	 * from privileged ports succeed so that ordinary users
	 * can't connect and start talking to in.mpathd
	 */
	on = 1;
	if (setsockopt(s, IPPROTO_TCP, TCP_ANONPRIVBIND, &on,
	    sizeof (on)) < 0) {
		Perror0_exit("connect_to_mpathd: setsockopt");
	}
	switch (family) {
	case AF_INET:
		sin->sin_port = 0;
		sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addrlen = sizeof (struct sockaddr_in);
		break;
	case AF_INET6:
		sin6->sin6_port = 0;
		sin6->sin6_addr = loopback_addr;
		addrlen = sizeof (struct sockaddr_in6);
		break;
	}
	ret = bind(s, (struct sockaddr *)&ss, addrlen);
	if (ret != 0) {
		(void) close(s);
		return (-1);
	}

	switch (family) {
	case AF_INET:
		sin->sin_port = htons(MPATHD_PORT);
		break;
	case AF_INET6:
		sin6->sin6_port = htons(MPATHD_PORT);
		break;
	}
	ret = connect(s, (struct sockaddr *)&ss, addrlen);
	(void) close(s);
	return (ret);
}

/* ARGSUSED */
static int
setifgroupname(char *grpname, int64_t param)
{
	if (debug) {
		(void) printf("Setting groupname %s on interface %s\n",
		    grpname, name);
	}
	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	(void) strncpy(lifr.lifr_groupname, grpname,
	    sizeof (lifr.lifr_groupname));
	if (ioctl(s, SIOCSLIFGROUPNAME, (caddr_t)&lifr) < 0) {
		Perror0_exit("setifgroupname: SIOCSLIFGROUPNAME");
	}

	/*
	 * If the SUNW_NO_MPATHD environment variable is set then don't
	 * bother starting up in.mpathd.  See PSARC/2002/249 for the
	 * depressing details on this bit of stupidity.
	 */
	if (getenv("SUNW_NO_MPATHD") != NULL) {
		return (0);
	}

	/*
	 * Try to connect to in.mpathd using IPv4. If we succeed,
	 * we conclude that in.mpathd is running, and quit.
	 */
	if (connect_to_mpathd(AF_INET) == 0) {
		/* connect succeeded, mpathd is already running */
		return (0);
	}
	/*
	 * Try to connect to in.mpathd using IPv6. If we succeed,
	 * we conclude that in.mpathd is running, and quit.
	 */
	if (connect_to_mpathd(AF_INET6) == 0) {
		/* connect succeeded, mpathd is already running */
		return (0);
	}

	/*
	 * in.mpathd may not be running. Start it now. If it is already
	 * running, in.mpathd will take care of handling multiple incarnations
	 * of itself. ifconfig only tries to optimize performance by not
	 * starting another incarnation of in.mpathd.
	 */
	switch (fork()) {

	case -1:
		Perror0_exit("setifgroupname: fork");
		/* NOTREACHED */
	case 0:
		(void) execl(MPATHD_PATH, MPATHD_PATH, NULL);
		_exit(1);
		/* NOTREACHED */
	default:
		return (0);
	}
}


/*
 * To list all the modules above a given network interface.
 */
/* ARGSUSED */
static int
modlist(char *null, int64_t param)
{
	int muxid_fd;
	int muxfd;
	int ipfd_lowstr;
	int arpfd_lowstr;
	int num_mods;
	int i;
	struct str_list strlist;
	int orig_arpid;

	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ip_domux2fd(&muxfd, &muxid_fd, &ipfd_lowstr, &arpfd_lowstr,
	    &orig_arpid) < 0) {
		return (-1);
	}
	if ((num_mods = ioctl(ipfd_lowstr, I_LIST, NULL)) < 0) {
		Perror0("cannot I_LIST to get the number of modules");
	} else {
		if (debug > 0) {
			(void) printf("Listing (%d) modules above %s\n",
			    num_mods, name);
		}

		strlist.sl_nmods = num_mods;
		strlist.sl_modlist = malloc(sizeof (struct str_mlist) *
		    num_mods);
		if (strlist.sl_modlist == NULL) {
			Perror0("cannot malloc");
		} else {
			if (ioctl(ipfd_lowstr, I_LIST, (caddr_t)&strlist) < 0) {
				Perror0("cannot I_LIST for module names");
			} else {
				for (i = 0; i < strlist.sl_nmods; i++) {
					(void) printf("%d %s\n", i,
					    strlist.sl_modlist[i].l_name);
				}
			}
			free(strlist.sl_modlist);
		}
	}
	return (ip_plink(muxfd, muxid_fd, ipfd_lowstr, arpfd_lowstr,
	    orig_arpid));
}

#define	MODINSERT_OP	'i'
#define	MODREMOVE_OP	'r'

/*
 * To insert a module to the stream of the interface.  It is just a
 * wrapper.  The real function is modop().
 */
/* ARGSUSED */
static int
modinsert(char *arg, int64_t param)
{
	return (modop(arg, MODINSERT_OP));
}

/*
 * To remove a module from the stream of the interface.  It is just a
 * wrapper.  The real function is modop().
 */
/* ARGSUSED */
static int
modremove(char *arg, int64_t param)
{
	return (modop(arg, MODREMOVE_OP));
}

/*
 * Open a stream on /dev/udp{,6}, pop off all undesired modules (note that
 * the user may have configured autopush to add modules above
 * udp), and push the arp module onto the resulting stream.
 * This is used to make IP+ARP be able to atomically track the muxid
 * for the I_PLINKed STREAMS, thus it isn't related to ARP running the ARP
 * protocol.
 */
static int
open_arp_on_udp(char *udp_dev_name)
{
	int fd;

	if ((fd = open(udp_dev_name, O_RDWR)) == -1) {
		Perror2("open", udp_dev_name);
		return (-1);
	}
	errno = 0;
	while (ioctl(fd, I_POP, 0) != -1)
		;
	if (errno != EINVAL) {
		Perror2("pop", udp_dev_name);
	} else if (ioctl(fd, I_PUSH, ARP_MOD_NAME) == -1) {
		Perror2("arp PUSH", udp_dev_name);
	} else {
		return (fd);
	}
	(void) close(fd);
	return (-1);
}

/*
 * Helper function for mod*() functions.  It gets a fd to the lower IP
 * stream and I_PUNLINK's the lower stream.  It also initializes the
 * global variable lifr.
 *
 * Param:
 *	int *muxfd: fd to /dev/udp{,6} for I_PLINK/I_PUNLINK
 *	int *muxid_fd: fd to /dev/udp{,6} for LIFMUXID
 *	int *ipfd_lowstr: fd to the lower IP stream.
 *	int *arpfd_lowstr: fd to the lower ARP stream.
 *
 * Return:
 *	-1 if operation fails, 0 otherwise.
 *
 * Please see the big block comment above plumb_one_device()
 * for the logic of the PLINK/PUNLINK
 */
static int
ip_domux2fd(int *muxfd, int *muxid_fd, int *ipfd_lowstr, int *arpfd_lowstr,
    int *orig_arpid)
{
	uint64_t	flags;
	char		*udp_dev_name;

	*orig_arpid = 0;
	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCGLIFFLAGS, (caddr_t)&lifr) < 0) {
		Perror0_exit("status: SIOCGLIFFLAGS");
	}
	flags = lifr.lifr_flags;
	if (flags & IFF_IPV4) {
		udp_dev_name = UDP_DEV_NAME;
	} else if (flags & IFF_IPV6) {
		udp_dev_name = UDP6_DEV_NAME;
	} else {
		return (-1);
	}

	if ((*muxid_fd = open(udp_dev_name, O_RDWR)) < 0) {
		Perror2("open", udp_dev_name);
		return (-1);
	}
	if (ioctl(*muxid_fd, SIOCGLIFMUXID, (caddr_t)&lifr) < 0) {
		Perror2("SIOCGLIFMUXID", udp_dev_name);
		return (-1);
	}
	if (debug > 0) {
		(void) printf("ARP_muxid %d IP_muxid %d\n",
		    lifr.lifr_arp_muxid, lifr.lifr_ip_muxid);
	}

	/*
	 * Use /dev/udp{,6} as the mux to avoid linkcycles.
	 */
	if ((*muxfd = open_arp_on_udp(udp_dev_name)) == -1)
		return (-1);

	if (lifr.lifr_arp_muxid != 0) {
		if ((*arpfd_lowstr = ioctl(*muxfd, _I_MUXID2FD,
		    lifr.lifr_arp_muxid)) < 0) {
			if ((errno == EINVAL) &&
			    (flags & (IFF_NOARP | IFF_IPV6))) {
				/*
				 * Some plumbing utilities set the muxid to
				 * -1 or some invalid value to signify that
				 * there is no arp stream. Set the muxid to 0
				 * before trying to unplumb the IP stream.
				 * IP does not allow the IP stream to be
				 * unplumbed if it sees a non-null arp muxid,
				 * for consistency of IP-ARP streams.
				 */
				*orig_arpid = lifr.lifr_arp_muxid;
				lifr.lifr_arp_muxid = 0;
				(void) ioctl(*muxid_fd, SIOCSLIFMUXID,
				    (caddr_t)&lifr);
				*arpfd_lowstr = -1;
			} else {
				Perror0("_I_MUXID2FD");
				return (-1);
			}
		} else if (ioctl(*muxfd, I_PUNLINK,
		    lifr.lifr_arp_muxid) < 0) {
			Perror2("I_PUNLINK", udp_dev_name);
			return (-1);
		}
	} else {
		*arpfd_lowstr = -1;
	}

	if ((*ipfd_lowstr = ioctl(*muxfd, _I_MUXID2FD,
	    lifr.lifr_ip_muxid)) < 0) {
		Perror0("_I_MUXID2FD");
		/* Undo any changes we made */
		if (*orig_arpid != 0) {
			lifr.lifr_arp_muxid = *orig_arpid;
			(void) ioctl(*muxid_fd, SIOCSLIFMUXID, (caddr_t)&lifr);
		}
		return (-1);
	}
	if (ioctl(*muxfd, I_PUNLINK, lifr.lifr_ip_muxid) < 0) {
		Perror2("I_PUNLINK", udp_dev_name);
		/* Undo any changes we made */
		if (*orig_arpid != 0) {
			lifr.lifr_arp_muxid = *orig_arpid;
			(void) ioctl(*muxid_fd, SIOCSLIFMUXID, (caddr_t)&lifr);
		}
		return (-1);
	}
	return (0);
}

/*
 * Helper function for mod*() functions.  It I_PLINK's back the upper and
 * lower IP streams.  Note that this function must be called after
 * ip_domux2fd().  In ip_domux2fd(), the global variable lifr is initialized
 * and ip_plink() needs information in lifr.  So ip_domux2fd() and ip_plink()
 * must be called in pairs.
 *
 * Param:
 *	int muxfd: fd to /dev/udp{,6} for I_PLINK/I_PUNLINK
 *	int muxid_fd: fd to /dev/udp{,6} for LIFMUXID
 *	int ipfd_lowstr: fd to the lower IP stream.
 *	int arpfd_lowstr: fd to the lower ARP stream.
 *
 * Return:
 *	-1 if operation fails, 0 otherwise.
 *
 * Please see the big block comment above plumb_one_device()
 * for the logic of the PLINK/PUNLINK
 */
static int
ip_plink(int muxfd, int muxid_fd, int ipfd_lowstr, int arpfd_lowstr,
    int orig_arpid)
{
	int ip_muxid;

	ip_muxid = ioctl(muxfd, I_PLINK, ipfd_lowstr);
	if (ip_muxid < 0) {
		Perror2("I_PLINK", UDP_DEV_NAME);
		return (-1);
	}

	/*
	 * If there is an arp stream, plink it. If there is no
	 * arp stream, then it is possible that the plumbing
	 * utility could have stored any value in the arp_muxid.
	 * If so, restore it from orig_arpid.
	 */
	if (arpfd_lowstr != -1) {
		if (ioctl(muxfd, I_PLINK, arpfd_lowstr) < 0) {
			Perror2("I_PLINK", UDP_DEV_NAME);
			return (-1);
		}
	} else if (orig_arpid != 0) {
		/* Undo the changes we did in ip_domux2fd */
		lifr.lifr_arp_muxid = orig_arpid;
		lifr.lifr_ip_muxid = ip_muxid;
		(void) ioctl(muxid_fd, SIOCSLIFMUXID, (caddr_t)&lifr);
	}

	(void) close(muxfd);
	(void) close(muxid_fd);
	return (0);
}

/*
 * The real function to perform module insertion/removal.
 *
 * Param:
 *	char *arg: the argument string module_name@position
 *	char op: operation, either MODINSERT_OP or MODREMOVE_OP.
 *
 * Return:
 *	Before doing ip_domux2fd(), this function calls exit(1) in case of
 *	error.  After ip_domux2fd() is done, it returns -1 for error, 0
 *	otherwise.
 */
static int
modop(char *arg, char op)
{
	char *pos_p;
	int muxfd;
	int muxid_fd;
	int ipfd_lowstr;  /* IP stream (lower stream of mux) to be plinked */
	int arpfd_lowstr; /* ARP stream (lower stream of mux) to be plinked */
	struct strmodconf mod;
	char *at_char = "@";
	char *arg_str;
	int orig_arpid;

	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));

	/* Need to save the original string for -a option. */
	if ((arg_str = malloc(strlen(arg) + 1)) == NULL) {
		Perror0("cannot malloc");
		return (-1);
	}
	(void) strcpy(arg_str, arg);

	if (*arg_str == *at_char) {
		(void) fprintf(stderr,
		    "ifconfig: must supply a module name\n");
		exit(1);
	}
	mod.mod_name = strtok(arg_str, at_char);
	if (strlen(mod.mod_name) > FMNAMESZ) {
		(void) fprintf(stderr, "ifconfig: module name too long: %s\n",
		    mod.mod_name);
		exit(1);
	}

	/*
	 * Need to make sure that the core TCP/IP stack modules are not
	 * removed.  Otherwise, "bad" things can happen.  If a module
	 * is removed and inserted back, it loses its old state.  But
	 * the modules above it still have the old state.  E.g. IP assumes
	 * fast data path while tunnel after re-inserted assumes that it can
	 * receive M_DATA only in fast data path for which it does not have
	 * any state.  This is a general caveat of _I_REMOVE/_I_INSERT.
	 */
	if (op == MODREMOVE_OP &&
	    (strcmp(mod.mod_name, ARP_MOD_NAME) == 0 ||
	    strcmp(mod.mod_name, IP_MOD_NAME) == 0 ||
	    strcmp(mod.mod_name, TUN_NAME) == 0 ||
	    strcmp(mod.mod_name, ATUN_NAME) == 0 ||
	    strcmp(mod.mod_name, TUN6TO4_NAME) == 0)) {
		(void) fprintf(stderr, "ifconfig: cannot remove %s\n",
		    mod.mod_name);
		exit(1);
	}

	if ((pos_p = strtok(NULL, at_char)) == NULL) {
		(void) fprintf(stderr, "ifconfig: must supply a position\n");
		exit(1);
	}
	mod.pos = atoi(pos_p);

	if (ip_domux2fd(&muxfd, &muxid_fd, &ipfd_lowstr, &arpfd_lowstr,
	    &orig_arpid) < 0) {
		free(arg_str);
		return (-1);
	}
	switch (op) {
	case MODINSERT_OP:
		if (debug > 0) {
			(void) printf("Inserting module %s at %d\n",
			    mod.mod_name, mod.pos);
		}
		if (ioctl(ipfd_lowstr, _I_INSERT, (caddr_t)&mod) < 0) {
			Perror2("fail to insert module", mod.mod_name);
		}
		break;
	case MODREMOVE_OP:
		if (debug > 0) {
			(void) printf("Removing module %s at %d\n",
			    mod.mod_name, mod.pos);
		}
		if (ioctl(ipfd_lowstr, _I_REMOVE, (caddr_t)&mod) < 0) {
			Perror2("fail to remove module", mod.mod_name);
		}
		break;
	default:
		/* Should never get to here. */
		(void) fprintf(stderr, "Unknown operation\n");
		break;
	}
	free(arg_str);
	return (ip_plink(muxfd, muxid_fd, ipfd_lowstr, arpfd_lowstr,
	    orig_arpid));
}

/*
 * Set tunnel source address
 */
/* ARGSUSED */
static int
setiftsrc(char *addr, int64_t param)
{
	return (settaddr(addr, icfg_set_tunnel_src));
}

/*
 * Set tunnel destination address
 */
/* ARGSUSED */
static int
setiftdst(char *addr, int64_t param)
{
	return (settaddr(addr, icfg_set_tunnel_dest));
}

/*
 * sets tunnels src|dst address.  settaddr() expects the following:
 * addr: Points to a printable string containing the address to be
 *       set, e.g. 129.153.128.110.
 * fn:   Pointer to a libinetcfg routine that will do the actual work.
 *       The only valid functions are icfg_set_tunnel_src and
 *       icfg_set_tunnel_dest.
 */
static int
settaddr(char *addr,
    int (*fn)(icfg_handle_t, const struct sockaddr *, socklen_t))
{
	icfg_handle_t handle;
	icfg_if_t interface;
	struct sockaddr_storage laddr;
	int lower;
	int rc;

	if (strchr(name, ':') != NULL) {
		errno = EPERM;
		Perror0_exit("Tunnel params on logical interfaces");
	}
	(void) strncpy(interface.if_name, name, sizeof (interface.if_name));
	interface.if_protocol = SOCKET_AF(af);

	/* Open interface. */
	if ((rc = icfg_open(&handle, &interface)) != ICFG_SUCCESS)
		Perror0_exit((char *)icfg_errmsg(rc));

	rc = icfg_get_tunnel_lower(handle, &lower);
	if (rc != ICFG_SUCCESS)
		Perror0_exit((char *)icfg_errmsg(rc));

	if (lower == AF_INET) {
		in_getaddr(addr, (struct sockaddr *)&laddr, NULL);
	} else {
		in6_getaddr(addr, (struct sockaddr *)&laddr, NULL);
	}

	/* Call fn to do the real work, and close the interface. */
	rc = (*fn)(handle, (struct sockaddr *)&laddr,
	    sizeof (struct sockaddr_storage));
	icfg_close(handle);

	if (rc != ICFG_SUCCESS)
		Perror0_exit((char *)icfg_errmsg(rc));

	return (0);
}

/* Set tunnel encapsulation limit. */
/* ARGSUSED */
static int
set_tun_encap_limit(char *arg, int64_t param)
{
	short limit;
	icfg_if_t interface;
	icfg_handle_t handle;
	int rc;

	if (strchr(name, ':') != NULL) {
		errno = EPERM;
		Perror0_exit("Tunnel params on logical interfaces");
	}

	if ((sscanf(arg, "%hd", &limit) != 1) || (limit < 0) ||
	    (limit > 255)) {
		errno = EINVAL;
		Perror0_exit("Invalid encapsulation limit");
	}

	/* Open interface for configuration. */
	(void) strncpy(interface.if_name, name, sizeof (interface.if_name));
	interface.if_protocol = SOCKET_AF(af);
	if (icfg_open(&handle, &interface) != ICFG_SUCCESS)
		Perror0_exit("couldn't open interface");

	rc = icfg_set_tunnel_encaplimit(handle, (int)limit);
	icfg_close(handle);

	if (rc != ICFG_SUCCESS)
		Perror0_exit("Could not configure tunnel encapsulation limit");

	return (0);
}

/* Disable encapsulation limit. */
/* ARGSUSED */
static int
clr_tun_encap_limit(char *arg, int64_t param)
{
	icfg_if_t interface;
	icfg_handle_t handle;
	int rc;

	if (strchr(name, ':') != NULL) {
		errno = EPERM;
		Perror0_exit("Tunnel params on logical interfaces");
	}

	/* Open interface for configuration. */
	(void) strncpy(interface.if_name, name, sizeof (interface.if_name));
	interface.if_protocol = SOCKET_AF(af);
	if (icfg_open(&handle, &interface) != ICFG_SUCCESS)
		Perror0_exit("couldn't open interface");

	rc = icfg_set_tunnel_encaplimit(handle, -1);
	icfg_close(handle);

	if (rc != ICFG_SUCCESS)
		Perror0_exit((char *)icfg_errmsg(rc));

	return (0);
}

/* Set tunnel hop limit. */
/* ARGSUSED */
static int
set_tun_hop_limit(char *arg, int64_t param)
{
	unsigned short limit;
	icfg_if_t interface;
	icfg_handle_t handle;
	int rc;

	if (strchr(name, ':') != NULL) {
		errno = EPERM;
		Perror0_exit("Tunnel params on logical interfaces");
	}

	/*
	 * Check limit here since it's really only an 8-bit unsigned quantity.
	 */
	if ((sscanf(arg, "%hu", &limit) != 1) || (limit > 255)) {
		errno = EINVAL;
		Perror0_exit("Invalid hop limit");
	}

	/* Open interface for configuration. */
	(void) strncpy(interface.if_name, name, sizeof (interface.if_name));
	interface.if_protocol = SOCKET_AF(af);
	if (icfg_open(&handle, &interface) != ICFG_SUCCESS)
		Perror0_exit("couldn't open interface");

	rc = icfg_set_tunnel_hoplimit(handle, (uint8_t)limit);
	icfg_close(handle);

	if (rc != ICFG_SUCCESS)
		Perror0_exit("Could not configure tunnel hop limit");

	return (0);
}

/* Set zone ID */
static int
setzone(char *arg, int64_t param)
{
	zoneid_t zoneid = GLOBAL_ZONEID;

	if (param == NEXTARG) {
		/* zone must be active */
		if ((zoneid = getzoneidbyname(arg)) == -1) {
			(void) fprintf(stderr,
			    "ifconfig: unknown zone '%s'\n", arg);
			exit(1);
		}
	}
	(void) strlcpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	lifr.lifr_zoneid = zoneid;
	if (ioctl(s, SIOCSLIFZONE, (caddr_t)&lifr) == -1)
		Perror0_exit("SIOCSLIFZONE");
	return (0);
}

/* Put interface into all zones */
/* ARGSUSED */
static int
setallzones(char *arg, int64_t param)
{
	(void) strlcpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	lifr.lifr_zoneid = ALL_ZONES;
	if (ioctl(s, SIOCSLIFZONE, (caddr_t)&lifr) == -1)
		Perror0_exit("SIOCSLIFZONE");
	return (0);
}

/* Set source address to use */
/* ARGSUSED */
static int
setifsrc(char *arg, int64_t param)
{
	uint_t ifindex = 0;
	int rval;

	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));

	/*
	 * Argument can be either an interface name or "none". The latter means
	 * that any previous selection is cleared.
	 */

	rval = strcmp(arg, name);
	if (rval == 0) {
		(void) fprintf(stderr,
		    "ifconfig: Cannot specify same interface for usesrc"
		    " group\n");
		exit(1);
	}

	rval = strcmp(arg, NONE_STR);
	if (rval != 0) {
		if ((ifindex = if_nametoindex(arg)) == 0) {
			(void) strncpy(lifr.lifr_name, arg, LIFNAMSIZ);
			Perror0_exit("Could not get interface index");
		}
		lifr.lifr_index = ifindex;
	} else {
		if (ioctl(s, SIOCGLIFUSESRC, (caddr_t)&lifr) != 0)
			Perror0_exit("Not a valid usesrc consumer");
		lifr.lifr_index = 0;
	}

	if (debug)
		(void) printf("setifsrc: lifr_name %s, lifr_index %d\n",
		    lifr.lifr_name, lifr.lifr_index);

	if (ioctl(s, SIOCSLIFUSESRC, (caddr_t)&lifr) == -1) {
		if (rval == 0)
			Perror0_exit("Cannot reset usesrc group");
		else
			Perror0_exit("Could not set source interface");
	}

	return (0);
}

/*
 * Print the interface status line associated with `ifname'
 */
static void
ifstatus(const char *ifname)
{
	uint64_t flags;
	char if_usesrc_name[LIFNAMSIZ];
	char *newbuf;
	int n, numifs, rval = 0;
	struct lifreq *lifrp;
	struct lifsrcof lifs;

	(void) strncpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCGLIFFLAGS, (caddr_t)&lifr) < 0) {
		Perror0_exit("status: SIOCGLIFFLAGS");
	}
	flags = lifr.lifr_flags;

	/*
	 * In V4 compatibility mode, we don't print the IFF_IPV4 flag or
	 * interfaces with IFF_IPV6 set.
	 */
	if (v4compat) {
		flags &= ~IFF_IPV4;
		if (flags & IFF_IPV6)
			return;
	}

	(void) printf("%s: ", ifname);
	print_flags(flags);

	(void) strncpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCGLIFMETRIC, (caddr_t)&lifr) < 0) {
		Perror0_exit("status: SIOCGLIFMETRIC");
	} else {
		if (lifr.lifr_metric)
			(void) printf(" metric %d", lifr.lifr_metric);
	}
	if (ioctl(s, SIOCGLIFMTU, (caddr_t)&lifr) >= 0)
		(void) printf(" mtu %u", lifr.lifr_mtu);

	/* don't print index or zone when in compatibility mode */
	if (!v4compat) {
		if (ioctl(s, SIOCGLIFINDEX, (caddr_t)&lifr) >= 0)
			(void) printf(" index %d", lifr.lifr_index);
		/*
		 * Stack instances use GLOBAL_ZONEID for IP data structures
		 * even in the non-global zone.
		 */
		if (ioctl(s, SIOCGLIFZONE, (caddr_t)&lifr) >= 0 &&
		    lifr.lifr_zoneid != getzoneid() &&
		    lifr.lifr_zoneid != GLOBAL_ZONEID) {
			char zone_name[ZONENAME_MAX];

			if (lifr.lifr_zoneid == ALL_ZONES) {
				(void) printf("\n\tall-zones");
			} else if (getzonenamebyid(lifr.lifr_zoneid, zone_name,
			    sizeof (zone_name)) < 0) {
				(void) printf("\n\tzone %d", lifr.lifr_zoneid);
			} else {
				(void) printf("\n\tzone %s", zone_name);
			}
		}
	}

	if (ioctl(s, SIOCGLIFINDEX, (caddr_t)&lifr) >= 0) {
		lifs.lifs_ifindex = lifr.lifr_index;

		/*
		 * Find the number of interfaces that use this interfaces'
		 * address as a source address
		 */
		lifs.lifs_buf = NULL;
		lifs.lifs_maxlen = 0;
		for (;;) {
			/* The first pass will give the bufsize we need */
			rval = ioctl(s, SIOCGLIFSRCOF, (char *)&lifs);
			if (rval < 0) {
				if (lifs.lifs_buf != NULL) {
					free(lifs.lifs_buf);
					lifs.lifs_buf = NULL;
				}
				lifs.lifs_len = 0;
				break;
			}
			if (lifs.lifs_len <= lifs.lifs_maxlen)
				break;
			/* Use kernel's size + a small margin to avoid loops */
			lifs.lifs_maxlen = lifs.lifs_len +
			    5 * sizeof (struct lifreq);
			/* For the first pass, realloc acts like malloc */
			newbuf = realloc(lifs.lifs_buf, lifs.lifs_maxlen);
			if (newbuf == NULL) {
				if (lifs.lifs_buf != NULL) {
					free(lifs.lifs_buf);
					lifs.lifs_buf = NULL;
				}
				lifs.lifs_len = 0;
				break;
			}
			lifs.lifs_buf = newbuf;
		}


		numifs = lifs.lifs_len / sizeof (struct lifreq);
		if (numifs > 0) {
			lifrp = lifs.lifs_req;
			(void) printf("\n\tsrcof");
			for (n = numifs; n > 0; n--, lifrp++) {
				(void) printf(" %s", lifrp->lifr_name);
			}
		}

		if (lifs.lifs_buf != NULL)
			free(lifs.lifs_buf);
	}

	/* Find the interface whose source address this interface uses */
	if (ioctl(s, SIOCGLIFUSESRC, (caddr_t)&lifr) == 0) {
		if (lifr.lifr_index != 0) {
			if (if_indextoname(lifr.lifr_index,
			    if_usesrc_name) == NULL) {
				(void) printf("\n\tusesrc ifIndex %d",
				    lifr.lifr_index);
			} else {
				(void) printf("\n\tusesrc %s", if_usesrc_name);
			}
		}
	}

	(void) putchar('\n');
}


/*
 * Print the status of the interface.  If an address family was
 * specified, show it and it only; otherwise, show them all.
 */
static void
status(void)
{
	struct afswtch *p = afp;
	uint64_t flags;

	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCGLIFFLAGS, (caddr_t)&lifr) < 0) {
		Perror0_exit("status: SIOCGLIFFLAGS");
	}

	flags = lifr.lifr_flags;

	/*
	 * Only print the interface status if the address family matches
	 * the interface family flag.
	 */
	if (p != NULL) {
		if (((p->af_af == AF_INET6) && (flags & IFF_IPV4)) ||
		    ((p->af_af == AF_INET) && (flags & IFF_IPV6)))
			return;
	}

	/*
	 * In V4 compatibility mode, don't print IFF_IPV6 interfaces.
	 */
	if (v4compat && (flags & IFF_IPV6))
		return;

	ifstatus(name);

	if (p != NULL) {
		(*p->af_status)(1, flags);
	} else {
		for (p = afs; p->af_name; p++) {
			(void) close(s);
			s = socket(SOCKET_AF(p->af_af), SOCK_DGRAM, 0);
			/* set global af for use in p->af_status */
			af = p->af_af;
			if (s == -1) {
				Perror0_exit("socket");
			}
			(*p->af_status)(0, flags);
		}

		/*
		 * Historically, 'ether' has been an address family,
		 * so print it here.
		 */
		print_ifether(name);
	}
}

/*
 * Print the status of the interface in a format that can be used to
 * reconfigure the interface later. Code stolen from status() above.
 */
/* ARGSUSED */
static int
configinfo(char *null, int64_t param)
{
	struct afswtch *p = afp;
	uint64_t flags;
	char phydevname[LIFNAMSIZ];
	char if_usesrc_name[LIFNAMSIZ];
	char *cp;

	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCGLIFFLAGS, (caddr_t)&lifr) < 0) {
		Perror0_exit("status: SIOCGLIFFLAGS");
	}
	flags = lifr.lifr_flags;

	if (debug) {
		(void) printf("configinfo: name %s flags  0x%llx af_af %d\n",
		    name, flags, p != NULL ? p->af_af : -1);
	}

	/* remove LIF component */
	(void) strncpy(phydevname, name, sizeof (phydevname));
	cp = strchr(phydevname, ':');
	if (cp) {
		*cp = 0;
	}
	phydevname[sizeof (phydevname) - 1] = '\0';

	/*
	 * if the interface is IPv4
	 *	if we have a IPv6 address family restriction return
	 *		so it won't print
	 *	if we are in IPv4 compatibility mode, clear out IFF_IPV4
	 *		so we don't print it.
	 */
	if (flags & IFF_IPV4) {
		if (p && p->af_af == AF_INET6)
			return (-1);
		if (v4compat)
			flags &= ~IFF_IPV4;

		(void) printf("%s inet plumb", phydevname);
	} else if (flags & IFF_IPV6) {
		/*
		 * else if the interface is IPv6
		 *	if we have a IPv4 address family restriction return
		 *	or we are in IPv4 compatibiltiy mode, return.
		 */
		if (p && p->af_af == AF_INET)
			return (-1);
		if (v4compat)
			return (-1);

		(void) printf("%s inet6 plumb", phydevname);
	}

	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCGLIFMETRIC, (caddr_t)&lifr) < 0) {
		Perror0_exit("configinfo: SIOCGLIFMETRIC");
	} else {
		if (lifr.lifr_metric)
			(void) printf(" metric %d ", lifr.lifr_metric);
	}
	if (((flags & (IFF_VIRTUAL|IFF_LOOPBACK)) != IFF_VIRTUAL) &&
	    ioctl(s, SIOCGLIFMTU, (caddr_t)&lifr) >= 0)
		(void) printf(" mtu %d", lifr.lifr_metric);

	/* don't print index when in compatibility mode */
	if (!v4compat) {
		if (ioctl(s, SIOCGLIFINDEX, (caddr_t)&lifr) >= 0)
			(void) printf(" index %d", lifr.lifr_index);
	}

	if (ioctl(s, SIOCGLIFUSESRC, (caddr_t)&lifr) == 0) {
		if (lifr.lifr_index != 0) {
			if (if_indextoname(lifr.lifr_index,
			    if_usesrc_name) != NULL) {
				(void) printf(" usesrc %s", if_usesrc_name);
			}
		}
	}

	if (p != NULL) {
		(*p->af_configinfo)(1, flags);
	} else {
		for (p = afs; p->af_name; p++) {
			(void) close(s);
			s = socket(SOCKET_AF(p->af_af), SOCK_DGRAM, 0);
			/* set global af for use in p->af_configinfo */
			af = p->af_af;
			if (s == -1) {
				Perror0_exit("socket");
			}
			(*p->af_configinfo)(0, flags);
		}
	}

	(void) printf("\n");

	return (0);
}

static void
print_tsec(struct iftun_req *tparams)
{
	ipsec_req_t *ipsr;

	(void) printf("\ttunnel security settings  ");
	/*
	 * Deal with versioning, for now just point
	 * an ipsec_req_t at ifta_secinfo.  If versions
	 * change, something else will overlay ifta_secinfo.
	 */
	assert(tparams->ifta_vers == IFTUN_VERSION);

	if (tparams->ifta_flags & IFTUN_COMPLEX_SECURITY) {
		(void) printf("-->  use 'ipsecconf -ln -i %s'",
		    tparams->ifta_lifr_name);
	} else {
		ipsr = (ipsec_req_t *)(&tparams->ifta_secinfo);
		if (ipsr->ipsr_ah_req & IPSEC_PREF_REQUIRED) {
			(void) printf("ah (%s)  ",
			    rparsealg(ipsr->ipsr_auth_alg, IPSEC_PROTO_AH));
		}
		if (ipsr->ipsr_esp_req & IPSEC_PREF_REQUIRED) {
			(void) printf("esp (%s",
			    rparsealg(ipsr->ipsr_esp_alg, IPSEC_PROTO_ESP));
			(void) printf("/%s)",
			    rparsealg(ipsr->ipsr_esp_auth_alg, IPSEC_PROTO_AH));
		}
	}
	(void) printf("\n");
}

static void
tun_status(void)
{
	icfg_if_t interface;
	int rc;
	icfg_handle_t handle;
	int protocol;
	char srcbuf[INET6_ADDRSTRLEN];
	char dstbuf[INET6_ADDRSTRLEN];
	boolean_t tabbed;
	uint8_t hoplimit;
	int16_t encaplimit;
	struct sockaddr_storage taddr;
	socklen_t socklen = sizeof (taddr);

	(void) strncpy(interface.if_name, name, sizeof (interface.if_name));
	interface.if_protocol = SOCKET_AF(af);
	if ((rc = icfg_open(&handle, &interface)) != ICFG_SUCCESS)
		Perror0_exit((char *)icfg_errmsg(rc));

	/*
	 * only print tunnel info for lun 0.  If ioctl fails, assume
	 * we are not a tunnel
	 */
	if (strchr(name, ':') != NULL ||
	    icfg_get_tunnel_lower(handle, &protocol) != ICFG_SUCCESS) {
		icfg_close(handle);
		return;
	}

	switch (protocol) {
	case AF_INET:
		(void) printf("\tinet");
		break;
	case AF_INET6:
		(void) printf("\tinet6");
		break;
	default:
		Perror0_exit("\ttunnel: Illegal lower stream\n\t");
		break;
	}

	rc = icfg_get_tunnel_src(handle, (struct sockaddr *)&taddr, &socklen);
	if (rc == ICFG_NOT_SET) {
		(void) strlcpy(srcbuf, (protocol == AF_INET) ? "0.0.0.0" :
		    "::", sizeof (srcbuf));
	} else if (rc != ICFG_SUCCESS) {
		Perror0_exit((char *)icfg_errmsg(rc));
	} else {
		rc = icfg_sockaddr_to_str(protocol, (struct sockaddr *)&taddr,
		    srcbuf, sizeof (srcbuf));
		if (rc != ICFG_SUCCESS) {
			Perror0_exit((char *)icfg_errmsg(rc));
		}
	}

	(void) printf(" tunnel src %s ", srcbuf);

	rc = icfg_get_tunnel_dest(handle, (struct sockaddr *)&taddr, &socklen);
	if (rc == ICFG_NOT_SET) {
		(void) printf("\n");
	} else {
		rc = icfg_sockaddr_to_str(protocol, (struct sockaddr *)&taddr,
		    dstbuf, sizeof (dstbuf));
		if (rc != ICFG_SUCCESS) {
			Perror0_exit((char *)icfg_errmsg(rc));
		}
		(void) printf("tunnel dst %s\n", dstbuf);
	}

	if (handle->ifh_tunnel_params != NULL &&
	    (handle->ifh_tunnel_params->ifta_flags & IFTUN_SECURITY))
		print_tsec(handle->ifh_tunnel_params);

	/*
	 * tabbed indicates tabbed and printed.  Use it tell us whether
	 * to tab and that we've printed something here, so we need a
	 * newline
	 */
	tabbed = _B_FALSE;

	if (icfg_get_tunnel_hoplimit(handle, &hoplimit) == ICFG_SUCCESS) {
		(void) printf("\ttunnel hop limit %d ", hoplimit);
		tabbed = _B_TRUE;
	}

	if ((protocol == AF_INET6) &&
	    (icfg_get_tunnel_encaplimit(handle, &encaplimit) ==
	    ICFG_SUCCESS)) {
		if (!tabbed) {
			(void) printf("\t");
			tabbed = _B_TRUE;
		}
		if (encaplimit >= 0) {
			(void) printf("tunnel encapsulation limit %d",
			    encaplimit);
		} else {
			(void) printf("tunnel encapsulation limit disabled");
		}
	}

	if (tabbed)
		(void) printf("\n");

	icfg_close(handle);
}

static void
in_status(int force, uint64_t flags)
{
	struct sockaddr_in *sin, *laddr;
	struct	sockaddr_in netmask = { AF_INET };

	if (debug)
		(void) printf("in_status(%s) flags 0x%llx\n", name, flags);

	/* only print status for IPv4 interfaces */
	if (!(flags & IFF_IPV4))
		return;

	/* if the interface is a tunnel, print the tunnel status */
	tun_status();

	if (!(flags & IFF_NOLOCAL)) {
		(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
		if (ioctl(s, SIOCGLIFADDR, (caddr_t)&lifr) < 0) {
			if (errno == EADDRNOTAVAIL || errno == EAFNOSUPPORT ||
			    errno == ENXIO) {
				if (!force)
					return;
				(void) memset(&lifr.lifr_addr, 0,
				    sizeof (lifr.lifr_addr));
			} else
				Perror0_exit("in_status: SIOCGLIFADDR");
		}
		sin = (struct sockaddr_in *)&lifr.lifr_addr;
		(void) printf("\tinet %s ", inet_ntoa(sin->sin_addr));
		laddr = sin;
	} else {
		(void) printf("\tinet ");
	}

	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCGLIFSUBNET, (caddr_t)&lifr) < 0) {
		if (errno == EADDRNOTAVAIL || errno == EAFNOSUPPORT ||
		    errno == ENXIO) {
			if (!force)
				return;
			(void) memset(&lifr.lifr_addr, 0,
			    sizeof (lifr.lifr_addr));
		} else {
			Perror0_exit("in_status: SIOCGLIFSUBNET");
		}
	}
	sin = (struct sockaddr_in *)&lifr.lifr_addr;
	if ((flags & IFF_NOLOCAL) ||
	    sin->sin_addr.s_addr != laddr->sin_addr.s_addr) {
		(void) printf("subnet %s/%d ", inet_ntoa(sin->sin_addr),
		    lifr.lifr_addrlen);
	}
	if (sin->sin_family != AF_INET) {
		(void) printf("Wrong family: %d\n", sin->sin_family);
	}

	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCGLIFNETMASK, (caddr_t)&lifr) < 0) {
		if (errno != EADDRNOTAVAIL)
			Perror0_exit("in_status: SIOCGLIFNETMASK");
		(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));
	} else
		netmask.sin_addr =
		    ((struct sockaddr_in *)&lifr.lifr_addr)->sin_addr;
	if (flags & IFF_POINTOPOINT) {
		(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
		if (ioctl(s, SIOCGLIFDSTADDR, (caddr_t)&lifr) < 0) {
			if (errno == EADDRNOTAVAIL)
				(void) memset(&lifr.lifr_addr, 0,
				    sizeof (lifr.lifr_addr));
			else
				Perror0_exit("in_status: SIOCGLIFDSTADDR");
		}
		sin = (struct sockaddr_in *)&lifr.lifr_dstaddr;
		(void) printf("--> %s ", inet_ntoa(sin->sin_addr));
	}
	(void) printf("netmask %x ", ntohl(netmask.sin_addr.s_addr));
	if (flags & IFF_BROADCAST) {
		(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
		if (ioctl(s, SIOCGLIFBRDADDR, (caddr_t)&lifr) < 0) {
			if (errno == EADDRNOTAVAIL)
				(void) memset(&lifr.lifr_addr, 0,
				    sizeof (lifr.lifr_addr));
			else
				Perror0_exit("in_status: SIOCGLIFBRDADDR");
		}
		sin = (struct sockaddr_in *)&lifr.lifr_addr;
		if (sin->sin_addr.s_addr != 0) {
			(void) printf("broadcast %s",
			    inet_ntoa(sin->sin_addr));
		}
	}
	/* If there is a groupname, print it for lun 0 alone */
	if (strchr(name, ':') == NULL) {
		(void) memset(lifr.lifr_groupname, 0,
		    sizeof (lifr.lifr_groupname));
		if (ioctl(s, SIOCGLIFGROUPNAME, (caddr_t)&lifr) >= 0) {
			if (strlen(lifr.lifr_groupname) > 0) {
				(void) printf("\n\tgroupname %s",
				    lifr.lifr_groupname);
			}
		}
	}
	(void) putchar('\n');
}

static void
in6_status(int force, uint64_t flags)
{
	char abuf[INET6_ADDRSTRLEN];
	struct sockaddr_in6 *sin6, *laddr6;

	if (debug)
		(void) printf("in6_status(%s) flags 0x%llx\n", name, flags);

	if (!(flags & IFF_IPV6))
		return;

	/* if the interface is a tunnel, print the tunnel status */
	tun_status();

	if (!(flags & IFF_NOLOCAL)) {
		(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
		if (ioctl(s, SIOCGLIFADDR, (caddr_t)&lifr) < 0) {
			if (errno == EADDRNOTAVAIL || errno == EAFNOSUPPORT ||
			    errno == ENXIO) {
				if (!force)
					return;
				(void) memset(&lifr.lifr_addr, 0,
				    sizeof (lifr.lifr_addr));
			} else
				Perror0_exit("in_status6: SIOCGLIFADDR");
		}
		sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;
		(void) printf("\tinet6 %s/%d ",
		    inet_ntop(AF_INET6, (void *)&sin6->sin6_addr,
		    abuf, sizeof (abuf)),
		    lifr.lifr_addrlen);
		laddr6 = sin6;
	} else {
		(void) printf("\tinet6 ");
	}
	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCGLIFSUBNET, (caddr_t)&lifr) < 0) {
		if (errno == EADDRNOTAVAIL || errno == EAFNOSUPPORT ||
		    errno == ENXIO) {
			if (!force)
				return;
			(void) memset(&lifr.lifr_addr, 0,
			    sizeof (lifr.lifr_addr));
		} else
			Perror0_exit("in_status6: SIOCGLIFSUBNET");
	}
	sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;
	if ((flags & IFF_NOLOCAL) ||
	    !IN6_ARE_ADDR_EQUAL(&sin6->sin6_addr, &laddr6->sin6_addr)) {
		(void) printf("subnet %s/%d ",
		    inet_ntop(AF_INET6, (void *)&sin6->sin6_addr,
		    abuf, sizeof (abuf)),
		    lifr.lifr_addrlen);
	}
	if (sin6->sin6_family != AF_INET6) {
		(void) printf("Wrong family: %d\n", sin6->sin6_family);
	}
	if (flags & IFF_POINTOPOINT) {
		(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
		if (ioctl(s, SIOCGLIFDSTADDR, (caddr_t)&lifr) < 0) {
			if (errno == EADDRNOTAVAIL)
				(void) memset(&lifr.lifr_addr, 0,
				    sizeof (lifr.lifr_addr));
			else
				Perror0_exit("in_status6: SIOCGLIFDSTADDR");
		}
		sin6 = (struct sockaddr_in6 *)&lifr.lifr_dstaddr;
		(void) printf("--> %s ",
		    inet_ntop(AF_INET6, (void *)&sin6->sin6_addr,
		    abuf, sizeof (abuf)));
	}
	if (verbose) {
		(void) putchar('\n');
		(void) putchar('\t');
		(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
		if (ioctl(s, SIOCGLIFTOKEN, (caddr_t)&lifr) < 0) {
			if (errno == EADDRNOTAVAIL || errno == EINVAL)
				(void) memset(&lifr.lifr_addr, 0,
				    sizeof (lifr.lifr_addr));
			else
				Perror0_exit("in_status6: SIOCGLIFTOKEN");
		} else {
			sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;
			(void) printf("token %s/%d ",
			    inet_ntop(AF_INET6, (void *)&sin6->sin6_addr,
			    abuf, sizeof (abuf)),
			    lifr.lifr_addrlen);
		}
		if (ioctl(s, SIOCGLIFLNKINFO, (caddr_t)&lifr) < 0) {
			if (errno != EINVAL) {
				Perror0_exit("in_status6: SIOCGLIFLNKINFO");
			}
		} else {
			(void) printf("maxhops %u, reachtime %u ms, "
			    "reachretrans %u ms, maxmtu %u ",
			    lifr.lifr_ifinfo.lir_maxhops,
			    lifr.lifr_ifinfo.lir_reachtime,
			    lifr.lifr_ifinfo.lir_reachretrans,
			    lifr.lifr_ifinfo.lir_maxmtu);
		}
	}
	/* If there is a groupname, print it for only the physical interface */
	if (strchr(name, ':') == NULL) {
		if (ioctl(s, SIOCGLIFGROUPNAME, &lifr) >= 0 &&
		    lifr.lifr_groupname[0] != '\0') {
			(void) printf("\n\tgroupname %s", lifr.lifr_groupname);
		}
	}
	(void) putchar('\n');
}

static void
in_configinfo(int force, uint64_t flags)
{
	struct sockaddr_in *sin, *laddr;
	struct	sockaddr_in netmask = { AF_INET };

	if (debug)
		(void) printf("in_configinfo(%s) flags 0x%llx\n", name, flags);

	/* only configinfo info for IPv4 interfaces */
	if (!(flags & IFF_IPV4))
		return;

	if (!(flags & IFF_NOLOCAL)) {
		(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
		if (ioctl(s, SIOCGLIFADDR, (caddr_t)&lifr) < 0) {
			if (errno == EADDRNOTAVAIL || errno == EAFNOSUPPORT ||
			    errno == ENXIO) {
				if (!force)
					return;
				(void) memset(&lifr.lifr_addr, 0,
				    sizeof (lifr.lifr_addr));
			} else
				Perror0_exit("in_configinfo: SIOCGLIFADDR");
		}
		sin = (struct sockaddr_in *)&lifr.lifr_addr;
		if (strchr(name, ':') != NULL) {
			(void) printf(" addif %s ", inet_ntoa(sin->sin_addr));
		} else {
			(void) printf(" set %s ", inet_ntoa(sin->sin_addr));
		}
		laddr = sin;
	}

	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCGLIFSUBNET, (caddr_t)&lifr) < 0) {
		if (errno == EADDRNOTAVAIL || errno == EAFNOSUPPORT ||
		    errno == ENXIO) {
			if (!force)
				return;
			(void) memset(&lifr.lifr_addr, 0,
			    sizeof (lifr.lifr_addr));
		} else {
			Perror0_exit("in_configinfo: SIOCGLIFSUBNET");
		}
	}
	sin = (struct sockaddr_in *)&lifr.lifr_addr;

	if ((flags & IFF_NOLOCAL) ||
	    sin->sin_addr.s_addr != laddr->sin_addr.s_addr) {
		(void) printf(" subnet %s/%d ", inet_ntoa(sin->sin_addr),
		    lifr.lifr_addrlen);
	}
	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCGLIFNETMASK, (caddr_t)&lifr) < 0) {
		if (errno != EADDRNOTAVAIL)
			Perror0_exit("in_configinfo: SIOCGLIFNETMASK");
		(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));
	} else
		netmask.sin_addr =
		    ((struct sockaddr_in *)&lifr.lifr_addr)->sin_addr;
	if (flags & IFF_POINTOPOINT) {
		(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
		if (ioctl(s, SIOCGLIFDSTADDR, (caddr_t)&lifr) < 0) {
			if (errno == EADDRNOTAVAIL)
				(void) memset(&lifr.lifr_addr, 0,
				    sizeof (lifr.lifr_addr));
			else
				Perror0_exit("in_configinfo: SIOCGLIFDSTADDR");
		}
		sin = (struct sockaddr_in *)&lifr.lifr_dstaddr;
		(void) printf(" destination %s ", inet_ntoa(sin->sin_addr));
	}
	(void) printf(" netmask 0x%x ", ntohl(netmask.sin_addr.s_addr));
	if (flags & IFF_BROADCAST) {
		(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
		if (ioctl(s, SIOCGLIFBRDADDR, (caddr_t)&lifr) < 0) {
			if (errno == EADDRNOTAVAIL)
				(void) memset(&lifr.lifr_addr, 0,
				    sizeof (lifr.lifr_addr));
			else
				Perror0_exit("in_configinfo: SIOCGLIFBRDADDR");
		}
		sin = (struct sockaddr_in *)&lifr.lifr_addr;
		if (sin->sin_addr.s_addr != 0) {
			(void) printf(" broadcast %s ",
			    inet_ntoa(sin->sin_addr));
		}
	}

	/* If there is a groupname, print it for only the physical interface */
	if (strchr(name, ':') == NULL) {
		if (ioctl(s, SIOCGLIFGROUPNAME, &lifr) >= 0 &&
		    lifr.lifr_groupname[0] != '\0') {
			(void) printf(" group %s ", lifr.lifr_groupname);
		}
	}

	/* Print flags to configure */
	print_config_flags(flags);

	/* IFF_NOARP applies to AF_INET only */
	if (flags & IFF_NOARP) {
		(void) printf("-arp ");
	}
}

static void
in6_configinfo(int force, uint64_t flags)
{
	char abuf[INET6_ADDRSTRLEN];
	struct sockaddr_in6 *sin6, *laddr6;

	if (debug)
		(void) printf("in6_configinfo(%s) flags 0x%llx\n", name,
		    flags);

	if (!(flags & IFF_IPV6))
		return;

	if (!(flags & IFF_NOLOCAL)) {
		(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
		if (ioctl(s, SIOCGLIFADDR, (caddr_t)&lifr) < 0) {
			if (errno == EADDRNOTAVAIL || errno == EAFNOSUPPORT ||
			    errno == ENXIO) {
				if (!force)
					return;
				(void) memset(&lifr.lifr_addr, 0,
				    sizeof (lifr.lifr_addr));
			} else
				Perror0_exit("in6_configinfo: SIOCGLIFADDR");
		}
		sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;
		if (strchr(name, ':') != NULL) {
			(void) printf(" addif %s/%d ",
			    inet_ntop(AF_INET6, (void *)&sin6->sin6_addr,
			    abuf, sizeof (abuf)),
			    lifr.lifr_addrlen);
		} else {
			(void) printf(" set %s/%d ",
			    inet_ntop(AF_INET6, (void *)&sin6->sin6_addr,
			    abuf, sizeof (abuf)),
			    lifr.lifr_addrlen);
		}
		laddr6 = sin6;
	}
	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCGLIFSUBNET, (caddr_t)&lifr) < 0) {
		if (errno == EADDRNOTAVAIL || errno == EAFNOSUPPORT ||
		    errno == ENXIO) {
			if (!force)
				return;
			(void) memset(&lifr.lifr_addr, 0,
			    sizeof (lifr.lifr_addr));
		} else
			Perror0_exit("in6_configinfo: SIOCGLIFSUBNET");
	}
	sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;
	if ((flags & IFF_NOLOCAL) ||
	    !IN6_ARE_ADDR_EQUAL(&sin6->sin6_addr, &laddr6->sin6_addr)) {
		(void) printf(" subnet %s/%d ",
		    inet_ntop(AF_INET6, (void *)&sin6->sin6_addr,
		    abuf, sizeof (abuf)),
		    lifr.lifr_addrlen);
	}

	if (flags & IFF_POINTOPOINT) {
		(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
		if (ioctl(s, SIOCGLIFDSTADDR, (caddr_t)&lifr) < 0) {
			if (errno == EADDRNOTAVAIL)
				(void) memset(&lifr.lifr_addr, 0,
				    sizeof (lifr.lifr_addr));
			else
				Perror0_exit("in6_configinfo: SIOCGLIFDSTADDR");
		}
		sin6 = (struct sockaddr_in6 *)&lifr.lifr_dstaddr;
		(void) printf(" destination %s ",
		    inet_ntop(AF_INET6, (void *)&sin6->sin6_addr,
		    abuf, sizeof (abuf)));
	}

	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(s, SIOCGLIFTOKEN, (caddr_t)&lifr) < 0) {
		if (errno == EADDRNOTAVAIL || errno == EINVAL)
			(void) memset(&lifr.lifr_addr, 0,
			    sizeof (lifr.lifr_addr));
		else
			Perror0_exit("in6_configinfo: SIOCGLIFTOKEN");
	} else {
		sin6 = (struct sockaddr_in6 *)&lifr.lifr_addr;
		(void) printf(" token %s/%d ",
		    inet_ntop(AF_INET6, (void *)&sin6->sin6_addr,
		    abuf, sizeof (abuf)),
		    lifr.lifr_addrlen);
	}

	/* If there is a groupname, print it for only the physical interface */
	if (strchr(name, ':') == NULL) {
		if (ioctl(s, SIOCGLIFGROUPNAME, &lifr) >= 0 &&
		    lifr.lifr_groupname[0] != '\0') {
			(void) printf(" group %s ", lifr.lifr_groupname);
		}
	}

	/* Print flags to configure */
	print_config_flags(flags);

	/* IFF_NONUD applies to AF_INET6 only */
	if (flags & IFF_NONUD) {
		(void) printf("-nud ");
	}
}

/*
 * We need to plink both the arp-device stream and the arp-ip-device stream.
 * However the muxid is stored only in IP. Plumbing 2 streams individually
 * is not atomic, and if ifconfig is killed, the resulting plumbing can
 * be inconsistent. For eg. if only the arp stream is plumbed, we have lost
 * the muxid, and the half-baked plumbing can neither be unplumbed nor
 * replumbed, thus requiring a reboot. To avoid the above the following
 * scheme is used.
 *
 * Ifconfig asks IP to enforce atomicity of plumbing the arp and IP streams.
 * This is done by pushing arp on to the mux (/dev/udp). ARP adds some
 * extra information in the I_PLINK and I_PUNLINK ioctls to let IP know
 * that the plumbing/unplumbing has to be done atomically. Ifconfig plumbs
 * the IP stream first, and unplumbs it last. The kernel (IP) does not
 * allow IP stream to be unplumbed without unplumbing arp stream. Similarly
 * it does not allow arp stream to be plumbed before IP stream is plumbed.
 * There is no need to use SIOCSLIFMUXID, since the whole operation is atomic,
 * and IP uses the info in the I_PLINK message to get the muxid.
 *
 * a. STREAMS does not allow us to use /dev/ip itself as the mux. So we use
 *    /dev/udp{,6}.
 * b. SIOCGLIFMUXID returns the muxid corresponding to the V4 or V6 stream
 *    depending on the open i.e. V4 vs V6 open. So we need to use /dev/udp
 *    or /dev/udp6 for SIOCGLIFMUXID and SIOCSLIFMUXID.
 * c. We need to push ARP in order to get the required kernel support for
 *    atomic plumbings. The actual work done by ARP is explained in arp.c
 *    Without pushing ARP, we will still be able to plumb/unplumb. But
 *    it is not atomic, and is supported by the kernel for backward
 *    compatibility for other utilities like atmifconfig etc. In this case
 *    the utility must use SIOCSLIFMUXID.
 */
static void
plumb_one_device(int af)
{
	int	arp_muxid = -1, ip_muxid;
	int	mux_fd, ip_fd, arp_fd;
	int 	retval;
	uint_t	ppa;
	char	*udp_dev_name;
	char    provider[DLPI_LINKNAME_MAX];
	dlpi_handle_t	dh_arp, dh_ip;

	/*
	 * We use DLPI_NOATTACH because the ip module will do the attach
	 * itself for DLPI style-2 devices.
	 */
	retval = dlpi_open(name, &dh_ip, DLPI_NOATTACH);
	if (retval != DLPI_SUCCESS)
		Perrdlpi_exit("cannot open link", name, retval);

	if ((retval = dlpi_parselink(name, provider, &ppa)) != DLPI_SUCCESS)
		Perrdlpi_exit("dlpi_parselink", name, retval);

	if (debug) {
		(void) printf("ifconfig: plumb_one_device: provider %s,"
		    " ppa %u\n", provider, ppa);
	}

	ip_fd = dlpi_fd(dh_ip);
	if (ioctl(ip_fd, I_PUSH, IP_MOD_NAME) == -1)
		Perror2_exit("I_PUSH", IP_MOD_NAME);

	/*
	 * Push the ARP module onto the interface stream. IP uses
	 * this to send resolution requests up to ARP. We need to
	 * do this before the SLIFNAME ioctl is sent down because
	 * the interface becomes publicly known as soon as the SLIFNAME
	 * ioctl completes. Thus some other process trying to bring up
	 * the interface after SLIFNAME but before we have pushed ARP
	 * could hang. We pop the module again later if it is not needed.
	 */
	if (ioctl(ip_fd, I_PUSH, ARP_MOD_NAME) == -1)
		Perror2_exit("I_PUSH", ARP_MOD_NAME);

	/*
	 * Set IFF_IPV4/IFF_IPV6 flags.
	 * At this point in time the kernel also allows an
	 * override of the CANTCHANGE flags.
	 */
	lifr.lifr_name[0] = '\0';
	if (ioctl(ip_fd, SIOCGLIFFLAGS, (char *)&lifr) == -1)
		Perror0_exit("plumb_one_device: SIOCGLIFFLAGS");

	/* Set the name string and the IFF_IPV* flag */
	if (af == AF_INET6) {
		lifr.lifr_flags |= IFF_IPV6;
		lifr.lifr_flags &= ~(IFF_BROADCAST | IFF_IPV4);
	} else {
		lifr.lifr_flags |= IFF_IPV4;
		lifr.lifr_flags &= ~IFF_IPV6;
	}

	/* record the device and module names as interface name */
	lifr.lifr_ppa = ppa;
	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));

	/* set the interface name */
	if (ioctl(ip_fd, SIOCSLIFNAME, (char *)&lifr) == -1) {
		if (errno != EEXIST)
			Perror0_exit("SIOCSLIFNAME for ip");
		/*
		 * This difference between the way we behave for EEXIST
		 * and that with other errors exists to preserve legacy
		 * behaviour. Earlier when foreachinterface() and matchif()
		 * were doing the duplicate interface name checks, for
		 * already existing interfaces, inetplumb() returned "0".
		 * To preserve this behaviour, Perror0() and return are
		 * called for EEXIST.
		 */
		Perror0("SIOCSLIFNAME for ip");
		return;
	}

	/* Get the full set of existing flags for this stream */
	if (ioctl(ip_fd, SIOCGLIFFLAGS, (char *)&lifr) == -1)
		Perror0_exit("plumb_one_device: SIOCFLIFFLAGS");

	if (debug) {
		(void) printf("ifconfig: plumb_one_device: %s got flags:\n",
		    lifr.lifr_name);
		print_flags(lifr.lifr_flags);
		(void) putchar('\n');
	}

	/* Check if arp is not actually needed */
	if (lifr.lifr_flags & (IFF_NOARP|IFF_IPV6)) {
		if (ioctl(ip_fd, I_POP, 0) == -1)
			Perror2_exit("I_POP", ARP_MOD_NAME);
	}

	/*
	 * Open "/dev/udp" for use as a multiplexor to PLINK the
	 * interface stream under. We use "/dev/udp" instead of "/dev/ip"
	 * since STREAMS will not let you PLINK a driver under itself,
	 * and "/dev/ip" is typically the driver at the bottom of
	 * the stream for tunneling interfaces.
	 */
	if (af == AF_INET6)
		udp_dev_name = UDP6_DEV_NAME;
	else
		udp_dev_name = UDP_DEV_NAME;
	if ((mux_fd = open_arp_on_udp(udp_dev_name)) == -1)
		exit(EXIT_FAILURE);

	/* Check if arp is not needed */
	if (lifr.lifr_flags & (IFF_NOARP|IFF_IPV6)) {
		/*
		 * PLINK the interface stream so that ifconfig can exit
		 * without tearing down the stream.
		 */
		if ((ip_muxid = ioctl(mux_fd, I_PLINK, ip_fd)) == -1)
			Perror0_exit("I_PLINK for ip");
		(void) close(mux_fd);
		return;
	}

	/*
	 * This interface does use ARP, so set up a separate stream
	 * from the interface to ARP.
	 *
	 * Note: modules specified by the user are pushed
	 * only on the interface stream, not on the ARP stream.
	 */
	if (debug)
		(void) printf("ifconfig: plumb_one_device: ifname: %s\n", name);

	/*
	 * We use DLPI_NOATTACH because the arp module will do the attach
	 * itself for DLPI style-2 devices.
	 */
	retval = dlpi_open(name, &dh_arp, DLPI_NOATTACH);
	if (retval != DLPI_SUCCESS)
		Perrdlpi_exit("cannot open link", name, retval);

	arp_fd = dlpi_fd(dh_arp);
	if (ioctl(arp_fd, I_PUSH, ARP_MOD_NAME) == -1)
		Perror2_exit("I_PUSH", ARP_MOD_NAME);

	/*
	 * Tell ARP the name and unit number for this interface.
	 * Note that arp has no support for transparent ioctls.
	 */
	if (strioctl(arp_fd, SIOCSLIFNAME, (char *)&lifr,
	    sizeof (lifr)) == -1) {
		if (errno != EEXIST)
			Perror0_exit("SIOCSLIFNAME for arp");
		Perror0("SIOCSLIFNAME for arp");
		dlpi_close(dh_arp);
		dlpi_close(dh_ip);
		(void) close(mux_fd);
		return;
	}
	/*
	 * PLINK the IP and ARP streams so that ifconfig can exit
	 * without tearing down the stream.
	 */
	if ((ip_muxid = ioctl(mux_fd, I_PLINK, ip_fd)) == -1)
		Perror0_exit("I_PLINK for ip");
	if ((arp_muxid = ioctl(mux_fd, I_PLINK, arp_fd)) == -1) {
		(void) ioctl(mux_fd, I_PUNLINK, ip_muxid);
		Perror0_exit("I_PLINK for arp");
	}

	if (debug)
		(void) printf("arp muxid = %d\n", arp_muxid);
	dlpi_close(dh_ip);
	dlpi_close(dh_arp);
	(void) close(mux_fd);
}


/*
 * If this is a physical interface then remove it.
 * If it is a logical interface name use SIOCLIFREMOVEIF to
 * remove it. In both cases fail if it doesn't exist.
 */
/* ARGSUSED */
static int
inetunplumb(char *arg, int64_t param)
{
	int ip_muxid, arp_muxid;
	int mux_fd;
	int muxid_fd;
	char *udp_dev_name;
	char *strptr;
	uint64_t flags;
	boolean_t changed_arp_muxid = _B_FALSE;
	int save_errno;

	strptr = strchr(name, ':');
	if (strptr != NULL || strcmp(name, LOOPBACK_IF) == 0) {
		/* Can't unplumb logical interface zero */
		if (strptr != NULL && strcmp(strptr, ":0") == 0) {
			(void) fprintf(stderr, "ifconfig: unplumb:"
			    " Cannot unplumb %s: Invalid interface\n", name);
			exit(1);
		}
		(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
		(void) memset(&lifr.lifr_addr, 0, sizeof (lifr.lifr_addr));

		if (ioctl(s, SIOCLIFREMOVEIF, (caddr_t)&lifr) < 0)
			Perror0_exit("unplumb: SIOCLIFREMOVEIF");
		return (0);
	}

	/*
	 * We used /dev/udp or udp6 to set up the mux. So we have to use
	 * the same now for PUNLINK also.
	 */
	if (afp->af_af == AF_INET6)
		udp_dev_name = UDP6_DEV_NAME;
	else
		udp_dev_name = UDP_DEV_NAME;

	if ((muxid_fd = open(udp_dev_name, O_RDWR)) == -1)
		exit(EXIT_FAILURE);

	if ((mux_fd = open_arp_on_udp(udp_dev_name)) == -1)
		exit(EXIT_FAILURE);

	(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
	if (ioctl(muxid_fd, SIOCGLIFFLAGS, (caddr_t)&lifr) < 0) {
		Perror0_exit("unplumb: SIOCGLIFFLAGS");
	}
	flags = lifr.lifr_flags;
	if (ioctl(muxid_fd, SIOCGLIFMUXID, (caddr_t)&lifr) < 0) {
		Perror0_exit("unplumb: SIOCGLIFMUXID");
	}
	arp_muxid = lifr.lifr_arp_muxid;
	ip_muxid = lifr.lifr_ip_muxid;
	/*
	 * We don't have a good way of knowing whether the arp stream is
	 * plumbed. We can't rely on IFF_NOARP because someone could
	 * have turned it off later using "ifconfig xxx -arp".
	 */
	if (arp_muxid != 0) {
		if (debug)
			(void) printf("arp_muxid %d\n", arp_muxid);
		if (ioctl(mux_fd, I_PUNLINK, arp_muxid) < 0) {
			if ((errno == EINVAL) &&
			    (flags & (IFF_NOARP | IFF_IPV6))) {
				/*
				 * Some plumbing utilities set the muxid to
				 * -1 or some invalid value to signify that
				 * there is no arp stream. Set the muxid to 0
				 * before trying to unplumb the IP stream.
				 * IP does not allow the IP stream to be
				 * unplumbed if it sees a non-null arp muxid,
				 * for consistency of IP-ARP streams.
				 */
				lifr.lifr_arp_muxid = 0;
				(void) ioctl(muxid_fd, SIOCSLIFMUXID,
				    (caddr_t)&lifr);
				changed_arp_muxid = _B_TRUE;
			} else {
				Perror0("I_PUNLINK for arp");
			}
		}
	}
	if (debug)
		(void) printf("ip_muxid %d\n", ip_muxid);

	if (ioctl(mux_fd, I_PUNLINK, ip_muxid) < 0) {
		if (changed_arp_muxid) {
			/*
			 * Some error occurred, and we need to restore
			 * everything back to what it was.
			 */
			save_errno = errno;
			lifr.lifr_arp_muxid = arp_muxid;
			lifr.lifr_ip_muxid = ip_muxid;
			(void) ioctl(muxid_fd, SIOCSLIFMUXID, (caddr_t)&lifr);
			errno = save_errno;
		}
		Perror0_exit("I_PUNLINK for ip");
	}
	(void) close(mux_fd);
	(void) close(muxid_fd);
	return (0);
}

/*
 * If this is a physical interface then create it unless it is already
 * present. If it is a logical interface name use SIOCLIFADDIF to
 * create and (and fail it if already exists.)
 * As a special case send SIOCLIFADDIF for the loopback interface. This
 * is needed since there is no other notion of plumbing the loopback
 * interface.
 */
/* ARGSUSED */
static int
inetplumb(char *arg, int64_t param)
{
	char		*strptr;
	boolean_t	islo;
	zoneid_t	zoneid;

	strptr = strchr(name, ':');
	islo = (strcmp(name, LOOPBACK_IF) == 0);

	if (strptr != NULL || islo) {
		(void) memset(&lifr, 0, sizeof (lifr));
		(void) strlcpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
		if (islo && ioctl(s, SIOCGLIFADDR, (caddr_t)&lifr) >= 0) {
			if (debug) {
				(void) fprintf(stderr,
				    "ifconfig: %s already exists\n", name);
			}
			return (0);
		}
		if (ioctl(s, SIOCLIFADDIF, (caddr_t)&lifr) < 0) {
			if (errno == EEXIST) {
				if (debug) {
					(void) fprintf(stderr,
					    "ifconfig: %s already exists\n",
					    name);
				}
			} else {
				Perror2_exit("plumb: SIOCLIFADDIF", name);
			}
		}
		/*
		 * IP can create the new logical interface on a different
		 * physical interface in the same IPMP group. Take the new
		 * interface into account for further operations.
		 */
		(void) strncpy(name, lifr.lifr_name, sizeof (name));
		return (0);
	}

	/*
	 * For global zone, check if the interface is used by a non-global
	 * zone, note that the non-global zones doesn't need this check,
	 * because zoneadm has taken care of this when the zone boots.
	 */
	zoneid = getzoneid();
	if (zoneid == GLOBAL_ZONEID) {
		int ret;

		zoneid = ALL_ZONES;
		ret = zone_check_datalink(&zoneid, name);
		if (ret == 0) {
			char zonename[ZONENAME_MAX];

			(void) getzonenamebyid(zoneid, zonename, ZONENAME_MAX);
			(void) fprintf(stderr, "%s is used by non-global"
			    "zone: %s\n", name, zonename);
			return (1);
		}
	}

	if (debug)
		(void) printf("inetplumb: %s af %d\n", name, afp->af_af);

	plumb_one_device(afp->af_af);
	return (0);
}

void
Perror0(const char *cmd)
{
	Perror2(cmd, lifr.lifr_name);
}

void
Perror0_exit(const char *cmd)
{
	Perror0(cmd);
	exit(1);
	/* NOTREACHED */
}

void
Perror2(const char *cmd, const char *str)
{
	int error = errno;

	(void) fprintf(stderr, "ifconfig: %s: ", cmd);

	switch (error) {
	case ENXIO:
		(void) fprintf(stderr, "%s: no such interface\n", str);
		break;
	case EPERM:
		(void) fprintf(stderr, "%s: permission denied\n", str);
		break;
	case EEXIST:
		(void) fprintf(stderr, "%s: already exists\n", str);
		break;
	default:
		errno = error;
		perror(str);
	}
}

/*
 * Print out error message (Perror2()) and exit
 */
void
Perror2_exit(const char *cmd, const char *str)
{
	Perror2(cmd, str);
	exit(1);
	/* NOTREACHED */
}

void
Perrdlpi(const char *cmd, const char *linkname, int err)
{
	(void) fprintf(stderr, "ifconfig: %s \"%s\": %s\n", cmd,
	    linkname, dlpi_strerror(err));
}

/*
 * Print out error message (Perrdlpi()) and exit
 */
void
Perrdlpi_exit(const char *cmd, const char *linkname, int err)
{
	Perrdlpi(cmd, linkname, err);
	exit(1);
}

/*
 * If the last argument is non-NULL allow a <addr>/<n> syntax and
 * pass out <n> in *plenp.
 * If <n> doesn't parse return BAD_ADDR as *plenp.
 * If no /<n> is present return NO_PREFIX as *plenp.
 */
static void
in_getaddr(char *s, struct sockaddr *saddr, int *plenp)
{
	/* LINTED: alignment */
	struct sockaddr_in *sin = (struct sockaddr_in *)saddr;
	struct hostent *hp;
	struct netent *np;
	char str[BUFSIZ];
	int error_num;

	(void) strncpy(str, s, sizeof (str));

	/*
	 * Look for '/'<n> is plenp
	 */
	if (plenp != NULL) {
		char *cp;

		*plenp = in_getprefixlen(str, _B_TRUE, IP_ABITS);
		if (*plenp == BAD_ADDR)
			return;
		cp = strchr(str, '/');
		if (cp != NULL)
			*cp = '\0';
	} else if (strchr(str, '/') != NULL) {
		(void) fprintf(stderr, "ifconfig: %s: unexpected '/'\n", str);
		exit(1);
	}

	(void) memset(sin, 0, sizeof (*sin));

	/*
	 *	Try to catch attempts to set the broadcast address to all 1's.
	 */
	if (strcmp(str, "255.255.255.255") == 0 ||
	    (strtoul(str, (char **)NULL, 0) == 0xffffffffUL)) {
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = 0xffffffff;
		return;
	}

	hp = getipnodebyname(str, AF_INET, 0, &error_num);
	if (hp) {
		sin->sin_family = hp->h_addrtype;
		(void) memcpy(&sin->sin_addr, hp->h_addr, hp->h_length);
		freehostent(hp);
		return;
	}
	np = getnetbyname(str);
	if (np) {
		sin->sin_family = np->n_addrtype;
		sin->sin_addr = inet_makeaddr(np->n_net, INADDR_ANY);
		return;
	}
	if (error_num == TRY_AGAIN) {
		(void) fprintf(stderr, "ifconfig: %s: bad address "
		    "(try again later)\n", s);
	} else {
		(void) fprintf(stderr, "ifconfig: %s: bad address\n", s);
	}
	exit(1);
}

/*
 * If the last argument is non-NULL allow a <addr>/<n> syntax and
 * pass out <n> in *plenp.
 * If <n> doesn't parse return BAD_ADDR as *plenp.
 * If no /<n> is present return NO_PREFIX as *plenp.
 */
static void
in6_getaddr(char *s, struct sockaddr *saddr, int *plenp)
{
	/* LINTED: alignment */
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)saddr;
	struct hostent *hp;
	char str[BUFSIZ];
	int error_num;

	(void) strncpy(str, s, sizeof (str));

	/*
	 * Look for '/'<n> is plenp
	 */
	if (plenp != NULL) {
		char *cp;

		*plenp = in_getprefixlen(str, _B_TRUE, IPV6_ABITS);
		if (*plenp == BAD_ADDR)
			return;
		cp = strchr(str, '/');
		if (cp != NULL)
			*cp = '\0';
	} else if (strchr(str, '/') != NULL) {
		(void) fprintf(stderr, "ifconfig: %s: unexpected '/'\n", str);
		exit(1);
	}

	(void) memset(sin6, 0, sizeof (*sin6));

	hp = getipnodebyname(str, AF_INET6, 0, &error_num);
	if (hp) {
		sin6->sin6_family = hp->h_addrtype;
		(void) memcpy(&sin6->sin6_addr, hp->h_addr, hp->h_length);
		freehostent(hp);
		return;
	}
	if (error_num == TRY_AGAIN) {
		(void) fprintf(stderr, "ifconfig: %s: bad address "
		    "(try again later)\n", s);
	} else {
		(void) fprintf(stderr, "ifconfig: %s: bad address\n", s);
	}
	exit(1);
}

/*
 * If "slash" is zero this parses the whole string as
 * an integer. With "slash" non zero it parses the tail part as an integer.
 *
 * If it is not a valid integer this returns BAD_ADDR.
 * If there is /<n> present this returns NO_PREFIX.
 */
static int
in_getprefixlen(char *addr, boolean_t slash, int max_plen)
{
	int prefixlen;
	char *str, *end;

	if (slash) {
		str = strchr(addr, '/');
		if (str == NULL)
			return (NO_PREFIX);
		str++;
	} else
		str = addr;

	prefixlen = strtol(str, &end, 10);
	if (prefixlen < 0)
		return (BAD_ADDR);
	if (str == end)
		return (BAD_ADDR);
	if (max_plen != 0 && max_plen < prefixlen)
		return (BAD_ADDR);
	return (prefixlen);
}

/*
 * Convert a prefix length to a mask.
 * Returns 1 if ok. 0 otherwise.
 * Assumes the mask array is zero'ed by the caller.
 */
static boolean_t
in_prefixlentomask(int prefixlen, int maxlen, uchar_t *mask)
{
	if (prefixlen < 0 || prefixlen > maxlen)
		return (0);

	while (prefixlen > 0) {
		if (prefixlen >= 8) {
			*mask++ = 0xFF;
			prefixlen -= 8;
			continue;
		}
		*mask |= 1 << (8 - prefixlen);
		prefixlen--;
	}
	return (1);
}

static void
print_flags(uint64_t flags)
{
	boolean_t first = _B_TRUE;
	int cnt, i;

	(void) printf("flags=%llx", flags);
	cnt = sizeof (if_flags_tbl) / sizeof (if_flags_t);
	for (i = 0; i < cnt; i++) {
		if (flags & if_flags_tbl[i].iff_value) {
			if (first) {
				(void) printf("<");
				first = _B_FALSE;
			} else {
				/*
				 * It has to be here and not with the
				 * printf below because for the last one,
				 * we don't want a comma before the ">".
				 */
				(void) printf(",");
			}
			(void) printf("%s", if_flags_tbl[i].iff_name);
		}
	}
	if (!first)
		(void) printf(">");
}

static void
print_config_flags(uint64_t flags)
{
	int cnt, i;

	cnt = sizeof (if_config_cmd_tbl) / sizeof (if_config_cmd_t);
	for (i = 0; i < cnt; i++) {
		if (flags & if_config_cmd_tbl[i].iff_flag) {
			(void) printf("%s ", if_config_cmd_tbl[i].iff_name);
		}
	}
}

/*
 * Use the configured directory lookup mechanism (e.g. files/NIS/NIS+/...)
 * to find the network mask.  Returns true if we found one to set.
 *
 * The parameter addr_set controls whether we should get the address of
 * the working interface for the netmask query.  If addr_set is true,
 * we will use the address provided.  Otherwise, we will find the working
 * interface's address and use it instead.
 */
static boolean_t
in_getmask(struct sockaddr_in *saddr, boolean_t addr_set)
{
	struct sockaddr_in ifaddr;

	/*
	 * Read the address from the interface if it is not passed in.
	 */
	if (!addr_set) {
		(void) strncpy(lifr.lifr_name, name, sizeof (lifr.lifr_name));
		if (ioctl(s, SIOCGLIFADDR, (caddr_t)&lifr) < 0) {
			if (errno != EADDRNOTAVAIL) {
				(void) fprintf(stderr, "Need net number for "
				    "mask\n");
			}
			return (_B_FALSE);
		}
		ifaddr = *((struct sockaddr_in *)&lifr.lifr_addr);
	} else {
		ifaddr.sin_addr = saddr->sin_addr;
	}
	if (getnetmaskbyaddr(ifaddr.sin_addr, &saddr->sin_addr) == 0) {
		saddr->sin_family = AF_INET;
		return (_B_TRUE);
	}
	return (_B_FALSE);
}

static int
strioctl(int s, int cmd, char *buf, int buflen)
{
	struct strioctl ioc;

	(void) memset(&ioc, 0, sizeof (ioc));
	ioc.ic_cmd = cmd;
	ioc.ic_timout = 0;
	ioc.ic_len = buflen;
	ioc.ic_dp = buf;
	return (ioctl(s, I_STR, (char *)&ioc));
}

static void
add_ni(const char *name)
{
	ni_t **pp;
	ni_t *p;

	for (pp = &ni_list; (p = *pp) != NULL; pp = &(p->ni_next)) {
		if (strcmp(p->ni_name, name) == 0) {
			if (debug > 2)
				(void) fprintf(stderr, "'%s' is a duplicate\n",
				    name);
			return;
		}
	}

	if (debug > 2)
		(void) fprintf(stderr, "adding '%s'\n",
		    name);

	if ((p = malloc(sizeof (ni_t))) == NULL)
		return;

	(void) strlcpy(p->ni_name, name, sizeof (p->ni_name));
	p->ni_next = NULL;

	*pp = p;
	num_ni++;
}

/* ARGSUSED2 */
static boolean_t
ni_entry(const char *linkname, void *arg)
{
	dlpi_handle_t	dh;

	if (dlpi_open(linkname, &dh, 0) != DLPI_SUCCESS)
		return (_B_FALSE);

	add_ni(linkname);

	dlpi_close(dh);
	return (_B_FALSE);
}

/*
 * dhcp-related routines
 */

static int
setifdhcp(const char *caller, const char *ifname, int argc, char *argv[])
{
	dhcp_ipc_request_t	*request;
	dhcp_ipc_reply_t	*reply	= NULL;
	int			timeout = DHCP_IPC_WAIT_DEFAULT;
	dhcp_ipc_type_t		type	= DHCP_START;
	int			error;
	boolean_t		is_primary = _B_FALSE;
	boolean_t		started = _B_FALSE;

	for (argv++; --argc > 0; argv++) {

		if (strcmp(*argv, "primary") == 0) {
			is_primary = _B_TRUE;
			continue;
		}

		if (strcmp(*argv, "wait") == 0) {
			if (--argc <= 0) {
				usage();
				return (DHCP_EXIT_BADARGS);
			}
			argv++;

			if (strcmp(*argv, "forever") == 0) {
				timeout = DHCP_IPC_WAIT_FOREVER;
				continue;
			}

			if (sscanf(*argv, "%d", &timeout) != 1) {
				usage();
				return (DHCP_EXIT_BADARGS);
			}

			if (timeout < 0) {
				usage();
				return (DHCP_EXIT_BADARGS);
			}
			continue;
		}

		type = dhcp_string_to_request(*argv);
		if (type == -1) {
			usage();
			return (DHCP_EXIT_BADARGS);
		}
	}

	/*
	 * Only try to start agent on start or inform; in all other cases it
	 * has to already be running for anything to make sense.
	 */
	if (type == DHCP_START || type == DHCP_INFORM) {
		if (dhcp_start_agent(DHCP_IPC_MAX_WAIT) == -1) {
			(void) fprintf(stderr, "%s: unable to start %s\n",
			    caller, DHCP_AGENT_PATH);
			return (DHCP_EXIT_FAILURE);
		}
		started = _B_TRUE;
	}

	if (is_primary)
		type |= DHCP_PRIMARY;

	if (af != AF_INET)
		type |= DHCP_V6;

	request = dhcp_ipc_alloc_request(type, ifname, NULL, 0, DHCP_TYPE_NONE);
	if (request == NULL) {
		(void) fprintf(stderr, "%s: out of memory\n", caller);
		return (DHCP_EXIT_SYSTEM);
	}

	error = dhcp_ipc_make_request(request, &reply, timeout);
	if (error != 0) {
		free(request);
		/*
		 * Re-map connect error to not under control if we didn't try a
		 * start operation, as this has to be true and results in a
		 * clearer message, not to mention preserving compatibility
		 * with the days when we always started dhcpagent for every
		 * request.
		 */
		if (error == DHCP_IPC_E_CONNECT && !started)
			error = DHCP_IPC_E_UNKIF;
		(void) fprintf(stderr, "%s: %s: %s\n", caller, ifname,
		    dhcp_ipc_strerror(error));
		return (DHCP_EXIT_FAILURE);
	}

	error = reply->return_code;
	if (error != 0) {
		free(request);
		free(reply);

		if (error == DHCP_IPC_E_TIMEOUT && timeout == 0)
			return (DHCP_EXIT_SUCCESS);

		(void) fprintf(stderr, "%s: %s: %s\n", caller, ifname,
		    dhcp_ipc_strerror(error));

		if (error == DHCP_IPC_E_TIMEOUT)
			return (DHCP_EXIT_TIMEOUT);
		else
			return (DHCP_EXIT_IF_FAILURE);
	}

	if (DHCP_IPC_CMD(type) == DHCP_STATUS) {
		(void) printf("%s", dhcp_status_hdr_string());
		(void) printf("%s", dhcp_status_reply_to_string(reply));
	}

	free(request);
	free(reply);
	return (DHCP_EXIT_SUCCESS);
}

static void
usage(void)
{
	(void) fprintf(stderr,
	    "usage: ifconfig <interface> | -a[ 4 | 6 | D ][ u | d ][ Z ]\n");

	(void) fprintf(stderr, "%s",
	    "\t[ <addr_family> ]\n"
	    "\t[ <address>[/<prefix_length>] [ <dest_address> ] ]\n"
	    "\t[ set [ <address>][/<prefix_length>] ]"
	    " [ <address>/<prefix_length>] ]\n"
	    "\t[ destination <dest_address> ]\n"
	    "\t[ addif <address>[/<prefix_length>]"
	    "  [ <dest_address> ] ]\n"
	    "\t[ removeif <address>[/<prefix_length>] ]\n"
	    "\t[ arp | -arp ]\n"
	    "\t[ auto-revarp ]\n"
	    "\t[ broadcast <broad_addr> ]\n"
	    "\t[ index <if_index> ]\n"
	    "\t[ metric <n> ] [ mtu <n> ]\n"
	    "\t[ netmask <mask> ]\n"
	    "\t[ plumb ] [ unplumb ]\n"
	    "\t[ preferred | -preferred ]\n"
	    "\t[ private | -private ]\n"
	    "\t[ local | -local ]\n"
	    "\t[ router | -router ]\n"
	    "\t[ subnet <subnet_address>]\n"
	    "\t[ trailers | -trailers ]\n"
	    "\t[ token <address>/<prefix_length> ]\n"
	    "\t[ tsrc <tunnel_src_address> ]\n"
	    "\t[ tdst <tunnel_dest_address> ]\n"
	    "\t[ auth_algs <tunnel_AH_authentication_algorithm> ]\n"
	    "\t[ encr_algs <tunnel_ESP_encryption_algorithm> ]\n"
	    "\t[ encr_auth_algs <tunnel_ESP_authentication_algorithm> ]\n"
	    "\t[ up ] [ down ]\n"
	    "\t[ xmit | -xmit ]\n"
	    "\t[ modlist ]\n"
	    "\t[ modinsert <module_name@position> ]\n"
	    "\t[ modremove <module_name@position> ]\n"
	    "\t[ group <groupname>] | [ group \"\"]\n"
	    "\t[ deprecated | -deprecated ]\n"
	    "\t[ standby | -standby ]\n"
	    "\t[ failover | -failover ]\n"
	    "\t[ zone <zonename> | -zone ]\n"
	    "\t[ usesrc <interface> ]\n"
	    "\t[ all-zones ]\n");

	(void) fprintf(stderr, "or\n");
	(void) fprintf(stderr,
	    "\tifconfig <interface> |  -a[ 4 | 6 | D ] [ u | d ]\n");

	(void) fprintf(stderr, "%s", "\tauto-dhcp | dhcp\n"
	    "\t[ wait <time> | forever ]\n\t[ primary ]\n"
	    "\tstart | drop | ping | release | status | inform\n");
}
