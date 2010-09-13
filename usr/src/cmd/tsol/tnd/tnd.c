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
 *  Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 *  Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <locale.h>
#include <langinfo.h>
#include <search.h>
#include <tsol/label.h>
#include <errno.h>
#include <sys/tsol/tndb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <sys/signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <syslog.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <door.h>
#include <synch.h>
#include <sys/tsol/tsyscall.h>
#include <nss_dbdefs.h>
#include <libtsnet.h>
#include <zone.h>

#include "tnd.h"

static FILE *tnlog_open(char *);
static void usage();
static void parse_opts(int, char **);
static int check_debugl(int);
static void load_tp();
static void load_tp_entry();
static void tnd_serve();
static void detachfromtty();
static void terminate();
static void noop();
static char *gettime();
static int isnumber(char *);
static void poll_now();
static int nss_get_tp();
static int nss_get_rh();
static void timer();
static void load_rh_marked();
static int rhtable_search_and_update(struct tsol_rhent *ent, int duplflag);
static int is_better_match(in_addr_t newaddr, int indx, tnrh_tlb_t *tlbt);
static int walk_cache_table(in_addr_t newaddr, char *name,
    int indx, tnd_tnrhdb_t *src);
static tnrh_tlb_t *lookup_cache_table(in_addr_t addr);
static int update_cache_table(tsol_rhent_t *ent, tnd_tnrhdb_t *src);
static void update_rh_entry(int op, struct tsol_rhent *rhentp);
static int handle_unvisited_nodes();
static in_addr_t rh_index_to_mask(uint_t masklen);
static tnrh_tlb_ipv6_t *lookup_cache_table_v6(in6_addr_t addr);
static in6_addr_t *rh_index_to_mask_v6(uint_t masklen, in6_addr_t *bitmask);
static void load_rh_marked_v6();
static int
    rhtable_search_and_update_v6(struct tsol_rhent *ent, int duplflag);
static int walk_cache_table_v6(in6_addr_t newaddr, char *name,
    int indx, tnd_tnrhdb_t *src);
static int update_cache_table_v6(tsol_rhent_t *ent, tnd_tnrhdb_t *src);
static int handle_unvisited_nodes_v6();

#ifdef DEBUG
static void print_entry(tsol_rhent_t *ent, int af);
static void print_tlbt(tnrh_tlb_t *tlbt);
static void rhtable_print();
static void cachetable_print();
static void rhtable_walk(void (*action)());
static void cachetable_print_v6();
static void rhtable_print_v6();
static void rhtable_walk_v6(void (*action)());
#endif /* DEBUG */

/*
 * The following constants and structures and the functions
 * that operate on them are similar to the ip_ire.c and ip6_ire.c
 * code in the kernel.
 */
#define	TNRH_TABLE_HASH_SIZE 256
#define	IP_ABITS 32
#define	IP_MASK_TABLE_SIZE (IP_ABITS + 1)
#define	RH_HOST_MASK (in_addr_t)0xffffffffU

#define	IPV6_ABITS 128
#define	IPV6_MASK_TABLE_SIZE (IPV6_ABITS + 1)
#define	s6_addr8 _S6_un._S6_u8
#define	s6_addr32 _S6_un._S6_u32

/*
 * Exclusive-or the 6 bytes that are likely to contain the MAC
 * address. Assumes table_size does not exceed 256.
 * Assumes EUI-64 format for good hashing.
 */
#define	TNRH_ADDR_HASH_V6(addr)				\
	(((addr).s6_addr8[8] ^ (addr).s6_addr8[9] ^	\
	(addr).s6_addr8[10] ^ (addr).s6_addr8[13] ^	\
	(addr).s6_addr8[14] ^ (addr).s6_addr8[15]) % TNRH_TABLE_HASH_SIZE)

#define	TNRH_ADDR_MASK_HASH_V6(addr, mask)	\
	((((addr).s6_addr8[8] & (mask).s6_addr8[8]) ^	\
	((addr).s6_addr8[9] & (mask).s6_addr8[9]) ^	\
	((addr).s6_addr8[10] & (mask).s6_addr8[10]) ^	\
	((addr).s6_addr8[13] & (mask).s6_addr8[13]) ^	\
	((addr).s6_addr8[14] & (mask).s6_addr8[14]) ^	\
	((addr).s6_addr8[15] & (mask).s6_addr8[15])) % TNRH_TABLE_HASH_SIZE)

/* Mask comparison: is IPv6 addr a, and'ed with mask m, equal to addr b? */
#define	V6_MASK_EQ(a, m, b)	\
	((((a).s6_addr32[0] & (m).s6_addr32[0]) == (b).s6_addr32[0]) && \
	(((a).s6_addr32[1] & (m).s6_addr32[1]) == (b).s6_addr32[1]) &&  \
	(((a).s6_addr32[2] & (m).s6_addr32[2]) == (b).s6_addr32[2]) &&  \
	(((a).s6_addr32[3] & (m).s6_addr32[3]) == (b).s6_addr32[3]))


const in6_addr_t ipv6_all_zeros = { 0, 0, 0, 0 };

/*
 * This is a table of hash tables to keep
 * all the name service entries. We don't have
 * a separate hash bucket structure, instead mantain
 * a pointer to the hash chain.
 */
tnd_tnrhdb_t **tnrh_entire_table[IP_MASK_TABLE_SIZE];
tnd_tnrhdb_t **tnrh_entire_table_v6[IPV6_MASK_TABLE_SIZE];

/* reader/writer lock for tnrh_entire_table */
rwlock_t entire_rwlp;
rwlock_t entire_rwlp_v6;


/*
 * This is a hash table which keeps fully resolved
 * tnrhdb entries <IP address, Host type>. We don't have
 * a separate hash bucket structure, instead
 * mantain a pointer to the hash chain.
 */
tnrh_tlb_t *tnrh_cache_table[TNRH_TABLE_HASH_SIZE];
tnrh_tlb_ipv6_t *tnrh_cache_table_v6[TNRH_TABLE_HASH_SIZE];

/* reader/writer lock for tnrh_cache_table */
rwlock_t cache_rwlp;
rwlock_t cache_rwlp_v6;

FILE	 *logf;
int	 debugl = 0;
int	 poll_interval = TND_DEF_POLL_TIME;
int	 delay_poll_flag = 0;

void	*tp_tree;

#define	_SZ_TIME_BUF 100
char time_buf[_SZ_TIME_BUF];

#define	cprint(s, param) { \
		register FILE *consl; \
\
		if ((consl = fopen("/dev/msglog", "w")) != NULL) { \
		    setbuf(consl, NULL); \
		    (void) fprintf(consl, "tnd: "); \
		    (void) fprintf(consl, s, param); \
		    (void) fclose(consl); \
			} \
	    }

#define	RHENT_BUF_SIZE 300
#define	TPENT_BUF_SIZE 2000

/* 128 privs * (24 bytes + 1 deliminator)= 3200 bytes + 1200 cushion */
#define	STRING_PRIVS_SIZE 4800
#define	ID_ENT_SIZE 500

int
main(int argc, char **argv)
{


	const ucred_t	*uc = NULL;
	const priv_set_t	*pset;
	struct sigaction act;

	/* set the locale for only the messages system (all else is clean) */
	(void) setlocale(LC_ALL, "");
#ifndef TEXT_DOMAIN			/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (getzoneid() != GLOBAL_ZONEID) {
		syslog(LOG_ERR,	"can not run tnd from a local zone");
		exit(-1);
	}


	if (((uc = ucred_get(getpid())) == NULL) ||
	    ((pset = ucred_getprivset(uc, PRIV_EFFECTIVE)) == NULL)) {
		syslog(LOG_ERR,	"don't have privilege set");
		exit(-1);
	}

	if (!priv_ismember(pset, PRIV_SYS_NET_CONFIG)) {
		syslog(LOG_ERR,	"don't have privilege to run tnd");
		exit(-1);
	}


	/* parse command line options */
	(void) parse_opts(argc, argv);

	/*
	 * Initialize reader/writer locks. To be
	 * used within this process only.
	 */
	if ((rwlock_init(&entire_rwlp, USYNC_THREAD, 0) != 0) ||
	    (rwlock_init(&entire_rwlp_v6, USYNC_THREAD, 0) != 0) ||
	    (rwlock_init(&cache_rwlp, USYNC_THREAD, 0) != 0) ||
	    (rwlock_init(&cache_rwlp_v6, USYNC_THREAD, 0) != 0)) {
		syslog(LOG_ERR, "cannot initialize lock");
		exit(-1);
	}

	/* catch the usual termination signals for graceful exit */
	(void) sigset(SIGINT, terminate);
	(void) sigset(SIGTERM, terminate);
	(void) sigset(SIGQUIT, terminate);
	(void) sigset(SIGUSR1, noop);

	act.sa_handler = timer;
	act.sa_flags = SA_RESTART;
	(void *) sigemptyset(&act.sa_mask);
	(void *) sigaddset(&act.sa_mask, SIGALRM);
	(void *) sigaddset(&act.sa_mask, SIGHUP);
	(void *) sigaction(SIGALRM, &act, NULL);
	(void *) sigaction(SIGHUP, &act, NULL);

	if (debugl == MAX_TND_DEBUG) {
		(void) fprintf(logf, "%s : ", gettime());
		(void) fprintf(logf, gettext("tnd started. pid= %d\n"),
		    getpid());
		(void) fprintf(logf, "%s : ", gettime());
		(void) fprintf(logf,
		    gettext("max level debugging! not forking\n"));
		(void) fflush(logf);
	} else {
		detachfromtty();
	}

	if (!delay_poll_flag) {
		(void) sigprocmask(SIG_BLOCK, &act.sa_mask, NULL);
		timer();
		(void) sigprocmask(SIG_UNBLOCK, &act.sa_mask, NULL);
	}

	if (debugl != MAX_TND_DEBUG) {
		(void) sigsend(P_PID, getppid(), SIGUSR1);
	}

	(void) tnd_serve();

	/* NOT REACHED */
	return (0);
}


/*
 * Compare addresses after masking off unneeded bits.
 * We do this to handle addresses where prefix_len is
 * less than the bit length.
 */
static int
rhaddr_compar_mask(struct sockaddr_in *tp1, struct tnd_tnrhdb_c *tp2, int i)
{
	struct sockaddr_in *saddrp;
	in_addr_t tmpmask = rh_index_to_mask(i);

	saddrp = (struct sockaddr_in *)(&tp2->rh_ent.rh_address.ip_addr_v4);

#ifdef DEBUG
	(void) fprintf(logf, gettext("rhaddr_compar_mask mask = 0x%4x, \
	    tp1 = 0x%4x, tp2 = 0x%4x\n"), tmpmask, (tp1->sin_addr),
	    (saddrp->sin_addr.s_addr & tmpmask));
	(void) fprintf(logf, gettext("rhaddr_compar_mask return = %d\n"),
	    (tp1->sin_addr.s_addr == (saddrp->sin_addr.s_addr & tmpmask)));
#endif
	return (tp1->sin_addr.s_addr == (saddrp->sin_addr.s_addr & tmpmask));
}


/*
 * we use this where exact match is needed.
 */
static int
rhaddr_compar(struct sockaddr_in *tp1, struct tnd_tnrhdb_c *tp2)
{
	struct sockaddr_in *saddrp;

	saddrp = (struct sockaddr_in *)(&tp2->rh_ent.rh_address.ip_addr_v4);

#ifdef DEBUG
	(void) fprintf(logf, gettext("\t tp1 saddrp IP : %s %s\n"),
	    inet_ntoa(tp1->sin_addr), inet_ntoa(saddrp->sin_addr));
#endif

	return (tp1->sin_addr.s_addr == saddrp->sin_addr.s_addr);
}

/*
 * Compare v6 addresses after masking off unneeded bits.
 * We do this to handle addresses where prefix_len is
 * less than the bit length.
 */
static int
rhaddr_compar_mask_v6(struct sockaddr_in6 *tp1, struct tnd_tnrhdb_c *tp2, int i)
{
	struct sockaddr_in6 *saddrp;
	in6_addr_t tmpmask;

	(void) rh_index_to_mask_v6(i, &tmpmask);
	saddrp = (struct sockaddr_in6 *)(&tp2->rh_ent.rh_address.ip_addr_v6);
	return (V6_MASK_EQ(tp1->sin6_addr, tmpmask, saddrp->sin6_addr));
}

/*
 * we use this where v6 exact match is needed.
 */
static int
rhaddr_compar_v6(struct sockaddr_in6 *tp1, struct tnd_tnrhdb_c *tp2)
{
	struct sockaddr_in6 *saddrp;

	saddrp = (struct sockaddr_in6 *)(&tp2->rh_ent.rh_address.ip_addr_v6);
	return (IN6_ARE_ADDR_EQUAL(&tp1->sin6_addr, &saddrp->sin6_addr));
}

static int
get_hashvalue(in_addr_t addr)
{
	unsigned char *bp;

	bp = (unsigned char *) &addr;
	return ((bp[0] ^ bp[1] ^ bp[2] ^ bp[3]) % TNRH_TABLE_HASH_SIZE);
}

/*
 * Convert length for a mask to the mask.
 */
static in_addr_t
rh_index_to_mask(uint_t masklen)
{
	if (masklen == 0)
		return (0);
	return (htonl(RH_HOST_MASK << (IP_ABITS - masklen)));
}

/*
 * Convert length for a mask to the mask.
 * Returns the argument bitmask.
 */
static in6_addr_t *
rh_index_to_mask_v6(uint_t masklen, in6_addr_t *bitmask)
{
	uint32_t *ptr;

	*bitmask = ipv6_all_zeros;

	ptr = (uint32_t *)bitmask;
	while (masklen > 32) {
		*ptr++ = 0xffffffffU;
		masklen -= 32;
	}
	*ptr = htonl(0xffffffffU << (32 - masklen));
	return (bitmask);
}


static void
parse_opts(argc, argv)
	int argc;
	char **argv;
{
	char *logfile = TNDLOG;
	extern char *optarg;
	int c;

	while ((c = getopt(argc, argv, "d:f:p:n")) != EOF)
	    switch (c) {
	    case 'd':
		if (isnumber(optarg)) {
		    debugl = atoi(optarg);
		    if (check_debugl(debugl) == -1)
		    debugl = 1; /* default to 1 */
		} else {
		    usage();
		    exit(1);
		}
		break;
	    case 'f':
		logfile = optarg;
		break;
	    case 'p':
		if (isnumber(optarg)) {
		    poll_interval = atoi(optarg);
		    if (poll_interval == 0)
			usage();
		} else {
		    usage();
		}
		break;
	    case 'n':
		delay_poll_flag = 1;
		break;
	    case '?':
		usage();
	    }

	logf = tnlog_open(logfile);
}

static int
check_debugl(debug_level)
	int debug_level;
{
	if (debug_level > MAX_TND_DEBUG) {
	    if ((debugl > 0) && (logf != NULL)) {
		(void) fprintf(logf, "%s : ", gettime());
		(void) fprintf(logf,
		    gettext("invalid debug level: %d, not changed!\n"),
			debug_level);
		(void) fflush(logf);
	    }
	    cprint("invalid debug level: %d, not changed!\n",
		debug_level);
	    return (-1);
	}
	return (0);
}

static FILE *
tnlog_open(logfile)
	char *logfile;
{
	FILE *fp;

	if ((fp = fopen(logfile, "a")) == NULL) {
		syslog(LOG_ERR, "unable to open logfile %s",
			logfile);
		exit(-1);
	}
	(void) fprintf(fp, "%s : ", gettime());
	(void) fprintf(fp, gettext("tnd starting\n"));

	return (fp);
}

static void
detachfromtty()
{
	pid_t tnd_pid;

	(void) close(0);
	(void) close(1);
	(void) close(2);
	switch (tnd_pid = fork()) {
	case (pid_t)-1:
		if (debugl && (logf != NULL)) {
			(void) fprintf(logf, "%s : ", gettime());
			(void) fprintf(logf,
			    gettext("fork() failed: %s\n"), strerror(errno));
			(void) fflush(logf);
		}
		cprint("fork() failed: %s\n", strerror(errno));
		break;
	case 0:
		break;
	default:
		if (debugl && (logf != NULL)) {
			(void) fprintf(logf, "%s : ", gettime());
			(void) fprintf(logf,
			    gettext("tnd started. pid= %d\n"), tnd_pid);
			(void) fflush(logf);
		}
		/*
		 * Suspend parent till child signals it. We catch the signal
		 * in order to return correct exit value.
		 */

		(void) pause();
		exit(0);
	}
	(void) setsid();
	(void) open("/dev/null", O_RDWR, 0);
	(void) dup(0);
	(void) dup(0);
}

static void
usage()
{
	(void) fprintf(stderr, gettext(
	    "Usage:\n\ttnd [-d debug-level][-f debug-file]"
	    "[-p poll-interval]\n"));

	exit(1);
}

static int
isnumber(s)
char *s;
{
	register int c;

	/* LINTED */
	while (c = *s++)
		if (!isdigit(c))
			return (0);
	return (1);
}


/*
 * match any entry in any tree
 *	used in tree removal
 */
/* ARGSUSED */
static int
any_compar(const void *v1, const void *v2)
{
	return (0);
}

static int
tp_compar(const void *v1, const void *v2)
{
	struct tnd_tnrhtp_c	*tp1 = (struct tnd_tnrhtp_c *)v1;
	struct tnd_tnrhtp_c	*tp2 = (struct tnd_tnrhtp_c *)v2;
	return (strcmp(tp1->tp_ent.name, tp2->tp_ent.name));
}

/*
 * Build tree of tp entries, tossing duplicates
 */
static int
nss_get_tp()
{
	tsol_tpent_t tp; /* to store result */
	tsol_tpent_t *tpp;
	struct tnd_tnrhtp_c *new, **old;
	int count = 0;

	tpp = &tp;

	tsol_settpent(1);

	while ((tpp = (tsol_tpent_t *)tsol_gettpent()) != NULL) {
		if ((new = (struct tnd_tnrhtp_c *)
		    calloc(1, sizeof (struct tnd_tnrhtp_c))) == NULL)
			continue;
		(void) memcpy(&new->tp_ent, tpp, sizeof (tp));
		old = (struct tnd_tnrhtp_c **)tsearch(new, &tp_tree, tp_compar);
		if (*old != new)
			free(new);
		else
			count++;
	}
	tsol_endtpent();

	return (count);
}

/* load tp ents into kernel */
static void
load_tp()
{
	twalk(tp_tree, load_tp_entry);
}


static void
/* LINTED */
load_tp_entry(struct tnd_tnrhtp_c **tppp, VISIT visit, int level)
{
	struct tnd_tnrhtp_c *tpp;

	if (!(visit == postorder || visit == leaf))
		return;

	tpp = *tppp;
	if (tnrhtp(TNDB_LOAD, &tpp->tp_ent)) {
		if (debugl && (logf != NULL)) {
			(void) fprintf(logf, "%s : ", gettime());
			(void) fprintf(logf, gettext("tnrhtp() failed 0: %s\n"),
			    strerror(errno));
			(void) fprintf(logf,
			    gettext("load of remote-host template "
			    "%s into kernel cache failed\n"),
			    tpp->tp_ent.name);
			(void) fflush(logf);
		}
		cprint("tnrhtp() failed here 1: %s\n", strerror(errno));
	}
}

static void
tp_flush_cache()
{
	struct tnd_tnrhtp_c	dummy;
	struct tnd_tnrhtp_c	*tp;

	while (tp = tfind(&dummy, tp_tree, any_compar)) {
		(void) tdelete(tp, &tp_tree, tp_compar);
		free(tp);
	}
}

/*
 * Build/update the table of rh entries from the
 * name service sources, files, ldap etc.
 */
static int
nss_get_rh()
{
	int found_entry = 0;
	int count = 0;
	int newflag = 0;
	struct tsol_rhent rh; /* to store result */
	struct tsol_rhent *rhp;
	tsol_tpent_t tp;
	sa_family_t af;
	int v6cnt = 0;

	rhp = &rh;

	tsol_setrhent(1);
	while ((rhp = (struct tsol_rhent *)
	    tsol_getrhent()) != NULL) {
		/*
		 * Check if this is a known template name
		 * Entries with missing template in kernel will be logged
		 * and not added to cache.
		 */

		(void) fprintf(logf, gettext("getrhent template name: %s\n"),
		    rhp->rh_template);

		(void) strncpy(tp.name, rhp->rh_template, TNTNAMSIZ - 1);
		if (tnrhtp(TNDB_GET, &tp) != 0) {
			if (debugl && (logf != NULL))
				(void) fprintf(logf,
				    gettext("Unknown template name: %s\n"),
				    rhp->rh_template);
			cprint(gettext("Unknown template name: %s\n"),
			    rhp->rh_template);
			continue;
		}
		found_entry++;		/* found a valid tnrhdb entry */
		af = rhp->rh_address.ta_family;

		if (af == AF_INET) {
#ifdef DEBUG
			(void) fprintf(logf, gettext("nss_get_rh() v4\n"));
#endif
			(void) rw_wrlock(&entire_rwlp);
			(void) rw_wrlock(&cache_rwlp);

			/*
			 * Both cache table and entire table can be modified
			 * by this function. So, get both locks.
			 */
			newflag = rhtable_search_and_update(rhp, 1);

			(void) rw_unlock(&cache_rwlp);
			(void) rw_unlock(&entire_rwlp);
		} else if (af == AF_INET6) {
#ifdef DEBUG
			(void) fprintf(logf, gettext("nss_get_rh() v6\n"));
#endif
			v6cnt++;
			(void) rw_wrlock(&entire_rwlp_v6);
			(void) rw_wrlock(&cache_rwlp_v6);

			/*
			 * Both cache table and entire table can be modified
			 * by this function. So, get both locks.
			 */
			newflag = rhtable_search_and_update_v6(rhp, 1);

			(void) rw_unlock(&cache_rwlp_v6);
			(void) rw_unlock(&entire_rwlp_v6);
		}
		if (newflag)
			count++;
	}
	tsol_endrhent();

	/*
	 * If the first tsol_getrhent() failed, we bail out and
	 * try again at the next poll interval, just in case the
	 * name service was not reachable the first time.
	 */
	if (!found_entry) {
#ifdef	DEBUG
		if (logf != NULL)
			(void) fprintf(logf,
			    gettext("Unable to contact ldap server?\n"));
#endif
		return (count);
	}

	(void) rw_wrlock(&entire_rwlp);
	(void) rw_wrlock(&cache_rwlp);
	/*
	 * Handle deletions in the name service entries
	 * Both cache table and entire table can be modified
	 * by this function. So, get both locks.
	 */
	count += handle_unvisited_nodes();

	(void) rw_unlock(&cache_rwlp);
	(void) rw_unlock(&entire_rwlp);

	if (v6cnt > 0) {
		(void) rw_wrlock(&entire_rwlp_v6);
		(void) rw_wrlock(&cache_rwlp_v6);
		/*
		 * Handle deletions in the name service entries
		 * Both cache table and entire table can be modified
		 * by this function. So, get both locks.
		 */
		count += handle_unvisited_nodes_v6();

		(void) rw_unlock(&cache_rwlp_v6);
		(void) rw_unlock(&entire_rwlp_v6);
	}

	return (count);
}

/*
 * Check if any deletions in  the name service tables
 * affect the cache entries. We need to do this
 * in order to not flush the entrie kernel tnrhdb
 * cache every time we poll the name services.
 */
static int
handle_unvisited_nodes()
{
	int i, j, cnt = 0;
	tnrh_tlb_t *tlbt;
	tnd_tnrhdb_t *rhent, *prev;

	for (i = 0; i < TNRH_TABLE_HASH_SIZE; i++)
		if ((tlbt = tnrh_cache_table[i]) != NULL)
			do {
				if (tlbt->src->visited == 0) {
					/*
					 * Mark for deletion of both our cache
					 * entry and the kernel cache entry.
					 */
					tlbt->reload = TNDB_DELETE;
					cnt++;
				}

				tlbt = tlbt->next;
			} while (tlbt != NULL);

	/*
	 * Remove any unvisited nodes. This can
	 * happen if they are not in use by any cache entry. Then,
	 * mark all nodes in entire_table, un-visited, for next iteration.
	 */

	for (i = 0; i <= IP_ABITS; i++) {
		if (tnrh_entire_table[i] == NULL)
			continue;

		for (j = 0; j < TNRH_TABLE_HASH_SIZE; j++) {
			prev = rhent = tnrh_entire_table[i][j];

			while (rhent != NULL) {
				if (rhent->visited == 0) {
					/*
					 * Check if start node
					 */
					if (rhent == tnrh_entire_table[i][j]) {
						prev = tnrh_entire_table[i][j] =
						    rhent->rh_next;
					} else {
						/* bypass the deleted node */
						prev->rh_next = rhent->rh_next;
						prev = prev->rh_next;
					}

					free(rhent);

					if (prev == NULL)
						break;
					else {
						rhent = prev;
						continue;
					}
				} else
					rhent->visited = 0;

				prev = rhent;
				rhent = rhent->rh_next;
			}
		}
	}

	return (cnt);
}

/*
 * Check if any deletions in  the name service tables
 * affect the cache entries. We need to do this
 * in order to not flush the entrie kernel tnrhdb
 * cache every time we poll the name services.
 */
static int
handle_unvisited_nodes_v6()
{
	int i, j, cnt = 0;
	tnrh_tlb_ipv6_t *tlbt;
	tnd_tnrhdb_t *rhent, *prev;

	for (i = 0; i < TNRH_TABLE_HASH_SIZE; i++)
	if ((tlbt = tnrh_cache_table_v6[i]) != NULL)
	do {
		if (tlbt->src->visited == 0) {
			/*
			 * Mark for deletion of both our cache entry
			 * and the kernel cache entry.
			 */
			tlbt->reload = TNDB_DELETE;
			cnt++;
		}

		tlbt = tlbt->next;
	} while (tlbt != NULL);

	/*
	 * Remove any unvisited nodes. This can
	 * happen if they are not in use by any cache entry. Then,
	 * mark all nodes in entire_table, un-visited, for next iteration.
	 */

	for (i = 0; i <= IPV6_ABITS; i++) {
	if (tnrh_entire_table_v6[i] == NULL)
		continue;

	for (j = 0; j < TNRH_TABLE_HASH_SIZE; j++) {
		prev = rhent = tnrh_entire_table_v6[i][j];

		while (rhent != NULL) {
		if (rhent->visited == 0) {	/* delete the node */
			/* Check if start node */
			if (rhent == tnrh_entire_table_v6[i][j]) {
				prev = tnrh_entire_table_v6[i][j] =
				    rhent->rh_next;
			} else {
				/* bypass the deleted node */
				prev->rh_next = rhent->rh_next;
				prev = prev->rh_next;
			}

			free(rhent);
			if (prev == NULL)
				break;
			else {
				rhent = prev;
				continue;
			}
		} else
			rhent->visited = 0;

		prev = rhent;
		rhent = rhent->rh_next;
		}
	}
	}

	return (cnt);
}


/*
 * Search the hash chain for the address. If not found,
 * add the entry to the hash table. If necessary,
 * construct the hash table.
 * If the rh entry is in table, we may update its template name
 */
static int
rhtable_search_and_update(struct tsol_rhent *ent, int duplflag)
{
	struct sockaddr_in *saddrp;
	unsigned char hash;
	tnd_tnrhdb_t *rhent;
	int i;
	int rflag = 1;

	struct tnd_tnrhdb_c *new;

	saddrp = (struct sockaddr_in *)&ent->rh_address.ip_addr_v4;
	hash = (unsigned char) get_hashvalue(saddrp->sin_addr.s_addr);
	i = ent->rh_prefix;

#ifdef DEBUG
	(void) fprintf(logf, gettext("\trhtable_search_and_update IP address:\
		%s\n"), inet_ntoa(saddrp->sin_addr));
#endif

	if (tnrh_entire_table[i] == NULL) {
		if ((tnrh_entire_table[i] = (tnd_tnrhdb_t **)calloc(
		    TNRH_TABLE_HASH_SIZE, sizeof (tnd_tnrhdb_t *))) == NULL) {
			return (0);
		}
	}

	rhent = tnrh_entire_table[i][hash];
#ifdef DEBUG
	(void) fprintf(logf, gettext("\tsearch_and_update i = %d hash = %d\n"),
	    i, hash);
	if (rhent != NULL) {
		(void) fprintf(logf, gettext("\trhent visited  = %d\n"),
		    rhent->visited);
		print_entry(&rhent->rh_ent, AF_INET);
	} else {
		(void) fprintf(logf, gettext("\tsearch_and_update null\n"));
	}
#endif
	while (rhent != NULL) {
		if (rhaddr_compar(saddrp, rhent) == 1) {
			/* Check if this is a duplicate entry */
			if ((rhent->visited == 1) && duplflag)
				return (0);

			if (duplflag)
				rhent->visited = 1;

			if (strcmp(ent->rh_template,
			    rhent->rh_ent.rh_template) != 0) {
				/*
				 * Template is changed in the name service.
				 * Use the new template.
				 */
				(void) strcpy(rhent->rh_ent.rh_template,
				    ent->rh_template);
				/*
				 * Check if this modified entry
				 * affects the cache table.
				 */
				rflag = update_cache_table(ent, rhent);
				return (rflag);
			} else
				return (0);
		}
		rhent = rhent->rh_next;
	}

	/* Not found. Add the entry */
	new = (struct tnd_tnrhdb_c *)calloc(1,
	    sizeof (struct tnd_tnrhdb_c));
	if (new == NULL)
		return (0);
	(void) memcpy(&new->rh_ent, ent, sizeof (struct tsol_rhent));
	if (duplflag)
		new->visited = 1;	/* Mark all new nodes visited */

	/* linked list. Insert in the beginning */
	new->rh_next = tnrh_entire_table[i][hash];
	tnrh_entire_table[i][hash] = new;
#ifdef DEBUG
	(void) fprintf(logf, gettext("rhtable added i = %d, hash = %d\n"),
	    i, hash);
#endif

	/* Check if the new entry affects the cache table */
	rflag = update_cache_table(ent, new);

#ifdef DEBUG
	(void) fprintf(logf, gettext("search_and_update rflag=%d\n"), rflag);
#endif
	return (rflag);
}

/*
 * Search the hash chain for the address. If not found,
 * add the entry to the hash table. If necessary,
 * construct the hash table.
 */
static int
rhtable_search_and_update_v6(struct tsol_rhent *ent, int duplflag)
{
	struct sockaddr_in6 *saddrp;
	unsigned char hash;
	tnd_tnrhdb_t *rhent;
	int i;
	int rflag = 1;

	struct tnd_tnrhdb_c *new;
	in6_addr_t tmpmask6;

	saddrp = (struct sockaddr_in6 *)&ent->rh_address.ip_addr_v6;
	i = ent->rh_prefix;
	(void) rh_index_to_mask_v6(i, &tmpmask6);
	hash = (unsigned char) TNRH_ADDR_MASK_HASH_V6(saddrp->sin6_addr,
	    tmpmask6);

	if (tnrh_entire_table_v6[i] == NULL) {
		if ((tnrh_entire_table_v6[i] = (tnd_tnrhdb_t **)calloc(
		    TNRH_TABLE_HASH_SIZE, sizeof (tnd_tnrhdb_t *))) == NULL) {
			return (0);
		}
	}

	rhent = tnrh_entire_table_v6[i][hash];
	while (rhent != NULL) {
		if (rhaddr_compar_v6(saddrp, rhent) == 1) {
			/* Check if this is a duplicate entry */
			if ((rhent->visited == 1) && duplflag)
				return (0);

			if (duplflag)
				rhent->visited = 1;

			if (strcmp(ent->rh_template,
			    rhent->rh_ent.rh_template) != 0) {
				/*
				 * Template is changed in the name service.
				 * Use the new template.
				 */
				(void) strcpy(rhent->rh_ent.rh_template,
				    ent->rh_template);
				/*
				 * Check if this modified entry
				 * affects the cache table.
				 */
				rflag = update_cache_table_v6(ent, rhent);
				return (rflag);
			} else
				return (0);
		}
		rhent = rhent->rh_next;
	}

	/* Not found. Add the entry */
	new = (struct tnd_tnrhdb_c *)calloc(1, sizeof (struct tnd_tnrhdb_c));
	if (new == NULL)
		return (0);
	(void) memcpy(&new->rh_ent, ent, sizeof (struct tsol_rhent));
	if (duplflag)
		new->visited = 1;	/* Mark all new nodes visited */

	/* linked list. Insert in the beginning */
	new->rh_next = tnrh_entire_table_v6[i][hash];
	tnrh_entire_table_v6[i][hash] = new;

	/* Check if the new entry affects the cache table */
	rflag = update_cache_table_v6(ent, new);

	return (rflag);
}

/*
 * The array element i points to the hash table.
 * Search the hash chain for the address.
 */
static struct tnd_tnrhdb_c *
rhtable_lookup(struct sockaddr_in *saddrp, int i)
{
	unsigned char hash;
	tnd_tnrhdb_t *rhent;

	if (tnrh_entire_table[i] == NULL)
		return (NULL);

	hash = (unsigned char) get_hashvalue(saddrp->sin_addr.s_addr);
	rhent = tnrh_entire_table[i][hash];

#ifdef DEBUG
	(void) fprintf(logf, gettext("rhtable_lookup i = %d, hash = %d\n"),
	    i, hash);
#endif

	while (rhent != NULL) {
#ifdef DEBUG
	struct sockaddr_in *saddrp2;
	saddrp2 = (struct sockaddr_in *)(&rhent->rh_ent.rh_address.ip_addr_v4);
	(void) fprintf(logf, gettext("rhtable_lookup addr = %s, tmpl = %s\n"),
	    inet_ntoa(saddrp2->sin_addr), rhent->rh_ent.rh_template);
#endif
		if (rhaddr_compar_mask(saddrp, rhent, i) == 1)
			return (rhent);
		rhent = rhent->rh_next;
	}

#ifdef DEBUG
	(void) fprintf(logf, gettext("\trhtable_lookup failed\n"));
#endif

	/* Not found */
	return (NULL);
}

/*
 * The array element i points to the hash table.
 * Search the hash chain for the address.
 */
static struct tnd_tnrhdb_c *
rhtable_lookup_v6(struct sockaddr_in6 *saddrp, in6_addr_t mask, int i)
{
	unsigned char hash;
	tnd_tnrhdb_t *rhent;

	if (tnrh_entire_table_v6[i] == NULL)
		return (NULL);

	hash = (unsigned char) TNRH_ADDR_MASK_HASH_V6(saddrp->sin6_addr, mask);
	rhent = tnrh_entire_table_v6[i][hash];

	while (rhent != NULL) {
		if (rhaddr_compar_mask_v6(saddrp, rhent, i) == 1)
			return (rhent);
		rhent = rhent->rh_next;
	}

	/* Not found */
	return (NULL);
}

void
add_cache_entry(in_addr_t addr, char *name, int indx,
    tnd_tnrhdb_t *src)
{
	unsigned char hash;
	tnrh_tlb_t *tlbt;

	hash = (unsigned char) get_hashvalue(addr);

	/* Look if some other thread already added this entry */
	if (lookup_cache_table(addr) != NULL)
		return;
#ifdef DEBUG
	(void) fprintf(logf, gettext("\tenter add_cache_entry\n"));
#endif
	if ((tlbt = (tnrh_tlb_t *)calloc(1, sizeof (tnrh_tlb_t))) == NULL)
		return;
	tlbt->addr = addr;
	(void) strncpy(tlbt->template_name, name, TNTNAMSIZ-1);
	tlbt->masklen_used = indx;
	tlbt->reload = TNDB_LOAD;
	tlbt->src = src;

#ifdef DEBUG
	(void) fprintf(logf, gettext("adding cache entry\n"));
	print_tlbt(tlbt);
#endif
	/* Add to the chain */
	if (tnrh_cache_table[hash] == NULL) {
		tnrh_cache_table[hash] = tlbt;
	} else {
		/* Add in the beginning */
		tlbt->next = tnrh_cache_table[hash];
		tnrh_cache_table[hash] = tlbt;
	}
}

static tnrh_tlb_t *
lookup_cache_table(in_addr_t addr)
{
	tnrh_tlb_t *tlbt = NULL;
	unsigned char hash;

	hash = (unsigned char) get_hashvalue(addr);
	tlbt = tnrh_cache_table[hash];
	while (tlbt != NULL) {
		if (addr == tlbt->addr)
			break;
		tlbt = tlbt->next;
	}
	return (tlbt);
}

static void
add_cache_entry_v6(in6_addr_t addr, char *name, int indx,
				tnd_tnrhdb_t *src)
{
	unsigned char hash;
	tnrh_tlb_ipv6_t *tlbt;

	hash = (unsigned char) TNRH_ADDR_HASH_V6(addr);

	/* Look if some other thread already added this entry */
	if (lookup_cache_table_v6(addr) != NULL)
		return;

	if ((tlbt = (tnrh_tlb_ipv6_t *)calloc(1,
	    sizeof (tnrh_tlb_ipv6_t))) == NULL)
		return;
	(void) memcpy(&tlbt->addr, &addr, sizeof (in6_addr_t));
	(void) strncpy(tlbt->template_name, name, TNTNAMSIZ-1);
	tlbt->masklen_used = indx;
	tlbt->reload = TNDB_LOAD;
	tlbt->src = src;

	/* Add to the chain */
	if (tnrh_cache_table_v6[hash] == NULL) {
		tnrh_cache_table_v6[hash] = tlbt;
	} else {
		/* Add in the beginning */
		tlbt->next = tnrh_cache_table_v6[hash];
		tnrh_cache_table_v6[hash] = tlbt;
	}
}

static tnrh_tlb_ipv6_t *
lookup_cache_table_v6(in6_addr_t addr)
{
	tnrh_tlb_ipv6_t *tlbt = NULL;
	unsigned char hash;

	hash = (unsigned char) TNRH_ADDR_HASH_V6(addr);
	tlbt = tnrh_cache_table_v6[hash];
	while (tlbt != NULL) {
		if (IN6_ARE_ADDR_EQUAL(&addr, &tlbt->addr))
			break;
		tlbt = tlbt->next;
	}
	return (tlbt);
}


/*
 * Walk the cache table and check if this IP address/address prefix
 * will be a better match for an existing entry in the cache.
 * will add cache if not already exists
 */
static int
update_cache_table(tsol_rhent_t *ent, tnd_tnrhdb_t *src)
{
	int i;
	char result[TNTNAMSIZ];
	in_addr_t tmpmask;
	in_addr_t addr;
	struct sockaddr_in *saddrp;
	tnrh_tlb_t *tlbt;
	struct tnd_tnrhdb_c	*rhp;
	int rflag = 0;

	saddrp = (struct sockaddr_in *)&ent->rh_address.ip_addr_v4;
	addr = saddrp->sin_addr.s_addr;

	(void) rw_rdlock(&cache_rwlp);
	tlbt = lookup_cache_table(addr);
	(void) rw_unlock(&cache_rwlp);

	if (tlbt == NULL) {
		(void) rw_rdlock(&entire_rwlp);
		for (i = (IP_MASK_TABLE_SIZE - 1); i >= 0; i--) {
#ifdef DEBUG
			(void) fprintf(logf, "update_cache_table i = %d\n", i);
#endif
			if (tnrh_entire_table[i] == NULL)
				continue;

			tmpmask = rh_index_to_mask(i);
			saddrp->sin_addr.s_addr &= tmpmask;
#ifdef DEBUG
			(void) fprintf(logf,
			    "update_cache_table found i = %d\n", i);
			(void) fprintf(logf, "\ti = %d, tmpmask = 0x%4x\n",
			    i, tmpmask);
#endif
			rhp = (struct tnd_tnrhdb_c *)rhtable_lookup(saddrp, i);
			if (rhp != NULL) {
				(void) strcpy(result, rhp->rh_ent.rh_template);
				/* Add this result to the cache also */
				(void) rw_wrlock(&cache_rwlp);
				add_cache_entry(addr, result, i, rhp);
				rflag++;
				(void) rw_unlock(&cache_rwlp);
				break;
			} else {
#ifdef DEBUG
				(void) fprintf(logf,
				    "rhtable_lookup return null !!");
#endif
			}
		}
		(void) rw_unlock(&entire_rwlp);
	}

	rflag += walk_cache_table(addr, ent->rh_template, ent->rh_prefix, src);
	return (rflag);
}

/*
 * Walk the cache table and check if this IP address/address prefix
 * will be a better match for an existing entry in the cache.
 */
static int
update_cache_table_v6(tsol_rhent_t *ent, tnd_tnrhdb_t *src)
{
	int i;
	char result[TNTNAMSIZ];
	in6_addr_t addr;
	struct sockaddr_in6 *saddrp;
	tnrh_tlb_ipv6_t *tlbt;
	struct tnd_tnrhdb_c	*rhp;
	in6_addr_t tmpmask6;
	int rflag = 0;

	saddrp = (struct sockaddr_in6 *)&ent->rh_address.ip_addr_v6;
	(void) memcpy(&addr, &saddrp->sin6_addr, sizeof (in6_addr_t));

	/* Look in the cache first */
	(void) rw_rdlock(&cache_rwlp);
	tlbt = lookup_cache_table_v6(addr);
	(void) rw_unlock(&cache_rwlp);


	if (tlbt == NULL) {
		(void) rw_rdlock(&entire_rwlp_v6);
		for (i = (IPV6_MASK_TABLE_SIZE - 1); i >= 0; i--) {
			if (tnrh_entire_table_v6[i] == NULL)
				continue;
			(void) rh_index_to_mask_v6(i, &tmpmask6);
			rhp = (struct tnd_tnrhdb_c *)
			    rhtable_lookup_v6(saddrp, tmpmask6, i);
			if (rhp != NULL) {
				(void) strcpy(result, rhp->rh_ent.rh_template);
				/* Add this result to the cache also */
				(void) rw_wrlock(&cache_rwlp_v6);
				add_cache_entry_v6(addr, result, i, rhp);
				rflag++;
				(void) rw_unlock(&cache_rwlp_v6);
				break;
			}
		}
		(void) rw_unlock(&entire_rwlp_v6);
	}

	rflag += walk_cache_table_v6(addr, ent->rh_template,
	    ent->rh_prefix, src);
	return (rflag);
}


/*
 * Check if this prefix addr will be a better match
 * for an existing entry.
 */
static int
is_better_match(in_addr_t newaddr, int indx, tnrh_tlb_t *tlbt)
{
	if (tlbt->masklen_used <= indx) {
		in_addr_t tmpmask = rh_index_to_mask(indx);

		if ((newaddr) == (tlbt->addr & tmpmask))
			return (1);
	}

	return (0);
}

/*
 * Walk the cache table and update entries if needed.
 * Mark entries for reload to kernel, if somehow their
 * template changed.
 * why is_better_match() is called???
 */
static int
walk_cache_table(in_addr_t newaddr, char *name, int indx, tnd_tnrhdb_t *src)
{
	int i;
	tnrh_tlb_t *tlbt;
	int rflag = 0;

	for (i = 0; i < TNRH_TABLE_HASH_SIZE; i++) {
		tlbt = tnrh_cache_table[i];

		while (tlbt != NULL) {
			if (is_better_match(newaddr, indx, tlbt)) {
				tlbt->masklen_used = indx;
				tlbt->src = src;
				/*
				 * Reload to the kernel only if the
				 * host type changed. There is no need
				 * to load, if only the mask used has changed,
				 * since the kernel does not need that
				 * information.
				 */
				if (strcmp(name, tlbt->template_name) != 0) {
					(void) strncpy(tlbt->template_name,
					    name, TNTNAMSIZ-1);
					tlbt->reload = TNDB_LOAD;
					rflag ++;
				}
			}

			tlbt = tlbt->next;
		}
	}
#ifdef DEBUG
	(void) fprintf(logf, gettext("walk_cache_table rflag=%d\n"), rflag);
#endif
	return (rflag);
}

/*
 * Check if this prefix addr will be a better match
 * for an existing entry.
 */
static int
is_better_match_v6(in6_addr_t newaddr, int indx, tnrh_tlb_ipv6_t *tlbt)
{
	in6_addr_t tmpmask;

	if (tlbt->masklen_used <= indx) {
		(void) rh_index_to_mask_v6(indx, &tmpmask);

		if (V6_MASK_EQ(newaddr, tmpmask, tlbt->addr))
			return (1);
	}

	return (0);
}


/*
 * Walk the cache table and update entries if needed.
 * Mark entries for reload to kernel, if somehow their
 * template changed.
 */
static int
walk_cache_table_v6(in6_addr_t newaddr, char *name, int indx, tnd_tnrhdb_t *src)
{
	int i;
	tnrh_tlb_ipv6_t *tlbt;
	int rflag = 0;

	for (i = 0; i < TNRH_TABLE_HASH_SIZE; i++) {
		tlbt = tnrh_cache_table_v6[i];

		while (tlbt != NULL) {
			if (is_better_match_v6(newaddr, indx, tlbt)) {
				tlbt->masklen_used = indx;
				tlbt->src = src;
				/*
				 * Reload to the kernel only if the
				 * host type changed. There is no need
				 * to load, if only the mask used has changed,
				 * since the kernel does not need that
				 * information.
				 */
				if (strcmp(name, tlbt->template_name) != 0) {
					(void) strncpy(tlbt->template_name,
					    name, TNTNAMSIZ-1);
					tlbt->reload = TNDB_LOAD;
					rflag ++;
				}
			}

			tlbt = tlbt->next;
		}
	}

	return (rflag);
}

/*
 * load/delete marked rh ents into kernel
 * depending on the reload flag by invoking tnrh().
 * It will mark other entries as TNDB_NOOP
 */
static void
load_rh_marked()
{
	int i;
	tnrh_tlb_t *tlbt, *prev;
	struct tsol_rhent rhentp;

	(void) memset((char *)&rhentp, '\0', sizeof (rhentp));

	for (i = 0; i < TNRH_TABLE_HASH_SIZE; i++) {

		prev = tlbt = tnrh_cache_table[i];

		while (tlbt != NULL) {
			if ((tlbt->reload == TNDB_LOAD) ||
			    (tlbt->reload == TNDB_DELETE)) {
			/*
			 * We have to call tnrh() with tsol_rhent argument.
			 * Construct such a struct from the tlbt struct we have.
			 */
				rhentp.rh_address.ip_addr_v4.sin_addr.s_addr =
				    tlbt->addr;
				rhentp.rh_address.ip_addr_v4.sin_family =
				    AF_INET;
				rhentp.rh_prefix = tlbt->masklen_used;
				(void) strcpy(rhentp.rh_template,
				    tlbt->template_name);

#ifdef DEBUG
				(void) fprintf(logf, "load op =%d\n",
				    tlbt->reload);
				print_tlbt(tlbt);
#endif
				update_rh_entry(tlbt->reload, &rhentp);

				if (tlbt->reload == TNDB_DELETE) {
					if (tlbt == tnrh_cache_table[i]) {
						tnrh_cache_table[i] =
						    tlbt->next;
						prev = tnrh_cache_table[i];
					} else {
						prev->next = tlbt->next;
						prev = prev->next;
					}

					free(tlbt);
					if (prev == NULL)
						break;
					else {
						tlbt = prev;
						continue;
					}
				}
				tlbt->reload = TNDB_NOOP;
			}

			prev = tlbt;
			tlbt = tlbt->next;
		}
	}

}

/* load marked rh ents into kernel */
static void
load_rh_marked_v6()
{
	int i;
	tnrh_tlb_ipv6_t *tlbt, *prev;
	struct tsol_rhent rhentp;

	(void) memset((char *)&rhentp, '\0', sizeof (rhentp));

	for (i = 0; i < TNRH_TABLE_HASH_SIZE; i++) {
		prev = tlbt = tnrh_cache_table_v6[i];

		while (tlbt != NULL) {
		if ((tlbt->reload == TNDB_LOAD) ||
		    (tlbt->reload == TNDB_DELETE)) {
			/*
			 * We have to call tnrh() with tsol_rhent argument.
			 * Construct such a struct from the tlbt struct we have.
			 */
			(void) memcpy(&rhentp.rh_address.ip_addr_v6.sin6_addr,
			    &tlbt->addr, sizeof (in6_addr_t));
			rhentp.rh_address.ip_addr_v6.sin6_family = AF_INET6;
			rhentp.rh_prefix = tlbt->masklen_used;
			(void) strcpy(rhentp.rh_template, tlbt->template_name);

			update_rh_entry(tlbt->reload, &rhentp);

			if (tlbt->reload == TNDB_DELETE) {
				if (tlbt == tnrh_cache_table_v6[i]) {
					tnrh_cache_table_v6[i] =
					    tlbt->next;
					prev = tnrh_cache_table_v6[i];
				} else {
					prev->next = tlbt->next;
					prev = prev->next;
				}

				free(tlbt);
				if (prev == NULL)
					break;
				else {
					tlbt = prev;
					continue;
				}
			}
			tlbt->reload = TNDB_NOOP;
		}

		prev = tlbt;
		tlbt = tlbt->next;
	}
	}

}

/*
 * Does the real load/delete for the entry depending on op code.
 */

static void
update_rh_entry(int op, struct tsol_rhent *rhentp)
{
#ifdef DEBUG
	(void) fprintf(logf, gettext("\t###update_rh_entry op = %d\n"), op);
	print_entry(rhentp, AF_INET);
#endif
	if (tnrh(op, rhentp) != 0) {
		if (debugl && (logf != NULL)) {
			(void) fprintf(logf, "%s : ", gettime());
			(void) fprintf(logf, gettext("tnrh() failed: %s\n"),
			    strerror(errno));
			if (op == TNDB_LOAD)
			(void) fprintf(logf,
			    gettext("load of remote host database "
			    "%s into kernel cache failed\n"),
			    rhentp->rh_template);
			if (op == TNDB_DELETE)
			(void) fprintf(logf,
			    gettext("delete of remote host database "
			    "%s from kernel cache failed\n"),
			    rhentp->rh_template);
			(void) fflush(logf);
		}
		cprint("tnrh() failed..: %s\n", strerror(errno));
	}
}

static void
timer()
{
	poll_now();
	(void) alarm(poll_interval);
}

#define	max(a, b)	((a) > (b) ? (a) : (b))

static void
poll_now()
{

	(void) fprintf(logf, "enter poll_now at %s \n", gettime());
	(void) fflush(logf);

	if (nss_get_tp() > 0) {
		load_tp();
		tp_flush_cache();
	}

#ifdef DEBUG
	(void) fprintf(logf, "now search for tnrhdb update %s \n", gettime());
#endif

	if (nss_get_rh() > 0) {
		if (logf != NULL) {
			(void) fprintf(logf, "tnrhdb needs update %s \n",
			    gettime());
		}

		(void) rw_wrlock(&cache_rwlp);
		/* This function will cleanup cache table */
		load_rh_marked();
		(void) rw_unlock(&cache_rwlp);

		(void) rw_wrlock(&cache_rwlp_v6);
		/* This function will cleanup cache table */
		load_rh_marked_v6();
		(void) rw_unlock(&cache_rwlp_v6);
	}

#ifdef DEBUG
	if (logf != NULL) {
		cachetable_print();
		cachetable_print_v6();

		(void) fprintf(logf, "rh table begin\n");
		rhtable_print();
		rhtable_print_v6();
		(void) fprintf(logf, "rh table end \n");
		(void) fprintf(logf, "-------------------------\n\n");
		(void) fflush(logf);
	}
#endif
}

static void
tnd_serve()
{
	for (;;) {
		(void) pause();
	}
}

static void
terminate()
{
	if (debugl && (logf != NULL)) {
		(void) fprintf(logf, "%s : ", gettime());
		(void) fprintf(logf, gettext("tnd terminating on signal.\n"));
		(void) fflush(logf);
	}
	exit(1);
}

static void
noop()
{
}

static char *
gettime()
{
	time_t now;
	struct tm *tp, tm;
	char *fmt;

	(void) time(&now);
	tp = localtime(&now);
	(void) memcpy(&tm, tp, sizeof (struct tm));
	fmt = nl_langinfo(_DATE_FMT);

	(void) strftime(time_buf, _SZ_TIME_BUF, fmt, &tm);

	return (time_buf);
}
/*
 * debugging routines
 */


#ifdef DEBUG
static void
print_cache_entry(tnrh_tlb_t *tlbt)
{
	struct in_addr addr;

	addr.s_addr = tlbt->addr;
	(void) fprintf(logf, "\tIP address: %s", inet_ntoa(addr));
	(void) fprintf(logf, "\tTemplate name: %s", tlbt->template_name);
	(void) fprintf(logf, "\tMask length used: %d\n", tlbt->masklen_used);
}

static void
print_cache_entry_v6(tnrh_tlb_ipv6_t *tlbt)
{
	char abuf[INET6_ADDRSTRLEN];

	(void) fprintf(logf, "\tIP address: %s",
	    inet_ntop(AF_INET6, &tlbt->addr, abuf, sizeof (abuf)));
	(void) fprintf(logf, "\tTemplate name: %s", tlbt->template_name);
	(void) fprintf(logf, "\tMask length used: %d\n", tlbt->masklen_used);
}

static void
cachetable_print()
{
	int i;
	tnrh_tlb_t *tlbt;

	(void) fprintf(logf, "-------------------------\n");
	(void) fprintf(logf, "Cache table begin\n");

	for (i = 0; i < TNRH_TABLE_HASH_SIZE; i++) {
		if ((tlbt = tnrh_cache_table[i]) != NULL)
			print_cache_entry(tlbt);
	}

	(void) fprintf(logf, "Cache table end \n");
	(void) fprintf(logf, "-------------------------\n\n");
}

static void
cachetable_print_v6()
{
	int i;
	tnrh_tlb_ipv6_t *tlbt;

	(void) fprintf(logf, "-------------------------\n");
	(void) fprintf(logf, "Cache table begin\n");

	for (i = 0; i < TNRH_TABLE_HASH_SIZE; i++) {
		if ((tlbt = tnrh_cache_table_v6[i]) != NULL)
			print_cache_entry_v6(tlbt);
	}

	(void) fprintf(logf, "Cache table end \n");
	(void) fprintf(logf, "-------------------------\n\n");
}


static void
print_entry(tsol_rhent_t *ent, int af)
{
	struct sockaddr_in *saddrp;
	struct sockaddr_in6 *saddrp6;
	char abuf[INET6_ADDRSTRLEN];

	if (af == AF_INET) {
		saddrp = (struct sockaddr_in *)&ent->rh_address.ip_addr_v4;
		(void) fprintf(logf, gettext("\tIP address: %s"),
		    inet_ntoa(saddrp->sin_addr));
	} else if (af == AF_INET6) {
		saddrp6 = (struct sockaddr_in6 *)&ent->rh_address.ip_addr_v6;
		(void) fprintf(logf, gettext("\tIP address: %s"),
		    inet_ntop(AF_INET6, &saddrp6->sin6_addr, abuf,
		    sizeof (abuf)));
	}

	(void) fprintf(logf,
	    gettext("\tTemplate name: %s"), ent->rh_template);
	(void) fprintf(logf, gettext("\tprefix_len: %d\n"), ent->rh_prefix);
	(void) fflush(logf);
}

static void
print_tlbt(tnrh_tlb_t *tlbt)
{
	(void) fprintf(logf, "tlbt addr = 0x%4x name = %s \
	    mask = %u, reload = %d\n", tlbt->addr, tlbt->template_name,
	    tlbt->masklen_used, tlbt->reload);
}

static void
rhtable_print()
{
	rhtable_walk(print_entry);
	(void) fprintf(logf, "-----------------------------\n\n");
}

static void
rhtable_print_v6()
{
	rhtable_walk_v6(print_entry);
	(void) fprintf(logf, "-----------------------------\n\n");
}

/*
 * Walk through all the entries in tnrh_entire_table[][]
 * and execute the function passing the entry as argument.
 */
static void
rhtable_walk(void (*action)())
{
	int i, j;
	tnd_tnrhdb_t *rhent;

	for (i = 0; i <= IP_ABITS; i++) {
		if (tnrh_entire_table[i] == NULL)
			continue;

		for (j = 0; j < TNRH_TABLE_HASH_SIZE; j++) {
			rhent = tnrh_entire_table[i][j];

			while (rhent != NULL) {
				action(&rhent->rh_ent, AF_INET);
				rhent = rhent->rh_next;
			}
		}
	}
}

/*
 * Walk through all the entries in tnrh_entire_table_v6[][]
 * and execute the function passing the entry as argument.
 */
static void
rhtable_walk_v6(void (*action)())
{
	int i, j;
	tnd_tnrhdb_t *rhent;

	for (i = 0; i <= IPV6_ABITS; i++) {
		if (tnrh_entire_table_v6[i] == NULL)
			continue;

		for (j = 0; j < TNRH_TABLE_HASH_SIZE; j++) {
			rhent = tnrh_entire_table_v6[i][j];

			while (rhent != NULL) {
				action(&rhent->rh_ent, AF_INET6);
				rhent = rhent->rh_next;
			}
		}
	}
}
#endif /* DEBUG */
