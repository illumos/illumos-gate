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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <rpc/rpc.h>
#include <netdir.h>
#include <rpcsvc/rstat.h>
#include <rpc/pmap_clnt.h>


#define	MACHINELEN	15	/* length of machine name printed out */
#define	MACHINELENMAX	128	/* maximum machine name length */
#define	AVENSIZE	(3 * sizeof (long))
#define	SLOTS	256

int machinecmp();
int loadcmp();
int uptimecmp();
static int collectnames();
int singlehost();		/* returns 1 if rup of given host fails */
void printsinglehosts();
void printnames();
static void putline();
int netbufeq(struct netbuf *ap, struct netbuf *bp);
void usage(void);

struct entry {
	struct netconfig *nconf;
	struct netbuf *addr;
	char *machine;
	struct timeval boottime;
	time_t curtime;
	long avenrun[3];
};

int total_entries;
int curentry;
struct entry *entry;
int vers;			/* which version did the broadcasting */
int lflag;			/* load: sort by load average */
int tflag;			/* time: sort by uptime average */
int hflag;			/* host: sort by machine name */
int dflag;			/* debug: list only first n machines */
int debug;

int
main(int argc, char *argv[])
{
	statsvar sv;
	statstime st;
	int single, nfailed;

	/*
	 * set number of slots to be 256 to begin with,
	 * this is large enough for most subnets but not all
	 */

	curentry = 0;
	total_entries = SLOTS;
	entry = malloc(sizeof (struct entry) * total_entries);
	single = nfailed = 0;
	while (argc > 1) {
		if (argv[1][0] != '-') {
			single++;
			nfailed += singlehost(argv[1]);
		} else {
			switch (argv[1][1]) {

			case 'l':
				lflag++;
				break;
			case 't':
				tflag++;
				break;
			case 'h':
				hflag++;
				break;
			case 'd':
				dflag++;
				if (argc < 3)
					usage();
				debug = atoi(argv[2]);
				argc--;
				argv++;
				break;
			default:
				usage();
			}
		}
		argv++;
		argc--;
	}
	if (single > 0) {
		if (hflag || tflag || lflag)
			printsinglehosts();
		if (nfailed == single) {
			free(entry);
			exit(1);	/* all hosts we tried failed */
		} else {
			free(entry);
			exit(0);
		}

	}
	if (hflag || tflag || lflag) {
		printf("collecting responses... ");
		fflush(stdout);
	}

	sv.cp_time.cp_time_val = (int *)NULL;
	sv.dk_xfer.dk_xfer_val = (int *)NULL;

	/*
	 * Null out pointers in the statsvar struct
	 * so that we don't follow a random pointer
	 * somewhere when we get our results back.
	 * Set lengths to zero so we don't allocate
	 * some random amount of space we don't need
	 * (in the case where the reply was program
	 *  not registered).
	 */
	sv.cp_time.cp_time_len = 0;
	sv.cp_time.cp_time_val = (int *)NULL;
	sv.dk_xfer.dk_xfer_len = 0;
	sv.dk_xfer.dk_xfer_val = (int *)NULL;

	vers = RSTATVERS_VAR;
	(void) rpc_broadcast(RSTATPROG, RSTATVERS_VAR, RSTATPROC_STATS,
			xdr_void, NULL, xdr_statsvar, (caddr_t)&sv,
			(resultproc_t)collectnames, (char *)0);
	vers = RSTATVERS_TIME;
	(void) rpc_broadcast(RSTATPROG, RSTATVERS_TIME, RSTATPROC_STATS,
			xdr_void, NULL, xdr_statstime, (caddr_t)&st,
			(resultproc_t)collectnames, (char *)0);
	if (hflag || tflag || lflag)
		printnames();



	free(entry);
	return (0);
}

int
singlehost(host)
	char *host;
{
	static int debugcnt;
	enum clnt_stat err;
	statstime st;
	statsvar sw_var;
	bool_t is_var_vers = FALSE;


	if (curentry >= total_entries) {
		struct entry *tmp;

		total_entries += SLOTS;
		tmp = realloc((struct entry *)entry, sizeof (struct entry)
						* total_entries);
		if (tmp == NULL) {
			return (1);
		}
		entry = tmp;
	}

	sw_var.cp_time.cp_time_val = (int *)NULL;
	sw_var.dk_xfer.dk_xfer_val = (int *)NULL;
	err = (enum clnt_stat)callrpc(host, RSTATPROG, RSTATVERS_VAR,
			RSTATPROC_STATS, xdr_void, 0, xdr_statsvar, &sw_var);
	if (err == RPC_SUCCESS) {
		is_var_vers = TRUE;
	} else if (err == RPC_PROGVERSMISMATCH) {
		err = (enum clnt_stat)callrpc(host, RSTATPROG, RSTATVERS_TIME,
			RSTATPROC_STATS, xdr_void, 0, xdr_statstime, &st);
		if (err != RPC_SUCCESS)
			goto error;
	} else
		goto error;

	debugcnt++;
	if (!hflag && !lflag && !tflag) {
		printf("%*.*s  ", MACHINELEN, MACHINELEN, host);
		if (is_var_vers == TRUE)
			putline(sw_var.curtime.tv_sec, sw_var.boottime,
				sw_var.avenrun);
		else
			putline(st.curtime.tv_sec, st.boottime, st.avenrun);
		return (0);		/* success */
	} else {
		entry[curentry].machine = host;
		if (is_var_vers == FALSE) { /* RSTATVERS_TIME */
			entry[curentry].boottime.tv_sec = st.boottime.tv_sec;
			entry[curentry].boottime.tv_usec =
				st.boottime.tv_usec;
			entry[curentry].curtime = st.curtime.tv_sec;
			memcpy(entry[curentry].avenrun, st.avenrun, AVENSIZE);
		} else { /* RSTATVERS_VAR */
			entry[curentry].boottime.tv_sec =
				sw_var.boottime.tv_sec;
			entry[curentry].boottime.tv_usec =
				sw_var.boottime.tv_usec;
			entry[curentry].curtime = sw_var.curtime.tv_sec;
			memcpy(entry[curentry].avenrun, sw_var.avenrun,
							AVENSIZE);
		}
	}
	curentry++;
	if (dflag && debugcnt >= debug)
		return (1);
	return (0);

error:
	fprintf(stderr, "%*.*s: ", MACHINELEN, MACHINELEN, host);
	clnt_perrno(err);
	/*
	 * clnt_perrno now prints a newline
	 */
	/* fprintf(stderr, "\n"); */
	return (1);		/* a failure */
}

static void
putline(now, boottime, avenrun)
	time_t now;
	struct timeval boottime;
	long avenrun[];
{
	int uptime, days, hrs, mins, i;

	uptime = now - boottime.tv_sec;
	uptime += 30;
	if (uptime < 0)		/* unsynchronized clocks */
		uptime = 0;
	days = uptime / (60*60*24);
	uptime %= (60*60*24);
	hrs = uptime / (60*60);
	uptime %= (60*60);
	mins = uptime / 60;

	printf("  up");
	if (days > 0)
		printf(" %2d day%s", days, days > 1 ? "s," : ", ");
	else
		printf("         ");
	if (hrs > 0)
		printf(" %2d:%02d,  ", hrs, mins);
	else
		printf(" %2d min%s", mins, mins > 1 ? "s," : ", ");

	/*
	 * Print 1, 5, and 15 minute load averages.
	 * (Found by looking in kernel for avenrun).
	 */
	printf("  load average:");
	for (i = 0; i < (AVENSIZE / sizeof (avenrun[0])); i++) {
		if (i > 0)
			printf(",");
		printf(" %.2f", (double)avenrun[i]/FSCALE);
	}
	printf("\n");
}

static int
collectnames(resultsp, taddr, nconf)
	char *resultsp;
	struct t_bind *taddr;
	struct netconfig *nconf;
{
	static int debugcnt;
	register struct entry *entryp, *lim;
	statstime *st;
	statsvar *sv;
	struct nd_hostservlist *hs;
	extern struct netbuf *netbufdup();
	extern struct netconfig *netconfigdup();
	extern int netbufeq();

	/*
	 * need to realloc more space if we have more than 256 machines
	 * that responded to the broadcast
	 */

	if (curentry >= total_entries) {
		struct entry *tmp;

		total_entries += SLOTS;
		tmp = realloc((struct entry *)entry, sizeof (struct entry)
						* total_entries);
		if (tmp == NULL) {
			return (1);
		}
		entry = tmp;
	}
	/*
	 * weed out duplicates
	 */
	lim = entry + curentry;
	for (entryp = entry; entryp < lim; entryp++)
		if (netbufeq(&taddr->addr, entryp->addr))
			return (0);

	if (vers == RSTATVERS_TIME) {
		st = (statstime *)resultsp;
	} else if (vers == RSTATVERS_VAR) {
		sv = (statsvar *)resultsp;
	} else {
		return (0);	/* we don't handle this version */
	}
	debugcnt++;
	entry[curentry].nconf = netconfigdup(nconf);
	entry[curentry].addr = netbufdup(&taddr->addr);

	/*
	 * if raw, print this entry out immediately
	 * otherwise store for later sorting
	 */
	if (!hflag && !lflag && !tflag) {
		if (netdir_getbyaddr(nconf, &hs, &taddr->addr) == ND_OK)
			printf("%*.*s  ", MACHINELEN, MACHINELEN,
				hs->h_hostservs->h_host);
		else {
			char *uaddr = taddr2uaddr(nconf, &taddr->addr);

			if (uaddr) {
				printf("  %*.*s", MACHINELEN, MACHINELEN,
					uaddr);
				(void) free(uaddr);
			} else
				printf("  %*.*s", MACHINELEN, MACHINELEN,
					"unknown");
		}
		if (vers == RSTATVERS_TIME) {
			putline(st->curtime.tv_sec, st->boottime, st->avenrun);
		} else if (vers == RSTATVERS_VAR) {
			putline(sv->curtime.tv_sec, sv->boottime, sv->avenrun);
		}
	} else {
		if (vers == RSTATVERS_TIME) {
			entry[curentry].boottime.tv_sec = st->boottime.tv_sec;
			entry[curentry].boottime.tv_usec =
				st->boottime.tv_usec;
			entry[curentry].curtime = st->curtime.tv_sec;
			memcpy(entry[curentry].avenrun, st->avenrun, AVENSIZE);
		} else if (vers == RSTATVERS_VAR) {
			entry[curentry].boottime.tv_sec = sv->boottime.tv_sec;
			entry[curentry].boottime.tv_usec =
				sv->boottime.tv_usec;
			entry[curentry].curtime = sv->curtime.tv_sec;
			memcpy(entry[curentry].avenrun, sv->avenrun, AVENSIZE);
		}
	}
	curentry++;
	if (dflag && debugcnt >= debug)
		return (1);
	return (0);
}

void
printsinglehosts()
{
	register int i;
	register struct entry *ep;


	if (hflag)
		qsort(entry, curentry, sizeof (struct entry), machinecmp);
	else if (lflag)
		qsort(entry, curentry, sizeof (struct entry), loadcmp);
	else
		qsort(entry, curentry, sizeof (struct entry), uptimecmp);
	for (i = 0; i < curentry; i++) {
		ep = &entry[i];
		printf("%*.*s  ", MACHINELEN, MACHINELEN, ep->machine);
		putline(ep->curtime, ep->boottime, ep->avenrun);

	}
}

void
printnames()
{
	char buf[MACHINELENMAX+1];
	struct nd_hostservlist *hs;
	register int i;
	register struct entry *ep;


	for (i = 0; i < curentry; i++) {
		ep = &entry[i];
		if (netdir_getbyaddr(ep->nconf, &hs, ep->addr) == ND_OK)
			sprintf(buf, "%s", hs->h_hostservs->h_host);
		else {
			char *uaddr = taddr2uaddr(ep->nconf, ep->addr);

			if (uaddr) {
				sprintf(buf, "%s", uaddr);
				(void) free(uaddr);
			} else
				sprintf(buf, "%s", "unknown");
		}
		if (ep->machine = (char *)malloc(MACHINELENMAX + 1))
			strcpy(ep->machine, buf);
	}
	printf("\n");
	printsinglehosts();
}

int
machinecmp(struct entry *a, struct entry *b)
{
	return (strcmp(a->machine, b->machine));
}

int
uptimecmp(struct entry *a, struct entry *b)
{
	if (a->boottime.tv_sec != b->boottime.tv_sec)
		return (a->boottime.tv_sec - b->boottime.tv_sec);
	else
		return (a->boottime.tv_usec - b->boottime.tv_usec);
}

int
loadcmp(struct entry *a, struct entry *b)
{
	register int i;

	for (i = 0; i < AVENSIZE / sizeof (a->avenrun[0]); i++)
		if (a->avenrun[i] != b->avenrun[i])
			return (a->avenrun[i] - b->avenrun[i]);

	return (0);
}

struct netbuf *
netbufdup(ap)
	register struct netbuf	*ap;
{
	register struct netbuf	*np;

	np = (struct netbuf *) malloc(sizeof (struct netbuf) + ap->len);
	if (np) {
		np->maxlen = np->len = ap->len;
		np->buf = ((char *)np) + sizeof (struct netbuf);
		(void) memcpy(np->buf, ap->buf, ap->len);
	}
	return (np);
}

struct netconfig *
netconfigdup(onp)
	register struct netconfig *onp;
{
	register int nlookupdirs;
	register struct netconfig *nnp;
	extern char *strdup();

	nnp = (struct netconfig *)malloc(sizeof (struct netconfig));
	if (nnp) {
		nnp->nc_netid = strdup(onp->nc_netid);
		nnp->nc_semantics = onp->nc_semantics;
		nnp->nc_flag = onp->nc_flag;
		nnp->nc_protofmly = strdup(onp->nc_protofmly);
		nnp->nc_proto = strdup(onp->nc_proto);
		nnp->nc_device = strdup(onp->nc_device);
		nnp->nc_nlookups = onp->nc_nlookups;
		if (onp->nc_nlookups == 0)
			nnp->nc_lookups = (char **)0;
		else {
			register int i;

			nnp->nc_lookups = (char **)malloc(onp->nc_nlookups *
			    sizeof (char *));
			if (nnp->nc_lookups)
				for (i = 0; i < onp->nc_nlookups; i++)
					nnp->nc_lookups[i] =
						strdup(onp->nc_lookups[i]);
		}
	}

	return (nnp);
}

int
netbufeq(struct netbuf *ap, struct netbuf *bp)
{
	return (ap->len == bp->len && !memcmp(ap->buf, bp->buf, ap->len));
}

void
usage(void)
{
	fprintf(stderr, "Usage: rup [-h] [-l] [-t] [host ...]\n");
	free(entry);
	exit(1);
}
