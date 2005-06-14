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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <netconfig.h>
#include <netdir.h>
#include <rpc/rpc.h>
#include <rpcsvc/rusers.h>
#include <string.h>
#include <limits.h>

#define	NMAX	12		/* These are used as field width specifiers */
#define	LMAX	8		/* when printing.			    */
#define	HMAX	16		/* "Logged in" host name. */

#define	MACHINELEN 16		/* length of machine name printed out */
#define	NUMENTRIES 256
#define	min(a, b) ((a) < (b) ? (a) : (b))

struct entry {
	int cnt;
	int idle;		/* set to INT_MAX if not present */
	char *machine;
	utmp_array users;
};

static int curentry;
static int total_entries;
static struct entry *entry;
static int hflag;		/* host: sort by machine name */
static int iflag;		/* idle: sort by idle time */
static int uflag;		/* users: sort by number of users */
static int lflag;		/* print out long form */
static int aflag;		/* all: list all machines */
static int dflag;		/* debug: list only first n machines */
static int sorted;
static int debug;
static int debugcnt;
static char *nettype;

static int hcompare(const struct entry *, const struct entry *);
static int icompare(const struct entry *, const struct entry *);
static int ucompare(const struct entry *, const struct entry *);
static int print_info(struct utmpidlearr *, const char *);
static int print_info_3(utmp_array *, const char *);
static int collectnames(void *, struct netbuf *, struct netconfig *);
static int collectnames_3(void *, struct netbuf *, struct netconfig *);
static void singlehost(char *);
static void printnames(void);
static void putline_2(char *, struct utmpidle *);
static void putline_3(char *, rusers_utmp *);
static void prttime(uint_t, char *);
static void usage(void);

/*
 * rusers [-ahilu] [host...]
 */
int
main(int argc, char *argv[])
{
	int c;
	uint_t errflag = 0;
	uint_t single = 0;
	struct utmpidlearr utmpidlearr;
	utmp_array	utmp_array_res;

	curentry = 0;
	total_entries = NUMENTRIES;
	entry = malloc(sizeof (struct entry) * total_entries);

	while ((c = getopt(argc, argv, ":ad:hilun:")) != -1) {
		switch (c) {
		case 'a':
			aflag++;
			break;
		case 'd':
			dflag++;
			debug = atoi(optarg);
			(void) printf("Will collect %d responses.\n", debug);
			break;
		case 'h':
			hflag++;
			sorted++;
			if (iflag || uflag)
				errflag++;
			break;
		case 'i':
			iflag++;
			sorted++;
			if (hflag || uflag)
				errflag++;
			break;
		case 'u':
			uflag++;
			sorted++;
			if (hflag || iflag)
				errflag++;
			break;
		case 'l':
			lflag++;
			break;
		case ':':	/* required operand missing */
			errflag++;
			break;
		case 'n':
			nettype = optarg;
			break;
		default:
		case '?':	/* Unrecognized option */
			errflag++;
			break;
		}
	}
	if (errflag)
		usage();

	for (; optind < argc; optind++) {
		single++;
		singlehost(argv[optind]);
	}
	if (single) {
		if (sorted)
			printnames();
		free(entry);
		exit(0);
	}

	if (sorted) {
		(void) printf("Collecting responses...\n");
		(void) fflush(stdout);
	}
	utmp_array_res.utmp_array_val = NULL;
	utmp_array_res.utmp_array_len = 0;
	(void) printf("Sending broadcast for rusersd protocol version 3...\n");
	(void) rpc_broadcast(RUSERSPROG, RUSERSVERS_3,
		RUSERSPROC_NAMES, (xdrproc_t)xdr_void, NULL,
		(xdrproc_t)xdr_utmp_array, (char *)&utmp_array_res,
		(resultproc_t)collectnames_3, nettype);
	utmpidlearr.uia_arr = NULL;
	(void) printf("Sending broadcast for rusersd protocol version 2...\n");
	(void) rpc_broadcast(RUSERSPROG, RUSERSVERS_IDLE,
		RUSERSPROC_NAMES, (xdrproc_t)xdr_void, NULL,
		(xdrproc_t)xdr_utmpidlearr, (char *)&utmpidlearr,
		(resultproc_t)collectnames, nettype);

	if (sorted)
		printnames();

	free(entry);
	return (0);
}

static void
singlehost(char *name)
{
	enum clnt_stat err;
	struct utmpidlearr utmpidlearr;
	utmp_array	utmp_array_res;

	if (curentry >= total_entries) {
		struct entry *tmp;

		total_entries += NUMENTRIES;
		if ((tmp = realloc(entry, sizeof (struct entry)
						* total_entries)) == NULL)
			return;
		entry = tmp;
	}
	utmp_array_res.utmp_array_val = NULL;
	utmp_array_res.utmp_array_len = 0;
	err = rpc_call(name, RUSERSPROG, RUSERSVERS_3,
		RUSERSPROC_NAMES, (xdrproc_t)xdr_void, 0,
		(xdrproc_t)xdr_utmp_array, (char *)&utmp_array_res,
		nettype);
	if (err == RPC_SUCCESS) {
		(void) print_info_3(&utmp_array_res, name);
		return;
	}
	if (err == RPC_PROGVERSMISMATCH) {
		utmpidlearr.uia_arr = NULL;
		err = rpc_call(name, RUSERSPROG, RUSERSVERS_IDLE,
				RUSERSPROC_NAMES, (xdrproc_t)xdr_void, 0,
				(xdrproc_t)xdr_utmpidlearr,
				(char *)&utmpidlearr, nettype);
	}
	if (err != RPC_SUCCESS) {
		(void) fprintf(stderr, "%s: ", name);
		clnt_perrno(err);
		return;
	}
	(void) print_info(&utmpidlearr, name);
}

/*
 * Collect responses from RUSERSVERS_IDLE broadcast, convert to
 * RUSERSVERS_3 format, and store in entry database.
 */
static int
collectnames(void *resultsp, struct netbuf *raddrp, struct netconfig *nconf)
{
	struct utmpidlearr utmpidlearr;
	struct entry *entryp, *lim;
	struct nd_hostservlist *hs;
	char host[MACHINELEN + 1];

	utmpidlearr = *(struct utmpidlearr *)resultsp;
	if (utmpidlearr.uia_cnt < 1 && !aflag)
		return (0);

	if (netdir_getbyaddr(nconf, &hs, raddrp)) {
#ifdef DEBUG
		netdir_perror("netdir_getbyaddr");
#endif
		/* netdir routine couldn't resolve addr;just print out uaddr */
		(void) sprintf(host, "%.*s", MACHINELEN,
						taddr2uaddr(nconf, raddrp));
	} else {
		(void) sprintf(host, "%.*s", MACHINELEN,
						hs->h_hostservs->h_host);
		netdir_free((char *)hs, ND_HOSTSERVLIST);
	}
	/*
	 * need to realloc more space if we have more than 256 machines
	 * that respond to broadcast
	 */
	if (curentry >= total_entries) {
		struct entry *tmp;

		total_entries += NUMENTRIES;
		if ((tmp = realloc(entry, sizeof (struct entry)
						* total_entries)) == NULL)
			return (1);
		entry = tmp;
	}


	/*
	 * weed out duplicates
	 */
	lim = entry + curentry;
	for (entryp = entry; entryp < lim; entryp++) {
		if (strcmp(entryp->machine, host) == 0)
			return (0);
	}
	return (print_info((struct utmpidlearr *)resultsp, host));
}

static int
print_info(struct utmpidlearr *utmpidlearrp, const char *name)
{
	utmp_array *iconvert;
	int i, cnt, minidle;
	char host[MACHINELEN + 1];
	char username[NMAX + 1];

	cnt = utmpidlearrp->uia_cnt;
	(void) sprintf(host, "%.*s", MACHINELEN, name);

	/*
	 * if raw, print this entry out immediately
	 * otherwise store for later sorting
	 */
	if (!sorted) {
		if (lflag && (cnt > 0))
			for (i = 0; i < cnt; i++)
				putline_2(host, utmpidlearrp->uia_arr[i]);
		else {
		    (void) printf("%-*.*s", MACHINELEN, MACHINELEN, host);
		    for (i = 0; i < cnt; i++) {
			(void) strlcpy(username,
				    utmpidlearrp->uia_arr[i]->ui_utmp.ut_name,
				    NMAX + 1);
			(void) printf(" %.*s", NMAX, username);
		    }
		    (void) printf("\n");
		}
		/* store just the name */
		entry[curentry].machine = malloc(MACHINELEN + 1);
		if (entry[curentry].machine == NULL) {
			(void) fprintf(stderr, "Ran out of memory - exiting\n");
			exit(1);
		}
		(void) strlcpy(entry[curentry].machine, name, MACHINELEN + 1);
		entry[curentry++].cnt = 0;
		if (dflag && (++debugcnt >= debug))
			return (1);
		return (0);
	}
	entry[curentry].machine = malloc(MACHINELEN + 1);
	if (entry[curentry].machine == NULL) {
		(void) fprintf(stderr, "Ran out of memory - exiting\n");
		exit(1);
	}
	(void) strlcpy(entry[curentry].machine, name, MACHINELEN + 1);
	entry[curentry].cnt = cnt;
	iconvert = &entry[curentry].users;
	iconvert->utmp_array_len = cnt;
	iconvert->utmp_array_val = malloc(cnt * sizeof (rusers_utmp));
	minidle = INT_MAX;
	for (i = 0; i < cnt; i++) {
		iconvert->utmp_array_val[i].ut_user =
			strdup(utmpidlearrp->uia_arr[i]->ui_utmp.ut_name);
		iconvert->utmp_array_val[i].ut_line =
			strdup(utmpidlearrp->uia_arr[i]->ui_utmp.ut_line);
		iconvert->utmp_array_val[i].ut_host =
			strdup(utmpidlearrp->uia_arr[i]->ui_utmp.ut_host);
		iconvert->utmp_array_val[i].ut_time =
			utmpidlearrp->uia_arr[i]->ui_utmp.ut_time;
		iconvert->utmp_array_val[i].ut_idle =
			utmpidlearrp->uia_arr[i]->ui_idle;
		minidle = min(minidle, utmpidlearrp->uia_arr[i]->ui_idle);
	}
	entry[curentry].idle = minidle;
	curentry++;
	if (dflag && (++debugcnt >= debug))
		return (1);
	return (0);
}


/*
 * Collect responses from RUSERSVERS_3 broadcast.
 */
static int
collectnames_3(void *resultsp, struct netbuf *raddrp, struct netconfig *nconf)
{
	utmp_array *uap;
	struct entry *entryp, *lim;
	struct nd_hostservlist *hs;
	char host[MACHINELEN + 1];

	uap = (utmp_array *)resultsp;
	if (uap->utmp_array_len < 1 && !aflag)
		return (0);

	if (netdir_getbyaddr(nconf, &hs, raddrp)) {
#ifdef DEBUG
	netdir_perror("netdir_getbyaddr");
#endif
		/* netdir routine couldn't resolve addr;just print out uaddr */
		(void) sprintf(host, "%.*s", MACHINELEN,
						taddr2uaddr(nconf, raddrp));
	} else {
		(void) sprintf(host, "%.*s", MACHINELEN,
						hs->h_hostservs->h_host);
		netdir_free((char *)hs, ND_HOSTSERVLIST);
	}

	/*
	 * need to realloc more space if we have more than 256 machines
	 * that respond to broadcast
	 */
	if (curentry >= total_entries) {
		struct entry *tmp;

		total_entries += NUMENTRIES;
		if ((tmp = realloc(entry, sizeof (struct entry)
						* total_entries)) == NULL)
			return (1);
		entry = tmp;
	}


	/*
	 * weed out duplicates
	 */
	lim = entry + curentry;
	for (entryp = entry; entryp < lim; entryp++) {
		if (strcmp(entryp->machine, host) == 0)
			return (0);
	}
	return (print_info_3(uap, host));
}

static int
print_info_3(utmp_array *uap, const char *name)
{
	int i, cnt, minidle;
	char host[MACHINELEN + 1];

	cnt = uap->utmp_array_len;

	(void) sprintf(host, "%.*s", MACHINELEN, name);

	/*
	 * if raw, print this entry out immediately
	 * otherwise store for later sorting
	 */
	if (!sorted) {
		if (lflag && (cnt > 0))
			for (i = 0; i < cnt; i++)
				putline_3(host, &uap->utmp_array_val[i]);
		else {
			(void) printf("%-*.*s", MACHINELEN, MACHINELEN, host);
			for (i = 0; i < cnt; i++)
				(void) printf(" %.*s", NMAX,
				    uap->utmp_array_val[i].ut_user);
			(void) printf("\n");
		}
		/* store just the name */
		entry[curentry].machine = malloc(MACHINELEN + 1);
		if (entry[curentry].machine == NULL) {
			(void) fprintf(stderr, "Ran out of memory - exiting\n");
			exit(1);
		}
		(void) strlcpy(entry[curentry].machine, name, MACHINELEN + 1);
		entry[curentry++].cnt = 0;
		if (dflag && (++debugcnt >= debug))
			return (1);
		return (0);
	}

	entry[curentry].machine = malloc(MACHINELEN + 1);
	if (entry[curentry].machine == NULL) {
		(void) fprintf(stderr, "Ran out of memory - exiting\n");
		exit(1);
	}
	(void) strlcpy(entry[curentry].machine, name, MACHINELEN + 1);
	entry[curentry].cnt = cnt;
	entry[curentry].users.utmp_array_len = cnt;
	entry[curentry].users.utmp_array_val = malloc(cnt *
		sizeof (rusers_utmp));
	minidle = INT_MAX;
	for (i = 0; i < cnt; i++) {
		entry[curentry].users.utmp_array_val[i].ut_user =
			strdup(uap->utmp_array_val[i].ut_user);
		entry[curentry].users.utmp_array_val[i].ut_line =
			strdup(uap->utmp_array_val[i].ut_line);
		entry[curentry].users.utmp_array_val[i].ut_host =
			strdup(uap->utmp_array_val[i].ut_host);
		entry[curentry].users.utmp_array_val[i].ut_time =
			uap->utmp_array_val[i].ut_time;
		entry[curentry].users.utmp_array_val[i].ut_idle =
			uap->utmp_array_val[i].ut_idle;
		minidle = min(minidle, uap->utmp_array_val[i].ut_idle);
	}
	entry[curentry].idle = minidle;
	curentry++;
	if (dflag && (++debugcnt >= debug))
		return (1);
	return (0);
}

static void
printnames(void)
{
	int i, j;
	int (*compare)(const void *, const void *);

	/* the name of the machine should already be in the structure */
	if (iflag)
		compare = (int (*)(const void *, const void *))icompare;
	else if (hflag)
		compare = (int (*)(const void *, const void *))hcompare;
	else
		compare = (int (*)(const void *, const void *))ucompare;
	qsort(entry, curentry, sizeof (struct entry), compare);
	for (i = 0; i < curentry; i++) {
		if (!lflag || (entry[i].cnt < 1)) {
			(void) printf("%-*.*s", MACHINELEN,
					MACHINELEN, entry[i].machine);
			for (j = 0; j < entry[i].cnt; j++)
				(void) printf(" %.*s", NMAX,
				    entry[i].users.utmp_array_val[j].ut_user);
			(void) printf("\n");
		} else {
			for (j = 0; j < entry[i].cnt; j++)
				putline_3(entry[i].machine,
					&entry[i].users.utmp_array_val[j]);
		}
	}
}

static int
hcompare(const struct entry *a, const struct entry *b)
{
	return (strcmp(a->machine, b->machine));
}

static int
ucompare(const struct entry *a, const struct entry *b)
{
	return (b->cnt - a->cnt);
}

static int
icompare(const struct entry *a, const struct entry *b)
{
	return (a->idle - b->idle);
}

static void
putline_2(char *host, struct utmpidle *uip)
{
	char *cbuf;
	struct ru_utmp *up;
	char buf[100];

	up = &uip->ui_utmp;
#define	NAMEMAX	((sizeof (up->ut_name) < NMAX) ? NMAX : sizeof (up->ut_name))
#define	NAMEMIN	((sizeof (up->ut_name) > NMAX) ? NMAX : sizeof (up->ut_name))
	/* Try and align this up nicely */
#define	LINEMAX	sizeof (up->ut_line)
#define	HOSTMAX	sizeof (up->ut_host)
	/*
	 * We copy the strings into a buffer because they aren't strictly
	 * speaking strings but byte arrays (and they may not have a
	 * terminating NULL.
	 */

	(void) strncpy(buf, up->ut_name, NAMEMAX);
	buf[NAMEMIN] = '\0';
	(void) printf("%-*.*s ", NAMEMAX, NAMEMAX, buf);

	(void) strcpy(buf, host);
	(void) strcat(buf, ":");
	(void) strncat(buf, up->ut_line, LINEMAX);
	buf[MACHINELEN+LINEMAX] = '\0';
	(void) printf("%-*.*s", MACHINELEN+LINEMAX, MACHINELEN+LINEMAX, buf);

	cbuf = (char *)ctime(&up->ut_time);
	(void) printf("  %.12s  ", cbuf+4);
	if (uip->ui_idle == INT_MAX)
		(void) printf("    ??");
	else
		prttime(uip->ui_idle, "");
	if (up->ut_host[0]) {
		(void) strncpy(buf, up->ut_host, HOSTMAX);
		buf[HOSTMAX] = '\0';
		(void) printf(" (%.*s)", HOSTMAX, buf);
	}
	(void) putchar('\n');
}

static void
putline_3(char *host, rusers_utmp *rup)
{
	char *cbuf;
	char buf[100];

	(void) printf("%-*.*s ", NMAX, NMAX, rup->ut_user);
	(void) strcpy(buf, host);
	(void) strcat(buf, ":");
	(void) strncat(buf, rup->ut_line, LMAX);
	(void) printf("%-*.*s", MACHINELEN+LMAX, MACHINELEN+LMAX, buf);

	cbuf = (char *)ctime((time_t *)&rup->ut_time);
	(void) printf("  %.12s  ", cbuf+4);
	if (rup->ut_idle == INT_MAX)
		(void) printf("    ??");
	else
		prttime(rup->ut_idle, "");
	if (rup->ut_host[0])
		(void) printf(" (%.*s)", HMAX, rup->ut_host);
	(void) putchar('\n');
}

/*
 * prttime prints a time in hours and minutes.
 * The character string tail is printed at the end, obvious
 * strings to pass are "", " ", or "am".
 */
static void
prttime(uint_t tim, char *tail)
{
	int didhrs = 0;

	if (tim >= 60) {
		(void) printf("%3d:", tim/60);
		didhrs++;
	} else {
		(void) printf("    ");
	}
	tim %= 60;
	if (tim > 0 || didhrs) {
		(void) printf(didhrs && tim < 10 ? "%02d" : "%2d", tim);
	} else {
		(void) printf("  ");
	}
	(void) printf("%s", tail);
}

#ifdef DEBUG
/*
 * for debugging
 */
int
printit(int i)
{
	int j, v;

	(void) printf("%12.12s: ", entry[i].machine);
	if (entry[i].cnt) {
		putline_3(entry[i].machine, &entry[i].users.utmp_array_val[0]);
		for (j = 1; j < entry[i].cnt; j++) {
			(void) printf("\t");
			putline_3(entry[i].machine,
				&entry[i].users.utmp_array_val[j]);
		}
	} else
		(void) printf("\n");
}
#endif

static void
usage(void)
{
	(void) fprintf(stderr, "Usage: rusers [-ahilu] [host ...]\n");
	free(entry);
	exit(1);
}
