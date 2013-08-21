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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */
/*
 * Program to examine or set process privileges.
 */

#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <libproc.h>
#include <priv.h>
#include <errno.h>
#include <ctype.h>

#include <locale.h>
#include <langinfo.h>

static int	look(char *);
static void	perr(char *);
static void	usage(void);
static void	loadprivinfo(void);
static int	parsespec(const char *);
static void	privupdate(prpriv_t *, const char *);
static void	privupdate_self(void);
static int	dumppriv(char **);
static void	flags2str(uint_t);

static char		*command;
static char		*procname;
static boolean_t	verb = B_FALSE;
static boolean_t	set = B_FALSE;
static boolean_t	exec = B_FALSE;
static boolean_t	Don = B_FALSE;
static boolean_t	Doff = B_FALSE;
static boolean_t	list = B_FALSE;
static boolean_t	mac_aware = B_FALSE;
static boolean_t	pfexec = B_FALSE;
static boolean_t	xpol = B_FALSE;
static int		mode = PRIV_STR_PORT;

int
main(int argc, char **argv)
{
	int rc = 0;
	int opt;
	struct rlimit rlim;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	if ((command = strrchr(argv[0], '/')) != NULL)
		command++;
	else
		command = argv[0];

	while ((opt = getopt(argc, argv, "lDMNPevs:xS")) != EOF) {
		switch (opt) {
		case 'l':
			list = B_TRUE;
			break;
		case 'D':
			set = B_TRUE;
			Don = B_TRUE;
			break;
		case 'M':
			mac_aware = B_TRUE;
			break;
		case 'N':
			set = B_TRUE;
			Doff = B_TRUE;
			break;
		case 'P':
			set = B_TRUE;
			pfexec = B_TRUE;
			break;
		case 'e':
			exec = B_TRUE;
			break;
		case 'S':
			mode = PRIV_STR_SHORT;
			break;
		case 'v':
			verb = B_TRUE;
			mode = PRIV_STR_LIT;
			break;
		case 's':
			set = B_TRUE;
			if ((rc = parsespec(optarg)) != 0)
				return (rc);
			break;
		case 'x':
			set = B_TRUE;
			xpol = B_TRUE;
			break;
		default:
			usage();
			/*NOTREACHED*/
		}
	}

	argc -= optind;
	argv += optind;

	if ((argc < 1 && !list) || Doff && Don || list && (set || exec) ||
	    (mac_aware && !exec))
		usage();

	/*
	 * Make sure we'll have enough file descriptors to handle a target
	 * that has many many mappings.
	 */
	if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
		rlim.rlim_cur = rlim.rlim_max;
		(void) setrlimit(RLIMIT_NOFILE, &rlim);
		(void) enable_extended_FILE_stdio(-1, -1);
	}

	if (exec) {
		privupdate_self();
		rc = execvp(argv[0], &argv[0]);
		(void) fprintf(stderr, "%s: %s: %s\n", command, argv[0],
		    strerror(errno));
	} else if (list) {
		rc = dumppriv(argv);
	} else {
		while (argc-- > 0)
			rc += look(*argv++);
	}

	return (rc);
}

static int
look(char *arg)
{
	struct ps_prochandle *Pr;
	int gcode;
	size_t sz;
	void *pdata;
	char *x;
	int i;
	boolean_t nodata;
	prpriv_t *ppriv;

	procname = arg;		/* for perr() */

	if ((Pr = proc_arg_grab(arg, set ? PR_ARG_PIDS : PR_ARG_ANY,
	    PGRAB_RETAIN | PGRAB_FORCE | (set ? 0 : PGRAB_RDONLY) |
	    PGRAB_NOSTOP, &gcode)) == NULL) {
		(void) fprintf(stderr, "%s: cannot examine %s: %s\n",
		    command, arg, Pgrab_error(gcode));
		return (1);
	}

	if (Ppriv(Pr, &ppriv) == -1) {
		perr(command);
		Prelease(Pr, 0);
		return (1);
	}
	sz = PRIV_PRPRIV_SIZE(ppriv);

	/*
	 * The ppriv fields are unsigned and may overflow, so check them
	 * separately.  Size must be word aligned, so check that too.
	 * Make sure size is "smallish" too.
	 */
	if ((sz & 3) || ppriv->pr_nsets == 0 ||
	    sz / ppriv->pr_nsets < ppriv->pr_setsize ||
	    ppriv->pr_infosize > sz || sz > 1024 * 1024) {
		(void) fprintf(stderr,
		    "%s: %s: bad PRNOTES section, size = %lx\n",
		    command, arg, (long)sz);
		Prelease(Pr, 0);
		free(ppriv);
		return (1);
	}

	if (set) {
		privupdate(ppriv, arg);
		if (Psetpriv(Pr, ppriv) != 0) {
			perr(command);
			Prelease(Pr, 0);
			free(ppriv);
			return (1);
		}
		Prelease(Pr, 0);
		free(ppriv);
		return (0);
	}

	if (Pstate(Pr) == PS_DEAD) {
		(void) printf("core '%s' of %d:\t%.70s\n",
		    arg, (int)Ppsinfo(Pr)->pr_pid, Ppsinfo(Pr)->pr_psargs);
		pdata = Pprivinfo(Pr);
		nodata = Pstate(Pr) == PS_DEAD && pdata == NULL;
	} else {
		(void) printf("%d:\t%.70s\n",
		    (int)Ppsinfo(Pr)->pr_pid, Ppsinfo(Pr)->pr_psargs);
		pdata = NULL;
		nodata = B_FALSE;
	}

	x = (char *)ppriv + sz - ppriv->pr_infosize;
	while (x < (char *)ppriv + sz) {
		/* LINTED: alignment */
		priv_info_t *pi = (priv_info_t *)x;
		priv_info_uint_t *pii;

		switch (pi->priv_info_type) {
		case PRIV_INFO_FLAGS:
			/* LINTED: alignment */
			pii = (priv_info_uint_t *)x;
			(void) printf("flags =");
			flags2str(pii->val);
			(void) putchar('\n');
			break;
		default:
			(void) fprintf(stderr, "%s: unknown priv_info: %d\n",
			    arg, pi->priv_info_type);
			break;
		}
		if (pi->priv_info_size > ppriv->pr_infosize ||
		    pi->priv_info_size <=  sizeof (priv_info_t) ||
		    (pi->priv_info_size & 3) != 0) {
			(void) fprintf(stderr, "%s: bad priv_info_size: %u\n",
			    arg, pi->priv_info_size);
			break;
		}
		x += pi->priv_info_size;
	}

	for (i = 0; i < ppriv->pr_nsets; i++) {
		extern const char *__priv_getsetbynum(const void *, int);
		const char *setnm = pdata ? __priv_getsetbynum(pdata, i) :
		    priv_getsetbynum(i);
		priv_chunk_t *pc =
		    (priv_chunk_t *)&ppriv->pr_sets[ppriv->pr_setsize * i];


		(void) printf("\t%c: ", setnm && !nodata ? *setnm : '?');
		if (!nodata) {
			extern char *__priv_set_to_str(void *,
			    const priv_set_t *, char, int);
			priv_set_t *pset = (priv_set_t *)pc;

			char *s;

			if (pdata)
				s = __priv_set_to_str(pdata, pset, ',', mode);
			else
				s = priv_set_to_str(pset, ',', mode);
			(void) puts(s);
			free(s);
		} else {
			int j;
			for (j = 0; j < ppriv->pr_setsize; j++)
				(void) printf("%08x", pc[j]);
			(void) putchar('\n');
		}
	}
	Prelease(Pr, 0);
	free(ppriv);
	return (0);
}

static void
fatal(const char *s)
{
	(void) fprintf(stderr, "%s: %s: %s\n", command, s, strerror(errno));
	exit(3);
}

static void
perr(char *s)
{
	int err = errno;

	if (s != NULL)
		(void) fprintf(stderr, "%s: ", procname);
	else
		s = procname;

	errno = err;
	perror(s);
}

static void
usage(void)
{
	(void) fprintf(stderr,
	    "usage:\t%s [-v] [-S] [-D|-N] [-s spec] { pid | core } ...\n"
	    "\t%s -e [-D|-N] [-M] [-s spec] cmd [args ...]\n"
	    "\t%s -l [-v] [privilege ...]\n"
	    "  (report, set or list process privileges)\n", command,
	    command, command);
	exit(2);
	/*NOTREACHED*/
}

/*
 * Parse the privilege bits to add and/or remove from
 * a privilege set.
 *
 * [EPIL][+-=]priv,priv,priv
 */

static int
strindex(char c, const char *str)
{
	const char *s;

	if (islower(c))
		c = toupper(c);

	s = strchr(str, c);

	if (s == NULL)
		return (-1);
	else
		return (s - str);
}

static void
badspec(const char *spec)
{
	(void) fprintf(stderr, "%s: bad privilege specification: \"%s\"\n",
	    command, spec);
	exit(3);
	/*NOTREACHED*/
}

/*
 * For each set, you can set either add and/or
 * remove or you can set assign.
 */
static priv_set_t **rem, **add, **assign;
static const priv_impl_info_t *pri = NULL;
static char *sets;

static void
loadprivinfo(void)
{
	int i;

	if (pri != NULL)
		return;

	pri = getprivimplinfo();

	if (pri == NULL)
		fatal("getprivimplinfo");

	sets = malloc(pri->priv_nsets + 1);
	if (sets == NULL)
		fatal("malloc");

	for (i = 0; i < pri->priv_nsets; i++) {
		sets[i] = *priv_getsetbynum(i);
		if (islower(sets[i]))
			sets[i] = toupper(sets[i]);
	}

	sets[pri->priv_nsets] = '\0';

	rem = calloc(pri->priv_nsets, sizeof (priv_set_t *));
	add = calloc(pri->priv_nsets, sizeof (priv_set_t *));
	assign = calloc(pri->priv_nsets, sizeof (priv_set_t *));
	if (rem == NULL || add == NULL || assign == NULL)
		fatal("calloc");
}

static int
parsespec(const char *spec)
{
	char *p;
	const char *q;
	int count;
	priv_set_t ***toupd;
	priv_set_t *upd;
	int i;
	boolean_t freeupd = B_TRUE;

	if (pri == NULL)
		loadprivinfo();

	p = strpbrk(spec, "+-=");

	if (p == NULL || p - spec > pri->priv_nsets)
		badspec(spec);

	if (p[1] == '\0' || (upd = priv_str_to_set(p + 1, ",", NULL)) == NULL)
		badspec(p + 1);

	count = p - spec;
	switch (*p) {
	case '+':
		toupd = &add;
		break;
	case '-':
		toupd = &rem;
		priv_inverse(upd);
		break;
	case '=':
		toupd = &assign;
		break;
	}

	/* Update all sets? */
	if (count == 0 || *spec == 'a' || *spec == 'A') {
		count = pri->priv_nsets;
		q = sets;
	} else
		q = spec;

	for (i = 0; i < count; i++) {
		int ind = strindex(q[i], sets);

		if (ind == -1)
			badspec(spec);

		/* Assign is mutually exclusive with add/remove and itself */
		if (((toupd == &rem || toupd == &add) && assign[ind] != NULL) ||
		    (toupd == &assign && (assign[ind] != NULL ||
		    rem[ind] != NULL || add[ind] != NULL))) {
			(void) fprintf(stderr, "%s: conflicting spec: %s\n",
			    command, spec);
			exit(1);
		}
		if ((*toupd)[ind] != NULL) {
			if (*p == '-')
				priv_intersect(upd, (*toupd)[ind]);
			else
				priv_union(upd, (*toupd)[ind]);
		} else {
			(*toupd)[ind] = upd;
			freeupd = B_FALSE;
		}
	}
	if (freeupd)
		priv_freeset(upd);
	return (0);
}

static void
privupdate(prpriv_t *pr, const char *arg)
{
	int i;

	if (sets != NULL) {
		for (i = 0; i < pri->priv_nsets; i++) {
			priv_set_t *target =
			    (priv_set_t *)&pr->pr_sets[pr->pr_setsize * i];
			if (rem[i] != NULL)
				priv_intersect(rem[i], target);
			if (add[i] != NULL)
				priv_union(add[i], target);
			if (assign[i] != NULL)
				priv_copyset(assign[i], target);
		}
	}

	if (Doff || Don || pfexec || xpol) {
		priv_info_uint_t *pii;
		int sz = PRIV_PRPRIV_SIZE(pr);
		char *x = (char *)pr + PRIV_PRPRIV_INFO_OFFSET(pr);
		uint32_t fl = 0;

		while (x < (char *)pr + sz) {
			/* LINTED: alignment */
			priv_info_t *pi = (priv_info_t *)x;

			if (pi->priv_info_type == PRIV_INFO_FLAGS) {
				/* LINTED: alignment */
				pii = (priv_info_uint_t *)x;
				fl = pii->val;
				goto done;
			}
			if (pi->priv_info_size > pr->pr_infosize ||
			    pi->priv_info_size <=  sizeof (priv_info_t) ||
			    (pi->priv_info_size & 3) != 0)
				break;
			x += pi->priv_info_size;
		}
		(void) fprintf(stderr,
		    "%s: cannot find privilege flags to set\n", arg);
		pr->pr_infosize = 0;
		return;
done:

		pr->pr_infosize = sizeof (priv_info_uint_t);
		/* LINTED: alignment */
		pii = (priv_info_uint_t *)
		    ((char *)pr + PRIV_PRPRIV_INFO_OFFSET(pr));

		if (Don)
			fl |= PRIV_DEBUG;
		if (Doff)
			fl &= ~PRIV_DEBUG;
		if (pfexec)
			fl |= PRIV_PFEXEC;
		if (xpol)
			fl |= PRIV_XPOLICY;

		pii->info.priv_info_size = sizeof (*pii);
		pii->info.priv_info_type = PRIV_INFO_FLAGS;
		pii->val = fl;
	} else {
		pr->pr_infosize = 0;
	}
}

static void
privupdate_self(void)
{
	int set;

	if (mac_aware) {
		if (setpflags(NET_MAC_AWARE, 1) != 0)
			fatal("setpflags(NET_MAC_AWARE)");
		if (setpflags(NET_MAC_AWARE_INHERIT, 1) != 0)
			fatal("setpflags(NET_MAC_AWARE_INHERIT)");
	}
	if (pfexec) {
		if (setpflags(PRIV_PFEXEC, 1) != 0)
			fatal("setpflags(PRIV_PFEXEC)");
	}

	if (sets != NULL) {
		priv_set_t *target = priv_allocset();

		if (target == NULL)
			fatal("priv_allocet");

		set = priv_getsetbyname(PRIV_INHERITABLE);
		if (rem[set] != NULL || add[set] != NULL ||
		    assign[set] != NULL) {
			(void) getppriv(PRIV_INHERITABLE, target);
			if (rem[set] != NULL)
				priv_intersect(rem[set], target);
			if (add[set] != NULL)
				priv_union(add[set], target);
			if (assign[set] != NULL)
				priv_copyset(assign[set], target);
			if (setppriv(PRIV_SET, PRIV_INHERITABLE, target) != 0)
				fatal("setppriv(Inheritable)");
		}
		set = priv_getsetbyname(PRIV_LIMIT);
		if (rem[set] != NULL || add[set] != NULL ||
		    assign[set] != NULL) {
			(void) getppriv(PRIV_LIMIT, target);
			if (rem[set] != NULL)
				priv_intersect(rem[set], target);
			if (add[set] != NULL)
				priv_union(add[set], target);
			if (assign[set] != NULL)
				priv_copyset(assign[set], target);
			if (setppriv(PRIV_SET, PRIV_LIMIT, target) != 0)
				fatal("setppriv(Limit)");
		}
		priv_freeset(target);
	}

	if (Doff || Don)
		(void) setpflags(PRIV_DEBUG, Don ? 1 : 0);
	if (xpol)
		(void) setpflags(PRIV_XPOLICY, 1);
	if (pfexec)
		(void) setpflags(PRIV_PFEXEC, 1);
}

static int
dopriv(const char *p)
{
	(void) puts(p);
	if (verb) {
		char *text = priv_gettext(p);
		char *p, *q;
		if (text == NULL)
			return (1);
		for (p = text; q = strchr(p, '\n'); p = q + 1) {
			*q = '\0';
			(void) printf("\t%s\n", p);
		}
		free(text);
	}
	return (0);
}

static int
dumppriv(char **argv)
{
	int rc = 0;
	const char *pname;
	int i;

	if (argv[0] == NULL) {
		for (i = 0; ((pname = priv_getbynum(i++)) != NULL); )
			rc += dopriv(pname);
	} else {
		for (; *argv; argv++) {
			priv_set_t *pset = priv_str_to_set(*argv, ",", NULL);

			if (pset == NULL) {
				(void) fprintf(stderr, "%s: %s: bad privilege"
				    " list\n", command, *argv);
				rc++;
				continue;
			}
			for (i = 0; ((pname = priv_getbynum(i++)) != NULL); )
				if (priv_ismember(pset, pname))
					rc += dopriv(pname);
		}
	}
	return (rc);
}

static struct {
	int flag;
	char *name;
} flags[] = {
	{ PRIV_DEBUG, "PRIV_DEBUG" },
	{ PRIV_AWARE, "PRIV_AWARE" },
	{ PRIV_AWARE_INHERIT, "PRIV_AWARE_INHERIT" },
	{ PRIV_AWARE_RESET, "PRIV_AWARE_RESET" },
	{ PRIV_XPOLICY, "PRIV_XPOLICY" },
	{ PRIV_PFEXEC, "PRIV_PFEXEC" },
	{ NET_MAC_AWARE, "NET_MAC_AWARE" },
	{ NET_MAC_AWARE_INHERIT, "NET_MAC_AWARE_INHERIT" },
};

/*
 * Print flags preceeded by a space.
 */
static void
flags2str(uint_t pflags)
{
	char c = ' ';
	int i;

	if (pflags == 0) {
		(void) fputs(" <none>", stdout);
		return;
	}
	for (i = 0; i < sizeof (flags)/sizeof (flags[0]) && pflags != 0; i++) {
		if ((pflags & flags[i].flag) != 0) {
			(void) printf("%c%s", c, flags[i].name);
			pflags &= ~flags[i].flag;
			c = '|';
		}
	}
	if (pflags != 0)
		(void) printf("%c<0x%x>", c, pflags);
}
