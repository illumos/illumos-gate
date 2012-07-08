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

/*
 * poolstat - report active pool statistics
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <unistd.h>
#include <locale.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <errno.h>
#include <stddef.h>

#include <pool.h>
#include "utils.h"
#include "poolstat.h"
#include "poolstat_utils.h"
#include "statcommon.h"

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

#define	addrof(s)  ((char **)&(s))

/* verify if a field is printable in respect of the current option flags */
#define	PRINTABLE(i)	((lf->plf_ffs[(i)].pff_prt & D_FIELD) || \
	(lf->plf_ffs[(i)].pff_prt & X_FIELD))

typedef int (* formatter) (char *, int, int, poolstat_field_format_t *, char *);

static uint_t timestamp_fmt = NODATE;

/* available field formatters	*/
static int default_f(char *, int, int, poolstat_field_format_t *, char *);
static int bigno_f(char *, int, int, poolstat_field_format_t *, char *);
static int used_stat_f(char *, int, int, poolstat_field_format_t *, char *);
static int header_f(char *, int, int, poolstat_field_format_t *, char *);

/* statistics bags used to collect data from various provider	*/
static statistic_bag_t 	pool_sbag_s;
static statistic_bag_t 	pset_sbag_s;
static statistic_bag_t 	*pool_sbag = &pool_sbag_s;
static statistic_bag_t 	*pset_sbag = &pset_sbag_s;

/* formatter objects for pset, defined in a default printing sequence	*/
static poolstat_field_format_t pset_ffs[] = {
	/* prt flags,name,header,type,width,minwidth,offset,formatter	*/
	{ DX_FIELD, "id", "id", LL, 3, 1, addrof(pool_sbag),
		offsetof(statistic_bag_t, sb_sysid),
		(formatter)default_f },
	{ DX_FIELD, "pool", "pool", STR, 20, 14, addrof(pool_sbag),
		offsetof(statistic_bag_t, sb_name),
		(formatter)default_f },
	{ DX_FIELD, "type", "type", STR, 4, 5, addrof(pset_sbag),
		offsetof(statistic_bag_t, sb_type),
		(formatter)default_f },
	{ D_FIELD, "rid", "rid", LL, 3, 1, addrof(pset_sbag_s.bag),
		offsetof(pset_statistic_bag_t, pset_sb_sysid),
		(formatter)default_f },
	{ DX_FIELD, "rset", "rset", STR, 20, 14, addrof(pset_sbag),
		offsetof(statistic_bag_t, sb_name),
		(formatter)default_f },
	{ DX_FIELD, "min", "min", ULL, 4, 1, addrof(pset_sbag_s.bag),
		offsetof(pset_statistic_bag_t, pset_sb_min),
		(formatter)bigno_f },
	{ DX_FIELD, "max", "max", ULL, 4, 1, addrof(pset_sbag_s.bag),
		offsetof(pset_statistic_bag_t, pset_sb_max),
		(formatter)bigno_f },
	{ DX_FIELD, "size", "size", ULL, 4, 1, addrof(pset_sbag_s.bag),
		offsetof(pset_statistic_bag_t, pset_sb_size),
		(formatter)default_f },
	{ DX_FIELD, "used", "used", FL, 4, -1, addrof(pset_sbag_s.bag),
		offsetof(pset_statistic_bag_t, pset_sb_used),
		(formatter)used_stat_f },
	{ DX_FIELD, "load", "load", FL, 4, -1, addrof(pset_sbag_s.bag),
		offsetof(pset_statistic_bag_t, pset_sb_load),
		(formatter)default_f }
};

/* formatter objects for pool, defined in a default printing sequence	*/
static poolstat_field_format_t pool_ffs[] = {
	/* prt flags,name,header,type,width,minwidth,offset,formatter	*/
	{ D_FIELD, "id", "id", LL, 3, 1, addrof(pool_sbag),
		offsetof(statistic_bag_t, sb_sysid),
		(formatter)default_f },
	{ D_FIELD, "pool", "pool", STR, 20, 13, addrof(pool_sbag),
		offsetof(statistic_bag_t, sb_name),
		(formatter)default_f },
	{ D_FIELD, "p_size", "size", ULL, 4, 1, addrof(pset_sbag_s.bag),
		offsetof(pset_statistic_bag_t, pset_sb_size),
		(formatter)default_f },
	{ D_FIELD, "p_used", "used", FL, 4, -1, addrof(pset_sbag_s.bag),
		offsetof(pset_statistic_bag_t, pset_sb_used),
		(formatter)default_f },
	{ D_FIELD, "p_load", "load", FL, 4, -1, addrof(pset_sbag_s.bag),
		offsetof(pset_statistic_bag_t, pset_sb_load),
		(formatter)default_f },
};

/* lists with formatter objects, one for each statistics field */
static poolstat_line_format_t   pool_lf; /* formatting list in default mode */
static poolstat_line_format_t   pset_lf; /* formatting list for psets    */

/* name of pools to be shown */
static poolstat_list_element_t	*pnames;
/*
 * type of resources to be shown, currently we only have one type 'pset'
 * but, poolstat can be extended to handle new upcoming resource types.
 */
static poolstat_list_element_t   *rtypes;

/* a handle to the pool configuration	*/
static pool_conf_t *conf;

/* option flags		*/
static int 	rflag;
static int 	pflag;
static int 	oflag;

/* operands	*/
static int 	interval = 0;	/* update interval	*/
static long 	count    = 1; 	/* one run		*/

/* data structure handlers	*/
static poolstat_list_element_t *
	create_prt_sequence_list(char *, poolstat_line_format_t *);
static poolstat_list_element_t *
	create_args_list(char *, poolstat_list_element_t *, const char *);

/* statistics update function	*/
static void sa_update(statistic_bag_t *, int);

/* statistics printing function	*/
static void prt_pool_stats(poolstat_list_element_t *);

static void
usage(void)
{
	(void) fprintf(stderr, gettext(
"Usage:\n"
"poolstat [-p pool-list] [-r rset-list] [-T d|u] [interval [count]]\n"
"poolstat [-p pool-list] [-o format -r rset-list] [-T d|u] [interval [count]]\n"
"  \'pool-list\' is a space-separated list of pool IDs or names\n"
"  \'rset-list\' is \'all\' or \'pset\'\n"
"  \'format\' for all resource types is one or more of:\n"
"\tid pool type rid rset min max size used load\n"));
	(void) exit(E_USAGE);
}

static int
Atoi(char *p, int *errp)
{
	int i;
	char *q;
	errno = 0;
	i = strtol(p, &q, 10);
	if (errno != 0 || q == p || *q != '\0')
		*errp = -1;
	else
		*errp = 0;
	return (i);
}

int
main(int argc, char *argv[])
{
	char		c;
	int 		error = 0;

	(void) getpname(argv[0]);
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/* pset_sbag_s is used to collect pset statistics   */
	pset_sbag_s.sb_type = PSET_TYPE_NAME;
	pset_sbag_s.bag	= ZALLOC(sizeof (pset_statistic_bag_t));
	pool_sbag_s.sb_type = POOL_TYPE_NAME;

	pset_lf.plf_ffs = pset_ffs;
	pset_lf.plf_ff_len = sizeof (pset_ffs) /
	    sizeof (poolstat_field_format_t);
	pool_lf.plf_ffs = pool_ffs;
	pool_lf.plf_ff_len = sizeof (pool_ffs) /
	    sizeof (poolstat_field_format_t);

	/* Don't let buffering interfere with piped output. */
	(void) setvbuf(stdout, NULL, _IOLBF, 0);

	while ((c = getopt(argc, argv, ":p:r:o:T:")) != EOF) {
		switch (c) {
		case 'p':	/* pool name specification	*/
			pflag++;
			pnames = create_args_list(optarg, pnames,
			    " \t");
			break;
		case 'r': {	/* resource type 		*/
			rflag++;
			rtypes = create_args_list(optarg, rtypes,
			    " \t,");
			break;
			}
		case 'o': { 	/* format specification		*/
			oflag++;
			if (create_prt_sequence_list(optarg, &pset_lf) == NULL)
				usage();
			break;
			}
		case 'T':
			if (optarg) {
				if (*optarg == 'u')
					timestamp_fmt = UDATE;
				else if (*optarg == 'd')
					timestamp_fmt = DDATE;
				else
					usage();
			} else {
					usage();
			}
			break;
		case ':': {
			(void) fprintf(stderr,
			    gettext(ERR_OPTION_ARGS), optopt);
			usage();
			/*NOTREACHED*/
			}
		default:
			(void) fprintf(stderr, gettext(ERR_OPTION), optopt);
			usage();
			/*NOTREACHED*/
		}
	}

	/* get operands	*/
	if (argc > optind) {
		if ((interval = Atoi(argv[optind++], &error)) < 1 || error != 0)
			usage();
		count = -1;
	}
	if (argc > optind) {
		if ((count = Atoi(argv[optind++], &error)) < 1 || error != 0)
			usage();
	}
	/* check for extra options/operands	*/
	if (argc > optind)
		usage();

	/* check options	*/
	if (oflag && !rflag)
		usage();

	/* global initializations	*/
	if (!oflag) {
		/* create the default print sequences	*/
		(void) create_prt_sequence_list(NULL, &pool_lf);
		(void) create_prt_sequence_list(NULL, &pset_lf);
	}

	if (rtypes == NULL || strcmp(rtypes->ple_obj, "all") == 0) {
		/* crate a default resource list	*/
		FREE(rtypes);
		rtypes = create_args_list("pset", NULL, " \t,");
	}

	if ((conf = pool_conf_alloc()) == NULL)
		die(gettext(ERR_NOMEM));
	if (pool_conf_open(conf, pool_dynamic_location(), PO_RDONLY)
	    != PO_SUCCESS)
		die(gettext(ERR_OPEN_DYNAMIC), get_errstr());

	/* initialize statistic adapters	*/
	sa_libpool_init(conf);
	sa_kstat_init(NULL);

	/* collect and print out statistics	*/
	while (count-- != 0) {
		sa_update(pool_sbag, SA_REFRESH);
		if (timestamp_fmt != NODATE)
			print_timestamp(timestamp_fmt);
		if (pool_sbag->sb_changed & POU_POOL)
				(void) printf(
				"<<State change>>\n");
		prt_pool_stats(pnames);
		if (count != 0) {
			(void) sleep(interval);
			if (rflag)
				(void) printf("\n");
		}
	}

	return (E_PO_SUCCESS);
}

/*
 * Take the arguments and create/append a string list to the 'le' list.
 */
static poolstat_list_element_t  *
create_args_list(char *arg, poolstat_list_element_t  *le, const char *delim)
{
	poolstat_list_element_t *head = le;

	while (arg != NULL && *arg != '\0') {
		char *name = arg;
		arg = strpbrk(arg, delim);
		if (arg != NULL) {
			*arg++ = '\0';
		}
		if (le == NULL) {
			/* create first element */
			NEW0(le);
			head = le;
		} else {
			/* find last and append	*/
			while (le->ple_next != NULL)
				le = le->ple_next;
			NEW0(le->ple_next);
			le = le->ple_next;
		}
		le->ple_obj = (void *)name;
	}

	return (head);
}

/*
 * Take the arguments to the -o option, and create a format field list in order
 * specified by 'arg'.
 * If 'arg' is NULL a list in a default printing order is created.
 */
static poolstat_list_element_t *
create_prt_sequence_list(char *arg, poolstat_line_format_t *lf)
{
	/*
	 * Create a default print sequence. It is the sequence defined
	 * statically in the format list. At the same time mark the fields
	 * printable according to the current option settings.
	 */
	if (arg == NULL) {
		int	i;
		NEW0(lf->plf_prt_seq);
		lf->plf_ffs[0].pff_prt |= PRINTABLE(0) ? PABLE_FIELD : 0;
		lf->plf_last = lf->plf_prt_seq;
		lf->plf_last->ple_obj = &(lf->plf_ffs[0]);
		for (i = 1; i < lf->plf_ff_len; i++) {
			lf->plf_ffs[i].pff_prt |=
			    PRINTABLE(i) ? PABLE_FIELD : 0;
			NEW0(lf->plf_last->ple_next);
			lf->plf_last = lf->plf_last->ple_next;
			lf->plf_last->ple_obj = &(lf->plf_ffs[i]);
		}
		return (lf->plf_prt_seq);
	}

	while (arg != NULL && *arg != '\0') {
		poolstat_field_format_t *ff;	/* current format field */
		int 	ffIdx;	/* format field index	    */
		char 	*name;	/* name of field	    */
		int	n; 	/* no. of chars to strip    */

		n = strspn(arg, " ,\t\r\v\f\n");
		arg += n;	/* strip multiples separator	*/
		name = arg;

		if (strlen(name) < 1)
			break;

		if ((arg = strpbrk(arg, " ,\t\r\v\f\n")) != NULL)
			*arg++ = '\0';

		/* search for a named format field */
		for (ffIdx = 0; ffIdx < lf->plf_ff_len; ffIdx++) {
			ff = lf->plf_ffs + ffIdx;
			if (strcmp(ff->pff_name, name) == 0) {
				ff->pff_prt |= PABLE_FIELD;
				break;
			}
		}
		/* if the name wasn't found	*/
		if (ffIdx == lf->plf_ff_len) {
			(void) fprintf(stderr, gettext(ERR_UNSUPP_STAT_FIELD),
			    name);
			usage();
		}
		if (lf->plf_last == NULL) {
			/* create first print handle */
			NEW0(lf->plf_prt_seq);
			lf->plf_last = lf->plf_prt_seq;
		} else {
			NEW0(lf->plf_last->ple_next);
			lf->plf_last = lf->plf_last->ple_next;
		}
		lf->plf_last->ple_obj = ff; 	/* refer to the format field */
	}

	return (lf->plf_prt_seq);
}

/* update the statistic data by adapters	*/
static void
sa_update(statistic_bag_t *sbag, int flags)
{
	sa_libpool_update(sbag, flags);
	sa_kstat_update(sbag, flags);
}

/*
 * Format one statistic field and put it into the 'str' buffer. 'ff' contains
 * the field formatting parameters. Return the number of used bytes.
 */
static int
default_f(char *str, int pos, int left, poolstat_field_format_t *ff, char *data)
{
	int  used;

	switch (ff->pff_type) {
	case LL: {
			int64_t v;
			v = *((int64_t *)(void *)(data + ff->pff_offset));
			used = snprintf(str + pos, left, "%*.*lld",
			    ff->pff_width, ff->pff_minwidth, v);
		}
		break;
	case ULL: {
			uint64_t v;
			v = *((uint64_t *)(void *)(data + ff->pff_offset));
			used = snprintf(str + pos, left, "%*.*llu",
			    ff->pff_width, ff->pff_minwidth, v);
		};
		break;
	case FL: {
			int	pw = 0;
			double v = *((double *)(void *)(data + ff->pff_offset));
			if (v < 10) {
				pw = ff->pff_width - 2;
			} else if (v < 100) {
				pw = ff->pff_width - 3;
			} else if (v < 1000) {
				pw = ff->pff_width - 4;
			}
			if (pw < 0)
				pw = 0;
			used = snprintf(str + pos, left, "%*.*f",
			    ff->pff_width, pw, v);
		};
		break;
	case STR: {
			char 	*v;
			int 	sl;
			v = *((char **)(void *)(data + ff->pff_offset));
			sl = strlen(v);
			/* truncate if it doesn't fit	*/
			if (sl > ff->pff_width) {
				char *cp = v +  ff->pff_width - 1;
				if (ff->pff_width < 4)
					die(gettext(ERR_STATS_FORMAT),
					    ff->pff_header);
				*cp-- = 0;
				*cp-- = '.';
				*cp-- = '.';
				*cp-- = '.';
			}
			used = snprintf(str + pos, left, "%-*s", ff->pff_width,
			    v);
		}
		break;
	}

	return (used);
}

/* format big numbers */
static int
bigno_f(char *str, int pos, int left, poolstat_field_format_t *ff, char *data)
{
	uint64_t v;
	char	tag;
	int	pw = ff->pff_width - 4;
	double 	pv;
	int  	used;

	v = *((uint64_t *)(void *)(data + ff->pff_offset));
	/*
	 * the max value can be ULONG_MAX, which is formatted as:
	 * E  P   T   G   M   K
	 * 18 446 744 073 709 551 615
	 * As a result ULONG_MAX is displayed as 18E
	 */
	pv = v;
	if (v < 1000) {
		pw = 0;
	} else if (v < KILO * 10) {
		pv = (double)v / KILO;
		tag = 'K';
	} else if (v < KILO * 100) {
		pv = (double)v / KILO;
		tag = 'K'; pw -= 1;
	} else if (v < KILO * 1000) {
		pv = (double)v / KILO;
		tag = 'K'; pw -= 2;
	} else if (v < MEGA * 10) {
		pv = (double)v / MEGA;
		tag = 'M';
	} else if (v < MEGA * 100) {
		pv = (double)v / MEGA;
		tag = 'M'; pw -= 1;
	} else if (v < MEGA * 1000) {
		pv = (double)v / MEGA;
		tag = 'M'; pw -= 2;
	} else if (v < GIGA * 10) {
		pv = (double)v / GIGA;
		tag = 'G';
	} else if (v < GIGA * 100) {
		pv = (double)v / GIGA;
		tag = 'G'; pw -= 1;
	} else if (v < GIGA * 1000) {
		pv = (double)v / GIGA;
		tag = 'G'; pw -= 2;
	} else if (v < TERA * 10) {
		pv = (double)v / TERA;
		tag = 'T';
	} else if (v < TERA * 100) {
		pv = (double)v / TERA;
		tag = 'T'; pw -= 1;
	} else if (v < TERA * 1000) {
		pv = (double)v / TERA;
		tag = 'T'; pw -= 2;
	} else if (v < PETA * 10) {
		pv = (double)v / PETA;
		tag = 'P';
	} else if (v < PETA * 100) {
		pv = (double)v / PETA;
		tag = 'P'; pw -= 1;
	} else if (v < PETA * 1000) {
		pv = (double)v / PETA;
		tag = 'P'; pw -= 2;
	} else if (v < EXA * 10) {
		pv = (double)v / EXA;
		tag = 'E';
	} else if (v < EXA * 100) {
		pv = (double)v / EXA;
		tag = 'E'; pw -= 1;
	} else {
		pv = (double)v / EXA;
		tag = 'E'; pw -= 2;
	}
	if (pw < 0)
		pw = 0;
	if (v < 1000)
		used = snprintf(str + pos, left, "%*.*f",
		    ff->pff_width, pw, pv);
	else
		used = snprintf(str + pos, left, "%*.*f%c",
		    ff->pff_width - 1, pw, pv, tag);

	return (used);
}

/* format usage statistic, if configuration has changed print '-'. */
static int
used_stat_f(char *str, int pos, int left, poolstat_field_format_t *ff,
	char *data)
{
	int	pw = 0;
	double v = *((double *)(void *)(data + ff->pff_offset));
	int  	used;

	if (pool_sbag->sb_changed & POU_POOL) {
		used = snprintf(str + pos, left, "%*c", ff->pff_width, '-');
	} else {
		if (v < 10) {
			pw = ff->pff_width - 2;
		} else if (v < 100) {
			pw = ff->pff_width - 3;
		} else if (v < 1000) {
			pw = ff->pff_width - 4;
		}
		if (pw < 0)
			pw = 0;
		used = snprintf(str + pos, left, "%*.*f",
		    ff->pff_width, pw, v);
	}
	return (used);
}

/*
 * Format one header field and put it into the 'str' buffer.
 */
/*ARGSUSED*/
static int
header_f(char *str, int pos, int left, poolstat_field_format_t *ff, char *data)
{
	int  used = 0;

	if (ff->pff_type == STR)
		/* strings are left justified	*/
		used = snprintf(str + pos, left, "%-*s",
		    ff->pff_width, ff->pff_header);
	else
		used = snprintf(str + pos, left, "%*s",
		    ff->pff_width, ff->pff_header);
	return (used);
}

/*
 * Print one statistic line according to the definitions in 'lf'.
 */
static void
prt_stat_line(poolstat_line_format_t *lf)
{
	poolstat_list_element_t *le; 	/* list element in the print sequence */
	char 	*line;
	int 	pos	= 0;		/* position in the printed line	*/
	int 	len 	= MAXLINE;	/* the length of the line	*/
	int	left 	= len;		/* chars left to use in the line */

	line = ZALLOC(len);
	for (le = lf->plf_prt_seq; le; le = le->ple_next) {
		int used;
		poolstat_field_format_t *ff =
		    (poolstat_field_format_t *)le->ple_obj;
		/* if the filed is marked to be printed	*/
		if (ff->pff_prt & PABLE_FIELD) {
			if (((used = ff->pff_format(line, pos, left, ff,
			    *ff->pff_data_ptr)) + 1) >= left) {
				/* if field doesn't fit allocate new space */
				len += used + MAXLINE;
				left += used + MAXLINE;
				line = REALLOC(line, len);
				if (((used = ff->pff_format(line, pos, left, ff,
				    *ff->pff_data_ptr)) + 1) >= left)
					die(gettext(ERR_STATS_FORMAT), line);
			}
			left -= used;
			pos += used;
			if (le->ple_next != NULL) {
				/* separate columns with a space */
				line[pos++] = ' ';
				left--;
			}
		}
	}

	(void) printf("%s\n", line);
	FREE(line);
}

/*
 * Print a statistics header line for a given resource type.
 */
static void
prt_stat_hd(const char *type)
{
	poolstat_line_format_t	*lf;	/* line format	*/
	poolstat_list_element_t *le; 	/* list element in the print sequence */
	char 	*line;
	int 	pos	= 0;		/* position in the printed line	 */
	int 	len 	= MAXLINE;	/* the length of the line	 */
	int	left 	= len;		/* chars left to use in the line */

	if (strcmp(type, POOL_TYPE_NAME) == 0) {
		/* pool format needs an extra header	*/
		(void) printf("%*s\n", 19 + 15, "pset");
		lf = &pool_lf;
	} else if (strcmp(type, PSET_TYPE_NAME) == 0) {
		lf = &pset_lf;
	} else {
		die(gettext(ERR_UNSUPP_RTYPE), type);
	}
	line = ZALLOC(len);
	for (le = lf->plf_prt_seq; le; le = le->ple_next) {
		int used;	/* used chars in line	*/
		poolstat_field_format_t *ff =
		    (poolstat_field_format_t *)le->ple_obj;
		/* if the filed is marked to be printed	*/
		if (ff->pff_prt& PABLE_FIELD) {
			if (((used = header_f(line, pos, left, ff, NULL)) + 1)
			    >= left) {
				/* if field doesn't fit allocate new space */
				len += used + MAXLINE;
				left += used + MAXLINE;
				line = REALLOC(line, len);
				if (((used = header_f(line, pos, left, ff,
				    NULL)) + 1) >= left)
					die(gettext(ERR_STATS_FORMAT), line);
			}
			left -= used;
			pos += used;
			if (le->ple_next != NULL) {
				/* separate columns with a space */
				line[pos++] = ' ';
				left--;
			}
		}
	}

	/* only header line with non space characters should be printed */
	pos = 0;
	while (*(line + pos) != '\n') {
		if (!isspace(*(line + pos))) {
			(void) printf("%s\n", line);

			break;
		}
		pos++;
	}
	FREE(line);
}

/*
 * Create a pool value instance and set its name to 'name'.
 */
static pool_value_t *
create_pool_value(const char *name)
{
	pool_value_t *pval;

	if ((pval = pool_value_alloc()) == NULL) {
		return (NULL);
	}
	if (pool_value_set_name(pval, name) != PO_SUCCESS) {
		pool_value_free(pval);
		return (NULL);
	}

	return (pval);
}

/*
 * Find all resources of type 'rtype'.
 * If 'pool_name' is defined find all resources bound to this pool.
 */
static pool_resource_t **
get_resources(const char *pool_name, const char *rtype, uint_t *nelem)
{
	pool_resource_t **resources = NULL;
	pool_value_t 	*pvals[] = { NULL, NULL, NULL};
	pool_value_t 	*pv_sys_id;
	pool_value_t 	*pv_name;
	char		*name_prop; /* set name property	*/

	if (strcmp(rtype, PSET_TYPE_NAME) == 0) {
		if ((pv_sys_id = create_pool_value(PSET_SYSID)) == NULL)
			goto on_error;
		name_prop = PSET_NAME;
	} else {
		die(gettext(ERR_UNSUPP_RTYPE), rtype);
	}

	if ((pvals[0] = create_pool_value("type")) == NULL)
		goto on_error;
	if ((pool_value_set_string(pvals[0], rtype)) == -1)
		goto on_error;

	if ((pv_name = create_pool_value(name_prop)) == NULL)
		goto on_error;

	if (pool_name != NULL) {
		/* collect resources associated to 'pool_name'	*/
		pool_t 	*pool;
		if ((pool = pool_get_pool(conf, pool_name)) == NULL)
			die(gettext(ERR_STATS_POOL_N), pool_name);
		if ((resources = pool_query_pool_resources(
		    conf, pool, nelem, pvals)) == NULL)
			goto on_error;
	} else {
		/* collect all resources  */
		if ((resources =
		    pool_query_resources(conf, nelem, pvals)) == NULL)
			goto on_error;
	}

	if (pv_name != NULL)
		pool_value_free(pv_name);
	if (pv_sys_id != NULL)
		pool_value_free(pv_sys_id);
	if (pvals[0] != NULL)
		pool_value_free(pvals[0]);

	return (resources);
on_error:
	die(gettext(ERR_STATS_RES), get_errstr());
	/*NOTREACHED*/
}

/*
 * Print statistics for all resources of type 'rtype' passed in 'resources'.
 */
static void
prt_resource_stats_by_type(pool_resource_t **resources, const char *rtype)
{
	int		i;
	pool_elem_t	*elem;
	pool_value_t 	*pv_name;
	char		*name_prop;

	poolstat_line_format_t	*lf;
	statistic_bag_t		*sbag;

	if (strcmp(rtype, PSET_TYPE_NAME) == 0) {
		name_prop = PSET_NAME;
		lf = &pset_lf;
		sbag = pset_sbag;
	} else {
		die(gettext(ERR_UNSUPP_RTYPE), rtype);
	}

	if ((pv_name = create_pool_value(name_prop)) == NULL)
		goto on_error;

	/* collect and print statistics for the given resources	*/
	for (i = 0; resources[i] != NULL; i++) {
		if ((elem = pool_resource_to_elem(conf, resources[i])) == NULL)
			goto on_error;
		if (pool_get_property(conf, elem, name_prop, pv_name) == -1)
			goto on_error;
		if (pool_value_get_string(pv_name, &sbag->sb_name) == -1)
			goto on_error;
		sa_update(sbag, 0);

		prt_stat_line(lf);
	}

	if (pv_name != NULL)
		pool_value_free(pv_name);
	return;
on_error:
	die(gettext(ERR_STATS_RES), get_errstr());
}

/*
 * Update statistics for all resources of type 'rtype' pased in 'resources'.
 */
static void
update_resource_stats(pool_resource_t *resource, const char *rtype)
{
	pool_elem_t	*elem;
	pool_value_t 	*pv_name;
	char		*name_prop; 		/* set name property	*/

	statistic_bag_t	*sbag;

	if (strcmp(rtype, PSET_TYPE_NAME) == 0) {
		name_prop = PSET_NAME;
		sbag 	= pset_sbag;
	} else {
		die(gettext(ERR_UNSUPP_RTYPE), rtype);
	}

	if ((pv_name = create_pool_value(name_prop)) == NULL)
		goto on_error;

	if ((elem = pool_resource_to_elem(conf, resource)) == NULL)
		goto on_error;
	if (pool_get_property(conf, elem, name_prop, pv_name) == -1)
		goto on_error;
	if (pool_value_get_string(pv_name, &sbag->sb_name) == -1)
		goto on_error;
	sa_update(sbag, 0);

	if (pv_name != NULL)
		pool_value_free(pv_name);
	return;

on_error:
	die(gettext(ERR_STATS_RES), get_errstr());
}

/*
 * For each pool in the configuration print statistics of associated resources.
 * If the pool name list 'pn' is defined, only print resources of pools
 * specified in the list. The list can specify the pool name or its system id.
 */
static void
prt_pool_stats(poolstat_list_element_t *pn)
{
	uint_t 		nelem;
	pool_elem_t	*elem;
	int		i;
	int 		error;
	pool_t 		**pools = NULL;
	pool_value_t 	*pvals[] = { NULL, NULL };
	pool_value_t 	*pv_name = NULL;
	pool_value_t 	*pv_sys_id = NULL;
	statistic_bag_t	*sbag = pool_sbag;
	poolstat_list_element_t 	*rtype;
	pool_resource_t **resources;

	if ((pv_sys_id = create_pool_value(POOL_SYSID)) == NULL)
		goto on_error;
	if ((pv_name = create_pool_value(POOL_NAME)) == NULL)
		goto on_error;

	if (pn == NULL) {
		/* collect all pools	*/
		if ((pools = pool_query_pools(conf, &nelem, NULL)) == NULL)
			goto on_error;
	} else {
		/*
		 * collect pools specified in the 'pn' list.
		 * 'poolid' the pool identifier can be a pool name or sys_id.
		 */
		poolstat_list_element_t	*poolid;
		for (poolid = pn, i = 1; poolid; poolid = poolid->ple_next)
			i++;
		pools = ZALLOC(sizeof (pool_t *) * (i + 1));
		for (poolid = pn, i = 0; poolid;
		    poolid = poolid->ple_next, i++) {
			pool_t **pool;
			int64_t sysid = Atoi(poolid->ple_obj, &error);
			if (error == 0) {
				/* the pool is identified by sys_id	*/
				pool_value_set_int64(pv_sys_id, sysid);
				pvals[0] = pv_sys_id;
				pool = pool_query_pools(conf, &nelem, pvals);
			} else {
				if (pool_value_set_string(pv_name,
				    poolid->ple_obj) == -1)
					die(gettext(ERR_NOMEM));
				pvals[0] = pv_name;
				pool = pool_query_pools(conf, &nelem, pvals);
			}
			if (pool == NULL)
				die(gettext(ERR_STATS_POOL_N), poolid->ple_obj);
			pools[i] = pool[0];
			FREE(pool);
		}
	}

	/* print statistic for all pools found		*/
	if (!rflag) {
		/* print the common resource header 	*/
		prt_stat_hd(POOL_TYPE_NAME);

		/* print statistics for the resources bound to the pools */
		for (i = 0; pools[i] != NULL; i++) {
			elem = pool_to_elem(conf, pools[i]);
			if (pool_get_property(conf, elem, POOL_NAME, pv_name)
			    == -1)
				goto on_error;
			if (pool_value_get_string(pv_name, &sbag->sb_name) != 0)
				goto on_error;
			if (pool_get_property(
			    conf, elem, "pool.sys_id", pv_sys_id) == -1)
				goto on_error;
			if (pool_value_get_int64(
			    pv_sys_id, &sbag->sb_sysid) != 0)
				goto on_error;

			for (rtype = rtypes; rtype; rtype = rtype->ple_next) {
				resources = get_resources(
				    sbag->sb_name, rtype->ple_obj, &nelem);
				update_resource_stats(*resources,
				    rtype->ple_obj);
				FREE(resources);
			}
			prt_stat_line(&pool_lf);
		}
	} else {
		/* print statistic for all resource types defined in rtypes */
		for (rtype = rtypes; rtype; rtype = rtype->ple_next) {
			prt_stat_hd(rtype->ple_obj);
			for (i = 0; pools[i] != NULL; i++) {
				elem = pool_to_elem(conf, pools[i]);
				if (pool_get_property(
				    conf, elem, POOL_NAME, pv_name) == -1)
					goto on_error;
				if (pool_value_get_string(
				    pv_name, &sbag->sb_name) != 0)
					goto on_error;
				if (pool_get_property(
				    conf, elem, POOL_SYSID, pv_sys_id) == -1)
					goto on_error;
				if (pool_value_get_int64(
				    pv_sys_id, &sbag->sb_sysid) != 0)
					goto on_error;
				resources = get_resources(
				    sbag->sb_name, rtype->ple_obj, &nelem);
				if (resources == NULL)
					continue;
				update_resource_stats(
				    *resources, rtype->ple_obj);
				prt_resource_stats_by_type(resources,
				    rtype->ple_obj);
				FREE(resources);
			}
		}
	}

	FREE(pools);
	if (pv_name != NULL)
		pool_value_free(pv_name);
	if (pv_sys_id != NULL)
		pool_value_free(pv_sys_id);

	return;
on_error:
	die(gettext(ERR_STATS_POOL), get_errstr());
}
