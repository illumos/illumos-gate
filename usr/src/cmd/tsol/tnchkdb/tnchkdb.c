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

/*
 * tnchkdb.c - Trusted network database checking utility
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <locale.h>
#include <malloc.h>
#include <string.h>
#include <libtsnet.h>
#include <netinet/in.h>
#include <nss_dbdefs.h>

static void usage(void);
static void check_tnrhtp(const char *);
static void check_tnrhdb(const char *);
static void check_tnzonecfg(const char *);

static boolean_t tnrhtp_bad;
static int exitval;

struct tsol_name_list {
	struct tsol_name_list *next;
	int linenum;
	char name[TNTNAMSIZ];
};

struct tsol_addr_list {
	struct tsol_addr_list *next;
	int linenum;
	int prefix_len;
	in6_addr_t addr;
};

static struct tsol_name_list *tp_list_head;
static struct tsol_addr_list *rh_list_head;
static struct tsol_name_list *zc_list_head;

typedef struct mlp_info_list_s {
	struct mlp_info_list_s *next;
	int linenum;
	tsol_mlp_t mlp;
	char name[TNTNAMSIZ];
} mlp_info_list_t;

static mlp_info_list_t *global_mlps;

static void
add_name(struct tsol_name_list **head, const char *name, int linenum)
{
	int err;
	struct tsol_name_list *entry;

	entry = malloc(sizeof (struct tsol_name_list));
	if (entry == NULL) {
		err = errno;

		(void) fprintf(stderr,
		    gettext("tnchkdb: allocating name list: %s\n"),
		    strerror(err));
		exit(1);
	}
	(void) strlcpy(entry->name, name, sizeof (entry->name));
	entry->next = *head;
	entry->linenum = linenum;
	*head = entry;
}

static struct tsol_name_list *
find_name(struct tsol_name_list *head, const char *name)
{
	struct tsol_name_list *entry;

	for (entry = head; entry != NULL; entry = entry->next)
		if (strcmp(entry->name, name) == 0)
			break;
	return (entry);
}

static void
add_addr(struct tsol_addr_list **head, int prefix_len, in6_addr_t addr,
    int linenum)
{
	int err;
	struct tsol_addr_list *entry;

	entry = malloc(sizeof (struct tsol_addr_list));
	if (entry == NULL) {
		err = errno;

		(void) fprintf(stderr,
		    gettext("tnchkdb: allocating addr list: %s\n"),
		    strerror(err));
		exit(2);
	}
	entry->prefix_len = prefix_len;
	entry->addr = addr;
	entry->next = *head;
	entry->linenum = linenum;
	*head = entry;
}

static struct tsol_addr_list *
find_addr(struct tsol_addr_list *head, int prefix_len, in6_addr_t addr)
{
	struct tsol_addr_list *entry;

	for (entry = head; entry != NULL; entry = entry->next)
		if (entry->prefix_len == prefix_len &&
		    IN6_ARE_ADDR_EQUAL(&entry->addr, &addr))
			break;
	return (entry);
}

static void
add_template(const char *name, int linenum)
{
	add_name(&tp_list_head, name, linenum);
}

static struct tsol_name_list *
find_template(const char *name)
{
	return (find_name(tp_list_head, name));
}

static void
add_host(int prefix_len, in6_addr_t addr, int linenum)
{
	add_addr(&rh_list_head, prefix_len, addr, linenum);
}

static struct tsol_addr_list *
find_host(int prefix_len, in6_addr_t addr)
{
	return (find_addr(rh_list_head, prefix_len, addr));
}

static void
add_zone(const char *name, int linenum)
{
	add_name(&zc_list_head, name, linenum);
}

static struct tsol_name_list *
find_zone(const char *name)
{
	return (find_name(zc_list_head, name));
}

int
main(int argc, char **argv)
{
	const char *tnrhdb_file = TNRHDB_PATH;
	const char *tnrhtp_file = TNRHTP_PATH;
	const char *tnzonecfg_file = TNZONECFG_PATH;
	int chr;

	/* set the locale for only the messages system (all else is clean) */
	(void) setlocale(LC_ALL, "");
#ifndef TEXT_DOMAIN		/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it wasn't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((chr = getopt(argc, argv, "h:t:z:")) != EOF) {
		switch (chr) {
		case 'h':
			tnrhdb_file = optarg;
			break;
		case 't':
			tnrhtp_file = optarg;
			break;
		case 'z':
			tnzonecfg_file = optarg;
			break;
		default:
			usage();
		}
	}

	check_tnrhtp(tnrhtp_file);
	check_tnrhdb(tnrhdb_file);
	check_tnzonecfg(tnzonecfg_file);

	return (exitval);
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "usage: tnchkdb [-h path] [-t path] [-z path]\n"));
	exit(2);
}

static void
print_error(int linenum, int err, const char *errstr)
{
	(void) fprintf(stderr, gettext("line %1$d: %2$s: %.32s\n"), linenum,
	    tsol_strerror(err, errno), errstr);
}

static void
cipso_representable(const bslabel_t *lab, int linenum, const char *template,
    const char *name)
{
	const _blevel_impl_t *blab = (const _blevel_impl_t *)lab;
	int lclass;
	uint32_t c8;

	if (!bltype(lab, SUN_SL_ID)) {
		(void) fprintf(stderr, gettext("tnchkdb: "
		    "%1$s type %2$d is invalid for cipso labels: "
		    "line %3$d entry %4$s\n"), name, GETBLTYPE(lab), linenum,
		    template);
		exitval = 1;
	}
	lclass = LCLASS(blab);
	if (lclass & 0xff00) {
		(void) fprintf(stderr, gettext("tnchkdb: "
		    "%1$s classification %2$x is invalid for cipso labels: "
		    "line %3$d entry %4$s\n"), name, lclass, linenum,
		    template);
		exitval = 1;
	}
	c8 = blab->compartments.c8;
#ifdef  _BIG_ENDIAN
	if (c8 & 0x0000ffff) {
#else
	if (c8 & 0xffff0000) {
#endif
		(void) fprintf(stderr, gettext("tnchkdb: %1$s "
		    "compartments 241-256 must be zero for cipso labels: "
		    "line %2$d entry %3$s\n"), name, linenum, template);
		exitval = 1;
	}
}

static void
check_tnrhtp(const char *file)
{
	tsol_tpent_t *tpentp;
	tsol_tpstr_t tpstr;
	int err;
	char *errstr;
	FILE *fp;
	blevel_t *l1, *l2;
	char line[2048], *cp;
	int linenum = 0;
	struct tsol_name_list *tnl;
	char buf[NSS_BUFLEN_TSOL_TP];
	uint32_t initial_doi = 0;
	boolean_t multiple_doi_found = B_FALSE;
	boolean_t doi_zero_found = B_FALSE;

	(void) printf(gettext("checking %s ...\n"), file);

	if ((fp = fopen(file, "r")) == NULL) {
		err = errno;
		(void) fprintf(stderr,
		    gettext("tnchkdb: failed to open %1$s: %2$s\n"), file,
		    strerror(err));
		exitval = 2;
		tnrhtp_bad = B_TRUE;
		return;
	}

	while (fgets(line, sizeof (line), fp) != NULL) {
		linenum++;
		if (line[0] == '#')
			continue;
		if ((cp = strchr(line, '\n')) != NULL)
			*cp = '\0';
		(void) str_to_tpstr(line, strlen(line), &tpstr, buf,
		    sizeof (buf));
		tpentp = tpstr_to_ent(&tpstr, &err, &errstr);
		if (tpentp == NULL) {
			if (err == LTSNET_EMPTY)
				continue;
			print_error(linenum, err, errstr);
			exitval = 1;
			/*
			 * Flag is set *only* for parsing errors, which result
			 * in omitting the entry from tsol_name_list.
			 */
			tnrhtp_bad = B_TRUE;
			continue;
		}

		switch (tpentp->host_type) {
		case UNLABELED:
			/*
			 * check doi
			 */
			if (initial_doi == 0)
				initial_doi = tpentp->tp_cipso_doi_unl;
			if (tpentp->tp_cipso_doi_unl != initial_doi)
				multiple_doi_found = B_TRUE;
			if (tpentp->tp_cipso_doi_unl == 0)
				doi_zero_found = B_TRUE;

			cipso_representable(&tpentp->tp_def_label, linenum,
			    tpentp->name, TP_DEFLABEL);

			/*
			 * check max_sl dominates min_sl
			 */
			l1 = &tpentp->tp_gw_sl_range.lower_bound;
			l2 = &tpentp->tp_gw_sl_range.upper_bound;
			if (!bldominates(l2, l1)) {
				(void) fprintf(stderr,
				    gettext("tnchkdb: max_sl does not "
				    "dominate min_sl: line %$1d entry %2$s\n"),
				    linenum, tpentp->name);
				exitval = 1;
			}

			cipso_representable(l1, linenum, tpentp->name,
			    TP_MINLABEL);
			l1 = (blevel_t *)&tpentp->tp_gw_sl_set[0];
			l2 = (blevel_t *)&tpentp->tp_gw_sl_set[NSLS_MAX];
			for (; l1 < l2; l1++) {
				if (bisinvalid(l1))
					break;
				cipso_representable(l1, linenum, tpentp->name,
				    TP_SET);
			}
			break;

		case SUN_CIPSO:
			/*
			 * check max_sl dominates min_sl
			 */
			l1 = &tpentp->tp_sl_range_cipso.lower_bound;
			l2 = &tpentp->tp_sl_range_cipso.upper_bound;
			if (!bldominates(l2, l1)) {
				(void) fprintf(stderr,
				    gettext("tnchkdb: max_sl does not "
				    "dominate min_sl: line %$1d entry %2$s\n"),
				    linenum, tpentp->name);
				exitval = 1;
			}

			cipso_representable(l1, linenum, tpentp->name,
			    TP_MINLABEL);

			l1 = (blevel_t *)&tpentp->tp_sl_set_cipso[0];
			l2 = (blevel_t *)&tpentp->tp_sl_set_cipso[NSLS_MAX];
			for (; l1 < l2; l1++) {
				if (bisinvalid(l1))
					break;
				cipso_representable(l1, linenum, tpentp->name,
				    TP_SET);
			}

			/*
			 * check doi
			 */
			if (initial_doi == 0)
				initial_doi = tpentp->tp_cipso_doi_cipso;
			if (tpentp->tp_cipso_doi_cipso != initial_doi)
				multiple_doi_found = B_TRUE;
			if (tpentp->tp_cipso_doi_cipso == 0)
				doi_zero_found = B_TRUE;
			break;

		default:
			(void) fprintf(stderr, gettext("tnchkdb: unknown host "
			    "type %$1d: line %2$d entry %3$s\n"),
			    tpentp->host_type, linenum, tpentp->name);
			exitval = 1;
		} /* switch */

		/*
		 * check if a duplicated entry
		 */
		if ((tnl = find_template(tpentp->name)) != NULL) {
			(void) fprintf(stderr, gettext("tnchkdb: duplicated "
			    "entry: %1$s at lines %2$d and %3$d\n"),
			    tpentp->name, tnl->linenum, linenum);
			exitval = 1;
		} else {
			add_template(tpentp->name, linenum);
		}
		tsol_freetpent(tpentp);
	}
	if (multiple_doi_found == B_TRUE) {
		(void) fprintf(stderr,
		    gettext("tnchkdb: Warning: tnrhtp entries do not all "
		    "contain the same DOI value\n"));
	}
	if (doi_zero_found == B_TRUE) {
		(void) fprintf(stderr,
		    gettext("tnchkdb: Warning: DOI=0 found in some "
		    "tnrhtp entries\n"));
	}
	(void) fclose(fp);
}

static void
check_tnrhdb(const char *file)
{
	tsol_rhent_t *rhentp;
	tsol_rhstr_t rhstr;
	int err;
	char *errstr;
	FILE *fp;
	char line[2048], *cp;
	int linenum;
	in6_addr_t addr;
	struct tsol_addr_list *tal;
	char buf[NSS_BUFLEN_TSOL_RH];

	(void) printf(gettext("checking %s ...\n"), file);

	if ((fp = fopen(file, "r")) == NULL) {
		err = errno;
		(void) fprintf(stderr,
		    gettext("tnchkdb: failed to open %s: %s\n"), file,
		    strerror(err));
		exitval = 2;
		return;
	}

	/*
	 * check that all templates used in tnrhdb file are defined by tnrhtp
	 */
	linenum = 0;
	while (fgets(line, sizeof (line), fp) != NULL) {
		linenum++;
		if (line[0] == '#')
			continue;
		if ((cp = strchr(line, '\n')) != NULL)
			*cp = '\0';
		(void) str_to_rhstr(line, strlen(line), &rhstr, buf,
		    sizeof (buf));
		rhentp = rhstr_to_ent(&rhstr, &err, &errstr);
		if (rhentp == NULL) {
			if (err == LTSNET_EMPTY)
				continue;
			print_error(linenum, err, errstr);
			exitval = 1;
			continue;
		}

		if (rhentp->rh_address.ta_family == AF_INET) {
			IN6_INADDR_TO_V4MAPPED(&rhentp->rh_address.ta_addr_v4,
			    &addr);
		} else {
			addr = rhentp->rh_address.ta_addr_v6;
		}
		if ((tal = find_host(rhentp->rh_prefix, addr)) != NULL) {
			(void) fprintf(stderr,
			    gettext("tnchkdb: duplicate entry: lines %1$d and "
			    "%2$d\n"), tal->linenum, linenum);
			exitval = 1;
		} else {
			add_host(rhentp->rh_prefix, addr, linenum);
		}

		if (!tnrhtp_bad && find_template(rhentp->rh_template) == NULL) {
			(void) fprintf(stderr,
			    gettext("tnchkdb: unknown template name: %1$s at "
			    "line %2$d\n"), rhentp->rh_template, linenum);
			exitval = 1;
		}

		tsol_freerhent(rhentp);
	}
	(void) fclose(fp);
}

static void
check_mlp_conflicts(tsol_mlp_t *mlps, boolean_t isglobal, const char *name,
    int linenum)
{
	tsol_mlp_t *mlpptr, *mlp2;
	mlp_info_list_t *mil;

	for (mlpptr = mlps; !TSOL_MLP_END(mlpptr); mlpptr++) {
		if (mlpptr->mlp_port_upper == 0)
			mlpptr->mlp_port_upper = mlpptr->mlp_port;

		/* First, validate against self for duplicates */
		for (mlp2 = mlps; mlp2 < mlpptr; mlp2++) {
			if (mlp2->mlp_ipp == mlpptr->mlp_ipp &&
			    !(mlp2->mlp_port_upper < mlpptr->mlp_port ||
			    mlp2->mlp_port > mlpptr->mlp_port_upper))
				break;
		}

		if (mlp2 < mlpptr) {
			(void) fprintf(stderr, gettext("tnchkdb: self-overlap "
			    "of %1$s MLP protocol %2$d port %3$d-%4$d with "
			    "%5$d-%6$d: zone %7$s line %8$d\n"),
			    gettext(isglobal ? "global" : "zone-specific"),
			    mlpptr->mlp_ipp, mlpptr->mlp_port,
			    mlpptr->mlp_port_upper, mlp2->mlp_port,
			    mlp2->mlp_port_upper, name, linenum);
			exitval = 1;
		}

		if (isglobal) {
			/* Next, validate against list for duplicates */
			for (mil = global_mlps; mil != NULL; mil = mil->next) {
				if (strcmp(mil->name, name) == 0)
					continue;
				if (mil->mlp.mlp_ipp == mlpptr->mlp_ipp &&
				    !(mil->mlp.mlp_port_upper <
				    mlpptr->mlp_port ||
				    mil->mlp.mlp_port >
				    mlpptr->mlp_port_upper))
					break;
			}

			if (mil != NULL) {
				(void) fprintf(stderr, gettext("tnchkdb: "
				    "overlap of global MLP protocol %2$d port "
				    "%3$d-%4$d with zone %$5s %6$d-%7$d: zone "
				    "%8$s lines %9$d and %10$d\n"),
				    mlpptr->mlp_ipp, mlpptr->mlp_port,
				    mlpptr->mlp_port_upper, mil->name,
				    mil->mlp.mlp_port, mil->mlp.mlp_port_upper,
				    name, mil->linenum, linenum);
				exitval = 1;
			}

			/* Now throw into list */
			if ((mil = malloc(sizeof (*mil))) == NULL) {
				(void) fprintf(stderr, gettext("tnchkdb: "
				    "malloc error: %s\n"), strerror(errno));
				exit(2);
			}
			(void) strlcpy(mil->name, name, sizeof (mil->name));
			mil->linenum = linenum;
			mil->mlp = *mlpptr;
			mil->next = global_mlps;
			global_mlps = mil;
		}
	}
}

static void
check_tnzonecfg(const char *file)
{
	tsol_zcent_t *zc;
	int err;
	char *errstr;
	FILE *fp;
	char line[2048], *cp;
	int linenum;
	boolean_t saw_global;
	struct tsol_name_list *tnl;

	(void) printf(gettext("checking %s ...\n"), file);

	if ((fp = fopen(file, "r")) == NULL) {
		err = errno;
		(void) fprintf(stderr,
		    gettext("tnchkdb: failed to open %s: %s\n"), file,
		    strerror(err));
		exitval = 2;
		return;
	}

	saw_global = B_FALSE;
	linenum = 0;
	while (fgets(line, sizeof (line), fp) != NULL) {
		if ((cp = strchr(line, '\n')) != NULL)
			*cp = '\0';

		linenum++;
		if ((zc = tsol_sgetzcent(line, &err, &errstr)) == NULL) {
			if (err == LTSNET_EMPTY)
				continue;
			print_error(linenum, err, errstr);
			exitval = 1;
			continue;
		}

		cipso_representable(&zc->zc_label, linenum, zc->zc_name,
		    "label");

		if (strcmp(zc->zc_name, "global") == 0)
			saw_global = B_TRUE;

		if ((tnl = find_zone(zc->zc_name)) != NULL) {
			(void) fprintf(stderr,
			    gettext("tnchkdb: duplicate zones: %1$s at lines "
			    "%2$d and %3$d\n"), zc->zc_name, tnl->linenum,
			    linenum);
			exitval = 1;
		} else {
			add_zone(zc->zc_name, linenum);
		}

		if (zc->zc_private_mlp != NULL)
			check_mlp_conflicts(zc->zc_private_mlp, B_FALSE,
			    zc->zc_name, linenum);
		if (zc->zc_shared_mlp != NULL)
			check_mlp_conflicts(zc->zc_shared_mlp, B_TRUE,
			    zc->zc_name, linenum);

		tsol_freezcent(zc);
	}
	(void) fclose(fp);

	if (!saw_global) {
		(void) fprintf(stderr, gettext("tnchkdb: missing required "
		    "entry for global zone in %s\n"), file);
		exitval = 1;
	}
}
