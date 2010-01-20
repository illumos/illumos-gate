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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * tninfo.c - Trusted network reporting utility
 */
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <stdlib.h>
#include <libtsnet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <tsol/label.h>
#include <zone.h>

static void usage(void);
static int print_rhtp(const char *);
static int print_rh(const char *);
static int print_mlp(const char *);

int
main(int argc, char *argv[])
{
	int chr;
	int ret = 0; /* return code */

	/* set the locale for only the messages system (all else is clean) */
	(void) setlocale(LC_ALL, "");
#ifndef TEXT_DOMAIN		/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif

	(void) textdomain(TEXT_DOMAIN);

	if (argc <= 1)
		usage();

	while ((chr = getopt(argc, argv, "h:m:t:")) != EOF) {
		switch (chr) {
		case 'h':
			ret |= print_rh(optarg);
			break;
		case 'm':
			ret |= print_mlp(optarg);
			break;
		case 't':
			ret |= print_rhtp(optarg);
			break;
		default:
			usage();
		}
	}

	return (ret);
}

static void
usage(void)
{
	(void) fprintf(stderr, gettext("usage: tninfo [-h host_name] "
	    "[-m zone_name] [-t template_name]\n"));
	exit(1);
}

static void
l_to_str(const m_label_t *l, char **str, int ltype)
{
	if (label_to_str(l, str, ltype, DEF_NAMES) != 0)
		*str = strdup(gettext("translation failed"));
}

static int
print_rhtp(const char *rhtp_name)
{
	tsol_tpent_t tp;
	char *str, *str2;
	const m_label_t *l1, *l2;
	int i;

	(void) strlcpy(tp.name, rhtp_name, sizeof (tp.name));

	if (tnrhtp(TNDB_GET, &tp) != 0) {
		if (errno == ENOENT)
			(void) fprintf(stderr, gettext("tninfo: tnrhtp entry "
			    "%1$s does not exist\n"), tp.name);
		else
			(void) fprintf(stderr,
			    gettext("tninfo: tnrhtp TNDB_GET(%1$s) failed: "
			    "%2$s\n"), tp.name, strerror(errno));
		return (1);
	}

	(void) printf("=====================================\n");
	(void) printf(gettext("Remote Host Template Table Entries:\n"));

	(void) printf("__________________________\n");
	(void) printf(gettext("template: %s\n"), tp.name);

	switch (tp.host_type) {
	case UNLABELED:
		(void) printf(gettext("host_type: UNLABELED\n"));
		(void) printf(gettext("doi: %d\n"), tp.tp_doi);

		if (tp.tp_mask_unl & TSOL_MSK_DEF_LABEL) {
			l_to_str(&tp.tp_def_label, &str, M_LABEL);
			l_to_str(&tp.tp_def_label, &str2, M_INTERNAL);
			(void) printf(gettext("def_label: %s\nhex: %s\n"),
			    str, str2);
			free(str);
			free(str2);
		}

		if (tp.tp_mask_unl & TSOL_MSK_SL_RANGE_TSOL) {
			(void) printf(gettext("For routing only:\n"));
			l_to_str(&tp.tp_gw_sl_range.lower_bound,
			    &str, M_LABEL);
			l_to_str(&tp.tp_gw_sl_range.lower_bound,
			    &str2, M_INTERNAL);
			(void) printf(gettext("min_sl: %s\nhex: %s\n"),
			    str, str2);
			free(str);
			free(str2);

			l_to_str(&tp.tp_gw_sl_range.upper_bound,
			    &str, M_LABEL);
			l_to_str(&tp.tp_gw_sl_range.upper_bound,
			    &str2, M_INTERNAL);
			(void) printf(gettext("max_sl: %s\nhex: %s\n"),
			    str, str2);
			free(str);
			free(str2);

			l1 = (const m_label_t *)&tp.tp_gw_sl_set[0];
			l2 = (const m_label_t *)&tp.tp_gw_sl_set[NSLS_MAX];
			for (i = 0; l1 < l2; l1++, i++) {
				if (label_to_str(l1, &str2, M_INTERNAL,
				    DEF_NAMES) != 0)
					break;
				l_to_str(l1, &str, M_LABEL);
				(void) printf(gettext("sl_set[%1$d]: %2$s\n"
				    "hex: %3$s\n"), i, str, str2);
				free(str);
				free(str2);
			}
		}
		break;

	case SUN_CIPSO:
		(void) printf(gettext("host_type: CIPSO\n"));
		(void) printf(gettext("doi: %d\n"), tp.tp_doi);
		if (tp.tp_mask_cipso & TSOL_MSK_SL_RANGE_TSOL) {
			l_to_str(&tp.tp_sl_range_cipso.lower_bound,
			    &str, M_LABEL);
			l_to_str(&tp.tp_sl_range_cipso.lower_bound,
			    &str2, M_INTERNAL);

			(void) printf(gettext("min_sl: %s\nhex: %s\n"),
			    str, str2);
			free(str);
			free(str2);

			l_to_str(&tp.tp_sl_range_cipso.upper_bound,
			    &str, M_LABEL);
			l_to_str(&tp.tp_sl_range_cipso.upper_bound,
			    &str2, M_INTERNAL);

			(void) printf(gettext("max_sl: %s\nhex: %s\n"),
			    str, str2);
			free(str);
			free(str2);

			l1 = (const m_label_t *)&tp.tp_sl_set_cipso[0];
			l2 = (const m_label_t *)&tp.tp_sl_set_cipso[NSLS_MAX];
			for (i = 0; l1 < l2; l1++, i++) {
				if (label_to_str(l1, &str2, M_INTERNAL,
				    DEF_NAMES) != 0)
					break;
				l_to_str(l1, &str, M_LABEL);

				(void) printf(gettext("sl_set[%1$d]: %2$s\n"
				    "hex: %3$s\n"), i, str, str2);
				free(str);
				free(str2);
			}
		}
		break;

	default:
		(void) printf(gettext("unsupported host type: %ld\n"),
		    tp.host_type);
	}
	return (0);
}

static int
print_rh(const char *rh_name)
{
	int herr;
	struct hostent *hp;
	in6_addr_t in6;
	char abuf[INET6_ADDRSTRLEN];
	tsol_rhent_t rhent;

	if ((hp = getipnodebyname(rh_name, AF_INET6,
	    AI_ALL | AI_ADDRCONFIG | AI_V4MAPPED, &herr)) == NULL) {
		(void) fprintf(stderr, gettext("tninfo: unknown host or "
		    "invalid literal address: %s\n"), rh_name);
		if (herr == TRY_AGAIN)
			(void) fprintf(stderr,
			    gettext("\t(try again later)\n"));
		return (1);
	}

	(void) memset(&rhent, 0, sizeof (rhent));
	(void) memcpy(&in6, hp->h_addr, hp->h_length);

	if (IN6_IS_ADDR_V4MAPPED(&in6)) {
		rhent.rh_address.ta_family = AF_INET;
		IN6_V4MAPPED_TO_INADDR(&in6, &rhent.rh_address.ta_addr_v4);
		(void) inet_ntop(AF_INET, &rhent.rh_address.ta_addr_v4, abuf,
		    sizeof (abuf));
	} else {
		rhent.rh_address.ta_family = AF_INET6;
		rhent.rh_address.ta_addr_v6 = in6;
		(void) inet_ntop(AF_INET6, &in6, abuf, sizeof (abuf));
	}

	(void) printf(gettext("IP address= %s\n"), abuf);

	if (tnrh(TNDB_GET, &rhent) != 0) {
		if (errno == ENOENT)
			(void) fprintf(stderr, gettext("tninfo: tnrhdb entry "
			    "%1$s does not exist\n"), abuf);
		else
			(void) fprintf(stderr, gettext("tninfo: TNDB_GET(%1$s) "
			    "failed: %2$s\n"), abuf, strerror(errno));
		return (1);
	}

	if (rhent.rh_template[0] != '\0')
		(void) printf(gettext("Template = %.*s\n"), TNTNAMSIZ,
		    rhent.rh_template);
	else
		(void) printf(gettext("No template exists.\n"));

	return (0);
}

static int
iterate_mlps(tsol_mlpent_t *tsme, const char *type)
{
	struct protoent *pe;

	/* get the first entry */
	tsme->tsme_mlp.mlp_ipp = 0;
	tsme->tsme_mlp.mlp_port = 0;
	tsme->tsme_mlp.mlp_port_upper = 0;
	if (tnmlp(TNDB_GET, tsme) == -1) {
		if (errno == ENOENT) {
			(void) printf(gettext("%s: no entries\n"), type);
			return (0);
		} else {
			perror("tnmlp TNDB_GET");
			return (-1);
		}
	}
	(void) printf("%s: ", type);
	for (;;) {
		(void) printf("%u", tsme->tsme_mlp.mlp_port);
		if (tsme->tsme_mlp.mlp_port != tsme->tsme_mlp.mlp_port_upper)
			(void) printf("-%u", tsme->tsme_mlp.mlp_port_upper);
		if ((pe = getprotobynumber(tsme->tsme_mlp.mlp_ipp)) == NULL)
			(void) printf("/%u", tsme->tsme_mlp.mlp_ipp);
		else
			(void) printf("/%s", pe->p_name);
		if (tsme->tsme_mlp.mlp_ipp == 255) {
			tsme->tsme_mlp.mlp_port++;
			tsme->tsme_mlp.mlp_ipp = 0;
		} else {
			tsme->tsme_mlp.mlp_ipp++;
		}
		if (tnmlp(TNDB_GET, tsme) == -1)
			break;
		(void) putchar(';');
	}
	(void) putchar('\n');
	return (0);
}

/*
 * Print all of the MLPs for the given zone.
 */
static int
print_mlp(const char *zonename)
{
	tsol_mlpent_t tsme;

	if ((tsme.tsme_zoneid = getzoneidbyname(zonename)) == -1) {
		(void) fprintf(stderr, gettext("tninfo: zone '%s' unknown\n"),
		    zonename);
		return (1);
	}
	tsme.tsme_flags = 0;
	if (iterate_mlps(&tsme, gettext("private")) == -1)
		return (1);
	tsme.tsme_flags = TSOL_MEF_SHARED;
	if (iterate_mlps(&tsme, gettext("shared")) == -1)
		return (1);
	return (0);
}
