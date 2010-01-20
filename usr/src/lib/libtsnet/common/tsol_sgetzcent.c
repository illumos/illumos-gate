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
 *
 * From	"tsol_tndb_parser.c	7.24	01/09/05 SMI; TSOL 2.x"
 *
 * These functions parse entries in the "tnzonecfg" (zone configuration) file.
 * Each entry in this file has five fields, separated by a colon.  These fields
 * are:
 *
 *	zone name : label : flags : zone-specific MLPs : global MLPs
 *
 * The fourth and fifth fields contain subfields consisting of MLP entries
 * separated by semicolons.  The MLP entries are of the form:
 *
 *	port[-port]/protocol
 *
 * In order to help preserve sanity, we do not allow more than four unescaped
 * colons in a line, nor any unescaped ';' characters in the non-MLP fields.
 * Such things are indicative of typing errors, not intentional configuration.
 */

#include <ctype.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <libtsnet.h>
#include <tsol/label.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <nss.h>
#include <errno.h>
#include <secdb.h>

/*
 * Parse an MLP specification in port1-port2/proto or port/proto form.
 */
static int
str_to_mlp(char *mlp_str, tsol_mlp_t *zone_mlp)
{
	char *fieldp;
	char *lasts, *cp;
	int i;
	ulong_t ulv;
	struct protoent proto;
	char gbuf[1024];

	(void) memset(zone_mlp, 0, sizeof (tsol_mlp_t));

	fieldp = strtok_r(mlp_str, KV_DELIMITER, &lasts);
	if (fieldp == NULL)
		return (-1);

	errno = 0;
	for (i = 0; fieldp != NULL && i < NMLP_MAX; i++) {
		ulv = strtoul(fieldp, &cp, 0);
		zone_mlp[i].mlp_port = (uint16_t)ulv;
		zone_mlp[i].mlp_port_upper = 0;
		if (errno != 0 || ulv > 65535)
			return (-1);
		if (*cp == '-') {
			ulv = strtol(cp + 1, &cp, 0);
			zone_mlp[i].mlp_port_upper = (uint16_t)ulv;
			if (errno != 0 || ulv > 65535)
				return (-1);
		}
		if (*cp != '/')
			return (-1);
		fieldp = cp + 1;
		ulv = strtol(fieldp, &cp, 0);
		if (errno == 0 && ulv <= 255 && *cp == '\0')
			zone_mlp->mlp_ipp = (uint8_t)ulv;
		else if (getprotobyname_r(fieldp, &proto, gbuf,
		    sizeof (gbuf)) != NULL)
			zone_mlp->mlp_ipp = proto.p_proto;
		else
			return (-1);
		fieldp = strtok_r(NULL, KV_DELIMITER, &lasts);
	}
	return (0);
}

static boolean_t
parse_mlp_list(tsol_mlp_t **list, char *str, int *errp, char **errstrp)
{
	int mmax;
	tsol_mlp_t *mlp;
	char *tokp, *finally;
	int mc;

	mmax = 0;
	if ((mlp = *list) != NULL) {
		while (!TSOL_MLP_END(mlp)) {
			mmax++;
			mlp++;
		}
		mmax++;
	}
	mlp = *list;
	tokp = strtok_r(str, KV_DELIMITER, &finally);
	for (mc = 0; tokp != NULL; mc++) {
		if (mc >= mmax) {
			mmax += 8;
			mlp = realloc(mlp, mmax * sizeof (*mlp));
			if (mlp == NULL) {
				*errp = LTSNET_SYSERR;
				*errstrp = tokp;
				return (B_FALSE);
			}
			*list = mlp;
		}
		if (str_to_mlp(tokp, mlp + mc) == -1) {
			*errp = LTSNET_ILL_MLP;
			*errstrp = tokp;
			return (B_FALSE);
		}
		tokp = strtok_r(NULL, KV_DELIMITER, &finally);
	}
	if (mc >= mmax) {
		mlp = realloc(mlp, (mmax + 1) * sizeof (*mlp));
		if (mlp == NULL) {
			*errp = LTSNET_SYSERR;
			*errstrp = finally;
			return (B_FALSE);
		}
		*list = mlp;
	}
	(void) memset(mlp + mc, 0, sizeof (*mlp));
	return (B_TRUE);
}

tsol_zcent_t *
tsol_sgetzcent(const char *instr, int *errp, char **errstrp)
{
	int err;
	m_label_t *slp;
	char *errstr;
	tsol_zcent_t *zc;
	const char *nextf;
	char *cp;
	char fieldbuf[1024];

	/*
	 * The user can specify NULL pointers for these.  Make sure that we
	 * don't have to deal with checking for NULL everywhere by just
	 * pointing to our own variables if the user gives NULL.
	 */
	if (errp == NULL)
		errp = &err;
	if (errstrp == NULL)
		errstrp = &errstr;

	/* The default, unless we find a more specific error locus. */
	*errstrp = (char *)instr;

	if ((zc = calloc(1, sizeof (*zc))) == NULL) {
		*errp = LTSNET_SYSERR;
		return (NULL);
	}

	/* First, parse off the zone name. */
	instr = parse_entry(zc->zc_name, sizeof (zc->zc_name), instr, "#;:\n");
	if (zc->zc_name[0] == '\0') {
		*errstrp = (char *)instr;
		if (*instr == '\0' || *instr == '#' || *instr == '\n')
			*errp = LTSNET_EMPTY;
		else if (*instr == ':')
			*errp = LTSNET_NO_NAME;
		else
			*errp = LTSNET_ILL_NAME;
		goto err_ret;
	}
	if (*instr != ':') {
		*errstrp = (char *)instr;
		if (*instr == '=' || *instr == ';')
			*errp = LTSNET_ILL_NAME;
		else
			*errp = LTSNET_ILL_ENTRY;
		goto err_ret;
	}
	instr++;

	/* Field two: parse off the label. */
	nextf = parse_entry(fieldbuf, sizeof (fieldbuf), instr, "#;:\n");
	if (*nextf != ':') {
		*errstrp = (char *)nextf;
		*errp = LTSNET_ILL_ENTRY;
		goto err_ret;
	}
	if (fieldbuf[0] == '\0') {
		*errstrp = (char *)instr;
		*errp = LTSNET_NO_LABEL;
		goto err_ret;
	}

	slp = &zc->zc_label;
	if (str_to_label(fieldbuf, &slp, MAC_LABEL, L_NO_CORRECTION, NULL)
	    != 0) {
		*errstrp = (char *)instr;
		*errp = LTSNET_ILL_LABEL;
		goto err_ret;
	}
	instr = nextf + 1;

	/* The kernel will apply the system doi to the zone label later */
	zc->zc_doi = 0;

	/* Field three: get match flag */
	errno = 0;
	zc->zc_match = (uchar_t)strtol(instr, &cp, 0);
	if (errno != 0 || (*cp != ':' && *cp != '\0')) {
		*errp = LTSNET_ILL_FLAG;
		*errstrp = (char *)instr;
		goto err_ret;
	}
	if (*cp != ':') {
		*errp = LTSNET_ILL_VALDELIM;
		*errstrp = cp;
		goto err_ret;
	}
	instr = cp + 1;

	/* Field four: get zone-specific MLP list. */
	nextf = parse_entry(fieldbuf, sizeof (fieldbuf), instr, "#:\n");
	if (*nextf != ':') {
		*errstrp = (char *)nextf;
		*errp = LTSNET_ILL_ENTRY;
		goto err_ret;
	}
	if (!parse_mlp_list(&zc->zc_private_mlp, fieldbuf, errp, errstrp)) {
		*errstrp = (char *)instr + (*errstrp - fieldbuf);
		goto err_ret;
	}
	instr = nextf + 1;

	/* Field five: get global MLP list. */
	nextf = parse_entry(fieldbuf, sizeof (fieldbuf), instr, "#:\n");
	if (*nextf != '\0' && *nextf != '#' && !isspace(*nextf)) {
		*errstrp = (char *)nextf;
		*errp = LTSNET_ILL_ENTRY;
		goto err_ret;
	}
	if (!parse_mlp_list(&zc->zc_shared_mlp, fieldbuf, errp, errstrp)) {
		*errstrp = (char *)instr + (*errstrp - fieldbuf);
		goto err_ret;
	}

	return (zc);

err_ret:
	err = errno;
	tsol_freezcent(zc);
	errno = err;
	return (NULL);
}

void
tsol_freezcent(tsol_zcent_t *zc)
{
	if (zc != NULL) {
		free(zc->zc_private_mlp);
		free(zc->zc_shared_mlp);
		free(zc);
	}
}
