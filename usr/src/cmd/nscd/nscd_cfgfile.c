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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *   routine to read configuration file
 *
 */
#include "nscd_config.h"
#include "nscd_log.h"
#include <locale.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>

static int
strbreak(char *field[], int array_size, char *s, char *sep)
{
	int	i;
	char	*lasts, *qp;
	int	inquote;

	qp = strchr(s, '"');
	for (i = 0; i < array_size && (field[i] = strtok_r((i?(char *)NULL:s),
	    sep, &lasts)); i++) {
		/* empty */
	}

	if (qp == NULL)
		return (i);

	inquote = 1;
	while (++qp < lasts) {

		switch (*qp) {

		case '"':
			inquote = (inquote == 0);
			break;

		case '\\':
			/* escape " */
			if (inquote == 1 && *(qp + 1) == '"')
				qp++;
			break;

		case '\0':
			if (inquote == 1) {
				*qp = ' ';
				i--;
			}

			break;
		}
	}

	return (i);
}


nscd_rc_t
_nscd_cfg_read_file(
	char			*filename,
	nscd_cfg_error_t	**errorp)
{
	char			*me = "_nscd_cfg_read_file";
	FILE			*in;
	char			buffer[255];
	char			*fields [128];
	int			linecnt;
	int			fieldcnt;
	nscd_rc_t		rc = NSCD_SUCCESS;
	nscd_cfg_handle_t	*h = NULL;
	nscd_cfg_param_desc_t	*pdesc;
	char			*dbname, *str;
	void			*data_p;
	int			i;
	char			msg[NSCD_CFG_MAX_ERR_MSG_LEN];

	union {
		int	i;
		char	data[256];
	} u;

	if ((in = fopen(filename, "r")) == NULL) {

		(void) snprintf(msg, sizeof (msg),
		    gettext("open of configuration file \"%s\" failed: %s"),
		    filename, strerror(errno));
		if (errorp != NULL)
			*errorp = _nscd_cfg_make_error(
			    NSCD_CFG_FILE_OPEN_ERROR, msg);

		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "%s\n", msg);

		return (NSCD_CFG_FILE_OPEN_ERROR);
	}

	linecnt = 0;
	msg[0] = '\0';
	while (fgets(buffer, sizeof (buffer), in) != NULL) {

		linecnt++;
		if ((fieldcnt = strbreak(fields, 128, buffer, " \t\n")) ==
		    0 || *fields[0] == '#') {
			/* skip blank or comment lines */
			continue;
		}

		switch (fieldcnt) {

		case 2:
			dbname = NULL;
			str = fields[1];
			break;

		case 3:
			dbname = fields[1];
			str = fields[2];
			break;

		default:

			(void) strlcpy(u.data, fields[0], sizeof (u.data));
			for (i = 1; i < fieldcnt; i++) {
				(void) strlcat(u.data, " ",
				    sizeof (u.data));
				(void) strlcat(u.data, fields[i],
				    sizeof (u.data));
			}

			(void) snprintf(msg, sizeof (msg),
		gettext("Syntax error: line %d of configuration "
			"file: %s : \"%s\""), linecnt, filename, u.data);
			if (errorp != NULL)
				*errorp = _nscd_cfg_make_error(
				    NSCD_CFG_SYNTAX_ERROR, msg);

			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
			(me, "%s\n", msg);

			rc = NSCD_CFG_SYNTAX_ERROR;
			break;
		}

		if (rc != NSCD_SUCCESS)
			break;

		rc = _nscd_cfg_get_handle(fields[0], dbname, &h, errorp);
		if (rc != NSCD_SUCCESS)
			break;

		pdesc = _nscd_cfg_get_desc(h);

		/* convert string to data */
		rc = _nscd_cfg_str_to_data(pdesc, str, &u.data,
		    &data_p, errorp);
		if (rc != NSCD_SUCCESS)
			break;

		/* do preliminary check based on data type */
		rc = _nscd_cfg_prelim_check(pdesc, data_p, errorp);
		if (rc != NSCD_SUCCESS)
			break;

		rc = _nscd_cfg_set_linked(h, data_p, errorp);
		_nscd_cfg_free_handle(h);
		h = NULL;
		if (rc != NSCD_CFG_READ_ONLY && rc != NSCD_SUCCESS)
			break;
		else {
			_nscd_cfg_free_error(*errorp);
			*errorp = NULL;
		}
	}
	/* NSCD_CFG_READ_ONLY is not fatal */
	if (rc == NSCD_CFG_READ_ONLY)
		rc = NSCD_SUCCESS;

	if (h != NULL)
		_nscd_cfg_free_handle(h);

	(void) fclose(in);

	if (msg[0] == '\0' && rc != NSCD_SUCCESS) {
		if (errorp != NULL)
			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
			(me, "%s\n", NSCD_ERR2MSG(*errorp));
	}

	return (rc);
}

nscd_rc_t
_nscd_cfg_read_nsswitch_file(
	char			*filename,
	nscd_cfg_error_t	**errorp)
{
	char			*me = "_nscd_cfg_read_nsswitch_file";
	char			*pname = "nsw-config-string";
	FILE			*in;
	char			buffer[255];
	char			*cc, *ce, *ce1, *c1, *c2;
	char			*db, *dbe;
	char			*nsscfg;
	int			syntax_err;
	int			linecnt;
	nscd_rc_t		rc = NSCD_SUCCESS;
	nscd_cfg_handle_t	*h = NULL;
	nscd_cfg_param_desc_t	*pdesc;
	void			*data_p;
	char			msg[NSCD_CFG_MAX_ERR_MSG_LEN];

	union {
		int	i;
		char	data[256];
	} u;

	if ((in = fopen(filename, "r")) == NULL) {

		(void) snprintf(msg, sizeof (msg),
		    gettext("open of configuration file \"%s\" failed: %s"),
		    filename, strerror(errno));
		if (errorp != NULL)
			*errorp = _nscd_cfg_make_error(
			    NSCD_CFG_FILE_OPEN_ERROR, msg);

		_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
		(me, "%s\n", msg);

		return (NSCD_CFG_FILE_OPEN_ERROR);
	}

	linecnt = 0;
	msg[0] = '\0';
	while (fgets(buffer, sizeof (buffer), in) != NULL) {

		linecnt++;
		syntax_err = 0;
		/* skip blank or comment lines */
		if (buffer[0] == '#' || buffer[0] == '\n')
			continue;
		/* skip end of line comment */
		if ((ce = strchr(buffer, '\n')) != NULL)
			*ce = '\0';
		else
			ce = &buffer[255];
		if ((ce1 = strchr(buffer, '#')) != NULL) {
			ce = ce1;
			*ce = '\0';
		}
		if ((cc = strchr(buffer, ':')) == NULL) {
			c1 = buffer;
			while (isalpha(*c1) && c1 < ce)
				c1++;
			if (c1 > ce)
				syntax_err = 1;
			else /* blank line */
				continue;
		} else {
			/*
			 * data name goes before ':',
			 * skip spaces on both ends
			 */
			c2 = cc - 1;
			while (buffer <= c2 && isspace(*c2))
				c2--;
			c1 = buffer;
			while (c1 <= cc && isspace(*c1))
				c1++;
			if (c1 > c2)
				syntax_err = 1;
			else {
				db = c1;
				dbe = c2 + 1;

				/*
				 * nss config goes after ':',
				 * skip spaces on both ends
				 */
				c1 = cc + 1;
				while (c1 <= ce && isspace(*c1))
					c1++;
				c2 = ce - 1;
				while (cc <= c2 && isspace(*c2))
					c2--;
				if (c1 > c2) {
					/* no source specified, it's OK */
					continue;
				} else {
					*dbe = '\0';
					nsscfg = c1;
					*(c2 + 1) = '\0';
				}
			}
		}

		if (syntax_err == 1) {

			(void) snprintf(msg, sizeof (msg),
		gettext("Syntax error: line %d of configuration "
			"file: %s : \"%s\""), linecnt, filename, buffer);
			if (errorp != NULL)
				*errorp = _nscd_cfg_make_error(
				    NSCD_CFG_SYNTAX_ERROR, msg);

			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
			(me, "%s\n", msg);

			rc = NSCD_CFG_SYNTAX_ERROR;
			return (rc);
		}

		rc = _nscd_cfg_get_handle(pname, db, &h, errorp);
		if (rc != NSCD_SUCCESS) {
			/* ignore unsupported switch database */
			if (rc == NSCD_CFG_UNSUPPORTED_SWITCH_DB) {
				_nscd_cfg_free_error(*errorp);
				*errorp = NULL;
				rc = NSCD_SUCCESS;
				continue;
			}
			break;
		}

		pdesc = _nscd_cfg_get_desc(h);

		/* convert string to data */
		rc = _nscd_cfg_str_to_data(pdesc, nsscfg, &u.data,
		    &data_p, errorp);
		if (rc != NSCD_SUCCESS)
			break;

		/* do preliminary check based on data type */
		rc = _nscd_cfg_prelim_check(pdesc, data_p, errorp);
		if (rc != NSCD_SUCCESS)
			break;

		rc = _nscd_cfg_set_linked(h, data_p, errorp);
		_nscd_cfg_free_handle(h);
		h = NULL;
		if (rc != NSCD_CFG_READ_ONLY && rc != NSCD_SUCCESS)
			break;
		else {
			_nscd_cfg_free_error(*errorp);
			*errorp = NULL;
		}
	}
	/* NSCD_CFG_READ_ONLY is not fatal */
	if (rc == NSCD_CFG_READ_ONLY)
		rc = NSCD_SUCCESS;

	if (h != NULL)
		_nscd_cfg_free_handle(h);

	(void) fclose(in);

	if (msg[0] == '\0' && rc != NSCD_SUCCESS) {
		if (errorp != NULL)
			_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
			(me, "%s\n", NSCD_ERR2MSG(*errorp));
	}

	return (rc);
}
