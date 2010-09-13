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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Provides accessors to configuration properties.
 *
 * slp_readConfig:	attempts to locate slp.conf, and reads in all
 *				properties specified therein.
 * slp_get_mtu:		returns the MTU
 * slp_get_next_onlist:	parses a comma separated list of integers (in
 *				string form), returning one at a time.
 * slp_parse_static_das: parses the list of DAs given in the DAAddresses
 *				property.
 *
 * Also see the config wrapper macros in slp-internal.h.
 */

#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <slp-internal.h>

/*
 * Reads from fp and dynamically reallocates the buffer if necessary.
 * Returns 1 on success, 0 on read completion, and -1 on failure.
 */
static int super_fgets(char **buf, size_t *bufsize, FILE *fp) {
	char *r, *p;
	size_t real_bufsize, readlen = 0;

	p = *buf;
	real_bufsize = *bufsize;
	for (;;) {
		r = fgets(p, (int)real_bufsize, fp);
		if (feof(fp) && !r)
			return (0);
		if (!r)
			return (-1);
		readlen += strlen(r);
		if ((*buf)[readlen - 1] == '\n')
			return (1);

		/* else	buf is too small */
		*bufsize *= 2;
		if (!(*buf = realloc(*buf, *bufsize))) {
			slp_err(LOG_CRIT, 0, "super_fgets", "out of memory");
			return (-1);
		}
		p = *buf + readlen;
		real_bufsize = *bufsize - readlen;
	}
}

static void skip_space(char **p) {
	while (*p && **p != '\n' && isspace(**p))
		(*p)++;
}

static void null_space(char *p) {
	for (; *p; p++)
		if (isspace(*p))
			*p = 0;
}

/*
 * Reads into the local property store all properties defined in
 * the config file.
 */
void slp_readConfig() {
	char *cfile, *buf;
	FILE *fp;
	size_t buflen = 512;

	/* check env for alternate config file */
	fp = NULL;
	if (cfile = getenv("SLP_CONF_FILE"))
		fp = fopen(cfile, "rF");
	if (!fp)
		if (!(fp = fopen(SLP_DEFAULT_CONFIG_FILE, "rF"))) {
			slp_err(LOG_INFO, 0, "readConfig",
				"cannot open config file");
			return;
		}

	if (!(buf = malloc(buflen))) {
		slp_err(LOG_CRIT, 0, "readConfig", "out of memory");
		(void) fclose(fp);
		return;
	}

	while (!feof(fp)) {
		char *val, *p;
		int err;

		/* read a line */
		err = super_fgets(&buf, &buflen, fp);
		if (err == 0) continue;
		if (err == -1) {
			slp_err(LOG_INFO, 0, "readConfig",
				"error reading file: %d",
				ferror(fp));
			(void) fclose(fp);
			free(buf);
			return;
		}

		/* skip comments and newlines */
		p = buf;
		skip_space(&p);
		if (*p == '#' || *p == ';' || *p == '\n')
			continue;

		/* get property and value */
		if (val = strchr(p, '=')) {
			*val++ = 0;
			skip_space(&val);
			/* remove the trailing newline */
			val[strlen(val) - 1] = 0;
		}
		null_space(p);

		SLPSetProperty(p, val ? val : "");
	}

	(void) fclose(fp);
	free(buf);
}

/*
 * Config convenience wrappers
 */
size_t slp_get_mtu() {
	size_t size;
	size = atoi(SLPGetProperty(SLP_CONFIG_MTU));
	size = size ? size : SLP_DEFAULT_SENDMTU;

	return (size);
}

/*
 * On the first invocation, *state should == the value of the property
 * to parse.
 * If there are no more timeouts, returns -1, otherwise the timeout.
 * If the value in the property is invalid, returns the default 2000.
 */
int slp_get_next_onlist(char **state) {
	char *p, buf[33];
	size_t l;
	int answer;

	if (!*state)
		return (-1);

	if (**state == ',') {
		(*state)++;	/* skip the ',' */
	}
	p = *state;
	*state = slp_utf_strchr(*state, ',');
	if (!*state)
		l = strlen(p);
	else {
		l = *state - p;
		l = (l > 32 ? 32 : l);
	}
	(void) strncpy(buf, p, l);
	buf[l] = 0;
	answer = atoi(buf);

	return (answer != 0 ? answer : 2000);
}

int slp_get_maxResults() {
	int num = atoi(SLPGetProperty(SLP_CONFIG_MAXRESULTS));

	return (num <= 0 ? -1 : num);
}
