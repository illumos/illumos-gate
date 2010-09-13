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

#include <sys/promif.h>
#include <sys/promimpl.h>

#ifdef	DPRINTF
#define	dprintf	prom_printf
#endif

/*
 * Check if the prom is 64-bit ready.
 */

/*
 * Table listing the minimum prom versions supported by this kernel.
 * The model value is expected to match the model in the flashprom node.
 */
static struct obp_rev_table {
	char *model;
	char *version;
} obp_min_revs[] = {
	{"SUNW,525-1414", "OBP 3.11.2 1997/12/05 10:25"},  /* pulsar */
	{"SUNW,525-1672", "OBP 3.7.107 1998/02/19 17:54"},  /* tazmo */
	{"SUNW,525-1431", "OBP 3.2.16 1998/06/08 16:58"},   /* sunfire */
	{ NULL, NULL}
};

#define	NMINS	60
#define	NHOURS	24
#define	NDAYS	31
#define	NMONTHS	12

#define	YEAR(y)	 ((y-1) * (NMONTHS * NDAYS * NHOURS * NMINS))
#define	MONTH(m) ((m-1) * (NDAYS * NHOURS * NMINS))
#define	DAY(d)   ((d-1) * (NHOURS * NMINS))
#define	HOUR(h)  ((h)   * (NMINS))
#define	MINUTE(m) (m)

static int
strtoi(char *str, char **pos)
{
	int c;
	int val = 0;

	for (c = *str++; c >= '0' && c <= '9'; c = *str++) {
		val *= 10;
		val += c - '0';
	}
	if (pos)
		*pos = str;
	return (val);
}

/*
 * obp_timestamp: based on the OBP flashprom version string of the
 * format "OBP x.y.z YYYY/MM/DD HH:MM" calculate a timestamp based
 * on the year, month, day, hour and minute by turning that into
 * a number of minutes.
 */
static int
obp_timestamp(char *v)
{
	char *c;
	int maj, year, month, day, hour, min;

	if (v[0] != 'O' || v[1] != 'B' || v[2] != 'P')
		return (-1);

	c = v + 3;

	/* Find first non-space character after OBP */
	while (*c != '\0' && (*c == ' ' || *c == '\t'))
		c++;
	if (prom_strlen(c) < 5)		/* need at least "x.y.z" */
		return (-1);

	maj = strtoi(c, &c);
	if (maj < 3)
		return (-1);

#if 0 /* XXX - not used */
	dot = dotdot = 0;
	if (*c == '.') {
		dot = strtoi(c + 1, &c);

		/* optional? dot-dot release */
		if (*c == '.')
			dotdot = strtoi(c + 1, &c);
	}
#endif

	/* Find space at the end of version number */
	while (*c != '\0' && *c != ' ')
		c++;
	if (prom_strlen(c) < 11)	/* need at least " xxxx/xx/xx" */
		return (-1);

	/* Point to first character of date */
	c++;

	/* Validate date format */
	if (c[4] != '/' || c[7] != '/')
		return (-1);

	year = strtoi(c, NULL);
	month = strtoi(c + 5, NULL);
	day = strtoi(c + 8, NULL);

	if (year < 1995 || month == 0 || day == 0)
		return (-1);

	/*
	 * Find space at the end of date number
	 */
	c += 10;
	while (*c != '\0' && *c != ' ')
		c++;
	if (prom_strlen(c) < 6)		/* need at least " xx:xx" */
		return (-1);

	/* Point to first character of time */
	c++;

	if (c[2] != ':')
		return (-1);

	hour = strtoi(c, NULL);
	min = strtoi(c + 3, NULL);

	return (YEAR(year) + MONTH(month) +
	    DAY(day) + HOUR(hour) + MINUTE(min));
}

/*
 * Check the prom against the obp_min_revs table and complain if
 * the system has an older prom installed.  The actual major/minor/
 * dotdot numbers are not checked, only the date/time stamp.
 */

static struct obp_rev_table *flashprom_ortp;
static pnode_t flashprom_node;
static int flashprom_checked;
static int flashprom_return_code;

int
check_timestamp(char *model, int tstamp)
{
	int min_tstamp;
	struct obp_rev_table *ortp;

	for (ortp = obp_min_revs; ortp->model != NULL; ortp++) {
		if (prom_strcmp(model, ortp->model) == 0) {
			min_tstamp = obp_timestamp(ortp->version);
			if (min_tstamp == -1) {
#ifdef	DEBUG
				prom_printf("prom_version_check: "
				    "invalid OBP version string in table "
				    " (entry %d)", (int)(ortp - obp_min_revs));
#endif
				continue;
			}
			if (tstamp < min_tstamp) {
#ifdef	DPRINTF
				dprintf("prom_version_check: "
				    "Down-rev OBP detected.  "
				    "Please update to at least:\n\t%s\n\n",
				    ortp->version);
#endif
				flashprom_ortp = ortp;
				return (1);
			}
		}
	} /* for each obp_rev_table entry */

	return (0);
}

static pnode_t
visit(pnode_t node)
{
	int tstamp, plen, i;
	char vers[512], model[64];
	static pnode_t openprom_node;
	static char version[] = "version";
	static char model_name[] = "model";
	static char flashprom[] = "flashprom";

	/*
	 * if name isn't 'flashprom', continue.
	 */
	if (prom_getproplen(node, OBP_NAME) != sizeof (flashprom))
		return ((pnode_t)0);
	(void) prom_getprop(node, OBP_NAME, model);
	if (prom_strncmp(model, flashprom, sizeof (flashprom)) != 0)
		return ((pnode_t)0);

	plen = prom_getproplen(node, version);
	if (plen <= 0 || plen > sizeof (vers))
		return ((pnode_t)0);
	(void) prom_getprop(node, version, vers);
	vers[plen] = '\0';

	/* Make sure it's an OBP flashprom */
	if (vers[0] != 'O' && vers[1] != 'B' && vers[2] != 'P')
		return ((pnode_t)0);

	plen = prom_getproplen(node, model_name);
	if (plen <= 0 || plen > sizeof (model))
		return ((pnode_t)0);
	(void) prom_getprop(node, model_name, model);
	model[plen] = '\0';

	tstamp = obp_timestamp(vers);
	if (tstamp == -1) {
		prom_printf("prom_version_check: node contains "
		    "improperly formatted version property,\n"
		    "\tnot checking prom version");
		return ((pnode_t)0);
	}

	i = check_timestamp(model, tstamp);

	if (i == 0)
		return ((pnode_t)0);

	/*
	 * We know that "node"'s flashprom image contains downrev firmware,
	 * however, a multi-board server might be running correct firmware.
	 * Check for that case by looking at the "/openprom" node,
	 * which always contains the running version. (We needed the
	 * "model" value to be able to do this, so we can use it as
	 * an index value into the table.)
	 *
	 * If it turns out we're running 'current' firmware,
	 * but detect down-rev firmware, use a different return code.
	 */

	flashprom_return_code = PROM_VER64_UPGRADE;

	openprom_node = prom_finddevice("/openprom");
	if (openprom_node == OBP_BADNODE)
		return (node);

	plen = prom_getproplen(node, version);
	if (plen <= 0 || plen > sizeof (vers))
		return (node);
	(void) prom_getprop(node, version, vers);
	vers[plen] = '\0';

	if (vers[0] != 'O' && vers[1] != 'B' && vers[2] != 'P') {
		prom_printf("prom_version_check: "
		    "unknown <version> string in </openprom>\n");
		return (node);
	}

	tstamp = obp_timestamp(vers);
	if (tstamp == -1) {
		prom_printf("prom_version_check: "
		    "</openprom> node <version> property: bad tstamp\n");
		return (node);
	}

	i = check_timestamp(model, tstamp);
	/*
	 * If that returned zero, then the running version is
	 * adequate ... so we can 'suggest' instead of 'require'.
	 */
	if (i == 0)
		flashprom_return_code = PROM_VER64_SUGGEST;

	return (node);
}

/*
 * visit each node in the device tree, until we get a non-null answer
 */
static pnode_t
walk(pnode_t node)
{
	pnode_t id;

	if (visit(node))
		return (node);

	for (node = prom_childnode(node); node; node = prom_nextnode(node))
		if ((id = walk(node)) != (pnode_t)0)
			return (id);

	return ((pnode_t)0);
}

/*
 * Check if the prom is 64-bit ready.
 *
 * If it's ready (or the test doesn't apply), return PROM_VER64_OK.
 * If downrev firmware is running, return PROM_VER64_UPGRADE.
 * If downrev firmware is detected (but not running), return PROM_VER64_SUGGEST.
 *
 * For PROM_VER64_UPGRADE and PROM_VER64_SUGGEST return code values:
 * Return the nodeid of the flashprom node in *nodeid.
 * and a printable message in *buf, buflen.
 */
int
prom_version_check(char *buf, size_t buflen, pnode_t *nodeid)
{
	char *p;
	pnode_t node = flashprom_node;
	size_t i;

	/*
	 * If we already checked, we already know the answer.
	 */
	if (flashprom_checked == 0) {
		flashprom_node = node = walk(prom_rootnode());
		flashprom_checked = 1;
	}

	if (nodeid)
		*nodeid = node;

	if (node == (pnode_t)0) {
		if (buf && buflen)
			*buf = '\0';
		return (PROM_VER64_OK);
	}

	/* bzero the callers buffer */
	for (i = buflen, p = buf; i != 0; --i, ++p)
		*p = '\0';

	/*
	 * Do a bounded copy of the output string into the callers buffer
	 */
	if (buflen <= 1)
		return (flashprom_return_code);

	(void) prom_strncpy(buf, flashprom_ortp->version, buflen - 1);
	return (flashprom_return_code);
}
