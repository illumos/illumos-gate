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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/inetutil.h>
#include <netinet/dhcp.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dhcpmsg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <libnvpair.h>

#include "defaults.h"

struct dhcp_default {

	const char	*df_name;	/* parameter name */
	const char	*df_default;	/* default value */
	int		df_min;		/* min value if type DF_INTEGER */
	int		df_max;		/* max value if type DF_INTEGER */
};

/*
 * note: keep in the same order as tunable parameter constants in defaults.h
 */

static struct dhcp_default defaults[] = {

	{ "RELEASE_ON_SIGTERM",  "0",	 0,   0	  },
	{ "IGNORE_FAILED_ARP",	 "1",	 0,   0	  },
	{ "OFFER_WAIT",		 "3",	 1,   20  },
	{ "ARP_WAIT",		 "1000", 100, 4000 },
	{ "CLIENT_ID",		 NULL,	 0,   0	  },
	{ "PARAM_REQUEST_LIST",  NULL,	 0,   0    },
	{ "REQUEST_HOSTNAME",	 "1",	 0,   0	  }
};

/*
 * df_build_cache(): builds the defaults nvlist cache
 *
 *   input: void
 *  output: a pointer to an nvlist of the current defaults, or NULL on failure
 */

static nvlist_t *
df_build_cache(void)
{
	char		entry[1024];
	int		i;
	char		*param, *value, *end;
	FILE		*fp;
	nvlist_t 	*nvlist;

	if ((fp = fopen(DHCP_AGENT_DEFAULTS, "r")) == NULL)
		return (NULL);

	if (nvlist_alloc(&nvlist, NV_UNIQUE_NAME, 0) != 0) {
		dhcpmsg(MSG_WARNING, "cannot build default value cache; "
		    "using built-in defaults");
		(void) fclose(fp);
		return (NULL);
	}

	while (fgets(entry, sizeof (entry), fp) != NULL) {
		for (i = 0; entry[i] == ' '; i++)
			;

		end = strrchr(entry, '\n');
		value = strchr(entry, '=');
		if (end == NULL || value == NULL || entry[i] == '#')
			continue;

		*end = '\0';
		*value++ = '\0';

		/*
		 * to be compatible with the old defread()-based code
		 * which ignored case, store the parameters (except for the
		 * leading interface name) in upper case.
		 */

		if ((param = strchr(entry, '.')) == NULL)
			param = entry;
		else
			param++;

		for (; *param != '\0'; param++)
			*param = toupper(*param);

		if (nvlist_add_string(nvlist, &entry[i], value) != 0) {
			dhcpmsg(MSG_WARNING, "cannot build default value cache;"
			    " using built-in defaults");
			nvlist_free(nvlist);
			nvlist = NULL;
			break;
		}
	}

	(void) fclose(fp);
	return (nvlist);
}

/*
 * df_get_string(): gets the string value of a given user-tunable parameter
 *
 *   input: const char *: the interface the parameter applies to
 *	    unsigned int: the parameter number to look up
 *  output: const char *: the parameter's value, or default if not set
 *			  (must be copied by caller to be kept)
 *    NOTE: df_get_string() is both used by functions outside this source
 *	    file to retrieve strings from the defaults file, *and*
 *	    internally by other df_get_*() functions.
 */

const char *
df_get_string(const char *if_name, unsigned int p)
{
	char			*value;
	char			param[256];
	struct stat		statbuf;
	static struct stat	df_statbuf;
	static boolean_t	df_unavail_msg = B_FALSE;
	static nvlist_t		*df_nvlist = NULL;

	if (p >= (sizeof (defaults) / sizeof (*defaults)))
		return (NULL);

	if (stat(DHCP_AGENT_DEFAULTS, &statbuf) != 0) {
		if (!df_unavail_msg) {
			dhcpmsg(MSG_WARNING, "cannot access %s; using "
			    "built-in defaults", DHCP_AGENT_DEFAULTS);
			df_unavail_msg = B_TRUE;
		}
		return (defaults[p].df_default);
	}

	/*
	 * if our cached parameters are stale, rebuild.
	 */

	if (statbuf.st_mtime != df_statbuf.st_mtime ||
	    statbuf.st_size != df_statbuf.st_size) {
		df_statbuf = statbuf;
		if (df_nvlist != NULL)
			nvlist_free(df_nvlist);
		df_nvlist = df_build_cache();
	}

	(void) snprintf(param, sizeof (param), "%s.%s", if_name,
	    defaults[p].df_name);

	/*
	 * first look for `if_name.param', then `param'.  if neither
	 * has been set, use the built-in default.
	 */

	if (nvlist_lookup_string(df_nvlist, param, &value) == 0 ||
	    nvlist_lookup_string(df_nvlist, defaults[p].df_name, &value) == 0)
		return (value);

	return (defaults[p].df_default);
}

/*
 * df_get_octet(): gets the integer value of a given user-tunable parameter
 *
 *   input: const char *: the interface the parameter applies to
 *	    unsigned int: the parameter number to look up
 *	    unsigned int *: the length of the returned value
 *  output: uchar_t *: a pointer to byte array (default value if not set)
 *		       (must be copied by caller to be kept)
 */

uchar_t *
df_get_octet(const char *if_name, unsigned int p, unsigned int *len)
{
	const char	*value;
	static uchar_t	octet_value[256]; /* as big as defread() returns */

	if (p >= (sizeof (defaults) / sizeof (*defaults)))
		return (NULL);

	value = df_get_string(if_name, p);
	if (value == NULL)
		goto do_default;

	if (strncasecmp("0x", value, 2) != 0) {
		*len = strlen(value);			/* no NUL */
		return ((uchar_t *)value);
	}

	/* skip past the 0x and convert the value to binary */
	value += 2;
	*len = sizeof (octet_value);
	if (hexascii_to_octet(value, strlen(value), octet_value, len) != 0) {
		dhcpmsg(MSG_WARNING, "df_get_octet: cannot convert value "
		    "for parameter `%s', using default", defaults[p].df_name);
		goto do_default;
	}
	return (octet_value);

do_default:
	if (defaults[p].df_default == NULL) {
		*len = 0;
		return (NULL);
	}

	*len = strlen(defaults[p].df_default);		/* no NUL */
	return ((uchar_t *)defaults[p].df_default);
}

/*
 * df_get_int(): gets the integer value of a given user-tunable parameter
 *
 *   input: const char *: the interface the parameter applies to
 *	    unsigned int: the parameter number to look up
 *  output: int: the parameter's value, or default if not set
 */

int
df_get_int(const char *if_name, unsigned int p)
{
	const char	*value;
	int		value_int;

	if (p >= (sizeof (defaults) / sizeof (*defaults)))
		return (0);

	value = df_get_string(if_name, p);
	if (value == NULL || !isdigit(*value))
		goto failure;

	value_int = atoi(value);
	if (value_int > defaults[p].df_max || value_int < defaults[p].df_min)
		goto failure;

	return (value_int);

failure:
	dhcpmsg(MSG_WARNING, "df_get_int: parameter `%s' is not between %d and "
	    "%d, defaulting to `%s'", defaults[p].df_name, defaults[p].df_min,
	    defaults[p].df_max, defaults[p].df_default);
	return (atoi(defaults[p].df_default));
}

/*
 * df_get_bool(): gets the boolean value of a given user-tunable parameter
 *
 *   input: const char *: the interface the parameter applies to
 *	    unsigned int: the parameter number to look up
 *  output: boolean_t: B_TRUE if true, B_FALSE if false, default if not set
 */

boolean_t
df_get_bool(const char *if_name, unsigned int p)
{
	const char	*value;

	if (p >= (sizeof (defaults) / sizeof (*defaults)))
		return (0);

	value = df_get_string(if_name, p);
	if (value != NULL) {

		if (strcasecmp(value, "true") == 0 ||
		    strcasecmp(value, "yes") == 0 || strcmp(value, "1") == 0)
			return (B_TRUE);

		if (strcasecmp(value, "false") == 0 ||
		    strcasecmp(value, "no") == 0 || strcmp(value, "0") == 0)
			return (B_FALSE);
	}

	dhcpmsg(MSG_WARNING, "df_get_bool: parameter `%s' has invalid value "
	    "`%s', defaulting to `%s'", defaults[p].df_name,
	    value ? value : "NULL", defaults[p].df_default);

	return ((atoi(defaults[p].df_default) == 0) ? B_FALSE : B_TRUE);
}
