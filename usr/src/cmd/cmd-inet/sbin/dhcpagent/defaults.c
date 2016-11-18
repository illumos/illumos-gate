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
 * Copyright (c) 2016-2017, Chris Fraire <cfraire@me.com>.
 */

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dhcpmsg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <libnvpair.h>

#include "common.h"
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
	{ "IGNORE_FAILED_ARP",	 "1",	 0,   -1  },
	{ "OFFER_WAIT",		 "3",	 1,   20  },
	{ "ARP_WAIT",		 "1000", 0,   -1  },
	{ "CLIENT_ID",		 NULL,	 0,   0	  },
	{ "PARAM_REQUEST_LIST",  NULL,	 0,   0   },
	{ "REQUEST_HOSTNAME",	 "1",	 0,   0	  },
	{ "DEBUG_LEVEL",	 "0",	 0,   3   },
	{ "VERBOSE",		 "0",	 0,   0   },
	{ "VERIFIED_LEASE_ONLY", "0",	 0,   0	  },
	{ "PARAM_IGNORE_LIST",	 NULL,	 0,   0   },
	{ "REQUEST_FQDN",	 "1",	 0,   0	  },
	{ "V4_DEFAULT_IAID_DUID",  "0",	 0,   0	  },
	{ "DNS_DOMAINNAME",  NULL,	 0,   0	  },
	{ "ADOPT_DOMAINNAME",	 "0",	 0,   0	  },
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
	char		*param, *pastv6, *value, *end;
	FILE		*fp;
	nvlist_t 	*nvlist;
	struct dhcp_default *defp;

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

		if ((param = strchr(entry, '.')) == NULL) {
			pastv6 = param = entry;
		} else {
			pastv6 = ++param;
			if (strncasecmp(param, "v6.", 3) == 0)
				pastv6 += 3;
		}

		for (defp = defaults;
		    (char *)defp < (char *)defaults + sizeof (defaults);
		    defp++) {
			if (strcasecmp(pastv6, defp->df_name) == 0) {
				if (defp->df_max == -1) {
					dhcpmsg(MSG_WARNING, "parameter %s is "
					    "obsolete; ignored", defp->df_name);
				}
				break;
			}
		}

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
 *	    boolean_t: B_TRUE for DHCPv6, B_FALSE for IPv4 DHCP
 *	    uint_t: the parameter number to look up
 *  output: const char *: the parameter's value, or default if not set
 *			  (must be copied by caller to be kept)
 *    NOTE: df_get_string() is both used by functions outside this source
 *	    file to retrieve strings from the defaults file, *and*
 *	    internally by other df_get_*() functions.
 */

const char *
df_get_string(const char *if_name, boolean_t isv6, uint_t param)
{
	char			*value;
	char			paramstr[256];
	char			name[256];
	struct stat		statbuf;
	static struct stat	df_statbuf;
	static boolean_t	df_unavail_msg = B_FALSE;
	static nvlist_t		*df_nvlist = NULL;

	if (param >= (sizeof (defaults) / sizeof (*defaults)))
		return (NULL);

	if (stat(DHCP_AGENT_DEFAULTS, &statbuf) != 0) {
		if (!df_unavail_msg) {
			dhcpmsg(MSG_WARNING, "cannot access %s; using "
			    "built-in defaults", DHCP_AGENT_DEFAULTS);
			df_unavail_msg = B_TRUE;
		}
		return (defaults[param].df_default);
	}

	/*
	 * if our cached parameters are stale, rebuild.
	 */

	if (statbuf.st_mtime != df_statbuf.st_mtime ||
	    statbuf.st_size != df_statbuf.st_size) {
		df_statbuf = statbuf;
		nvlist_free(df_nvlist);
		df_nvlist = df_build_cache();
	}

	if (isv6) {
		(void) snprintf(name, sizeof (name), ".V6.%s",
		    defaults[param].df_name);
		(void) snprintf(paramstr, sizeof (paramstr), "%s%s", if_name,
		    name);
	} else {
		(void) strlcpy(name, defaults[param].df_name, sizeof (name));
		(void) snprintf(paramstr, sizeof (paramstr), "%s.%s", if_name,
		    name);
	}

	/*
	 * first look for `if_name.[v6.]param', then `[v6.]param'.  if neither
	 * has been set, use the built-in default.
	 */

	if (nvlist_lookup_string(df_nvlist, paramstr, &value) == 0 ||
	    nvlist_lookup_string(df_nvlist, name, &value) == 0)
		return (value);

	return (defaults[param].df_default);
}

/*
 * df_get_int(): gets the integer value of a given user-tunable parameter
 *
 *   input: const char *: the interface the parameter applies to
 *	    boolean_t: B_TRUE for DHCPv6, B_FALSE for IPv4 DHCP
 *	    uint_t: the parameter number to look up
 *  output: int: the parameter's value, or default if not set
 */

int
df_get_int(const char *if_name, boolean_t isv6, uint_t param)
{
	const char	*value;
	int		value_int;

	if (param >= (sizeof (defaults) / sizeof (*defaults)))
		return (0);

	value = df_get_string(if_name, isv6, param);
	if (value == NULL || !isdigit(*value))
		goto failure;

	value_int = atoi(value);
	if (value_int > defaults[param].df_max ||
	    value_int < defaults[param].df_min)
		goto failure;

	return (value_int);

failure:
	dhcpmsg(MSG_WARNING, "df_get_int: parameter `%s' is not between %d and "
	    "%d, defaulting to `%s'", defaults[param].df_name,
	    defaults[param].df_min, defaults[param].df_max,
	    defaults[param].df_default);
	return (atoi(defaults[param].df_default));
}

/*
 * df_get_bool(): gets the boolean value of a given user-tunable parameter
 *
 *   input: const char *: the interface the parameter applies to
 *	    boolean_t: B_TRUE for DHCPv6, B_FALSE for IPv4 DHCP
 *	    uint_t: the parameter number to look up
 *  output: boolean_t: B_TRUE if true, B_FALSE if false, default if not set
 */

boolean_t
df_get_bool(const char *if_name, boolean_t isv6, uint_t param)
{
	const char	*value;

	if (param >= (sizeof (defaults) / sizeof (*defaults)))
		return (0);

	value = df_get_string(if_name, isv6, param);
	if (value != NULL) {

		if (strcasecmp(value, "true") == 0 ||
		    strcasecmp(value, "yes") == 0 || strcmp(value, "1") == 0)
			return (B_TRUE);

		if (strcasecmp(value, "false") == 0 ||
		    strcasecmp(value, "no") == 0 || strcmp(value, "0") == 0)
			return (B_FALSE);
	}

	dhcpmsg(MSG_WARNING, "df_get_bool: parameter `%s' has invalid value "
	    "`%s', defaulting to `%s'", defaults[param].df_name,
	    value != NULL ? value : "NULL", defaults[param].df_default);

	return ((atoi(defaults[param].df_default) == 0) ? B_FALSE : B_TRUE);
}
