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

#include "defs.h"
#include "tables.h"

/*
 * Parse the config file which consists of entries of the form:
 *	ifdefault	[<variable> <value>]*
 *	prefixdefault	[<variable> <value>]*
 *	if <ifname>	[<variable> <value>]*
 *	prefix <prefix>/<length> <ifname>	[<variable> <value>]*
 *
 * All "ifdefault" and "prefixdefault" entries must preceed any
 * "if" and "prefix" entries.
 *
 * Values (such as expiry dates) which contain white space
 * can be quoted with single or double quotes.
 */

/* maximum length of messages we send to syslog */
#define	NDPD_LOGMSGSIZE	1024
typedef	boolean_t	(*pfb_t)(char *, uint_t *);

struct configinfo {
	char	*ci_name;
	uint_t	ci_min;		/* 0: no min check */
	uint_t	ci_max;		/* ~0U: no max check */
	uint_t	ci_default;
	uint_t	ci_index;	/* Into result array */
	pfb_t	ci_parsefunc;	/* Parse function returns -1 on failure */
};

enum config_type { CONFIG_IF, CONFIG_PREFIX};
typedef enum config_type config_type_t;

static void set_protocol_defaults(void);
static void print_defaults(void);
static void parse_var_value(config_type_t, struct configinfo *, char *, char *,
    struct confvar *);
static void parse_default(config_type_t, struct configinfo *, char **, int,
    struct confvar *);
static void parse_if(struct configinfo *, char **, int);
static void parse_prefix(struct configinfo *, char **, int);
static boolean_t parse_onoff(char *, uint_t *);	/* boolean */
static boolean_t parse_int(char *, uint_t *);	/* integer */
static boolean_t parse_ms(char *, uint_t *);	/* milliseconds */
static boolean_t parse_s(char *, uint_t *);	/* seconds */
static boolean_t parse_date(char *, uint_t *);	/* date format */
static void conferr(char *fmt, ...);
static FILE *open_conffile(char *filename);
static int parse_line(char *line, char *argvec[], int argcount);
static int readline(FILE *fp, char *line, int length);
static int parse_addrprefix(char *strin, struct in6_addr *in6);

/*
 * Per interface configuration variables.
 * Min, max, and default values are from RFC 2461.
 */
static struct configinfo iflist[] = {
	/* Name, Min, Max, Default, Index */
	{ "DupAddrDetectTransmits", 0, 100, 1, I_DupAddrDetectTransmits,
	parse_int },
	{ "AdvSendAdvertisements", 0, 1, 0, I_AdvSendAdvertisements,
	parse_onoff },
	{ "MaxRtrAdvInterval", 4, 1800, 600, I_MaxRtrAdvInterval, parse_s },
	{ "MinRtrAdvInterval", 3, 1350, 200, I_MinRtrAdvInterval, parse_s },
	/*
	 * No greater than .75 * MaxRtrAdvInterval.
	 * Default: 0.33 * MaxRtrAdvInterval
	 */
	{ "AdvManagedFlag", 0, 1, 0, I_AdvManagedFlag, parse_onoff },
	{ "AdvOtherConfigFlag", 0, 1, 0, I_AdvOtherConfigFlag, parse_onoff },
	{ "AdvLinkMTU", IPV6_MIN_MTU, 65535, 0, I_AdvLinkMTU, parse_int },
	{ "AdvReachableTime", 0, 3600000, 0, I_AdvReachableTime, parse_ms },
	{ "AdvRetransTimer", 0, ~0U, 0, I_AdvRetransTimer, parse_ms },
	{ "AdvCurHopLimit", 0, 255, 0, I_AdvCurHopLimit, parse_int },
	{ "AdvDefaultLifetime", 0, 9000, 1800, I_AdvDefaultLifetime, parse_s },
	/*
	 * MUST be either zero or between MaxRtrAdvInterval and 9000 seconds.
	 * Default: 3 * MaxRtrAdvInterval
	 */
	{ "StatelessAddrConf", 0, 1, 1, I_StatelessAddrConf, parse_onoff },
	{ "StatefulAddrConf", 0, 1, 1, I_StatefulAddrConf, parse_onoff },
	/*
	 * Tmp* variables from RFC 3041, where defaults are defined.
	 */
	{ "TmpAddrsEnabled", 0, 1, 0, I_TmpAddrsEnabled, parse_onoff },
	{ "TmpValidLifetime", 0, ~0U, 604800, I_TmpValidLifetime, parse_s },
	{ "TmpPreferredLifetime", 0, ~0U, 86400, I_TmpPreferredLifetime,
	parse_s },
	{ "TmpRegenAdvance", 0, 60, 5, I_TmpRegenAdvance, parse_s },
	{ "TmpMaxDesyncFactor", 0, 600, 600, I_TmpMaxDesyncFactor, parse_s },
	{ NULL, 0, 0, 0, 0 }
};

/*
 * Per prefix: AdvPrefixList configuration variables.
 * Min, max, and default values are from RFC 2461.
 */
static struct configinfo prefixlist[] = {
	/* Name, Min, Max, Default, Index */
	{ "AdvValidLifetime", 0, ~0U, 2592000, I_AdvValidLifetime,
	parse_s },
	{ "AdvOnLinkFlag", 0, 1, 1, I_AdvOnLinkFlag, parse_onoff },
	{ "AdvPreferredLifetime", 0, ~0U, 604800, I_AdvPreferredLifetime,
	parse_s},
	{ "AdvAutonomousFlag", 0, 1, 1, I_AdvAutonomousFlag, parse_onoff },
	{ "AdvValidExpiration", 0, ~0U, 0, I_AdvValidExpiration,
	parse_date },
	{ "AdvPreferredExpiration", 0, ~0U, 0, I_AdvPreferredExpiration,
	parse_date},
	{ NULL, 0, 0, 0, 0 },
};

/*
 * Data structures used to merge above protocol defaults
 * with defaults specified in the configuration file.
 * ifdefault is not static because new interfaces can be
 * created outside of the configuration context.
 */
struct confvar ifdefaults[I_IFSIZE];
static struct confvar prefixdefaults[I_PREFIXSIZE];

static char	conf_filename[MAXPATHLEN];
static int	lineno;

/*
 * Checks for violations of section 5.5.3 (c) of RFC 2462.
 */
static void
check_var_consistency(struct confvar *cv, void *save, int size)
{
	boolean_t rollback = _B_FALSE;
	int prefl, prefe, valid;

	prefl = cv[I_AdvPreferredLifetime].cf_value;
	prefe = cv[I_AdvPreferredExpiration].cf_value;
	valid = cv[I_AdvValidLifetime].cf_value;

	if (prefl > valid) {
		conferr("AdvPreferredLifetime (%u) is greater than "
		    "valid lifetime (%u)\n", prefl, valid);
		rollback = _B_TRUE;
	}

	if (prefe > valid) {
		conferr("AdvPreferredExpiration (%u) is greater than "
		    "valid lifetime (%u)\n", prefe, valid);
		rollback = _B_TRUE;
	}

	if (rollback) {
		(void) memcpy(cv, save, size);
	}
}

/*
 * Check for invalid lifetime values for RFC3041 addresses
 */
static void
check_if_var_consistency(struct confvar *cv, void *save, int size)
{
	boolean_t rollback = _B_FALSE;
	int tpref, tvalid, tdesync, tregen;

	tpref = cv[I_TmpPreferredLifetime].cf_value;
	tvalid = cv[I_TmpValidLifetime].cf_value;
	tdesync = cv[I_TmpMaxDesyncFactor].cf_value;
	tregen = cv[I_TmpRegenAdvance].cf_value;

	/*
	 * Only need to do this if tmp addrs are enabled.
	 */
	if (cv[I_TmpAddrsEnabled].cf_value == 0)
		return;

	if (tdesync > tpref) {
		conferr("TmpDesyncFactor (%u) is greater than "
		    "TmpPreferredLifetime (%u)\n", tdesync, tpref);
		rollback = _B_TRUE;
	}

	if (tpref > tvalid) {
		conferr("TmpPreferredLifetime (%u) is greater than "
		    "TmpValidLifetime (%u)\n", tpref, tvalid);
		rollback = _B_TRUE;
	}

	if (tregen > tvalid) {
		conferr("TmpRegenAdvance (%u) is greater than "
		    "TmpValidLifetime (%u)\n", tregen, tvalid);
		rollback = _B_TRUE;
	}

	if (rollback) {
		(void) memcpy(cv, save, size);
	}
}

int
parse_config(char *config_file, boolean_t file_required)
{
	FILE *fp;
	char line[MAXLINELEN];
	char pline[MAXLINELEN];
	int argcount;
	char *argvec[MAXARGSPERLINE];
	int defaultdone = 0;	/* Set when first non-default command found */

	if (debug & D_CONFIG)
		logmsg(LOG_DEBUG, "parse_config()\n");

	set_protocol_defaults();
	if (debug & D_DEFAULTS)
		print_defaults();

	fp = open_conffile(config_file);
	if (fp == NULL) {
		if (errno == ENOENT && !file_required)
			return (0);
		logperror(config_file);
		return (-1);
	}
	while (readline(fp, line, sizeof (line)) != 0) {
		(void) strncpy(pline, line, sizeof (pline));
		pline[sizeof (pline) - 1] = '\0';	/* NULL terminate */
		argcount = parse_line(pline, argvec,
		    sizeof (argvec) / sizeof (argvec[0]));
		if (debug & D_PARSE) {
			int i;

			logmsg(LOG_DEBUG, "scanned %d args\n", argcount);
			for (i = 0; i < argcount; i++)
				logmsg(LOG_DEBUG, "arg[%d]: %s\n",
				    i, argvec[i]);
		}
		if (argcount == 0) {
			/* Empty line - or comment only line */
			continue;
		}
		if (strcmp(argvec[0], "ifdefault") == 0) {
			char save[sizeof (ifdefaults)];

			if (defaultdone) {
				conferr("ifdefault after non-default "
				    "command\n");
				continue;
			}
			/*
			 * Save existing values in case what we read is
			 * invalid and we need to restore previous settings.
			 */
			(void) memcpy(save, ifdefaults, sizeof (ifdefaults));
			parse_default(CONFIG_IF, iflist, argvec+1, argcount-1,
			    ifdefaults);
			check_if_var_consistency(ifdefaults, save,
			    sizeof (save));
		} else if (strcmp(argvec[0], "prefixdefault") == 0) {
			char save[sizeof (prefixdefaults)];

			if (defaultdone) {
				conferr("prefixdefault after non-default "
				    "command\n");
				continue;
			}
			/*
			 * Save existing values in case what we read is
			 * invalid and we need to restore previous settings.
			 */
			(void) memcpy(save, prefixdefaults,
			    sizeof (prefixdefaults));
			parse_default(CONFIG_PREFIX, prefixlist, argvec+1,
			    argcount-1, prefixdefaults);
			check_var_consistency(prefixdefaults, save,
			    sizeof (save));
		} else if (strcmp(argvec[0], "if") == 0) {
			defaultdone = 1;
			parse_if(iflist, argvec+1, argcount-1);
		} else if (strcmp(argvec[0], "prefix") == 0) {
			defaultdone = 1;
			parse_prefix(prefixlist, argvec+1, argcount-1);
		} else {
			conferr("Unknown command: %s\n", argvec[0]);
		}
	}
	(void) fclose(fp);
	if (debug & D_DEFAULTS)
		print_defaults();
	return (0);
}

/*
 * Extract the defaults from the configinfo tables to initialize
 * the ifdefaults and prefixdefaults arrays.
 * The arrays are needed to track which defaults have been changed
 * by the config file.
 */
static void
set_protocol_defaults(void)
{
	struct configinfo *cip;

	if (debug & D_DEFAULTS)
		logmsg(LOG_DEBUG, "extract_protocol_defaults\n");
	for (cip = iflist; cip->ci_name != NULL; cip++) {
		ifdefaults[cip->ci_index].cf_value = cip->ci_default;
		ifdefaults[cip->ci_index].cf_notdefault = _B_FALSE;
	}
	for (cip = prefixlist; cip->ci_name != NULL; cip++) {
		prefixdefaults[cip->ci_index].cf_value = cip->ci_default;
		prefixdefaults[cip->ci_index].cf_notdefault = _B_FALSE;
	}
}

void
print_iflist(struct confvar *confvar)
{
	struct configinfo *cip;

	for (cip = iflist; cip->ci_name != NULL; cip++) {
		logmsg(LOG_DEBUG, "\t%s min %u max %u def %u value %u set %d\n",
		    cip->ci_name, cip->ci_min, cip->ci_max, cip->ci_default,
		    confvar[cip->ci_index].cf_value,
		    confvar[cip->ci_index].cf_notdefault);
	}
}

void
print_prefixlist(struct confvar *confvar)
{
	struct configinfo *cip;

	for (cip = prefixlist; cip->ci_name != NULL; cip++) {
		logmsg(LOG_DEBUG, "\t%s min %u max %u def %u value %u set %d\n",
		    cip->ci_name, cip->ci_min, cip->ci_max, cip->ci_default,
		    confvar[cip->ci_index].cf_value,
		    confvar[cip->ci_index].cf_notdefault);
	}
}


static void
print_defaults(void)
{
	logmsg(LOG_DEBUG, "Default interface variables:\n");
	print_iflist(ifdefaults);
	logmsg(LOG_DEBUG, "Default prefix variables:\n");
	print_prefixlist(prefixdefaults);
}

/*
 * Read from fp. Handle \ at the end of the line by joining lines together.
 * Return 0 on EOF.
 */
static int
readline(FILE *fp, char *line, int length)
{
	int got = 0;

retry:
	errno = 0;
	if (fgets(line, length, fp) == NULL) {
		if (errno == EINTR)
			goto retry;
		if (got != 0)
			return (1);
		else
			return (0);
	}
	lineno++;
	got = strlen(line);
	/* Look for trailing \. Note that fgets includes the linefeed. */
	if (got >= 2 && line[got-2] == '\\') {
		/* Skip \ and LF */
		line += got - 2;
		length -= got - 2;
		goto retry;
	}
	/* Remove the trailing linefeed */
	if (got > 0)
		line[got-1] = '\0';

	return (1);
}

/*
 * Parse a line splitting it off at whitspace characters.
 * Modifies the content of the string by inserting NULLs.
 * If more arguments than fits in argvec/argcount then ignore the last.
 * Returns argcount.
 * Handles single quotes and double quotes.
 */
static int
parse_line(char *line, char *argvec[], int argcount)
{
	int i = 0;
	char *cp;
	boolean_t insingle_quote = _B_FALSE;
	boolean_t indouble_quote = _B_FALSE;

	/* Truncate at the beginning of a comment */
	cp = strchr(line, '#');
	if (cp != NULL)
		*cp = '\0';

	for (;;) {
		/* Skip any whitespace */
		while (isspace(*line) && *line != '\0')
			line++;

		if (*line == '\'') {
			line++;
			if (*line == '\0')
				return (i);
			insingle_quote = _B_TRUE;
		} else if (*line == '"') {
			line++;
			if (*line == '\0')
				return (i);
			indouble_quote = _B_TRUE;
		}
		argvec[i] = line;
		if (*line == '\0')
			return (i);
		i++;
		/* Skip until next whitespace or end of quoted text */
		if (insingle_quote) {
			while (*line != '\'' && *line != '\0')
				line++;
			if (*line == '\'') {
				*line = ' ';
			} else {
				/* Handle missing quote at end */
				i--;
				conferr("Missing end quote - ignoring <%s>\n",
				    argvec[i]);
				return (i);
			}
			insingle_quote = _B_FALSE;
		} else if (indouble_quote) {
			while (*line != '"' && *line != '\0')
				line++;
			if (*line == '"') {
				*line = ' ';
			} else {
				/* Handle missing quote at end */
				i--;
				conferr("Missing end quote - ignoring <%s>\n",
				    argvec[i]);
				return (i);
			}
			indouble_quote = _B_FALSE;
		} else {
			while (!isspace(*line) && *line != '\0')
				line++;
		}
		if (*line != '\0') {
			/* Break off argument */
			*line++ = '\0';
		}
		if (i > argcount)
			return (argcount);
	}
	/* NOTREACHED */
}

static void
parse_var_value(config_type_t type, struct configinfo *list, char *varstr,
    char *valstr, struct confvar *confvar)
{
	struct configinfo *cip;
	uint_t val;

	if (debug & D_CONFIG) {
		logmsg(LOG_DEBUG, "parse_var_value(%d, %s, %s)\n",
		    (int)type, varstr, valstr);
	}

	for (cip = list; cip->ci_name != NULL; cip++) {
		if (strcasecmp(cip->ci_name, varstr) == 0)
			break;
	}
	if (cip->ci_name == NULL) {
		conferr("Unknown variable: <%s>\n", varstr);
		return;
	}
	if (!(*cip->ci_parsefunc)(valstr, &val)) {
		conferr("Bad value: <%s>\n", valstr);
		return;
	}
	if (cip->ci_min != 0 && val < cip->ci_min) {
		conferr("Value %s is below minimum %u for %s\n",
		    valstr, cip->ci_min, varstr);
		return;
	}
	if (cip->ci_max != ~0U && val > cip->ci_max) {
		conferr("Value %s is above maximum %u for %s\n",
		    valstr, cip->ci_max, varstr);
		return;
	}
	/* Check against dynamic/relative limits */
	if (type == CONFIG_IF) {
		if (cip->ci_index == I_MinRtrAdvInterval &&
		    confvar[I_MaxRtrAdvInterval].cf_notdefault &&
		    val > confvar[I_MaxRtrAdvInterval].cf_value * 0.75) {
			conferr("MinRtrAdvInterval exceeds .75 * "
			    "MaxRtrAdvInterval (%u)\n",
			    confvar[I_MaxRtrAdvInterval].cf_value);
			return;
		}
		if (cip->ci_index == I_MaxRtrAdvInterval &&
		    confvar[I_MinRtrAdvInterval].cf_notdefault &&
		    confvar[I_MinRtrAdvInterval].cf_value > val * 0.75) {
			conferr("MinRtrAdvInterval (%u) exceeds .75 * "
			    "MaxRtrAdvInterval\n",
			    confvar[I_MinRtrAdvInterval].cf_value);
			return;
		}
		if (cip->ci_index == I_AdvDefaultLifetime &&
		    confvar[I_MaxRtrAdvInterval].cf_notdefault &&
		    val != 0 &&
		    val < confvar[I_MaxRtrAdvInterval].cf_value) {
			conferr("AdvDefaultLifetime is not between "
			    "MaxRtrAdrInterval (%u) and 9000 seconds\n",
			    confvar[I_MaxRtrAdvInterval].cf_value);
			return;
		}
		if (cip->ci_index == I_MaxRtrAdvInterval &&
		    confvar[I_AdvDefaultLifetime].cf_notdefault &&
		    confvar[I_AdvDefaultLifetime].cf_value < val) {
			conferr("AdvDefaultLifetime (%u) is not between "
			    "MaxRtrAdrInterval and 9000 seconds\n",
			    confvar[I_AdvDefaultLifetime].cf_value);
			return;
		}
	}
	confvar[cip->ci_index].cf_value = val;
	confvar[cip->ci_index].cf_notdefault = _B_TRUE;

	/* Derive dynamic/relative variables based on this one */
	if (type == CONFIG_IF) {
		if (cip->ci_index == I_MaxRtrAdvInterval &&
		    !confvar[I_MinRtrAdvInterval].cf_notdefault)
			confvar[I_MinRtrAdvInterval].cf_value = val / 3;
		if (cip->ci_index == I_MaxRtrAdvInterval &&
		    !confvar[I_AdvDefaultLifetime].cf_notdefault)
		    confvar[I_AdvDefaultLifetime].cf_value = 3 * val;
	}
}

/*
 * Split up the line into <variable> <value> pairs
 */
static void
parse_default(config_type_t type, struct configinfo *list,
    char *argvec[], int argcount, struct confvar *defaults)
{
	if (debug & D_CONFIG)
		logmsg(LOG_DEBUG, "parse_default: argc %d\n", argcount);
	while (argcount >= 2) {
		parse_var_value(type, list, argvec[0], argvec[1], defaults);

		argcount -= 2;
		argvec += 2;
	}
	if (argcount != 0)
		conferr("Trailing text <%s> ignored\n", argvec[0]);
}

/*
 * Returns true if ok; otherwise false.
 */
static void
parse_if(struct configinfo *list, char *argvec[], int argcount)
{
	char *ifname;
	struct phyint *pi;
	char save[sizeof (pi->pi_config)];

	if (debug & D_CONFIG)
		logmsg(LOG_DEBUG, "parse_if: argc %d\n", argcount);

	if (argcount < 1) {
		conferr("Missing interface name\n");
		return;
	}
	ifname = argvec[0];
	argvec++;
	argcount--;

	pi = phyint_lookup(ifname);
	if (pi == NULL) {
		/*
		 * Create the physical interface structure.
		 * Note, phyint_create() sets the interface
		 * defaults in pi_config.
		 */
		pi = phyint_create(ifname);
		if (pi == NULL) {
			conferr("Unable to use interface %s\n", ifname);
			return;
		}
	}

	(void) memcpy(save, pi->pi_config, sizeof (save));
	while (argcount >= 2) {
		parse_var_value(CONFIG_IF, list, argvec[0], argvec[1],
		    pi->pi_config);

		argcount -= 2;
		argvec += 2;
	}
	if (argcount != 0)
		logmsg(LOG_ERR, "Trailing text <%s> ignored\n", argvec[0]);
	check_if_var_consistency(pi->pi_config, save, sizeof (save));
}

static void
parse_prefix(struct configinfo *list, char *argvec[], int argcount)
{
	char *ifname, *prefix;
	struct phyint *pi;
	struct adv_prefix *adv_pr;
	struct in6_addr in6;
	int prefixlen;
	char save[sizeof (adv_pr->adv_pr_config)];

	if (debug & D_CONFIG)
		logmsg(LOG_DEBUG, "parse_prefix: argc %d\n", argcount);

	if (argcount < 2) {
		conferr("Missing prefix and/or interface name\n");
		return;
	}
	prefix = argvec[0];
	ifname = argvec[1];
	argvec += 2;
	argcount -= 2;

	prefixlen = parse_addrprefix(prefix, &in6);
	if (prefixlen == -1) {
		conferr("Bad prefix %s\n", prefix);
		return;
	}

	pi = phyint_lookup(ifname);
	if (pi == NULL) {
		/*
		 * Create the physical interface structure.
		 * Note, phyint_create() sets the interface
		 * defaults in pi_config.
		 */
		pi = phyint_create(ifname);
		if (pi == NULL) {
			conferr("Unable to use interface %s\n", ifname);
			return;
		}
	}
	adv_pr = adv_prefix_lookup(pi, in6, prefixlen);
	if (adv_pr == NULL) {
		int i;

		adv_pr = adv_prefix_create(pi, in6, prefixlen);
		if (adv_pr == NULL) {
			conferr("Unable to create prefix %s\n", prefix);
			return;
		}
		/*
		 * Copy the defaults from the default array.
		 */
		for (i = 0; i < I_PREFIXSIZE; i++) {
			adv_pr->adv_pr_config[i].cf_value =
			    prefixdefaults[i].cf_value;
			adv_pr->adv_pr_config[i].cf_notdefault =
			    prefixdefaults[i].cf_notdefault;
		}
	}

	(void) memcpy(save, adv_pr->adv_pr_config, sizeof (save));
	while (argcount >= 2) {
		parse_var_value(CONFIG_PREFIX, list, argvec[0], argvec[1],
		    adv_pr->adv_pr_config);

		argcount -= 2;
		argvec += 2;
	}
	check_var_consistency(adv_pr->adv_pr_config, save, sizeof (save));
	if (argcount != 0)
		logmsg(LOG_ERR, "Trailing text <%s> ignored\n", argvec[0]);
}

/*
 * Returns true if ok (and *resp updated) and false if failed.
 */
static boolean_t
parse_onoff(char *str, uint_t *resp)
{
	if (strcasecmp(str, "on") == 0) {
		*resp = 1;
		return (_B_TRUE);
	}
	if (strcasecmp(str, "off") == 0) {
		*resp = 0;
		return (_B_TRUE);
	}
	if (strcasecmp(str, "true") == 0) {
		*resp = 1;
		return (_B_TRUE);
	}
	if (strcasecmp(str, "false") == 0) {
		*resp = 0;
		return (_B_TRUE);
	}
	if (parse_int(str, resp)) {
		if (*resp == 0 || *resp == 1)
			return (_B_TRUE);
	}
	return (_B_FALSE);
}

/*
 * Returns true if ok (and *resp updated) and false if failed.
 */
static boolean_t
parse_int(char *str, uint_t *resp)
{
	char *end;
	int res;

	res = strtoul(str, &end, 0);
	if (end == str)
		return (_B_FALSE);
	*resp = res;
	return (_B_TRUE);
}

/*
 * Parse something with a unit of millseconds.
 * Regognizes the suffixes "ms", "s", "m", "h", and "d".
 *
 * Returns true if ok (and *resp updated) and false if failed.
 */
static boolean_t
parse_ms(char *str, uint_t *resp)
{
	/* Look at the last and next to last character */
	char *cp, *last, *nlast;
	char str2[BUFSIZ];	/* For local modification */
	int multiplier = 1;

	(void) strncpy(str2, str, sizeof (str2));
	str2[sizeof (str2) - 1] = '\0';

	last = str2;
	nlast = NULL;
	for (cp = str2; *cp != '\0'; cp++) {
		nlast = last;
		last = cp;
	}
	if (debug & D_PARSE) {
		logmsg(LOG_DEBUG, "parse_ms: last <%c> nlast <%c>\n",
		    (last != NULL ? *last : ' '),
		    (nlast != NULL ? *nlast : ' '));
	}
	switch (*last) {
	case 'd':
		multiplier *= 24;
		/* FALLTHRU */
	case 'h':
		multiplier *= 60;
		/* FALLTHRU */
	case 'm':
		multiplier *= 60;
		*last = '\0';
		multiplier *= 1000;	/* Convert to milliseconds */
		break;
	case 's':
		/* Could be "ms" or "s" */
		if (nlast != NULL && *nlast == 'm') {
			/* "ms" */
			*nlast = '\0';
		} else {
			*last = '\0';
			multiplier *= 1000;	/* Convert to milliseconds */
		}
		break;
	}

	if (!parse_int(str2, resp))
		return (_B_FALSE);

	*resp *= multiplier;
	return (_B_TRUE);
}

/*
 * Parse something with a unit of seconds.
 * Regognizes the suffixes "s", "m", "h", and "d".
 *
 * Returns true if ok (and *resp updated) and false if failed.
 */
static boolean_t
parse_s(char *str, uint_t *resp)
{
	/* Look at the last character */
	char *cp, *last;
	char str2[BUFSIZ];	/* For local modification */
	int multiplier = 1;

	(void) strncpy(str2, str, sizeof (str2));
	str2[sizeof (str2) - 1] = '\0';

	last = str2;
	for (cp = str2; *cp != '\0'; cp++) {
		last = cp;
	}
	if (debug & D_PARSE) {
		logmsg(LOG_DEBUG, "parse_s: last <%c>\n",
		    (last != NULL ? *last : ' '));
	}
	switch (*last) {
	case 'd':
		multiplier *= 24;
		/* FALLTHRU */
	case 'h':
		multiplier *= 60;
		/* FALLTHRU */
	case 'm':
		multiplier *= 60;
		/* FALLTHRU */
	case 's':
		*last = '\0';
		break;
	}
	if (!parse_int(str2, resp))
		return (_B_FALSE);

	*resp *= multiplier;
	return (_B_TRUE);
}

/*
 * Return prefixlen (0 to 128) if ok; -1 if failed.
 */
static int
parse_addrprefix(char *strin, struct in6_addr *in6)
{
	char str[BUFSIZ];	/* Local copy for modification */
	int prefixlen;
	char *cp;
	char *end;

	(void) strncpy(str, strin, sizeof (str));
	str[sizeof (str) - 1] = '\0';

	cp = strchr(str, '/');
	if (cp == NULL)
		return (-1);
	*cp = '\0';
	cp++;

	prefixlen = strtol(cp, &end, 10);
	if (cp == end)
		return (-1);

	if (prefixlen < 0 || prefixlen > IPV6_ABITS)
		return (-1);

	if (inet_pton(AF_INET6, str, in6) != 1)
		return (-1);

	return (prefixlen);
}

/*
 * Parse an absolute date using a datemsk config file.
 * Return the difference (measured in seconds) between that date/time and
 * the current date/time.
 * If the date has passed return zero.
 *
 * Returns true if ok (and *resp updated) and false if failed.
 * XXX Due to getdate limitations can not exceed year 2038.
 */
static boolean_t
parse_date(char *str, uint_t *resp)
{
	struct tm *tm;
	struct timeval tvs;
	time_t time, ntime;

	if (getenv("DATEMSK") == NULL) {
		(void) putenv("DATEMSK=/etc/inet/datemsk.ndpd");
	}

	if (gettimeofday(&tvs, NULL) < 0) {
		logperror("gettimeofday");
		return (_B_FALSE);
	}
	time = tvs.tv_sec;
	tm = getdate(str);
	if (tm == NULL) {
		logmsg(LOG_ERR, "Bad date <%s> (error %d)\n",
		    str, getdate_err);
		return (_B_FALSE);
	}

	ntime = mktime(tm);

	if (debug & D_PARSE) {
		char buf[BUFSIZ];

		(void) strftime(buf, sizeof (buf), "%Y-%m-%d %R %Z", tm);
		logmsg(LOG_DEBUG, "parse_date: <%s>, delta %ld seconds\n",
		    buf, ntime - time);
	}
	if (ntime < time) {
		conferr("Date in the past <%s>\n", str);
		*resp = 0;
		return (_B_TRUE);
	}
	*resp = (ntime - time);
	return (_B_TRUE);
}

/* PRINTFLIKE1 */
static void
conferr(char *fmt, ...)
{
	char msg[NDPD_LOGMSGSIZE];
	size_t slen;

	va_list ap;
	va_start(ap, fmt);

	(void) snprintf(msg, NDPD_LOGMSGSIZE, "%s line %d: ",
	    conf_filename, lineno);
	slen = strlen(msg);
	(void) vsnprintf(msg + slen, NDPD_LOGMSGSIZE - slen, fmt, ap);

	logmsg(LOG_ERR, "%s", msg);

	va_end(ap);
}

static FILE *
open_conffile(char *filename)
{
	if (strlcpy(conf_filename, filename, MAXPATHLEN) >= MAXPATHLEN) {
		logmsg(LOG_ERR, "config file pathname is too long\n");
		return (NULL);
	}

	lineno = 0;

	return (fopen(filename, "r"));

}
