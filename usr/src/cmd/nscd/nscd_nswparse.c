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

#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>

#define	__NSS_PRIVATE_INTERFACE
#include "nsswitch_priv.h"
#undef	__NSS_PRIVATE_INTERFACE

#define	islabel(c) 	(isalnum(c) || (c) == '_')

/*
 * The _nsw_getoneconfig_v1() in this file parses the switch policy
 * configuration for a switch database, e.g.,
 *
 * hosts: nis [NOTFOUND=return] files
 * or
 * printers: user files nis
 */

/*
 * Local routines
 */
static char *skip(char **, char);
static char *labelskip(char *);
static char *spaceskip(char *);
static void freeconf_v1(struct __nsw_switchconfig_v1 *);
static int alldigits(char *);

/*
 *
 * With the "lookup control" feature, the default criteria for NIS
 * and any new services (e.g. ldap) will be:
 *     [SUCCESS=return  NOTFOUND=continue UNAVAIL=continue TRYAGAIN=forever]
 *
 * For backward compat, NIS via NIS server in DNS forwarding mode will be:
 *     [SUCCESS=return  NOTFOUND=continue UNAVAIL=continue TRYAGAIN=continue]
 *
 * And also for backward compat, the default criteria for DNS will be:
 *     [SUCCESS=return  NOTFOUND=continue UNAVAIL=continue TRYAGAIN=continue]
 */



/*
 * The BIND resolver normally will retry several times on server non-response.
 * But now with the "lookup control" feature, we don't want the resolver doing
 * many retries, rather we want it to return control (reasonably) quickly back
 * to the switch engine.  However, when TRYAGAIN=N or TRYAGAIN=forever is
 * not explicitly set by the admin in the conf file, we want the old "resolver
 * retry a few times" rather than no retries at all.
 */
static int 	dns_tryagain_retry = 3;

/*
 * For backward compat (pre "lookup control"), the dns default behavior is
 * soft lookup.
 */
static void
set_dns_default_lkp(struct __nsw_lookup_v1 *lkp)
{
	if (strcasecmp(lkp->service_name, "dns") == 0) {
		lkp->actions[__NSW_TRYAGAIN] =
		    __NSW_TRYAGAIN_NTIMES;
		lkp->max_retries = dns_tryagain_retry;
	}
}

static void
freeconf_v1(struct __nsw_switchconfig_v1 *cfp)
{
	if (cfp) {
		if (cfp->dbase)
			free(cfp->dbase);
		if (cfp->lookups) {
			struct __nsw_lookup_v1 *nex, *cur;
			for (cur = cfp->lookups; cur; cur = nex) {
				free(cur->service_name);
				nex = cur->next;
				free(cur);
			}
		}
		free(cfp);
	}
}

/* give the next non-alpha character */
static char *
labelskip(char *cur)
{
	char *p = cur;
	while (islabel(*p))
		++p;
	return (p);
}

/* give the next non-space character */
static char *
spaceskip(char *cur)
{
	char *p = cur;
	while (*p == ' ' || *p == '\t')
		++p;
	return (p);
}

/*
 * terminate the *cur pointed string by null only if it is
 * followed by "key" surrounded by zero or more spaces and
 * return value is the same as the original *cur pointer and
 * *cur pointer is advanced to the first non {space, key} char
 * followed by the key. Otherwise, return NULL and keep
 * *cur unchanged.
 */
static char *
skip(char **cur, char key)
{
	char *p, *tmp;
	char *q = *cur;
	int found, tmpfound;

	tmp = labelskip(*cur);
	p = tmp;
	found = (*p == key);
	if (found) {
		*p++ = '\0'; /* overwrite the key */
		p = spaceskip(p);
	} else {
		while (*p == ' ' || *p == '\t') {
			tmpfound = (*++p == key);
			if (tmpfound) {
				found = tmpfound;
					/* null terminate the return token */
				*tmp = '\0';
				p++; /* skip the key */
			}
		}
	}
	if (!found)
		return (NULL); /* *cur unchanged */
	*cur = p;
	return (q);
}

/* Return 1 if the string contains all digits, else return 0. */
static int
alldigits(char *s)
{
	for (; *s; s++)
		if (!isdigit(*s))
			return (0);
	return (1);
}

struct __nsw_switchconfig_v1 *
_nsw_getoneconfig_v1(const char *name, char *linep, enum __nsw_parse_err *errp)
	/* linep   Nota Bene: not const char *	*/
	/* errp  Meanings are abused a bit	*/
{
	struct __nsw_switchconfig_v1 *cfp;
	struct __nsw_lookup_v1 *lkp, **lkq;
	int end_crit;
	action_t act;
	char *p, *tokenp;

	*errp = __NSW_CONF_PARSE_SUCCESS;

	if ((cfp = calloc(1, sizeof (struct __nsw_switchconfig_v1)))
	    == NULL) {
		*errp = __NSW_CONF_PARSE_SYSERR;
		return (NULL);
	}
	cfp->dbase = strdup(name);
	lkq = &cfp->lookups;

	/* linep points to a naming service name */
	for (;;) {
		int i;

		/* white space following the last service */
		if (*linep == '\0' || *linep == '\n') {
			return (cfp);
		}
		if ((lkp = calloc(1, sizeof (struct __nsw_lookup_v1)))
		    == NULL) {
			*errp = __NSW_CONF_PARSE_SYSERR;
			freeconf_v1(cfp);
			return (NULL);
		}

		*lkq = lkp;
		lkq = &lkp->next;

		for (i = 0; i < __NSW_STD_ERRS_V1; i++)
			if (i == __NSW_SUCCESS)
				lkp->actions[i] = __NSW_RETURN;
			else if (i == __NSW_TRYAGAIN)
				lkp->actions[i] = __NSW_TRYAGAIN_FOREVER;
			else
				lkp->actions[i] = __NSW_CONTINUE;

		/* get criteria for the naming service */
		if (tokenp = skip(&linep, '[')) { /* got criteria */

			/* premature end, illegal char following [ */
			if (!islabel(*linep))
				goto barf_line;
			lkp->service_name = strdup(tokenp);
			cfp->num_lookups++;

			set_dns_default_lkp(lkp);

			end_crit = 0;

			/* linep points to a switch_err */
			for (;;) {
				int ntimes = 0; /* try again max N times */
				int dns_continue = 0;

				if ((tokenp = skip(&linep, '=')) == NULL) {
					goto barf_line;
				}

				/* premature end, ill char following = */
				if (!islabel(*linep))
					goto barf_line;

				/* linep points to the string following '=' */
				p = labelskip(linep);
				if (*p == ']')
					end_crit = 1;
				else if (*p != ' ' && *p != '\t')
					goto barf_line;
				*p++ = '\0'; /* null terminate linep */
				p = spaceskip(p);
				if (!end_crit) {
					if (*p == ']') {
					end_crit = 1;
					*p++ = '\0';
					} else if (*p == '\0' || *p == '\n') {
						return (cfp);
					} else if (!islabel(*p))
					/* p better be the next switch_err */
						goto barf_line;
				}
				if (strcasecmp(linep, __NSW_STR_RETURN) == 0)
					act = __NSW_RETURN;
				else if (strcasecmp(linep,
						    __NSW_STR_CONTINUE) == 0) {
					if (strcasecmp(lkp->service_name,
						    "dns") == 0 &&
						strcasecmp(tokenp,
							__NSW_STR_TRYAGAIN)
							== 0) {
						/*
						 * Add one more condition
						 * so it retries only if it's
						 * "dns [TRYAGAIN=continue]"
						 */
						dns_continue = 1;
						act = __NSW_TRYAGAIN_NTIMES;
					} else
						act = __NSW_CONTINUE;
				} else if (strcasecmp(linep,
					    __NSW_STR_FOREVER) == 0)
					act = __NSW_TRYAGAIN_FOREVER;
				else if (alldigits(linep)) {
					act = __NSW_TRYAGAIN_NTIMES;
					ntimes = atoi(linep);
					if (ntimes < 0 || ntimes > INT_MAX)
						ntimes = 0;
				}
				else
					goto barf_line;

				if (__NSW_SUCCESS_ACTION(act) &&
				    strcasecmp(tokenp,
					    __NSW_STR_SUCCESS) == 0) {
					lkp->actions[__NSW_SUCCESS] = act;
				} else if (__NSW_NOTFOUND_ACTION(act) &&
					strcasecmp(tokenp,
					    __NSW_STR_NOTFOUND) == 0) {
					lkp->actions[__NSW_NOTFOUND] = act;
				} else if (__NSW_UNAVAIL_ACTION(act) &&
					strcasecmp(tokenp,
					    __NSW_STR_UNAVAIL) == 0) {
					lkp->actions[__NSW_UNAVAIL] = act;
				} else if (__NSW_TRYAGAIN_ACTION(act) &&
					strcasecmp(tokenp,
					    __NSW_STR_TRYAGAIN) == 0) {
					lkp->actions[__NSW_TRYAGAIN] = act;
					if (strcasecmp(lkp->service_name,
						    "nis") == 0)
						lkp->actions[
						    __NSW_NISSERVDNS_TRYAGAIN]
						    = act;
					if (act == __NSW_TRYAGAIN_NTIMES)
						lkp->max_retries =
						dns_continue ?
						dns_tryagain_retry : ntimes;
				} else {
					/*EMPTY*/
					/*
					 * convert string tokenp to integer
					 * and put in long_errs
					 */
				}
				if (end_crit) {
					linep = spaceskip(p);
					if (*linep == '\0' || *linep == '\n')
						return (cfp);
					break; /* process next naming service */
				}
				linep = p;
			} /* end of while loop for a name service's criteria */
		} else {
			/*
			 * no criteria for this naming service.
			 * linep points to name service, but not null
			 * terminated.
			 */
			p = labelskip(linep);
			if (*p == '\0' || *p == '\n') {
				*p = '\0';
				lkp->service_name = strdup(linep);
				set_dns_default_lkp(lkp);
				cfp->num_lookups++;
				return (cfp);
			}
			if (*p != ' ' && *p != '\t')
				goto barf_line;
			*p++ = '\0';
			lkp->service_name = strdup(linep);
			set_dns_default_lkp(lkp);
			cfp->num_lookups++;
			linep = spaceskip(p);
		}
	} /* end of while(1) loop for a name service */

barf_line:
	freeconf_v1(cfp);
	*errp = __NSW_CONF_PARSE_NOPOLICY;
	return (NULL);
}

int
__nsw_freeconfig_v1(
	struct __nsw_switchconfig_v1 *conf)
{
	freeconf_v1(conf);
	return (0);
}
