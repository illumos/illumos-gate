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
 * Copyright 2015 Gary Mills
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <synch.h>
#include <strings.h>
#include <sys/time.h>
#include <ctype.h>

#include "ldap_op.h"
#include "ldap_util.h"
#include "ldap_structs.h"
#include "ldap_ruleval.h"
#include "ldap_attr.h"
#include "ldap_print.h"
#include "ldap_glob.h"

#include "nis_parse_ldap_conf.h"

#ifndef LDAPS_PORT
#define	LDAPS_PORT	636
#endif

static int setupConList(char *serverList, char *who,
			char *cred, auth_method_t method);


/*
 * Build one of our internal LDAP search structures, containing copies of
 * the supplied input. return NULL in case of error.
 *
 * If 'filter' is NULL, build an AND-filter using the filter components.
 */
__nis_ldap_search_t *
buildLdapSearch(char *base, int scope, int numFilterComps, char **filterComp,
		char *filter, char **attrs, int attrsonly, int isDN) {
	__nis_ldap_search_t	*ls;
	char			**a;
	int			i, na, err = 0;
	char			*myself = "buildLdapSearch";

	ls = am(myself, sizeof (*ls));
	if (ls == 0)
		return (0);

	ls->base = sdup(myself, T, base);
	if (ls->base == 0 && base != 0)
		err++;
	ls->scope = scope;

	if (filterComp != 0 && numFilterComps > 0) {
		ls->filterComp = am(myself, numFilterComps *
					sizeof (ls->filterComp[0]));
		if (ls->filterComp == 0) {
			err++;
			numFilterComps = 0;
		}
		for (i = 0; i < numFilterComps; i++) {
			ls->filterComp[i] = sdup(myself, T, filterComp[i]);
			if (ls->filterComp[i] == 0 && filterComp[i] != 0)
				err++;
		}
		ls->numFilterComps = numFilterComps;
		if (filter == 0) {
			ls->filter = concatenateFilterComps(ls->numFilterComps,
					ls->filterComp);
			if (ls->filter == 0)
				err++;
		}
	} else {
		ls->filterComp = 0;
		ls->numFilterComps = 0;
		ls->filter = sdup(myself, T, filter);
		if (ls->filter == 0 && filter != 0)
			err++;
	}

	if (attrs != 0) {
		for (na = 0, a = attrs; *a != 0; a++, na++);
		ls->attrs = am(myself, (na + 1) * sizeof (ls->attrs[0]));
		if (ls->attrs != 0) {
			for (i = 0; i < na; i++) {
				ls->attrs[i] = sdup(myself, T, attrs[i]);
				if (ls->attrs[i] == 0 && attrs[i] != 0)
					err++;
			}
			ls->attrs[na] = 0;
			ls->numAttrs = na;
		} else {
			err++;
		}
	} else {
		ls->attrs = 0;
		ls->numAttrs = 0;
	}

	ls->attrsonly = attrsonly;
	ls->isDN = isDN;

	if (err > 0) {
		freeLdapSearch(ls);
		ls = 0;
	}

	return (ls);
}

void
freeLdapSearch(__nis_ldap_search_t *ls) {
	int	i;

	if (ls == 0)
		return;

	sfree(ls->base);
	if (ls->filterComp != 0) {
		for (i = 0; i < ls->numFilterComps; i++) {
			sfree(ls->filterComp[i]);
		}
		sfree(ls->filterComp);
	}
	sfree(ls->filter);
	if (ls->attrs != 0) {
		for (i = 0; i < ls->numAttrs; i++) {
			sfree(ls->attrs[i]);
		}
		sfree(ls->attrs);
	}

	free(ls);
}

/*
 * Given a table mapping, and a rule/value pointer,
 * return an LDAP search structure with values suitable for use
 * by ldap_search() or (if dn != 0) ldap_modify(). The rule/value
 * may be modified.
 *
 * If dn != 0 and *dn == 0, the function attemps to return a pointer
 * to the DN. This may necessitate an ldapSearch, if the rule set doesn't
 * produce a DN directly.
 *
 * if dn == 0, and the rule set produces a DN as well as other attribute/
 * value pairs, the function returns an LDAP search structure with the
 * DN only.
 *
 * If 'fromLDAP' is set, the caller wants base/scope/filter from
 * t->objectDN->read; otherwise, from t->objectDN->write.
 *
 * If 'rv' is NULL, the caller wants an enumeration of the container.
 *
 * Note that this function only creates a search structure for 't' itself;
 * if there are alternative mappings for the table, those must be handled
 * by our caller.
 */
__nis_ldap_search_t *
createLdapRequest(__nis_table_mapping_t *t,
		__nis_rule_value_t *rv, char **dn, int fromLDAP,
		int *res, __nis_object_dn_t *obj_dn) {
	int			i, j;
	__nis_ldap_search_t	*ls = 0;
	char			**locDN;
	int			numLocDN, stat = 0, count = 0;
	char			*myself = "createLdapRequest";
	__nis_object_dn_t 	*objectDN = NULL;

	if (t == 0)
		return (0);

	if (obj_dn == NULL)
		objectDN = t->objectDN;
	else
		objectDN = obj_dn;

	if (rv == 0) {
		char	*base;
		char	*filter;

		if (fromLDAP) {
			base = objectDN->read.base;
			filter = makeFilter(objectDN->read.attrs);
		} else {
			base = objectDN->write.base;
			filter = makeFilter(objectDN->write.attrs);
		}

		/* Create request to enumerate container */
		ls = buildLdapSearch(base, objectDN->read.scope, 0, 0, filter,
					0, 0, 0);
		sfree(filter);
		return (ls);
	}

	for (i = 0; i < t->numRulesToLDAP; i++) {
		rv = addLdapRuleValue(t, t->ruleToLDAP[i],
				mit_ldap, mit_nisplus, rv, !fromLDAP, &stat);
		if (rv == 0)
			return (0);
		if (stat == NP_LDAP_RULES_NO_VALUE)
			count++;
		stat = 0;
	}

	/*
	 * If none of the rules produced a value despite
	 * having enough NIS+ columns, return error.
	 */
	if (rv->numAttrs == 0 && count > 0) {
		*res = NP_LDAP_RULES_NO_VALUE;
		return (0);
	}

	/*
	 * 'rv' now contains everything we know about the attributes and
	 * values. Build an LDAP search structure from it.
	 */

	/* Look for a single-valued DN */
	locDN = findDNs(myself, rv, 1,
			fromLDAP ? objectDN->read.base :
					objectDN->write.base,
			&numLocDN);
	if (locDN != 0 && numLocDN == 1) {
		if (dn != 0 && *dn == 0) {
			*dn = locDN[0];
			sfree(locDN);
		} else {
			char	*filter;

			if (fromLDAP)
				filter = makeFilter(objectDN->read.attrs);
			else
				filter = makeFilter(objectDN->write.attrs);
			ls = buildLdapSearch(locDN[0], LDAP_SCOPE_BASE, 0, 0,
						filter, 0, 0, 1);
			sfree(filter);
			freeDNs(locDN, numLocDN);
		}
	} else {
		freeDNs(locDN, numLocDN);
	}

	if (ls != 0) {
		ls->useCon = 1;
		return (ls);
	}

	/*
	 * No DN, or caller wanted a search structure with the non-DN
	 * attributes.
	 */

	/* Initialize search structure */
	{
		char	*filter = (fromLDAP) ?
				makeFilter(objectDN->read.attrs) :
				makeFilter(objectDN->write.attrs);
		char	**ofc;
		int	nofc = 0;

		ofc = makeFilterComp(filter, &nofc);

		if (filter != 0 && ofc == 0) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: Unable to break filter into components: \"%s\"",
				myself, NIL(filter));
			sfree(filter);
			return (0);
		}

		if (fromLDAP)
			ls = buildLdapSearch(objectDN->read.base,
				objectDN->read.scope,
				nofc, ofc, 0, 0, 0, 0);
		else
			ls = buildLdapSearch(objectDN->write.base,
				objectDN->write.scope,
				nofc, ofc, 0, 0, 0, 0);
		sfree(filter);
		freeFilterComp(ofc, nofc);
		if (ls == 0)
			return (0);
	}

	/* Build and add the filter components */
	for (i = 0; i < rv->numAttrs; i++) {
		/* Skip DN */
		if (strcasecmp("dn", rv->attrName[i]) == 0)
			continue;

		/* Skip vt_ber values */
		if (rv->attrVal[i].type == vt_ber)
			continue;

		for (j = 0; j < rv->attrVal[i].numVals; j++) {
			__nis_buffer_t	b = {0, 0};
			char		**tmpComp;

			bp2buf(myself, &b, "%s=%s",
				rv->attrName[i], rv->attrVal[i].val[j].value);
			tmpComp = addFilterComp(b.buf, ls->filterComp,
						&ls->numFilterComps);
			if (tmpComp == 0) {
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: Unable to add filter component \"%s\"",
					myself, NIL(b.buf));
				sfree(b.buf);
				freeLdapSearch(ls);
				return (0);
			}
			ls->filterComp = tmpComp;
			sfree(b.buf);
		}
	}

	if (ls->numFilterComps > 0) {
		sfree(ls->filter);
		ls->filter = concatenateFilterComps(ls->numFilterComps,
							ls->filterComp);
		if (ls->filter == 0) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
			"%s: Unable to concatenate filter components",
				myself);
			freeLdapSearch(ls);
			return (0);
		}
	}

	if (dn != 0 && *dn == 0) {
		/*
		 * The caller wants a DN, but we didn't get one from the
		 * the rule set. We have an 'ls', so use it to ldapSearch()
		 * for an entry from which we can extract the DN.
		 */
		__nis_rule_value_t	*rvtmp;
		char			**locDN;
		int			nv = 0, numLocDN;

		rvtmp = ldapSearch(ls, &nv, 0, 0);
		locDN = findDNs(myself, rvtmp, nv, 0, &numLocDN);
		if (locDN != 0 && numLocDN == 1) {
			*dn = locDN[0];
			sfree(locDN);
		} else {
			freeDNs(locDN, numLocDN);
		}
		freeRuleValue(rvtmp, nv);
	}

	ls->useCon = 1;
	return (ls);
}

int	ldapConnAttemptRetryTimeout = 60;	/* seconds */

typedef struct {
	LDAP		*ld;
	mutex_t		mutex;		/* Mutex for update of structure */
	pthread_t	owner;		/* Thread holding mutex */
	mutex_t		rcMutex;	/* Mutex for refCount */
	int		refCount;	/* Reference count */
	int		isBound;	/* Is connection open and usable ? */
	time_t		retryTime;	/* When should open be retried */
	int		status;		/* Status of last operation */
	int		doDis;		/* To be disconnected if refCount==0 */
	int		doDel;		/* To be deleted if refCount zero */
	int		onList;		/* True if on the 'ldapCon' list */
	char		*sp;		/* server string */
	char		*who;
	char		*cred;
	auth_method_t	method;
	int		port;
	struct timeval	bindTimeout;
	struct timeval	searchTimeout;
	struct timeval	modifyTimeout;
	struct timeval	addTimeout;
	struct timeval	deleteTimeout;
	int		simplePage;	/* Can do simple-page */
	int		vlv;		/* Can do VLV */
	uint_t		batchFrom;	/* # entries read in one operation */
	void		*next;
} __nis_ldap_conn_t;

/*
 * List of connections, 'ldapCon', protected by an RW lock.
 *
 * The following locking scheme is used:
 *
 * (1)	Find a connection structure to use to talk to LDAP
 *		Rlock list
 *			Locate structure
 *			Acquire 'mutex'
 *				Acquire 'rcMutex'
 *					update refCount
 *				Release 'rcMutex'
 *			release 'mutex'
 *		Unlock list
 *		Use structure
 *		Release structure when done
 * (2)	Insert/delete structure(s) on/from list
 *		Wlock list
 *			Insert/delete structure; if deleting, must
 *			acquire 'mutex', and 'rcMutex' (in that order),
 *			and 'refCount' must be zero.
 *		Unlock list
 * (3)	Modify structure
 *		Find structure
 *		Acquire 'mutex'
 *			Modify (except refCount)
 *		Release 'mutex'
 *		Release structure
 */

__nis_ldap_conn_t		*ldapCon = 0;
__nis_ldap_conn_t		*ldapReferralCon = 0;
static rwlock_t			ldapConLock = DEFAULTRWLOCK;
static rwlock_t			referralConLock = DEFAULTRWLOCK;

void
exclusiveLC(__nis_ldap_conn_t *lc) {
	pthread_t	me = pthread_self();
	int		stat;

	if (lc == 0)
		return;

	stat = mutex_trylock(&lc->mutex);
	if (stat == EBUSY && lc->owner != me)
		mutex_lock(&lc->mutex);

	lc->owner = me;
}

/* Return 1 if mutex held by this thread, 0 otherwise */
int
assertExclusive(__nis_ldap_conn_t *lc) {
	pthread_t	me;
	int		stat;

	if (lc == 0)
		return (0);

	stat = mutex_trylock(&lc->mutex);

	if (stat == 0) {
		mutex_unlock(&lc->mutex);
		return (0);
	}

	me = pthread_self();
	if (stat != EBUSY || lc->owner != me)
		return (0);

	return (1);
}

void
releaseLC(__nis_ldap_conn_t *lc) {
	pthread_t	me = pthread_self();

	if (lc == 0 || lc->owner != me)
		return;

	lc->owner = 0;
	(void) mutex_unlock(&lc->mutex);
}

void
incrementRC(__nis_ldap_conn_t *lc) {
	if (lc == 0)
		return;

	(void) mutex_lock(&lc->rcMutex);
	lc->refCount++;
	(void) mutex_unlock(&lc->rcMutex);
}

void
decrementRC(__nis_ldap_conn_t *lc) {
	if (lc == 0)
		return;

	(void) mutex_lock(&lc->rcMutex);
	if (lc->refCount > 0)
		lc->refCount--;
	(void) mutex_unlock(&lc->rcMutex);
}

/* Accept a server/port indication, and call ldap_init() */
static LDAP *
ldapInit(char *srv, int port, bool_t use_ssl) {
	LDAP			*ld;
	int			ldapVersion = LDAP_VERSION3;
	int			derefOption = LDAP_DEREF_ALWAYS;
	int			timelimit = proxyInfo.search_time_limit;
	int			sizelimit = proxyInfo.search_size_limit;

	if (srv == 0)
		return (0);

	if (use_ssl) {
		ld = ldapssl_init(srv, port, 1);
	} else {
		ld = ldap_init(srv, port);
	}

	if (ld != 0) {
		(void) ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION,
					&ldapVersion);
		(void) ldap_set_option(ld, LDAP_OPT_DEREF, &derefOption);
		(void) ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
		(void) ldap_set_option(ld, LDAP_OPT_TIMELIMIT, &timelimit);
		(void) ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &sizelimit);
		(void) ldap_set_option(ld, LDAP_OPT_REBIND_ARG, 0);
	}

	return (ld);
}

/*
 * Bind the specified LDAP structure per the supplied authentication.
 * Note: tested with none, simple, and digest_md5. May or may not
 * work with other authentication methods, mostly depending on whether
 * or not 'who' and 'cred' contain sufficient information.
 */
static int
ldapBind(LDAP **ldP, char *who, char *cred, auth_method_t method,
		struct timeval timeout) {
	int		ret;
	LDAP		*ld;
	char		*myself = "ldapBind";

	if (ldP == 0 || (ld = *ldP) == 0)
		return (LDAP_PARAM_ERROR);

	if (method == none) {
		/* No ldap_bind() required (or even possible) */
		ret = LDAP_SUCCESS;
	} else if (method == simple) {
		struct timeval	tv;
		LDAPMessage	*msg = 0;

		tv = timeout;
		ret = ldap_bind(ld, who, cred, LDAP_AUTH_SIMPLE);
		if (ret != -1) {
			ret = ldap_result(ld, ret, 0, &tv, &msg);
			if (ret == 0) {
				ret = LDAP_TIMEOUT;
			} else if (ret == -1) {
				(void) ldap_get_option(ld,
							LDAP_OPT_ERROR_NUMBER,
							&ret);
			} else {
				ret = ldap_result2error(ld, msg, 0);
			}
			if (msg != 0)
				(void) ldap_msgfree(msg);
		} else {
			(void) ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER,
						&ret);
		}
	} else if (method == cram_md5) {
		/* Note: there is only a synchronous call for cram-md5 */
		struct berval ber_cred;

		ber_cred.bv_len = strlen(cred);
		ber_cred.bv_val = cred;
		ret = ldap_sasl_cram_md5_bind_s(ld, who, &ber_cred, NULL, NULL);
	} else if (method == digest_md5) {
		/* Note: there is only a synchronous call for digest-md5 */
		struct berval ber_cred;

		ber_cred.bv_len = strlen(cred);
		ber_cred.bv_val = cred;
		ret = ldap_x_sasl_digest_md5_bind_s(ld, who, &ber_cred, NULL,
			NULL);
	} else {
		ret = LDAP_AUTH_METHOD_NOT_SUPPORTED;
	}

	if (ret != LDAP_SUCCESS) {
		(void) ldap_unbind_s(ld);
		*ldP = 0;
		logmsg(MSG_NOTIMECHECK, LOG_WARNING,
			"%s: Unable to bind as: %s: %s",
			myself, who, ldap_err2string(ret));
	}

	return (ret);
}

/*
 * Free 'lc' and all related memory. Caller must hold the exclusive lock.
 * Return LDAP_UNAVAILABLE upon success, in which case the caller mustn't
 * try to use the structure pointer in any way.
 */
static int
freeCon(__nis_ldap_conn_t *lc) {

	if (!assertExclusive(lc))
		return (LDAP_PARAM_ERROR);

	incrementRC(lc);

	/* Must be unused, unbound, and not on the 'ldapCon' list */
	if (lc->onList || lc->refCount != 1 || lc->isBound) {
		lc->doDel++;
		decrementRC(lc);
		return (LDAP_BUSY);
	}

	sfree(lc->sp);
	sfree(lc->who);
	sfree(lc->cred);

	/* Delete structure with both mutex:es held */

	free(lc);

	return (LDAP_UNAVAILABLE);
}

/*
 * Disconnect the specified LDAP connection. Caller must have acquired 'mutex'.
 *
 * On return, if the status is LDAP_UNAVAILABLE, the caller must not touch
 * the structure in any way.
 */
static int
disconnectCon(__nis_ldap_conn_t *lc) {
	int	stat;
	char	*myself = "disconnectCon";

	if (lc == 0)
		return (LDAP_SUCCESS);

	if (!assertExclusive(lc))
		return (LDAP_UNAVAILABLE);

	if (lc->doDis) {

		/* Increment refCount to protect against interference */
		incrementRC(lc);
		/* refCount must be one (i.e., just us) */
		if (lc->refCount != 1) {
			/*
			 * In use; already marked for disconnect,
			 * so do nothing.
			 */
			decrementRC(lc);
			return (LDAP_BUSY);
		}

		stat = ldap_unbind_s(lc->ld);
		if (stat == LDAP_SUCCESS) {
			lc->ld = 0;
			lc->isBound = 0;
			lc->doDis = 0;
			/* Reset simple page and vlv indication */
			lc->simplePage = 0;
			lc->vlv = 0;
		} else if (verbose) {
			logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: ldap_unbind_s() => %d (%s)",
				myself, stat, ldap_err2string(stat));
		}

		decrementRC(lc);
	}

	if (lc->doDel) {
		if (LDAP_UNAVAILABLE == freeCon(lc))
			stat = LDAP_UNAVAILABLE;
	}

	return (stat);
}

/*
 * controlSupported will determine for a given connection whether a set
 * of controls is supported or not. The input parameters:
 *	lc	The connection
 *	ctrl	A an array of OID strings, the terminal string should be NULL
 * The returned values if LDAP_SUCCESS is returned:
 *	supported	A caller supplied array which will be set to TRUE or
 *			FALSE depending on whether the corresponding control
 *			is reported as supported.
 * Returns LDAP_SUCCESS if the supportedControl attribute is read.
 */

static int
controlSupported(__nis_ldap_conn_t *lc, char **ctrl, bool_t *supported) {
	LDAPMessage	*res, *e;
	char		*attr[2], *a, **val;
	int		stat, i;
	BerElement	*ber = 0;
	char		*myself = "controlSupported";

	attr[0] = "supportedControl";
	attr[1] = 0;

	stat = ldap_search_st(lc->ld, "", LDAP_SCOPE_BASE, "(objectclass=*)",
				attr, 0, &lc->searchTimeout, &res);
	if (stat != LDAP_SUCCESS) {
		logmsg(MSG_NOTIMECHECK, LOG_WARNING,
	"%s: Unable to retrieve supported control information for %s: %s",
			myself, NIL(lc->sp), ldap_err2string(stat));
		return (stat);
	}

	e = ldap_first_entry(lc->ld, res);
	if (e != 0) {
		a = ldap_first_attribute(lc->ld, e, &ber);
		if (a != 0) {
			val = ldap_get_values(lc->ld, e, a);
			if (val == 0) {
				ldap_memfree(a);
				if (ber != 0)
					ber_free(ber, 0);
			}
		}
	}
	if (e == 0 || a == 0 || val == 0) {
		ldap_msgfree(res);
		logmsg(MSG_NOTIMECHECK, LOG_INFO,
			"%s: Unable to get root DSE for %s",
			myself, NIL(lc->sp));
		return (LDAP_OPERATIONS_ERROR);
	}

	while (*ctrl != NULL) {
		*supported = FALSE;
		for (i = 0; val[i] != 0; i++) {
			if (strstr(val[i], *ctrl) != 0) {
				*supported = TRUE;
				break;
			}
		}
		logmsg(MSG_NOTIMECHECK, LOG_INFO,
			"%s: %s: %s: %s",
			myself, NIL(lc->sp), NIL(*ctrl),
			*supported ? "enabled" : "disabled");
		ctrl++;
		supported++;
	}

	ldap_value_free(val);
	ldap_memfree(a);
	if (ber != 0)
		ber_free(ber, 0);
	ldap_msgfree(res);

	return (stat);
}

/*
 * Connect the LDAP connection 'lc'. Caller must have acquired the 'mutex',
 * and the refCount must be zero.
 *
 * On return, if the status is LDAP_UNAVAILABLE, the caller must not touch
 * the structure in any way.
 */
static int
connectCon(__nis_ldap_conn_t *lc, int check_ctrl) {
	struct timeval	tp;
	int		stat;
	bool_t		supported[2] = {FALSE, FALSE};
	char		*ctrl[3] = {LDAP_CONTROL_SIMPLE_PAGE,
					LDAP_CONTROL_VLVREQUEST,
					NULL};

	if (lc == 0)
		return (LDAP_SUCCESS);

	if (!assertExclusive(lc))
		return (LDAP_PARAM_ERROR);

	incrementRC(lc);
	if (lc->refCount != 1) {
		/*
		 * Don't want to step on structure when it's used by someone
		 * else.
		 */
		decrementRC(lc);
		return (LDAP_BUSY);
	}

	(void) gettimeofday(&tp, 0);

	if (lc->ld != 0) {
		/* Try to disconnect */
		lc->doDis++;
		decrementRC(lc);
		/* disconnctCon() will do the delete if required */
		stat = disconnectCon(lc);
		if (stat != LDAP_SUCCESS)
			return (stat);
		incrementRC(lc);
		if (lc->refCount != 1 || lc->ld != 0) {
			decrementRC(lc);
			return (lc->ld != 0) ? LDAP_SUCCESS :
						LDAP_BUSY;
		}
	} else if (tp.tv_sec < lc->retryTime) {
		/* Too early to retry connect */
		decrementRC(lc);
		return (LDAP_SERVER_DOWN);
	}

	/* Set new retry time in case we fail below */
	lc->retryTime = tp.tv_sec + ldapConnAttemptRetryTimeout;

	lc->ld = ldapInit(lc->sp, lc->port, proxyInfo.tls_method != no_tls);
	if (lc->ld == 0) {
		decrementRC(lc);
		return (LDAP_LOCAL_ERROR);
	}

	stat = lc->status = ldapBind(&lc->ld, lc->who, lc->cred, lc->method,
		lc->bindTimeout);
	if (lc->status == LDAP_SUCCESS) {
		lc->isBound = 1;
		lc->retryTime = 0;
		if (check_ctrl) {
			(void) controlSupported(lc, ctrl, supported);
			lc->simplePage = supported[0];
			lc->vlv = supported[1];
			lc->batchFrom = 50000;
		}
	}

	decrementRC(lc);

	return (stat);
}

/*
 * Find and return a connection believed to be OK.
 */
static __nis_ldap_conn_t *
findCon(int *stat) {
	__nis_ldap_conn_t	*lc;
	int			ldapStat;
	char			*myself = "findCon";

	if (stat == 0)
		stat = &ldapStat;

	(void) rw_rdlock(&ldapConLock);

	if (ldapCon == 0) {
		/* Probably first call; try to set up the connection list */
		(void) rw_unlock(&ldapConLock);
		if ((*stat = setupConList(proxyInfo.default_servers,
					proxyInfo.proxy_dn,
					proxyInfo.proxy_passwd,
					proxyInfo.auth_method)) !=
					LDAP_SUCCESS)
			return (0);
		(void) rw_rdlock(&ldapConLock);
	}

	for (lc = ldapCon; lc != 0; lc = lc->next) {
		exclusiveLC(lc);
		if (!lc->isBound) {
			*stat = connectCon(lc, 1);
			if (*stat != LDAP_SUCCESS) {
				if (*stat != LDAP_UNAVAILABLE) {
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
		"%s: Cannot open connection to LDAP server (%s): %s",
						myself, NIL(lc->sp),
						ldap_err2string(*stat));
					releaseLC(lc);
				}
				continue;
			}
		} else if (lc->doDis || lc->doDel) {
			*stat = disconnectCon(lc);
			if (*stat != LDAP_UNAVAILABLE)
				releaseLC(lc);
			continue;
		}
		incrementRC(lc);
		releaseLC(lc);
		break;
	}

	(void) rw_unlock(&ldapConLock);

	return (lc);
}

/* Release connection; decrements ref count for the connection */
static void
releaseCon(__nis_ldap_conn_t *lc, int status) {
	int	stat;

	if (lc == 0)
		return;

	exclusiveLC(lc);

	lc->status = status;

	decrementRC(lc);

	if (lc->doDis)
		stat = disconnectCon(lc);
	else
		stat = LDAP_SUCCESS;

	if (stat != LDAP_UNAVAILABLE)
		releaseLC(lc);
}

static __nis_ldap_conn_t *
createCon(char *sp, char *who, char *cred, auth_method_t method, int port) {
	__nis_ldap_conn_t	*lc;
	char			*myself = "createCon";
	char			*r;

	if (sp == 0)
		return (0);

	lc = am(myself, sizeof (*lc));
	if (lc == 0)
		return (0);

	(void) mutex_init(&lc->mutex, 0, 0);
	(void) mutex_init(&lc->rcMutex, 0, 0);

	/* If we need to delete 'lc', freeCon() wants the mutex held */
	exclusiveLC(lc);

	lc->sp = sdup(myself, T, sp);
	if (lc->sp == 0) {
		(void) freeCon(lc);
		return (0);
	}

	if ((r = strchr(lc->sp, ']')) != 0) {
		/*
		 * IPv6 address. Does libldap want this with the
		 * '[' and ']' left in place ? Assume so for now.
		 */
		r = strchr(r, ':');
	} else {
		r = strchr(lc->sp, ':');
	}

	if (r != NULL) {
		*r++ = '\0';
		port = atoi(r);
	} else if (port == 0)
		port = proxyInfo.tls_method == ssl_tls ? LDAPS_PORT : LDAP_PORT;

	if (who != 0) {
		lc->who = sdup(myself, T, who);
		if (lc->who == 0) {
			(void) freeCon(lc);
			return (0);
		}
	}

	if (cred != 0) {
		lc->cred = sdup(myself, T, cred);
		if (lc->cred == 0) {
			(void) freeCon(lc);
			return (0);
		}
	}

	lc->method = method;
	lc->port = port;

	lc->bindTimeout = proxyInfo.bind_timeout;
	lc->searchTimeout = proxyInfo.search_timeout;
	lc->modifyTimeout = proxyInfo.modify_timeout;
	lc->addTimeout = proxyInfo.add_timeout;
	lc->deleteTimeout = proxyInfo.delete_timeout;

	/* All other fields OK at zero */

	releaseLC(lc);

	return (lc);
}

static int
setupConList(char *serverList, char *who, char *cred, auth_method_t method) {
	char			*sls, *sl, *s, *e;
	__nis_ldap_conn_t	*lc, *tmp;
	char			*myself = "setupConList";

	if (serverList == 0)
		return (LDAP_PARAM_ERROR);

	(void) rw_wrlock(&ldapConLock);

	if (ldapCon != 0) {
		/* Assume we've already been called and done the set-up */
		(void) rw_unlock(&ldapConLock);
		return (LDAP_SUCCESS);
	}

	/* Work on a copy of 'serverList' */
	sl = sls = sdup(myself, T, serverList);
	if (sl == 0) {
		(void) rw_unlock(&ldapConLock);
		return (LDAP_NO_MEMORY);
	}

	/* Remove leading white space */
	for (; *sl == ' ' || *sl == '\t'; sl++);

	/* Create connection for each server on the list */
	for (s = sl; *s != '\0'; s = e+1) {
		int	l;

		/* Find end of server/port token */
		for (e = s; *e != ' ' && *e != '\t' && *e != '\0'; e++);
		if (*e != '\0')
			*e = '\0';
		else
			e--;
		l = slen(s);

		if (l > 0) {
			lc = createCon(s, who, cred, method, 0);
			if (lc == 0) {
				free(sls);
				(void) rw_unlock(&ldapConLock);
				return (LDAP_NO_MEMORY);
			}
			lc->onList = 1;
			if (ldapCon == 0) {
				ldapCon = lc;
			} else {
				/* Insert at end of list */
				for (tmp = ldapCon; tmp->next != 0;
					tmp = tmp->next);
				tmp->next = lc;
			}
		}
	}

	free(sls);

	(void) rw_unlock(&ldapConLock);

	return (LDAP_SUCCESS);
}

static bool_t
is_same_connection(__nis_ldap_conn_t *lc, LDAPURLDesc *ludpp)
{
	return (strcasecmp(ludpp->lud_host, lc->sp) == 0 &&
	    ludpp->lud_port == lc->port);
}

static __nis_ldap_conn_t *
find_connection_from_list(__nis_ldap_conn_t *list,
			LDAPURLDesc *ludpp, int *stat)
{
	int			ldapStat;
	__nis_ldap_conn_t	*lc	= NULL;
	if (stat == 0)
		stat = &ldapStat;

	*stat = LDAP_SUCCESS;

	for (lc = list; lc != 0; lc = lc->next) {
		exclusiveLC(lc);
		if (is_same_connection(lc, ludpp)) {
			if (!lc->isBound) {
				*stat = connectCon(lc, 1);
				if (*stat != LDAP_SUCCESS) {
					releaseLC(lc);
					continue;
				}
			} else if (lc->doDis || lc->doDel) {
				(void) disconnectCon(lc);
				releaseLC(lc);
				continue;
			}
			incrementRC(lc);
			releaseLC(lc);
			break;
		}
		releaseLC(lc);
	}
	return (lc);
}

static __nis_ldap_conn_t *
findReferralCon(char **referralsp, int *stat)
{
	__nis_ldap_conn_t	*lc	= NULL;
	__nis_ldap_conn_t	*tmp;
	int			ldapStat;
	int			i;
	LDAPURLDesc		*ludpp	= NULL;
	char			*myself = "findReferralCon";

	if (stat == 0)
		stat = &ldapStat;

	*stat = LDAP_SUCCESS;

	/*
	 * We have the referral lock - to prevent multiple
	 * threads from creating a referred connection simultaneously
	 *
	 * Note that this code assumes that the ldapCon list is a
	 * static list - that it has previously been created
	 * (otherwise we wouldn't have gotten a referral) and that
	 * it will neither grow or shrink - elements may have new
	 * connections or unbound. If this assumption is no longer valid,
	 * the locking needs to be reworked.
	 */
	(void) rw_rdlock(&referralConLock);

	for (i = 0; referralsp[i] != NULL; i++) {
		if (ldap_url_parse(referralsp[i], &ludpp) != LDAP_SUCCESS)
			continue;
		/* Ignore referrals if not at the appropriate tls level */
#ifdef LDAP_URL_OPT_SECURE
		if (ludpp->lud_options & LDAP_URL_OPT_SECURE) {
			if (proxyInfo.tls_method != ssl_tls) {
				ldap_free_urldesc(ludpp);
				continue;
			}
		} else {
			if (proxyInfo.tls_method != no_tls) {
				ldap_free_urldesc(ludpp);
				continue;
			}
		}
#endif

		/* Determine if we already have a connection to the server */
		lc = find_connection_from_list(ldapReferralCon, ludpp, stat);
		if (lc == NULL)
			lc = find_connection_from_list(ldapCon, ludpp, stat);
		ldap_free_urldesc(ludpp);
		if (lc != NULL) {
			(void) rw_unlock(&referralConLock);
			return (lc);
		}
	}

	for (i = 0; referralsp[i] != NULL; i++) {
		if (ldap_url_parse(referralsp[i], &ludpp) != LDAP_SUCCESS)
			continue;
		/* Ignore referrals if not at the appropriate tls level */
#ifdef LDAP_URL_OPT_SECURE
		if (ludpp->lud_options & LDAP_URL_OPT_SECURE) {
			if (proxyInfo.tls_method != ssl_tls) {
				ldap_free_urldesc(ludpp);
				continue;
			}
		} else {
			if (proxyInfo.tls_method != no_tls) {
				ldap_free_urldesc(ludpp);
				continue;
			}
		}
#endif
		lc = createCon(ludpp->lud_host, proxyInfo.proxy_dn,
		    proxyInfo.proxy_passwd,
		    proxyInfo.auth_method,
		    ludpp->lud_port);
		if (lc == 0) {
			ldap_free_urldesc(ludpp);
			(void) rw_unlock(&referralConLock);
			*stat = LDAP_NO_MEMORY;
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
			    "%s: Could not connect to host: %s",
			    myself, NIL(ludpp->lud_host));
			return (NULL);
		}

		lc->onList = 1;
		if (ldapReferralCon == 0) {
			ldapReferralCon = lc;
		} else {
			/* Insert at end of list */
			for (tmp = ldapReferralCon; tmp->next != 0;
			    tmp = tmp->next) {}
			tmp->next = lc;
		}
		lc = find_connection_from_list(ldapReferralCon, ludpp, stat);
		ldap_free_urldesc(ludpp);
		if (lc != NULL)
			break;
	}
	(void) rw_unlock(&referralConLock);
	if (lc == NULL) {
		logmsg(MSG_NOTIMECHECK, LOG_INFO,
		    "%s: Could not find a connection to %s, ...",
		    myself, NIL(referralsp[0]));
	}

	return (lc);
}

/*
 * Find and return a connection believed to be OK and ensure children
 * will never use parent's connection.
 */
static __nis_ldap_conn_t *
findYPCon(__nis_ldap_search_t *ls, int *stat) {
	__nis_ldap_conn_t	*lc, *newlc;
	int			ldapStat, newstat;
	char			*myself = "findYPCon";

	if (stat == 0)
		stat = &ldapStat;

	(void) rw_rdlock(&ldapConLock);

	if (ldapCon == 0) {
		/* Probably first call; try to set up the connection list */
		(void) rw_unlock(&ldapConLock);
		if ((*stat = setupConList(proxyInfo.default_servers,
					proxyInfo.proxy_dn,
					proxyInfo.proxy_passwd,
					proxyInfo.auth_method)) !=
					LDAP_SUCCESS)
			return (0);
		(void) rw_rdlock(&ldapConLock);
	}

	for (lc = ldapCon; lc != 0; lc = lc->next) {
		exclusiveLC(lc);

		if (lc->isBound && (lc->doDis || lc->doDel)) {
			*stat = disconnectCon(lc);
			if (*stat != LDAP_UNAVAILABLE)
				releaseLC(lc);
			continue;
		}

		/*
		 * Use a new connection for all cases except when
		 * requested by the main thread in the parent ypserv
		 * process.
		 */
		if (ls->useCon == 0) {
			newlc = createCon(lc->sp, lc->who, lc->cred,
						lc->method, lc->port);
			if (!newlc) {
				releaseLC(lc);
				continue;
			}
			if (lc->ld != 0) {
				newlc->simplePage = lc->simplePage;
				newlc->vlv = lc->vlv;
				newlc->batchFrom = lc->batchFrom;
			}
			releaseLC(lc);
			exclusiveLC(newlc);
			newstat = connectCon(newlc, 0);
			if (newstat != LDAP_SUCCESS) {
				if (newstat != LDAP_UNAVAILABLE) {
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
			"%s: Cannot open connection to LDAP server (%s): %s",
						myself, NIL(newlc->sp),
						ldap_err2string(*stat));
				}
				(void) freeCon(newlc);
				newlc = 0;
				continue;
			}

			/*
			 * No need to put newlc on the ldapCon list as this
			 * connection will be freed after use.
			 */
			newlc->onList = 0;

			lc = newlc;
		} else  if (!lc->isBound) {
			*stat = connectCon(lc, 1);
			if (*stat != LDAP_SUCCESS) {
				if (*stat != LDAP_UNAVAILABLE) {
					logmsg(MSG_NOTIMECHECK, LOG_WARNING,
		"%s: Cannot open connection to LDAP server (%s): %s",
						myself, NIL(lc->sp),
						ldap_err2string(*stat));
					releaseLC(lc);
				}
				continue;
			}
		}

		incrementRC(lc);
		releaseLC(lc);
		break;
	}

	(void) rw_unlock(&ldapConLock);

	return (lc);
}

#define	SORTKEYLIST	"cn uid"

/*
 * Perform an LDAP search operation per 'ls', adding the result(s) to
 * a copy of the 'rvIn' structure; the copy becomes the return value.
 * The caller must deallocate both 'rvIn' and the result, if any.
 *
 * On entry, '*numValues' contains a hint regarding the expected
 * number of entries. Zero is the same as one, and negative values
 * imply no information. This is used to decide whether or not to
 * try an indexed search.
 *
 * On successful (non-NULL) return, '*numValues' contains the number
 * of __nis_rule_value_t elements in the returned array, and '*stat'
 * the LDAP operations status.
 */
__nis_rule_value_t *
ldapSearch(__nis_ldap_search_t *ls, int *numValues, __nis_rule_value_t *rvIn,
		int *ldapStat) {
	__nis_rule_value_t	*rv = 0;
	int			stat, numEntries, numVals, tnv, done, lprEc;
	LDAPMessage		*msg = 0, *m;
	__nis_ldap_conn_t	*lc;
	struct timeval		tv, start, now;
	LDAPsortkey		**sortKeyList = 0;
	LDAPControl		*ctrls[3], *sortCtrl = 0, *vlvCtrl = 0;
	LDAPControl		**retCtrls = 0;
	LDAPVirtualList		vList;
	struct berval		*spCookie = 0;
	int			doVLV = 0;
	int			doSP = 0;
	long			index;
	char			*myself = "ldapSearch";
	bool_t			follow_referral =
					proxyInfo.follow_referral == follow;
	int			doIndex = 1;
	char			**referralsp = NULL;

	ctrls[0] = ctrls[1] = ctrls[2] = 0;

	if (ldapStat == 0)
		ldapStat = &stat;

	if (ls == 0) {
		*ldapStat = LDAP_PARAM_ERROR;
		return (0);
	}

	if (yp2ldap) {
		/* make sure the parent's connection is not used by child */
		if ((lc = findYPCon(ls, ldapStat)) == 0) {
			*ldapStat = LDAP_SERVER_DOWN;
			return (0);
		}
	} else {
		if ((lc = findCon(ldapStat)) == 0) {
			*ldapStat = LDAP_SERVER_DOWN;
			return (0);
		}
	}

	if (numValues != 0 && (*numValues == 0 || *numValues == 1))
		doIndex = 0;

retry_new_conn:
	/* Prefer VLV over simple page, and SP over nothing */
	if (doIndex && lc->vlv) {
		stat = ldap_create_sort_keylist(&sortKeyList, SORTKEYLIST);
		if (stat != LDAP_SUCCESS) {
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"%s: Error creating sort keylist: %s",
				myself, ldap_err2string(stat));
			freeRuleValue(rv, numVals);
			*ldapStat = stat;
			rv = 0;
			goto retry_noVLV;
		}
		stat = ldap_create_sort_control(lc->ld, sortKeyList, 1,
						&sortCtrl);
		if (stat == LDAP_SUCCESS) {
			vList.ldvlist_before_count = 0;
			vList.ldvlist_after_count = lc->batchFrom - 1;
			vList.ldvlist_attrvalue = 0;
			vList.ldvlist_extradata = 0;
			index = 1;
			doVLV = 1;
		} else {
			ldap_get_option(lc->ld, LDAP_OPT_ERROR_NUMBER, &stat);
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"%s: Error creating VLV sort control: %s",
				myself, ldap_err2string(stat));
			freeRuleValue(rv, numVals);
			*ldapStat = stat;
			rv = 0;
		}
	}

retry_noVLV:

	if (doIndex && !doVLV && lc->simplePage) {
		spCookie = am(myself, sizeof (*spCookie));
		if (spCookie != 0 &&
				(spCookie->bv_val = sdup(myself, T, "")) != 0) {
			spCookie->bv_len = 0;
			doSP = 1;
		} else {
			logmsg(MSG_NOTIMECHECK, LOG_INFO,
	"%s: No memory for simple page cookie; using un-paged LDAP search",
				myself);
			freeRuleValue(rv, numVals);
			*ldapStat = stat;
			rv = 0;
			goto cleanup;
		}
	}

	if (!doVLV && !doSP)
		ctrls[0] = ctrls[1] = 0;

	numVals = 0;
	done = 0;

	if (ls->timeout.tv_sec || ls->timeout.tv_usec) {
		tv = ls->timeout;
	} else {
		tv = lc->searchTimeout;
	}
	(void) gettimeofday(&start, 0);

	do {
		/* don't do vlv or simple page for base level searches */
		if (doVLV && ls->base != LDAP_SCOPE_BASE) {
			vList.ldvlist_index = index;
			vList.ldvlist_size = 0;
			if (vlvCtrl != 0)
				ldap_control_free(vlvCtrl);
			stat = ldap_create_virtuallist_control(lc->ld,
					&vList, &vlvCtrl);
			if (stat != LDAP_SUCCESS) {
				ldap_get_option(lc->ld, LDAP_OPT_ERROR_NUMBER,
						&stat);
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: Error creating VLV at index %ld: %s",
					myself, index, ldap_err2string(stat));
				*ldapStat = stat;
				freeRuleValue(rv, numVals);
				rv = 0;
				goto cleanup;
			}
			ctrls[0] = sortCtrl;
			ctrls[1] = vlvCtrl;
			ctrls[2] = 0;
			stat = ldap_search_ext_s(lc->ld, ls->base,
					ls->scope, ls->filter, ls->attrs,
					ls->attrsonly, ctrls, 0, &tv,
					proxyInfo.search_size_limit, &msg);
		/* don't do vlv or simple page for base level searches */
		} else if (doSP && ls->base != LDAP_SCOPE_BASE) {
			if (ctrls[0] != 0)
				ldap_control_free(ctrls[0]);
			stat = ldap_create_page_control(lc->ld,
					lc->batchFrom, spCookie, 0, &ctrls[0]);
			if (stat != LDAP_SUCCESS) {
				ber_bvfree(spCookie);
				spCookie = 0;
				ldap_get_option(lc->ld, LDAP_OPT_ERROR_NUMBER,
						&stat);
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"%s: Simple page error: %s",
					myself, ldap_err2string(stat));
				freeRuleValue(rv, numVals);
				*ldapStat = stat;
				rv = 0;
				goto cleanup;
			}
			ctrls[1] = 0;
			stat = ldap_search_ext_s(lc->ld, ls->base,
					ls->scope, ls->filter, ls->attrs,
					ls->attrsonly, ctrls, 0, &tv,
					proxyInfo.search_size_limit, &msg);
		} else {
			stat = ldap_search_st(lc->ld, ls->base, ls->scope,
					ls->filter, ls->attrs, ls->attrsonly,
					&tv, &msg);
		}
		if (stat == LDAP_SUCCESS)
			ldap_get_option(lc->ld, LDAP_OPT_ERROR_NUMBER, &stat);

		if (stat == LDAP_SERVER_DOWN) {
			lc->doDis++;
			releaseCon(lc, stat);
			lc = (yp2ldap)?findYPCon(ls, ldapStat):
				findCon(ldapStat);
			if (lc == 0) {
				*ldapStat = LDAP_SERVER_DOWN;
				rv =  0;
				goto cleanup;
			}
			goto retry_new_conn;
		}

		if (stat == LDAP_REFERRAL && follow_referral) {
			(void) ldap_parse_result(lc->ld, msg, NULL, NULL, NULL,
				&referralsp, NULL, 0);
			if (referralsp != NULL) {
				/* We support at most one level of referrals */
				follow_referral = FALSE;
				releaseCon(lc, stat);
				lc = findReferralCon(referralsp, &stat);
				ldap_value_free(referralsp);
				if (lc == NULL) {
					freeRuleValue(rv, numVals);
					rv = 0;
					*ldapStat = stat;
					goto cleanup;
				}
				stat = LDAP_SUCCESS;
				goto retry_new_conn;
			}
		}
		*ldapStat = stat;

		if (*ldapStat == LDAP_NO_SUCH_OBJECT) {
			freeRuleValue(rv, numVals);
			rv = 0;
			goto cleanup;
		} else if (doVLV && *ldapStat == LDAP_INSUFFICIENT_ACCESS) {
			/*
			 * The LDAP server (at least Netscape 4.x) can return
			 * LDAP_INSUFFICIENT_ACCESS when VLV is supported,
			 * but not for the bind DN specified. So, just in
			 * case, we clean up, and try again without VLV.
			 */
			doVLV = 0;
			if (msg != 0) {
				(void) ldap_msgfree(msg);
				msg = 0;
			}
			if (ctrls[0] != 0) {
				ldap_control_free(ctrls[0]);
				ctrls[0] = 0;
			}
			if (ctrls[1] != 0) {
				ldap_control_free(ctrls[1]);
				ctrls[1] = 0;
			}
			logmsg(MSG_VLV_INSUFF_ACC, LOG_WARNING,
	"%s: VLV insufficient access from server %s; retrying without VLV",
				myself, NIL(lc->sp));
			goto retry_noVLV;
		} else if (*ldapStat != LDAP_SUCCESS) {
			logmsg(MSG_NOTIMECHECK, LOG_WARNING,
				"ldap_search(0x%x,\n\t\"%s\",\n\t %d,",
				lc->ld, NIL(ls->base), ls->scope);
			logmsg(MSG_NOTIMECHECK, LOG_WARNING,
				"\t\"%s\",\n\t0x%x,\n\t%d) => %d (%s)",
				NIL(ls->filter), ls->attrs, ls->attrsonly,
				*ldapStat, ldap_err2string(stat));
			freeRuleValue(rv, numVals);
			rv = 0;
			goto cleanup;
		}

		numEntries = ldap_count_entries(lc->ld, msg);
		if (numEntries == 0 && *ldapStat == LDAP_SUCCESS) {
			/*
			 * This is a bit weird, but the server (or, at least,
			 * ldap_search_ext()) can sometimes return
			 * LDAP_SUCCESS and no entries when it didn't
			 * find what we were looking for. Seems it ought to
			 * return LDAP_NO_SUCH_OBJECT or some such.
			 */
			freeRuleValue(rv, numVals);
			rv = 0;
			*ldapStat = LDAP_NO_SUCH_OBJECT;
			goto cleanup;
		}

		tnv = numVals + numEntries;
		if ((rv = growRuleValue(numVals, tnv, rv, rvIn)) == 0) {
			*ldapStat = LDAP_NO_MEMORY;
			goto cleanup;
		}

		for (m = ldap_first_entry(lc->ld, msg); m != 0;
				m = ldap_next_entry(lc->ld, m), numVals++) {
			char		*nm;
			BerElement	*ber = 0;

			if (numVals > tnv) {
				logmsg(MSG_NOTIMECHECK, LOG_INFO,
				"%s: Inconsistent LDAP entry count > %d",
					myself, numEntries);
				break;
			}

			nm = ldap_get_dn(lc->ld, m);
			if (nm == 0 || addSAttr2RuleValue("dn", nm,
					&rv[numVals])) {
				sfree(nm);
				*ldapStat = LDAP_NO_MEMORY;
				freeRuleValue(rv, tnv);
				rv = 0;
				goto cleanup;
			}
			sfree(nm);

			for (nm = ldap_first_attribute(lc->ld, m, &ber);
					nm != 0;
				nm = ldap_next_attribute(lc->ld, m, ber)) {
				struct berval	**val;
				int		i, nv;

				val = ldap_get_values_len(lc->ld, m, nm);
				nv = (val == 0) ? 0 :
						ldap_count_values_len(val);
				for (i = 0; i < nv; i++) {
					/*
					 * Since we don't know if the value is
					 * BER-encoded or not, we mark it as a
					 * string. All is well as long as we
					 * don't insist on 'vt_ber' when
					 * interpreting.
					 */
					if (addAttr2RuleValue(vt_string, nm,
							val[i]->bv_val,
							val[i]->bv_len,
							&rv[numVals])) {
						if (ber != 0)
							ber_free(ber, 0);
						ldap_value_free_len(val);
						*ldapStat = LDAP_NO_MEMORY;
						freeRuleValue(rv, tnv);
						rv = 0;
						goto cleanup;
					}
				}
				ldap_memfree(nm);
				if (val != 0)
					ldap_value_free_len(val);
			}
			if (ber != 0)
				ber_free(ber, 0);
		}

		if (numVals != tnv) {
			logmsg(MSG_NOTIMECHECK, LOG_WARNING,
		"%s: Inconsistent LDAP entry count, found = %d, expected %d",
				myself, numVals, tnv);
		}

		if (doVLV) {
			stat = ldap_parse_result(lc->ld, msg, &lprEc, 0, 0, 0,
						&retCtrls, 0);
			if (stat != LDAP_SUCCESS) {
				ldap_get_option(lc->ld, LDAP_OPT_ERROR_NUMBER,
						&stat);
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
					"%s: VLV parse result error: %s",
					myself, ldap_err2string(stat));
				*ldapStat = stat;
				freeRuleValue(rv, tnv);
				rv = 0;
				goto cleanup;
			}
			if (retCtrls != 0) {
				unsigned long	targetPosP = 0;
				unsigned long	listSize = 0;

				stat = ldap_parse_virtuallist_control(lc->ld,
					retCtrls, &targetPosP, &listSize,
					&lprEc);
				if (stat == LDAP_SUCCESS) {
					index = targetPosP + lc->batchFrom;
					if (index >= listSize)
						done = 1;
				}
				ldap_controls_free(retCtrls);
				retCtrls = 0;
			} else {
				done = 1;
			}
		} else if (doSP) {
			stat = ldap_parse_result(lc->ld, msg, &lprEc, 0, 0, 0,
						&retCtrls, 0);
			if (stat != LDAP_SUCCESS) {
				ldap_get_option(lc->ld, LDAP_OPT_ERROR_NUMBER,
						&stat);
				logmsg(MSG_NOTIMECHECK, LOG_ERR,
				"%s: Simple page parse result error: %s",
					myself, ldap_err2string(stat));
				*ldapStat = stat;
				freeRuleValue(rv, tnv);
				rv = 0;
				goto cleanup;
			}
			if (retCtrls != 0) {
				unsigned int	count;

				if (spCookie != 0) {
					ber_bvfree(spCookie);
					spCookie = 0;
				}
				stat = ldap_parse_page_control(lc->ld,
						retCtrls, &count, &spCookie);
				if (stat == LDAP_SUCCESS) {
					if (spCookie == 0 ||
						spCookie->bv_val == 0 ||
						spCookie->bv_len == 0)
						done = 1;
				}
				ldap_controls_free(retCtrls);
				retCtrls = 0;
			} else {
				done = 1;
			}
		} else {
			done = 1;
		}

		(void) ldap_msgfree(msg);
		msg = 0;

		/*
		 * If we're using VLV or SP, the timeout should apply
		 * to all calls as an aggregate, so we need to reduce
		 * 'tv' with the time spent on this chunk of data.
		 */
		if (!done) {
			struct timeval	tmp;

			(void) gettimeofday(&now, 0);
			tmp = now;
			now.tv_sec -= start.tv_sec;
			now.tv_usec -= start.tv_usec;
			if (now.tv_usec < 0) {
				now.tv_usec += 1000000;
				now.tv_sec -= 1;
			}
			tv.tv_sec -= now.tv_sec;
			tv.tv_usec -= now.tv_usec;
			if (tv.tv_usec < 0) {
				tv.tv_usec += 1000000;
				tv.tv_sec -= 1;
			}
			if (tv.tv_sec < 0) {
				*ldapStat = LDAP_TIMEOUT;
				freeRuleValue(rv, tnv);
				rv = 0;
				goto cleanup;
			}
			start = tmp;
		}

	} while (!done);

	if (numValues != 0)
		*numValues = numVals;

cleanup:
	if (NULL != lc) {
		if (yp2ldap && ls->useCon == 0) {
			/* Disconnect and free the connection */
			lc->doDis++;
			lc->doDel++;
			releaseCon(lc, stat);
			releaseLC(lc);

		} else {
			releaseCon(lc, stat);
		}
	}
	if (msg != 0)
		(void) ldap_msgfree(msg);
	if (ctrls[0] != 0)
		ldap_control_free(ctrls[0]);
	if (ctrls[1] != 0)
		ldap_control_free(ctrls[1]);
	if (spCookie != 0)
		ber_bvfree(spCookie);
	if (sortKeyList != 0)
		ldap_free_sort_keylist(sortKeyList);

	return (rv);
}

static void
freeLdapModEntry(LDAPMod *m) {

	if (m == 0)
		return;

	sfree(m->mod_type);
	if ((m->mod_op & LDAP_MOD_BVALUES) == 0) {
		char	**v = m->mod_values;

		if (v != 0) {
			while (*v != 0) {
				sfree(*v);
				v++;
			}
			free(m->mod_values);
		}
	} else {
		struct berval	**b = m->mod_bvalues;

		if (b != 0) {
			while (*b != 0) {
				sfree((*b)->bv_val);
				free(*b);
				b++;
			}
			free(m->mod_bvalues);
		}
	}

	free(m);
}

static void
freeLdapMod(LDAPMod **mods) {
	LDAPMod		*m, **org = mods;

	if (mods == 0)
		return;

	while ((m = *mods) != 0) {
		freeLdapModEntry(m);
		mods++;
	}

	free(org);
}

/*
 * Convert a rule-value structure to the corresponding LDAPMod.
 * If 'add' is set, attributes/values are added; object classes
 * are also added. If 'add' is cleared, attributes/values are modified,
 * and 'oc' controls whether or not object classes are added.
 */
LDAPMod **
search2LdapMod(__nis_rule_value_t *rv, int add, int oc) {
	LDAPMod		**mods;
	int		i, j, nm;
	char		*myself = "search2LdapMod";

	if (rv == 0 || rv->numAttrs <= 0)
		return (0);

	mods = am(myself, (rv->numAttrs + 1) * sizeof (mods[0]));
	if (mods == 0)
		return (0);

	for (i = 0, nm = 0; i < rv->numAttrs; i++) {
		int	isOc;
		/*
		 * If we're creating an LDAPMod array for an add operation,
		 * just skip attributes that should be deleted.
		 */
		if (add && rv->attrVal[i].numVals < 0)
			continue;

		/*
		 * Skip DN; it's specified separately to ldap_modify()
		 * and ldap_add(), and mustn't appear among the
		 * attributes to be modified/added.
		 */
		if (strcasecmp("dn", rv->attrName[i]) == 0)
			continue;

		/*
		 * If modifying, and 'oc' is off, skip object class
		 * attributes.
		 */
		isOc = (strcasecmp("objectclass", rv->attrName[i]) == 0);
		if (!add && !oc && isOc)
			continue;

		mods[nm] = am(myself, sizeof (*mods[nm]));
		if (mods[nm] == 0) {
			freeLdapMod(mods);
			return (0);
		}

		/* 'mod_type' is the attribute name */
		mods[nm]->mod_type = sdup(myself, T, rv->attrName[i]);
		if (mods[nm]->mod_type == 0) {
			freeLdapMod(mods);
			return (0);
		}

		/*
		 * numVals < 0 means attribute and all values should
		 * be deleted.
		 */
		if (rv->attrVal[i].numVals < 0) {
			mods[nm]->mod_op = LDAP_MOD_DELETE;
			mods[nm]->mod_values = 0;
			nm++;
			continue;
		}

		/* objectClass attributes always added */
		mods[nm]->mod_op = (add) ? 0 : ((isOc) ? 0 : LDAP_MOD_REPLACE);

		if (rv->attrVal[i].type == vt_string) {
			/*
			 * mods[]->mod_values is a NULL-terminated array
			 * of (char *)'s.
			 */
			mods[nm]->mod_values = am(myself,
					(rv->attrVal[i].numVals + 1) *
					sizeof (mods[nm]->mod_values[0]));
			if (mods[nm]->mod_values == 0) {
				freeLdapMod(mods);
				return (0);
			}
			for (j = 0; j < rv->attrVal[i].numVals; j++) {
				/*
				 * Just in case the string isn't NUL
				 * terminated, add one byte to the
				 * allocated length; am() will initialize
				 * the buffer to zero.
				 */
				mods[nm]->mod_values[j] = am(myself,
					rv->attrVal[i].val[j].length + 1);
				if (mods[nm]->mod_values[j] == 0) {
					freeLdapMod(mods);
					return (0);
				}
				memcpy(mods[nm]->mod_values[j],
					rv->attrVal[i].val[j].value,
					rv->attrVal[i].val[j].length);
			}
		} else {
			mods[nm]->mod_op |= LDAP_MOD_BVALUES;
			mods[nm]->mod_bvalues = am(myself,
					(rv->attrVal[i].numVals+1) *
					sizeof (mods[nm]->mod_bvalues[0]));
			if (mods[nm]->mod_bvalues == 0) {
				freeLdapMod(mods);
				return (0);
			}
			for (j = 0; j < rv->attrVal[i].numVals; j++) {
				mods[nm]->mod_bvalues[j] = am(myself,
					sizeof (*mods[nm]->mod_bvalues[j]));
				if (mods[nm]->mod_bvalues[j] == 0) {
					freeLdapMod(mods);
					return (0);
				}
				mods[nm]->mod_bvalues[j]->bv_val = am(myself,
					rv->attrVal[i].val[j].length);
				if (mods[nm]->mod_bvalues[j]->bv_val == 0) {
					freeLdapMod(mods);
					return (0);
				}
				mods[nm]->mod_bvalues[j]->bv_len =
					rv->attrVal[i].val[j].length;
				memcpy(mods[nm]->mod_bvalues[j]->bv_val,
					rv->attrVal[i].val[j].value,
					mods[nm]->mod_bvalues[j]->bv_len);
			}
		}
		nm++;
	}

	return (mods);
}

/*
 * Remove 'value' from 'val'. If value==0, remove the entire
 * __nis_single_value_t array from 'val'.
 */
static void
removeSingleValue(__nis_value_t *val, void *value, int length) {
	int	i;

	if (val == 0)
		return;

	if (value == 0) {
		for (i = 0; i < val->numVals; i++) {
			sfree(val->val[i].value);
		}
		sfree(val->val);
		val->val = 0;
		val->numVals = 0;
		return;
	}

	for (i = 0; i < val->numVals; i++) {
		if (val->val[i].value == 0 || (val->val[i].length != length))
			continue;
		if (memcmp(val->val[i].value, value, length) != 0)
			continue;
		sfree(val->val[i].value);
		if (i != (val->numVals - 1)) {
			(void) memmove(&val->val[i], &val->val[i+1],
				(val->numVals - 1 - i) * sizeof (val->val[0]));
		}
		val->numVals -= 1;
		break;
	}
}

/*
 * Helper function for LdapModify
 * When a modify operation fails with an object class violation,
 * the most probable reason is that the attributes we're modifying are new,
 * and the needed object class are not present. So, try the modify again,
 * but add the object classes this time.
 */

static int
ldapModifyObjectClass(__nis_ldap_conn_t **lc, char *dn,
		__nis_rule_value_t *rvIn, char *objClassAttrs)
{
	LDAPMod			**mods = 0;
	int			msgid;
	int			lderr;
	struct timeval		tv;
	int			stat;
	LDAPMessage		*msg = 0;
	char			**referralsp = NULL;
	__nis_rule_value_t	*rv, *rvldap;
	__nis_ldap_search_t	*ls;
	int			i, ocrv, ocrvldap, nv;
	char			*oc[2] = { "objectClass", 0};
	char			*myself = "ldapModifyObjectClass";

	rv = initRuleValue(1, rvIn);
	if (rv == 0)
		return (LDAP_NO_MEMORY);

	delAttrFromRuleValue(rv, "objectClass");
	rv = addObjectClasses(rv, objClassAttrs);
	if (rv == 0) {
		stat = LDAP_OPERATIONS_ERROR;
		logmsg(MSG_NOTIMECHECK, LOG_WARNING,
		    "%s: addObjectClasses failed for %s",
		    myself, NIL(dn));
		goto cleanup;
	}

	/*
	 * Before adding the object classes whole-sale, try retrieving
	 * the entry specified by the 'dn'. If it exists, we filter out
	 * those object classes that already are present in LDAP from our
	 * update.
	 */
	ls = buildLdapSearch(dn, LDAP_SCOPE_BASE, 0, 0, "objectClass=*",
	    oc, 0, 1);
	if (ls == 0) {
		logmsg(MSG_NOTIMECHECK, LOG_INFO,
		    "%s: Unable to build DN search for \"%s\"",
		    myself, NIL(dn));
		/* Fall through to try just adding the object classes */
		goto addObjectClasses;
	}

	nv = 0;
	rvldap = ldapSearch(ls, &nv, 0, &lderr);
	freeLdapSearch(ls);
	if (rvldap == 0) {
		logmsg(MSG_NOTIMECHECK, LOG_INFO,
		    "%s: No data for DN search (\"%s\"); LDAP status %d",
		    myself, NIL(dn), lderr);
		/* Fall through to try just adding the object classes */
		goto addObjectClasses;
	}

	/*
	 * Find the indices of the 'objectClass' attribute
	 * in 'rvldap' and 'rv'.
	 */
	for (i = 0, ocrvldap = -1; i < rvldap->numAttrs; i++) {
		if (rvldap->attrName[i] != 0 &&
		    strcasecmp("objectClass", rvldap->attrName[i]) == 0) {
			ocrvldap = i;
			break;
		}
	}
	for (i = 0, ocrv = -1; i < rv->numAttrs; i++) {
		if (rv->attrName[i] != 0 &&
		    strcasecmp("objectClass", rv->attrName[i]) == 0) {
			ocrv = i;
			break;
		}
	}

	/*
	 * Remove those object classes that already exist
	 * in LDAP (i.e., in 'rvldap') from 'rv'.
	 */
	if (ocrv >= 0 && ocrvldap >= 0) {
		for (i = 0; i < rvldap->attrVal[ocrvldap].numVals; i++) {
			removeSingleValue(&rv->attrVal[ocrv],
			    rvldap->attrVal[ocrvldap].val[i].value,
			    rvldap->attrVal[ocrvldap].val[i].length);
		}
		/*
		 * If no 'objectClass' values left in 'rv', delete
		 * 'objectClass' from 'rv'.
		 */
		if (rv->attrVal[ocrv].numVals == 0)
			delAttrFromRuleValue(rv, "objectClass");
	}

	/*
	 * 'rv' now contains the update we want to make, with just the
	 * object class(es) that need to be added. Fall through to the
	 * actual LDAP modify operation.
	 */
	freeRuleValue(rvldap, 1);

addObjectClasses:

	mods = search2LdapMod(rv, 0, 1);
	if (mods == 0) {
		stat = LDAP_OPERATIONS_ERROR;
		logmsg(MSG_NOTIMECHECK, LOG_WARNING,
	"%s: Unable to create LDAP modify changes with object classes for %s",
		    myself, NIL(dn));
		goto cleanup;
	}
	msgid = ldap_modify((*lc)->ld, dn, mods);
	if (msgid != -1) {
		tv = (*lc)->modifyTimeout;
		stat = ldap_result((*lc)->ld, msgid, 0, &tv, &msg);
		if (stat == 0) {
			stat = LDAP_TIMEOUT;
		} else if (stat == -1) {
			(void) ldap_get_option((*lc)->ld,
			    LDAP_OPT_ERROR_NUMBER, &stat);
		} else {
			stat = ldap_parse_result((*lc)->ld, msg, &lderr, NULL,
			    NULL, &referralsp, NULL, 0);
			if (stat == LDAP_SUCCESS)
				stat = lderr;
			stat = ldap_result2error((*lc)->ld, msg, 0);
		}
	} else {
		(void) ldap_get_option((*lc)->ld, LDAP_OPT_ERROR_NUMBER,
		    &stat);
	}
	if (proxyInfo.follow_referral == follow &&
	    stat == LDAP_REFERRAL && referralsp != NULL) {
		releaseCon(*lc, stat);
		if (msg != NULL)
			(void) ldap_msgfree(msg);
		msg = NULL;
		*lc = findReferralCon(referralsp, &stat);
		ldap_value_free(referralsp);
		referralsp = NULL;
		if (*lc == NULL)
			goto cleanup;
		msgid = ldap_modify((*lc)->ld, dn, mods);
		if (msgid == -1) {
			(void) ldap_get_option((*lc)->ld,
			    LDAP_OPT_ERROR_NUMBER, &stat);
			goto cleanup;
		}
		stat = ldap_result((*lc)->ld, msgid, 0, &tv, &msg);
		if (stat == 0) {
			stat = LDAP_TIMEOUT;
		} else if (stat == -1) {
			(void) ldap_get_option((*lc)->ld,
			    LDAP_OPT_ERROR_NUMBER, &stat);
		} else {
			stat = ldap_parse_result((*lc)->ld, msg, &lderr,
			    NULL, NULL, NULL, NULL, 0);
			if (stat == LDAP_SUCCESS)
				stat = lderr;
		}
	}
cleanup:
	if (mods != 0)
		freeLdapMod(mods);
	freeRuleValue(rv, 1);
	return (stat);
}

/*
 * Modify the specified 'dn' per the attribute names/values in 'rv'.
 * If 'rv' is NULL, we attempt to delete the entire entry.
 *
 * The 'objClassAttrs' parameter is needed if the entry must be added
 * (i.e., created), or a modify fails with an object class violation.
 *
 * If 'addFirst' is set, we try an add before a modify; modify before
 * add otherwise (ignored if we're deleting).
 */
int
ldapModify(char *dn, __nis_rule_value_t *rv, char *objClassAttrs,
		int addFirst) {
	int			stat, add = 0;
	LDAPMod			**mods = 0;
	__nis_ldap_conn_t	*lc;
	struct timeval		tv;
	LDAPMessage		*msg = 0;
	int			msgid;
	int			lderr;
	char			**referralsp = NULL;
	bool_t			delete = FALSE;

	if (dn == 0)
		return (LDAP_PARAM_ERROR);

	if ((lc = findCon(&stat)) == 0)
		return (stat);

	if (rv == 0) {
		delete = TRUE;
		/* Simple case: if rv == 0, try to delete the entire entry */
		msgid = ldap_delete(lc->ld, dn);
		if (msgid == -1) {
			(void) ldap_get_option(lc->ld, LDAP_OPT_ERROR_NUMBER,
						&stat);
			goto cleanup;
		}
		tv = lc->deleteTimeout;
		stat = ldap_result(lc->ld, msgid, 0, &tv, &msg);

		if (stat == 0) {
			stat = LDAP_TIMEOUT;
		} else if (stat == -1) {
			(void) ldap_get_option(lc->ld, LDAP_OPT_ERROR_NUMBER,
						&stat);
		} else {
			stat = ldap_parse_result(lc->ld, msg, &lderr, NULL,
				NULL, &referralsp, NULL, 0);
			if (stat == LDAP_SUCCESS)
				stat = lderr;
		}
		if (proxyInfo.follow_referral == follow &&
				stat == LDAP_REFERRAL && referralsp != NULL) {
			releaseCon(lc, stat);
			if (msg != NULL)
				(void) ldap_msgfree(msg);
			msg = NULL;
			lc = findReferralCon(referralsp, &stat);
			ldap_value_free(referralsp);
			if (lc == NULL)
				goto cleanup;
			msgid = ldap_delete(lc->ld, dn);
			if (msgid == -1) {
				(void) ldap_get_option(lc->ld,
					LDAP_OPT_ERROR_NUMBER, &stat);
				goto cleanup;
			}
			stat = ldap_result(lc->ld, msgid, 0, &tv, &msg);
			if (stat == 0) {
				stat = LDAP_TIMEOUT;
			} else if (stat == -1) {
				(void) ldap_get_option(lc->ld,
					LDAP_OPT_ERROR_NUMBER, &stat);
			} else {
				stat = ldap_parse_result(lc->ld, msg, &lderr,
					NULL, NULL, NULL, NULL, 0);
				if (stat == LDAP_SUCCESS)
					stat = lderr;
			}
		}
		/* No such object means someone else has done our job */
		if (stat == LDAP_NO_SUCH_OBJECT)
			stat = LDAP_SUCCESS;
	} else {
		if (addFirst) {
			stat = ldapAdd(dn, rv, objClassAttrs, lc);
			lc = NULL;
			if (stat != LDAP_ALREADY_EXISTS)
				goto cleanup;
			if ((lc = findCon(&stat)) == 0)
				return (stat);
		}

		/*
		 * First try the modify without specifying object classes
		 * (i.e., assume they're already present).
		 */
		mods = search2LdapMod(rv, 0, 0);
		if (mods == 0) {
			stat = LDAP_PARAM_ERROR;
			goto cleanup;
		}

		msgid = ldap_modify(lc->ld, dn, mods);
		if (msgid == -1) {
			(void) ldap_get_option(lc->ld, LDAP_OPT_ERROR_NUMBER,
						&stat);
			goto cleanup;
		}
		tv = lc->modifyTimeout;
		stat = ldap_result(lc->ld, msgid, 0, &tv, &msg);
		if (stat == 0) {
			stat = LDAP_TIMEOUT;
		} else if (stat == -1) {
			(void) ldap_get_option(lc->ld, LDAP_OPT_ERROR_NUMBER,
						&stat);
		} else {
			stat = ldap_parse_result(lc->ld, msg, &lderr, NULL,
				NULL, &referralsp, NULL, 0);
			if (stat == LDAP_SUCCESS)
				stat = lderr;
		}
		if (proxyInfo.follow_referral == follow &&
				stat == LDAP_REFERRAL && referralsp != NULL) {
			releaseCon(lc, stat);
			if (msg != NULL)
				(void) ldap_msgfree(msg);
			msg = NULL;
			lc = findReferralCon(referralsp, &stat);
			ldap_value_free(referralsp);
			referralsp = NULL;
			if (lc == NULL)
				goto cleanup;
			msgid = ldap_modify(lc->ld, dn, mods);
			if (msgid == -1) {
				(void) ldap_get_option(lc->ld,
					LDAP_OPT_ERROR_NUMBER, &stat);
				goto cleanup;
			}
			stat = ldap_result(lc->ld, msgid, 0, &tv, &msg);
			if (stat == 0) {
				stat = LDAP_TIMEOUT;
			} else if (stat == -1) {
				(void) ldap_get_option(lc->ld,
					LDAP_OPT_ERROR_NUMBER, &stat);
			} else {
				stat = ldap_parse_result(lc->ld, msg, &lderr,
					NULL, NULL, NULL, NULL, 0);
				if (stat == LDAP_SUCCESS)
					stat = lderr;
			}
		}

		/*
		 * If the modify failed with an object class violation,
		 * the most probable reason is that at least on of the
		 * attributes we're modifying didn't exist before, and
		 * neither did its object class. So, try the modify again,
		 * but add the object classes this time.
		 */
		if (stat == LDAP_OBJECT_CLASS_VIOLATION &&
				objClassAttrs != 0) {
			freeLdapMod(mods);
			mods = 0;
			stat = ldapModifyObjectClass(&lc, dn, rv,
				objClassAttrs);
		}

		if (stat == LDAP_NO_SUCH_ATTRIBUTE) {
			/*
			 * If there was at least one attribute delete, then
			 * the cause of this error could be that said attribute
			 * didn't exist in LDAP. So, do things the slow way,
			 * and try to delete one attribute at a time.
			 */
			int			d, numDelete, st;
			__nis_rule_value_t	*rvt;

			for (d = 0, numDelete = 0; d < rv->numAttrs; d++) {
				if (rv->attrVal[d].numVals < 0)
					numDelete++;
			}

			/* If there's just one, we've already tried */
			if (numDelete <= 1)
				goto cleanup;

			/* Make a copy of the rule value */
			rvt = initRuleValue(1, rv);
			if (rvt == 0)
				goto cleanup;

			/*
			 * Remove all delete attributes from the tmp
			 * rule value.
			 */
			for (d = 0; d < rv->numAttrs; d++) {
				if (rv->attrVal[d].numVals < 0) {
					delAttrFromRuleValue(rvt,
						rv->attrName[d]);
				}
			}

			/*
			 * Now put the attributes back in one by one, and
			 * invoke ourselves.
			 */
			for (d = 0; d < rv->numAttrs; d++) {
				if (rv->attrVal[d].numVals >= 0)
					continue;
				st = addAttr2RuleValue(rv->attrVal[d].type,
					rv->attrName[d], 0, 0, rvt);
				if (st != 0) {
					logmsg(MSG_NOMEM, LOG_ERR,
					"%s: Error deleting \"%s\" for \"%s\"",
						NIL(rv->attrName[d]), NIL(dn));
					stat = LDAP_NO_MEMORY;
					freeRuleValue(rvt, 1);
					goto cleanup;
				}
				stat = ldapModify(dn, rvt, objClassAttrs, 0);
				if (stat != LDAP_SUCCESS &&
					stat != LDAP_NO_SUCH_ATTRIBUTE) {
					freeRuleValue(rvt, 1);
					goto cleanup;
				}
				delAttrFromRuleValue(rvt, rv->attrName[d]);
			}

			/*
			 * If we got here, then all attributes that should
			 * be deleted either have been, or didn't exist. For
			 * our purposes, the latter is as good as the former.
			 */
			stat = LDAP_SUCCESS;
			freeRuleValue(rvt, 1);
		}

		if (stat == LDAP_NO_SUCH_OBJECT && !addFirst) {
			/*
			 * Entry doesn't exist, so try an ldap_add(). If the
			 * ldap_add() also fails, that could be because someone
			 * else added it between our modify and add operations.
			 * If so, we consider that foreign add to be
			 * authoritative (meaning we don't retry our modify).
			 *
			 * Also, if all modify operations specified by 'mods'
			 * are deletes, LDAP_NO_SUCH_OBJECT is a kind of
			 * success; we certainly don't want to create the
			 * entry.
			 */
			int	allDelete;
			LDAPMod	**m;

			for (m = mods, allDelete = 1; *m != 0 && allDelete;
					m++) {
				if (((*m)->mod_op & LDAP_MOD_DELETE) == 0)
					allDelete = 0;
			}

			add = 1;

			if (allDelete) {
				stat = LDAP_SUCCESS;
			} else if (objClassAttrs == 0) {
				/* Now we need it, so this is fatal */
				stat = LDAP_PARAM_ERROR;
			} else {
				stat = ldapAdd(dn, rv, objClassAttrs, lc);
				lc = NULL;
			}
		}
	}

cleanup:
	if (stat != LDAP_SUCCESS) {
		logmsg(MSG_NOTIMECHECK, LOG_INFO,
			"%s(0x%x (%s), \"%s\") => %d (%s)\n",
			!delete ? (add ? "ldap_add" : "ldap_modify") :
				"ldap_delete",
			lc != NULL ? lc->ld : 0,
			lc != NULL ? NIL(lc->sp) : "nil",
			dn, stat, ldap_err2string(stat));
	}

	releaseCon(lc, stat);
	freeLdapMod(mods);
	if (msg != 0)
		(void) ldap_msgfree(msg);

	return (stat);
}

/*
 * Create the entry specified by 'dn' to have the values per 'rv'.
 * The 'objClassAttrs' are the extra object classes we need when
 * creating an entry.
 *
 * If 'lc' is non-NULL, we use that connection; otherwise, we find
 * our own. CAUTION: This connection will be released on return. Regardless
 * of return value, this connection should not subsequently used by the
 * caller.
 *
 * Returns an LDAP status.
 */
int
ldapAdd(char *dn, __nis_rule_value_t *rv, char *objClassAttrs, void *lcv) {
	int			stat;
	LDAPMod			**mods = 0;
	struct timeval		tv;
	LDAPMessage		*msg = 0;
	__nis_ldap_conn_t	*lc = lcv;
	int			msgid;
	int			lderr;
	char			**referralsp = NULL;

	if (dn == 0 || rv == 0 || objClassAttrs == 0) {
		releaseCon(lc, LDAP_SUCCESS);
		return (LDAP_PARAM_ERROR);
	}

	if (lc == 0) {
		if ((lc = findCon(&stat)) == 0)
			return (stat);
	}

	rv = addObjectClasses(rv, objClassAttrs);
	if (rv == 0) {
		stat = LDAP_OPERATIONS_ERROR;
		goto cleanup;
	}

	mods = search2LdapMod(rv, 1, 0);
	if (mods == 0) {
		stat = LDAP_OPERATIONS_ERROR;
		goto cleanup;
	}

	msgid = ldap_add(lc->ld, dn, mods);
	if (msgid == -1) {
		(void) ldap_get_option(lc->ld, LDAP_OPT_ERROR_NUMBER, &stat);
		goto cleanup;
	}
	tv = lc->addTimeout;
	stat = ldap_result(lc->ld, msgid, 0, &tv, &msg);
	if (stat == 0) {
		stat = LDAP_TIMEOUT;
	} else if (stat == -1) {
		(void) ldap_get_option(lc->ld, LDAP_OPT_ERROR_NUMBER, &stat);
	} else {
		stat = ldap_parse_result(lc->ld, msg, &lderr, NULL, NULL,
			&referralsp, NULL, 0);
		if (stat == LDAP_SUCCESS)
			stat = lderr;
	}
	if (proxyInfo.follow_referral == follow && stat == LDAP_REFERRAL &&
			referralsp != NULL) {
		releaseCon(lc, stat);
		if (msg != NULL)
			(void) ldap_msgfree(msg);
		msg = NULL;
		lc = findReferralCon(referralsp, &stat);
		ldap_value_free(referralsp);
		if (lc == NULL)
			goto cleanup;
		msgid = ldap_add(lc->ld, dn, mods);
		if (msgid == -1) {
			(void) ldap_get_option(lc->ld,
				LDAP_OPT_ERROR_NUMBER, &stat);
			goto cleanup;
		}
		stat = ldap_result(lc->ld, msgid, 0, &tv, &msg);
		if (stat == 0) {
			stat = LDAP_TIMEOUT;
		} else if (stat == -1) {
			(void) ldap_get_option(lc->ld, LDAP_OPT_ERROR_NUMBER,
						&stat);
		} else {
			stat = ldap_parse_result(lc->ld, msg, &lderr, NULL,
				NULL, NULL, NULL, 0);
			if (stat == LDAP_SUCCESS)
				stat = lderr;
		}
	}

cleanup:
	if (stat != LDAP_SUCCESS) {
		logmsg(MSG_NOTIMECHECK, LOG_INFO,
			"ldap_add(0x%x (%s), \"%s\") => %d (%s)\n",
			lc != NULL ? lc->ld : 0,
			lc != NULL ? NIL(lc->sp) : "nil",
			dn, stat, ldap_err2string(stat));
	}

	releaseCon(lc, stat);
	freeLdapMod(mods);
	if (msg != 0)
		(void) ldap_msgfree(msg);

	return (stat);
}

/*
 * Change the entry at 'oldDn' to have the new DN (not RDN) 'dn'.
 * Returns an LDAP error status.
 */
int
ldapChangeDN(char *oldDn, char *dn) {
	int			stat;
	__nis_ldap_conn_t	*lc;
	int			i, j, lo, ln;
	char			*rdn;
	int			msgid;
	int			lderr;
	struct timeval		tv;
	LDAPMessage		*msg = 0;
	char			**referralsp = NULL;
	char			*myself = "ldapChangeDN";

	if ((lo = slen(oldDn)) <= 0 || (ln = slen(dn)) <= 0)
		return (LDAP_PARAM_ERROR);

	if (strcasecmp(oldDn, dn) == 0)
		return (LDAP_SUCCESS);

	if ((lc = findCon(&stat)) == 0)
		return (stat);

	rdn = sdup(myself, T, dn);
	if (rdn == 0) {
		releaseCon(lc, LDAP_SUCCESS);
		return (LDAP_NO_MEMORY);
	}

	/* Compare old and new DN from the end */
	for (i = lo-1, j = ln-1; i >= 0 && j >= 0; i--, j--) {
		if (tolower(oldDn[i]) != tolower(rdn[j])) {
			/*
			 * Terminate 'rdn' after this character in order
			 * to snip off the portion of the new DN that is
			 * the same as the old DN. What remains in 'rdn'
			 * is the relative DN.
			 */
			rdn[j+1] = '\0';
			break;
		}
	}

	stat = ldap_rename(lc->ld, oldDn, rdn, NULL, 1, NULL, NULL, &msgid);

	if (msgid != -1) {
		tv = lc->modifyTimeout;
		stat = ldap_result(lc->ld, msgid, 0, &tv, &msg);
		if (stat == 0) {
			stat = LDAP_TIMEOUT;
		} else if (stat == -1) {
			(void) ldap_get_option(lc->ld,
				LDAP_OPT_ERROR_NUMBER, &stat);
		} else {
			stat = ldap_parse_result(lc->ld, msg, &lderr, NULL,
				NULL, &referralsp, NULL, 0);
			if (stat == LDAP_SUCCESS)
				stat = lderr;
			stat = ldap_result2error(lc->ld, msg, 0);
		}
	} else {
		(void) ldap_get_option(lc->ld, LDAP_OPT_ERROR_NUMBER,
			&stat);
	}
	if (proxyInfo.follow_referral == follow &&
			stat == LDAP_REFERRAL && referralsp != NULL) {
		releaseCon(lc, stat);
		if (msg != NULL)
			(void) ldap_msgfree(msg);
		msg = NULL;
		lc = findReferralCon(referralsp, &stat);
		ldap_value_free(referralsp);
		referralsp = NULL;
		if (lc == NULL)
			goto cleanup;
		msgid = ldap_rename(lc->ld, oldDn, rdn, NULL, 1, NULL, NULL,
			&msgid);
		if (msgid == -1) {
			(void) ldap_get_option(lc->ld,
				LDAP_OPT_ERROR_NUMBER, &stat);
			goto cleanup;
		}
		stat = ldap_result(lc->ld, msgid, 0, &tv, &msg);
		if (stat == 0) {
			stat = LDAP_TIMEOUT;
		} else if (stat == -1) {
			(void) ldap_get_option(lc->ld,
				LDAP_OPT_ERROR_NUMBER, &stat);
		} else {
			stat = ldap_parse_result(lc->ld, msg, &lderr,
				NULL, NULL, NULL, NULL, 0);
			if (stat == LDAP_SUCCESS)
				stat = lderr;
		}
	}

cleanup:
	if (msg != NULL)
		(void) ldap_msgfree(msg);

#if	1
	fprintf(stderr, "%s: ldap_modrdn_s(0x%x, %s, %s, 1) => %s\n",
		myself, lc == NULL ? 0: lc->ld, NIL(oldDn), NIL(rdn),
		ldap_err2string(stat));
	logmsg(MSG_NOTIMECHECK, LOG_WARNING,
		"%s: ldap_modrdn_s(0x%x, %s, %s, 1) => %s",
		myself, lc == NULL ? 0: lc->ld, NIL(oldDn), NIL(rdn),
		ldap_err2string(stat));
#endif

	if (stat == LDAP_NO_SUCH_OBJECT) {
		/*
		 * Fine from our point of view, since all we want to do
		 * is to make sure that an update to the new DN doesn't
		 * leave the old entry around.
		 */
		stat = LDAP_SUCCESS;
	}

	releaseCon(lc, stat);
	sfree(rdn);

	return (stat);
}
