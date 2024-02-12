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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2023 RackTop Systems, Inc.
 */

#include <alloca.h>
#include <string.h>
#include <strings.h>
#include <lber.h>
#include <sasl/sasl.h>
#include <string.h>
#include <ctype.h>
#include <synch.h>
#include <atomic.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#include <syslog.h>
#include <sys/u8_textprep.h>
#include <sys/varargs.h>
#include "libadutils.h"
#include "adutils_impl.h"

/* List of DSs, needed by the idle connection reaper thread */
static pthread_mutex_t	adhostlock = PTHREAD_MUTEX_INITIALIZER;
static adutils_host_t	*host_head = NULL;

/*
 * List of query state structs -- needed so we can "route" LDAP results
 * to the right context if multiple threads should be using the same
 * connection concurrently
 */
static pthread_mutex_t		qstatelock = PTHREAD_MUTEX_INITIALIZER;
static adutils_query_state_t	*qstatehead = NULL;

static char *adutils_sid_ber2str(BerValue *bvalues);
static void adutils_lookup_batch_unlock(adutils_query_state_t **state);
static void delete_ds(adutils_ad_t *ad, const char *host, int port);

int ad_debug[AD_DEBUG_MAX+1] = {0};

typedef struct binary_attrs {
	const char	*name;
	char		*(*ber2str)(BerValue *bvalues);
} binary_attrs_t;

static binary_attrs_t binattrs[] = {
	{"objectSID", adutils_sid_ber2str},
	{NULL, NULL}
};


adutils_logger logger = syslog;


void
adutils_set_logger(adutils_logger funct)
{
	logger = funct;
}


/*
 * Turn "foo.bar.com" into "dc=foo,dc=bar,dc=com"
 */
static
char *
adutils_dns2dn(const char *dns)
{
	int num_parts;

	return (ldap_dns_to_dn((char *)dns, &num_parts));
}


/*
 * Turn "dc=foo,dc=bar,dc=com" into "foo.bar.com"; ignores any other
 * attributes (CN, etc...).
 */
char *
adutils_dn2dns(const char *dn)
{
	return (DN_to_DNS(dn));
}


/*
 * Convert a binary SID in a BerValue to a adutils_sid_t
 */
int
adutils_getsid(BerValue *bval, adutils_sid_t *sidp)
{
	int		i, j;
	uchar_t		*v;
	uint32_t	a;

	/*
	 * The binary format of a SID is as follows:
	 *
	 * byte #0: version, always 0x01
	 * byte #1: RID count, always <= 0x0f
	 * bytes #2-#7: SID authority, big-endian 48-bit unsigned int
	 *
	 * followed by RID count RIDs, each a little-endian, unsigned
	 * 32-bit int.
	 */
	/*
	 * Sanity checks: must have at least one RID, version must be
	 * 0x01, and the length must be 8 + rid count * 4
	 */
	if (bval->bv_len > 8 && bval->bv_val[0] == 0x01 &&
	    bval->bv_len == 1 + 1 + 6 + bval->bv_val[1] * 4) {
		v = (uchar_t *)bval->bv_val;
		sidp->version = v[0];
		sidp->sub_authority_count = v[1];
		sidp->authority =
		    /* big endian -- so start from the left */
		    ((u_longlong_t)v[2] << 40) |
		    ((u_longlong_t)v[3] << 32) |
		    ((u_longlong_t)v[4] << 24) |
		    ((u_longlong_t)v[5] << 16) |
		    ((u_longlong_t)v[6] << 8) |
		    (u_longlong_t)v[7];
		for (i = 0; i < sidp->sub_authority_count; i++) {
			j = 8 + (i * 4);
			/* little endian -- so start from the right */
			a = (v[j + 3] << 24) | (v[j + 2] << 16) |
			    (v[j + 1] << 8) | (v[j]);
			sidp->sub_authorities[i] = a;
		}
		return (0);
	}
	return (-1);
}

/*
 * Convert a adutils_sid_t to S-1-...
 */
char *
adutils_sid2txt(adutils_sid_t *sidp)
{
	int	rlen, i, len;
	char	*str, *cp;

	if (sidp->version != 1)
		return (NULL);

	len = sizeof ("S-1-") - 1;

	/*
	 * We could optimize like so, but, why?
	 *	if (sidp->authority < 10)
	 *		len += 2;
	 *	else if (sidp->authority < 100)
	 *		len += 3;
	 *	else
	 *		len += snprintf(NULL, 0"%llu", sidp->authority);
	 */
	len += snprintf(NULL, 0, "%llu", sidp->authority);

	/* Max length of a uint32_t printed out in ASCII is 10 bytes */
	len += 1 + (sidp->sub_authority_count + 1) * 10;

	if ((cp = str = malloc(len)) == NULL)
		return (NULL);

	rlen = snprintf(str, len, "S-1-%llu", sidp->authority);

	cp += rlen;
	len -= rlen;

	for (i = 0; i < sidp->sub_authority_count; i++) {
		assert(len > 0);
		rlen = snprintf(cp, len, "-%u", sidp->sub_authorities[i]);
		cp += rlen;
		len -= rlen;
		assert(len >= 0);
	}

	return (str);
}

/*
 * Convert a adutils_sid_t to on-the-wire encoding
 */
static
int
sid2binsid(adutils_sid_t *sid, uchar_t *binsid, int binsidlen)
{
	uchar_t		*p;
	int		i;
	uint64_t	a;
	uint32_t	r;

	if (sid->version != 1 ||
	    binsidlen != (1 + 1 + 6 + sid->sub_authority_count * 4))
		return (-1);

	p = binsid;
	*p++ = 0x01;		/* version */
	/* sub authority count */
	*p++ = sid->sub_authority_count;
	/* Authority */
	a = sid->authority;
	/* big-endian -- start from left */
	*p++ = (a >> 40) & 0xFF;
	*p++ = (a >> 32) & 0xFF;
	*p++ = (a >> 24) & 0xFF;
	*p++ = (a >> 16) & 0xFF;
	*p++ = (a >> 8) & 0xFF;
	*p++ = a & 0xFF;

	/* sub-authorities */
	for (i = 0; i < sid->sub_authority_count; i++) {
		r = sid->sub_authorities[i];
		/* little-endian -- start from right */
		*p++ = (r & 0x000000FF);
		*p++ = (r & 0x0000FF00) >> 8;
		*p++ = (r & 0x00FF0000) >> 16;
		*p++ = (r & 0xFF000000) >> 24;
	}

	return (0);
}

/*
 * Convert a stringified SID (S-1-...) into a hex-encoded version of the
 * on-the-wire encoding, but with each pair of hex digits pre-pended
 * with a '\', so we can pass this to libldap.
 */
int
adutils_txtsid2hexbinsid(const char *txt, const uint32_t *rid,
    char *hexbinsid, int hexbinsidlen)
{
	adutils_sid_t	sid = { 0 };
	int		i, j;
	const char	*cp;
	char		*ecp;
	u_longlong_t	a;
	unsigned long	r;
	uchar_t		*binsid, b, hb;

	/* Only version 1 SIDs please */
	if (strncmp(txt, "S-1-", strlen("S-1-")) != 0)
		return (-1);

	if (strlen(txt) < (strlen("S-1-") + 1))
		return (-1);

	/* count '-'s */
	for (j = 0, cp = strchr(txt, '-');
	    cp != NULL && *cp != '\0';
	    j++, cp = strchr(cp + 1, '-')) {
		/* can't end on a '-' */
		if (*(cp + 1) == '\0')
			return (-1);
	}

	/* Adjust count for version and authority */
	j -= 2;

	/* we know the version number and RID count */
	sid.version = 1;
	sid.sub_authority_count = (rid != NULL) ? j + 1 : j;

	/* must have at least one RID, but not too many */
	if (sid.sub_authority_count < 1 ||
	    sid.sub_authority_count > ADUTILS_SID_MAX_SUB_AUTHORITIES)
		return (-1);

	/* check that we only have digits and '-' */
	if (strspn(txt + 1, "0123456789-") < (strlen(txt) - 1))
		return (-1);

	cp = txt + strlen("S-1-");

	/* 64-bit safe parsing of unsigned 48-bit authority value */
	errno = 0;
	a = strtoull(cp, &ecp, 10);

	/* errors parsing the authority or too many bits */
	if (cp == ecp || (a == 0 && errno == EINVAL) ||
	    (a == ULLONG_MAX && errno == ERANGE) ||
	    (a & 0x0000ffffffffffffULL) != a)
		return (-1);

	cp = ecp;

	sid.authority = (uint64_t)a;

	for (i = 0; i < j; i++) {
		if (*cp++ != '-')
			return (-1);
		/* 64-bit safe parsing of unsigned 32-bit RID */
		errno = 0;
		r = strtoul(cp, &ecp, 10);
		/* errors parsing the RID or too many bits */
		if (cp == ecp || (r == 0 && errno == EINVAL) ||
		    (r == ULONG_MAX && errno == ERANGE) ||
		    (r & 0xffffffffUL) != r)
			return (-1);
		sid.sub_authorities[i] = (uint32_t)r;
		cp = ecp;
	}

	/* check that all of the string SID has been consumed */
	if (*cp != '\0')
		return (-1);

	if (rid != NULL)
		sid.sub_authorities[j] = *rid;

	j = 1 + 1 + 6 + sid.sub_authority_count * 4;

	if (hexbinsidlen < (j * 3))
		return (-2);

	/* binary encode the SID */
	binsid = (uchar_t *)alloca(j);
	(void) sid2binsid(&sid, binsid, j);

	/* hex encode, with a backslash before each byte */
	for (ecp = hexbinsid, i = 0; i < j; i++) {
		b = binsid[i];
		*ecp++ = '\\';
		hb = (b >> 4) & 0xF;
		*ecp++ = (hb <= 0x9 ? hb + '0' : hb - 10 + 'A');
		hb = b & 0xF;
		*ecp++ = (hb <= 0x9 ? hb + '0' : hb - 10 + 'A');
	}
	*ecp = '\0';

	return (0);
}

static
char *
convert_bval2sid(BerValue *bval, uint32_t *rid)
{
	adutils_sid_t	sid;

	if (adutils_getsid(bval, &sid) < 0)
		return (NULL);

	/*
	 * If desired and if the SID is what should be a domain/computer
	 * user or group SID (i.e., S-1-5-w-x-y-z-<user/group RID>) then
	 * save the last RID and truncate the SID
	 */
	if (rid != NULL && sid.authority == 5 && sid.sub_authority_count == 5)
		*rid = sid.sub_authorities[--sid.sub_authority_count];
	return (adutils_sid2txt(&sid));
}


/*
 * Return a NUL-terminated stringified SID from the value of an
 * objectSid attribute and put the last RID in *rid.
 */
char *
adutils_bv_objsid2sidstr(BerValue *bval, uint32_t *rid)
{
	char *sid;

	if (bval == NULL)
		return (NULL);
	/* objectSid is single valued */
	if ((sid = convert_bval2sid(bval, rid)) == NULL)
		return (NULL);
	return (sid);
}

static
char *
adutils_sid_ber2str(BerValue *bval)
{
	return (adutils_bv_objsid2sidstr(bval, NULL));
}


/*
 * Extract an int from the Ber value
 * Return B_TRUE if a valid integer was found, B_FALSE if not.
 */
boolean_t
adutils_bv_uint(BerValue *bval, unsigned int *result)
{
	char buf[40];	/* big enough for any int */
	unsigned int tmp;
	char *p;

	*result = 0;	/* for error cases */

	if (bval == NULL || bval->bv_val == NULL)
		return (B_FALSE);
	if (bval->bv_len >= sizeof (buf))
		return (B_FALSE);

	(void) memcpy(buf, bval->bv_val, bval->bv_len);
	buf[bval->bv_len] = '\0';

	tmp = strtoul(buf, &p, 10);

	/* Junk after the number? */
	if (*p != '\0')
		return (B_FALSE);

	*result = tmp;

	return (B_TRUE);
}

/* Return a NUL-terminated string from the Ber value */
char *
adutils_bv_str(BerValue *bval)
{
	char *s;

	if (bval == NULL || bval->bv_val == NULL)
		return (NULL);
	if ((s = malloc(bval->bv_len + 1)) == NULL)
		return (NULL);
	(void) snprintf(s, bval->bv_len + 1, "%.*s", bval->bv_len,
	    bval->bv_val);
	return (s);
}

/*ARGSUSED*/
int
saslcallback(LDAP *ld, unsigned flags, void *defaults, void *prompts)
{
	sasl_interact_t	*interact;

	if (prompts == NULL || flags != LDAP_SASL_INTERACTIVE)
		return (LDAP_PARAM_ERROR);

	/* There should be no extra arguemnts for SASL/GSSAPI authentication */
	for (interact = prompts; interact->id != SASL_CB_LIST_END;
	    interact++) {
		interact->result = NULL;
		interact->len = 0;
	}
	return (LDAP_SUCCESS);
}


#define	ADCONN_TIME	300

/*
 * Idle connection reaping side of connection management
 */
void
adutils_reap_idle_connections()
{
	adutils_host_t	*adh;
	time_t		now;

	(void) pthread_mutex_lock(&adhostlock);
	now = time(NULL);
	for (adh = host_head; adh != NULL; adh = adh->next) {
		(void) pthread_mutex_lock(&adh->lock);
		if (adh->ref == 0 && adh->idletime != 0 &&
		    adh->idletime + ADCONN_TIME < now) {
			if (adh->ld) {
				(void) ldap_unbind(adh->ld);
				adh->ld = NULL;
				adh->idletime = 0;
				adh->ref = 0;
			}
		}
		(void) pthread_mutex_unlock(&adh->lock);
	}
	(void) pthread_mutex_unlock(&adhostlock);
}


adutils_rc
adutils_ad_alloc(adutils_ad_t **new_ad, const char *domain_name,
    adutils_ad_partition_t part)
{
	adutils_ad_t *ad;

	*new_ad = NULL;

	if ((ad = calloc(1, sizeof (*ad))) == NULL)
		return (ADUTILS_ERR_MEMORY);
	ad->ref = 1;
	ad->partition = part;

	/* domain_name is required iff we are talking directly to a DC */
	if (part == ADUTILS_AD_DATA) {
		assert(domain_name != NULL);
		assert(*domain_name != '\0');

		ad->basedn = adutils_dns2dn(domain_name);
	} else {
		assert(domain_name == NULL);
		ad->basedn = strdup("");
	}
	if (ad->basedn == NULL)
		goto err;

	if (pthread_mutex_init(&ad->lock, NULL) != 0)
		goto err;
	*new_ad = ad;
	return (ADUTILS_SUCCESS);

err:
	free(ad->basedn);
	free(ad);
	return (ADUTILS_ERR_MEMORY);
}

void
adutils_ad_free(adutils_ad_t **ad)
{
	adutils_host_t *p;
	adutils_host_t *prev;

	if (ad == NULL || *ad == NULL)
		return;

	(void) pthread_mutex_lock(&(*ad)->lock);

	if (atomic_dec_32_nv(&(*ad)->ref) > 0) {
		(void) pthread_mutex_unlock(&(*ad)->lock);
		*ad = NULL;
		return;
	}

	(void) pthread_mutex_lock(&adhostlock);
	prev = NULL;
	p = host_head;
	while (p != NULL) {
		if (p->owner != (*ad)) {
			prev = p;
			p = p->next;
			continue;
		} else {
			delete_ds((*ad), p->host, p->port);
			if (prev == NULL)
				p = host_head;
			else
				p = prev->next;
		}
	}
	(void) pthread_mutex_unlock(&adhostlock);

	(void) pthread_mutex_unlock(&(*ad)->lock);
	(void) pthread_mutex_destroy(&(*ad)->lock);

	if ((*ad)->known_domains)
		free((*ad)->known_domains);
	free((*ad)->basedn);
	free(*ad);

	*ad = NULL;
}

static
int
open_conn(adutils_host_t *adh, int timeoutsecs)
{
	int zero = 0;
	int ldversion, rc;
	int timeoutms = timeoutsecs * 1000;

	if (adh == NULL)
		return (0);

	(void) pthread_mutex_lock(&adh->lock);

	if (!adh->dead && adh->ld != NULL)
		/* done! */
		goto out;

	if (adh->ld != NULL) {
		(void) ldap_unbind(adh->ld);
		adh->ld = NULL;
	}
	adh->num_requests = 0;

	atomic_inc_64(&adh->generation);

	/* Open and bind an LDAP connection */
	adh->ld = ldap_init(adh->host, adh->port);
	if (adh->ld == NULL) {
		logger(LOG_INFO, "ldap_init() to server "
		    "%s port %d failed. (%s)", adh->host,
		    adh->port, strerror(errno));
		goto out;
	}
	ldversion = LDAP_VERSION3;
	(void) ldap_set_option(adh->ld, LDAP_OPT_PROTOCOL_VERSION, &ldversion);
	(void) ldap_set_option(adh->ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
	(void) ldap_set_option(adh->ld, LDAP_OPT_TIMELIMIT, &zero);
	(void) ldap_set_option(adh->ld, LDAP_OPT_SIZELIMIT, &zero);
	(void) ldap_set_option(adh->ld, LDAP_X_OPT_CONNECT_TIMEOUT, &timeoutms);
	(void) ldap_set_option(adh->ld, LDAP_OPT_RESTART, LDAP_OPT_ON);

	rc = adutils_set_thread_functions(adh->ld);
	if (rc != LDAP_SUCCESS) {
		/* Error has already been logged */
		(void) ldap_unbind(adh->ld);
		adh->ld = NULL;
		goto out;
	}

	rc = ldap_sasl_interactive_bind_s(adh->ld, "" /* binddn */,
	    adh->saslmech, NULL, NULL, adh->saslflags, &saslcallback,
	    NULL);

	if (rc != LDAP_SUCCESS) {
		logger(LOG_INFO, "ldap_sasl_interactive_bind_s() to server "
		    "%s port %d failed. (%s)", adh->host, adh->port,
		    ldap_err2string(rc));
		ldap_perror(adh->ld, adh->host);
		(void) ldap_unbind(adh->ld);
		adh->ld = NULL;
		goto out;
	}

	logger(LOG_DEBUG, "Using server %s:%d",
	    adh->host, adh->port);

out:
	if (adh->ld != NULL) {
		atomic_inc_32(&adh->ref);
		adh->idletime = time(NULL);
		adh->dead = 0;
		(void) pthread_mutex_unlock(&adh->lock);
		return (1);
	}

	(void) pthread_mutex_unlock(&adh->lock);
	return (0);
}


/*
 * Connection management: find an open connection or open one
 */
static
adutils_host_t *
get_conn(adutils_ad_t *ad)
{
	adutils_host_t	*adh = NULL;
	int		tries;
	int		dscount = 0;
	int		timeoutsecs = ADUTILS_LDAP_OPEN_TIMEOUT;

retry:
	(void) pthread_mutex_lock(&adhostlock);

	if (host_head == NULL) {
		(void) pthread_mutex_unlock(&adhostlock);
		goto out;
	}

	if (dscount == 0) {
		/*
		 * First try: count the number of DSes.
		 *
		 * Integer overflow is not an issue -- we can't have so many
		 * DSes because they won't fit even DNS over TCP, and SMF
		 * shouldn't let you set so many.
		 */
		for (adh = host_head, tries = 0; adh != NULL; adh = adh->next) {
			if (adh->owner == ad)
				dscount++;
		}

		if (dscount == 0) {
			(void) pthread_mutex_unlock(&adhostlock);
			goto out;
		}

		tries = dscount * 3;	/* three tries per-ds */

		/*
		 * Begin round-robin at the next DS in the list after the last
		 * one that we had a connection to, else start with the first
		 * DS in the list.
		 */
		adh = ad->last_adh;
	}

	/*
	 * Round-robin -- pick the next one on the list; if the list
	 * changes on us, no big deal, we'll just potentially go
	 * around the wrong number of times.
	 */
	for (;;) {
		if (adh != NULL && adh->owner == ad && adh->ld != NULL &&
		    !adh->dead)
			break;
		if (adh == NULL || (adh = adh->next) == NULL)
			adh = host_head;
		if (adh->owner == ad)
			break;
	}

	ad->last_adh = adh;
	(void) pthread_mutex_unlock(&adhostlock);

	/* Found suitable DS, open it if not already opened */
	if (open_conn(adh, timeoutsecs))
		return (adh);

	tries--;
	if ((tries % dscount) == 0)
		timeoutsecs *= 2;
	if (tries > 0)
		goto retry;

out:
	logger(LOG_NOTICE, "Couldn't open an LDAP connection to any global "
	    "catalog server!");
	return (NULL);
}

static
void
release_conn(adutils_host_t *adh)
{
	int delete = 0;

	(void) pthread_mutex_lock(&adh->lock);
	if (atomic_dec_32_nv(&adh->ref) == 0) {
		if (adh->owner == NULL)
			delete = 1;
		adh->idletime = time(NULL);
	}
	(void) pthread_mutex_unlock(&adh->lock);

	/* Free this host if its owner no longer exists. */
	if (delete) {
		(void) pthread_mutex_lock(&adhostlock);
		delete_ds(NULL, adh->host, adh->port);
		(void) pthread_mutex_unlock(&adhostlock);
	}
}

/*
 * Create a adutils_host_t, populate it and add it to the list of hosts.
 */
adutils_rc
adutils_add_ds(adutils_ad_t *ad, const char *host, int port)
{
	adutils_host_t	*p;
	adutils_host_t	*new = NULL;
	int		ret;
	adutils_rc	rc;

	(void) pthread_mutex_lock(&adhostlock);
	for (p = host_head; p != NULL; p = p->next) {
		if (p->owner != ad)
			continue;

		if (strcmp(host, p->host) == 0 && p->port == port) {
			/* already added */
			rc = ADUTILS_SUCCESS;
			goto err;
		}
	}

	rc = ADUTILS_ERR_MEMORY;

	/* add new entry */
	new = (adutils_host_t *)calloc(1, sizeof (*new));
	if (new == NULL)
		goto err;
	new->owner = ad;
	new->port = port;
	new->dead = 0;
	new->max_requests = 80;
	new->num_requests = 0;
	if ((new->host = strdup(host)) == NULL)
		goto err;
	new->saslflags = LDAP_SASL_INTERACTIVE;
	new->saslmech = "GSSAPI";

	if ((ret = pthread_mutex_init(&new->lock, NULL)) != 0) {
		free(new->host);
		new->host = NULL;
		errno = ret;
		rc = ADUTILS_ERR_INTERNAL;
		goto err;
	}

	/* link in */
	rc = ADUTILS_SUCCESS;
	new->next = host_head;
	host_head = new;

err:
	(void) pthread_mutex_unlock(&adhostlock);

	if (rc != 0 && new != NULL) {
		if (new->host != NULL) {
			(void) pthread_mutex_destroy(&new->lock);
			free(new->host);
		}
		free(new);
	}

	return (rc);
}

/*
 * Free a DS configuration.
 * Caller must lock the adhostlock mutex
 */
static
void
delete_ds(adutils_ad_t *ad, const char *host, int port)
{
	adutils_host_t	**p, *q;

	for (p = &host_head; *p != NULL; p = &((*p)->next)) {
		if ((*p)->owner != ad || strcmp(host, (*p)->host) != 0 ||
		    (*p)->port != port)
			continue;
		/* found */

		(void) pthread_mutex_lock(&((*p)->lock));
		if ((*p)->ref > 0) {
			/*
			 * Still in use. Set its owner to NULL so
			 * that it can be freed when its ref count
			 * becomes 0.
			 */
			(*p)->owner = NULL;
			(void) pthread_mutex_unlock(&((*p)->lock));
			break;
		}
		(void) pthread_mutex_unlock(&((*p)->lock));

		q = *p;
		*p = (*p)->next;

		(void) pthread_mutex_destroy(&q->lock);

		if (q->ld)
			(void) ldap_unbind(q->ld);
		if (q->host)
			free(q->host);
		free(q);
		break;
	}

}
/*
 * Add known domain name and domain SID to AD configuration.
 */

adutils_rc
adutils_add_domain(adutils_ad_t *ad, const char *domain, const char *sid)
{
	struct known_domain *new;
	int num = ad->num_known_domains;

	ad->num_known_domains++;
	new = realloc(ad->known_domains,
	    sizeof (struct known_domain) * ad->num_known_domains);
	if (new != NULL) {
		ad->known_domains = new;
		(void) strlcpy(ad->known_domains[num].name, domain,
		    sizeof (ad->known_domains[num].name));
		(void) strlcpy(ad->known_domains[num].sid, sid,
		    sizeof (ad->known_domains[num].sid));
		return (ADUTILS_SUCCESS);
	} else {
		if (ad->known_domains != NULL) {
			free(ad->known_domains);
			ad->known_domains = NULL;
		}
		ad->num_known_domains = 0;
		return (ADUTILS_ERR_MEMORY);
	}
}


/*
 * Check that this AD supports this domain.
 * If there are no known domains assume that the
 * domain is supported by this AD.
 *
 * Returns 1 if this domain is supported by this AD
 * else returns 0;
 */

int
adutils_lookup_check_domain(adutils_query_state_t *qs, const char *domain)
{
	adutils_ad_t *ad = qs->qadh->owner;
	int i;

	for (i = 0; i < ad->num_known_domains; i++) {
		if (domain_eq(domain, ad->known_domains[i].name))
			return (1);
	}

	return ((i == 0) ? 1 : 0);
}


/*
 * Check that this AD supports the SID prefix.
 * The SID prefix should match the domain SID.
 * If there are no known domains assume that the
 * SID prefix is supported by this AD.
 *
 * Returns 1 if this sid prefix is supported by this AD
 * else returns 0;
 */

int
adutils_lookup_check_sid_prefix(adutils_query_state_t *qs, const char *sid)
{
	adutils_ad_t *ad = qs->qadh->owner;
	int i;


	for (i = 0; i < ad->num_known_domains; i++) {
		if (strcmp(sid, ad->known_domains[i].sid) == 0)
			return (1);
	}

	return ((i == 0) ? 1 : 0);
}


adutils_rc
adutils_lookup_batch_start(adutils_ad_t *ad, int nqueries,
    adutils_ldap_res_search_cb ldap_res_search_cb,
    void *ldap_res_search_argp,
    adutils_query_state_t **state)
{
	adutils_query_state_t	*new_state;
	adutils_host_t		*adh = NULL;

	if (ad == NULL)
		return (ADUTILS_ERR_INTERNAL);

	*state = NULL;
	adh = get_conn(ad);
	if (adh == NULL)
		return (ADUTILS_ERR_RETRIABLE_NET_ERR);

	new_state = calloc(1, sizeof (adutils_query_state_t) +
	    (nqueries - 1) * sizeof (adutils_q_t));
	if (new_state == NULL)
		return (ADUTILS_ERR_MEMORY);

	new_state->ref_cnt = 1;
	new_state->qadh = adh;
	new_state->qsize = nqueries;
	new_state->qadh_gen = adh->generation;
	new_state->qcount = 0;
	new_state->ldap_res_search_cb = ldap_res_search_cb;
	new_state->ldap_res_search_argp = ldap_res_search_argp;
	(void) pthread_cond_init(&new_state->cv, NULL);

	(void) pthread_mutex_lock(&qstatelock);
	new_state->next = qstatehead;
	qstatehead = new_state;
	(void) pthread_mutex_unlock(&qstatelock);
	*state = new_state;

	return (ADUTILS_SUCCESS);
}

/*
 * Find the adutils_query_state_t to which a given LDAP result msgid on a
 * given connection belongs. This routine increaments the reference count
 * so that the object can not be freed. adutils_lookup_batch_unlock()
 * must be called to decreament the reference count.
 */
static
int
msgid2query(adutils_host_t *adh, int msgid,
    adutils_query_state_t **state, int *qid)
{
	adutils_query_state_t	*p;
	int			i;
	int			ret;

	(void) pthread_mutex_lock(&qstatelock);
	for (p = qstatehead; p != NULL; p = p->next) {
		if (p->qadh != adh || adh->generation != p->qadh_gen)
			continue;
		for (i = 0; i < p->qcount; i++) {
			if ((p->queries[i]).msgid == msgid) {
				if (!p->qdead) {
					p->ref_cnt++;
					*state = p;
					*qid = i;
					ret = 1;
				} else
					ret = 0;
				(void) pthread_mutex_unlock(&qstatelock);
				return (ret);
			}
		}
	}
	(void) pthread_mutex_unlock(&qstatelock);
	return (0);
}

static
int
check_for_binary_attrs(const char *attr)
{
	int i;
	for (i = 0; binattrs[i].name != NULL; i++) {
		if (strcasecmp(binattrs[i].name, attr) == 0)
			return (i);
	}
	return (-1);
}

static
void
free_entry(adutils_entry_t *entry)
{
	int		i, j;
	adutils_attr_t	*ap;

	if (entry == NULL)
		return;
	if (entry->attr_nvpairs == NULL) {
		free(entry);
		return;
	}
	for (i = 0; i < entry->num_nvpairs; i++) {
		ap = &entry->attr_nvpairs[i];
		if (ap->attr_name == NULL) {
			ldap_value_free(ap->attr_values);
			continue;
		}
		if (check_for_binary_attrs(ap->attr_name) >= 0) {
			free(ap->attr_name);
			if (ap->attr_values == NULL)
				continue;
			for (j = 0; j < ap->num_values; j++)
				free(ap->attr_values[j]);
			free(ap->attr_values);
		} else if (strcasecmp(ap->attr_name, "dn") == 0) {
			free(ap->attr_name);
			ldap_memfree(ap->attr_values[0]);
			free(ap->attr_values);
		} else {
			free(ap->attr_name);
			ldap_value_free(ap->attr_values);
		}
	}
	free(entry->attr_nvpairs);
	free(entry);
}

void
adutils_freeresult(adutils_result_t **result)
{
	adutils_entry_t	*e, *next;

	if (result == NULL || *result == NULL)
		return;
	if ((*result)->entries == NULL) {
		free(*result);
		*result = NULL;
		return;
	}
	for (e = (*result)->entries; e != NULL; e = next) {
		next = e->next;
		free_entry(e);
	}
	free(*result);
	*result = NULL;
}

const adutils_entry_t *
adutils_getfirstentry(adutils_result_t *result)
{
	if (result != NULL)
		return (result->entries);
	return (NULL);
}


char **
adutils_getattr(const adutils_entry_t *entry, const char *attrname)
{
	int		i;
	adutils_attr_t	*ap;

	if (entry == NULL || entry->attr_nvpairs == NULL)
		return (NULL);
	for (i = 0; i < entry->num_nvpairs; i++) {
		ap = &entry->attr_nvpairs[i];
		if (ap->attr_name != NULL &&
		    strcasecmp(ap->attr_name, attrname) == 0)
			return (ap->attr_values);
	}
	return (NULL);
}


/*
 * Queue LDAP result for the given query.
 *
 * Return values:
 *  0 success
 * -1 ignore result
 * -2 error
 */
static
int
make_entry(adutils_q_t *q, adutils_host_t *adh, LDAPMessage *search_res,
    adutils_entry_t **entry)
{
	BerElement	*ber = NULL;
	BerValue	**bvalues = NULL;
	char		**strvalues;
	char		*attr = NULL, *dn = NULL, *domain = NULL;
	adutils_entry_t	*ep;
	adutils_attr_t	*ap;
	int		i, j, b, ret = -2;

	*entry = NULL;

	/* Check that this is the domain that we were looking for */
	if ((dn = ldap_get_dn(adh->ld, search_res)) == NULL)
		return (-2);
	if ((domain = adutils_dn2dns(dn)) == NULL) {
		ldap_memfree(dn);
		return (-2);
	}
	if (q->edomain != NULL) {
		if (!domain_eq(q->edomain, domain)) {
			ldap_memfree(dn);
			free(domain);
			return (-1);
		}
	}
	free(domain);

	/* Allocate memory for the entry */
	if ((ep = calloc(1, sizeof (*ep))) == NULL)
		goto out;

	/* For 'dn' */
	ep->num_nvpairs = 1;

	/* Count the number of name-value pairs for this entry */
	for (attr = ldap_first_attribute(adh->ld, search_res, &ber);
	    attr != NULL;
	    attr = ldap_next_attribute(adh->ld, search_res, ber)) {
		ep->num_nvpairs++;
		ldap_memfree(attr);
	}
	ber_free(ber, 0);
	ber = NULL;

	/* Allocate array for the attribute name-value pairs */
	ep->attr_nvpairs = calloc(ep->num_nvpairs, sizeof (*ep->attr_nvpairs));
	if (ep->attr_nvpairs == NULL) {
		ep->num_nvpairs = 0;
		goto out;
	}

	/* For dn */
	ap = &ep->attr_nvpairs[0];
	if ((ap->attr_name = strdup("dn")) == NULL)
		goto out;
	ap->num_values = 1;
	ap->attr_values = calloc(ap->num_values, sizeof (*ap->attr_values));
	if (ap->attr_values == NULL) {
		ap->num_values = 0;
		goto out;
	}
	ap->attr_values[0] = dn;
	dn = NULL;

	for (attr = ldap_first_attribute(adh->ld, search_res, &ber), i = 1;
	    attr != NULL;
	    ldap_memfree(attr), i++,
	    attr = ldap_next_attribute(adh->ld, search_res, ber)) {
		ap = &ep->attr_nvpairs[i];
		if ((ap->attr_name = strdup(attr)) == NULL)
			goto out;

		if ((b = check_for_binary_attrs(attr)) >= 0) {
			bvalues =
			    ldap_get_values_len(adh->ld, search_res, attr);
			if (bvalues == NULL)
				continue;
			ap->num_values = ldap_count_values_len(bvalues);
			if (ap->num_values == 0) {
				ldap_value_free_len(bvalues);
				bvalues = NULL;
				continue;
			}
			ap->attr_values = calloc(ap->num_values,
			    sizeof (*ap->attr_values));
			if (ap->attr_values == NULL) {
				ap->num_values = 0;
				goto out;
			}
			for (j = 0; j < ap->num_values; j++) {
				ap->attr_values[j] =
				    binattrs[b].ber2str(bvalues[j]);
				if (ap->attr_values[j] == NULL)
					goto out;
			}
			ldap_value_free_len(bvalues);
			bvalues = NULL;
			continue;
		}

		strvalues = ldap_get_values(adh->ld, search_res, attr);
		if (strvalues == NULL)
			continue;
		ap->num_values = ldap_count_values(strvalues);
		if (ap->num_values == 0) {
			ldap_value_free(strvalues);
			continue;
		}
		ap->attr_values = strvalues;
	}

	ret = 0;
out:
	ldap_memfree(attr);
	ldap_memfree(dn);
	ber_free(ber, 0);
	ldap_value_free_len(bvalues);
	if (ret < 0)
		free_entry(ep);
	else
		*entry = ep;
	return (ret);
}

/*
 * Put the search result onto the given adutils_q_t.
 * Returns:	  0 success
 *		< 0 error
 */
static
int
add_entry(adutils_host_t *adh, adutils_q_t *q, LDAPMessage *search_res)
{
	int			ret = -1;
	adutils_entry_t		*entry = NULL;
	adutils_result_t	*res;

	ret = make_entry(q, adh, search_res, &entry);
	if (ret < -1) {
		*q->rc = ADUTILS_ERR_MEMORY;
		goto out;
	} else if (ret == -1) {
		/* ignore result */
		goto out;
	}
	if (*q->result == NULL) {
		res = calloc(1, sizeof (*res));
		if (res == NULL) {
			*q->rc = ADUTILS_ERR_MEMORY;
			goto out;
		}
		res->num_entries = 1;
		res->entries = entry;
		*q->result = res;
	} else {
		res = *q->result;
		entry->next = res->entries;
		res->entries = entry;
		res->num_entries++;
	}
	*q->rc = ADUTILS_SUCCESS;
	entry = NULL;
	ret = 0;

out:
	free_entry(entry);
	return (ret);
}

/*
 * Try to get a result; if there is one, find the corresponding
 * adutils_q_t and process the result.
 *
 * Returns:	0 success
 *		-1 error
 */
static
int
get_adobject_batch(adutils_host_t *adh, struct timeval *timeout)
{
	adutils_query_state_t	*query_state;
	LDAPMessage		*res = NULL;
	int			rc, ret, msgid, qid;
	adutils_q_t		*que;
	int			num;

	(void) pthread_mutex_lock(&adh->lock);
	if (adh->dead || adh->num_requests == 0) {
		ret = (adh->dead) ? -1 : -2;
		(void) pthread_mutex_unlock(&adh->lock);
		return (ret);
	}

	/* Get one result */
	rc = ldap_result(adh->ld, LDAP_RES_ANY, 0, timeout, &res);
	if ((timeout != NULL && timeout->tv_sec > 0 && rc == LDAP_SUCCESS) ||
	    rc < 0)
		adh->dead = 1;

	if (rc == LDAP_RES_SEARCH_RESULT && adh->num_requests > 0)
		adh->num_requests--;
	if (adh->dead) {
		num = adh->num_requests;
		(void) pthread_mutex_unlock(&adh->lock);
		logger(LOG_DEBUG,
		    "AD ldap_result error - %d queued requests", num);
		return (-1);
	}

	switch (rc) {
	case LDAP_RES_SEARCH_RESULT:
		msgid = ldap_msgid(res);
		if (msgid2query(adh, msgid, &query_state, &qid)) {
			if (query_state->ldap_res_search_cb != NULL) {
				/*
				 * We use the caller-provided callback
				 * to process the result.
				 */
				query_state->ldap_res_search_cb(
				    adh->ld, &res, rc, qid,
				    query_state->ldap_res_search_argp);
				(void) pthread_mutex_unlock(&adh->lock);
			} else {
				/*
				 * No callback. We fallback to our
				 * default behaviour. All the entries
				 * gotten from this search have been
				 * added to the result list during
				 * LDAP_RES_SEARCH_ENTRY (see below).
				 * Here we set the return status to
				 * notfound if the result is still empty.
				 */
				(void) pthread_mutex_unlock(&adh->lock);
				que = &(query_state->queries[qid]);
				if (*que->result == NULL)
					*que->rc = ADUTILS_ERR_NOTFOUND;
			}
			atomic_dec_32(&query_state->qinflight);
			adutils_lookup_batch_unlock(&query_state);
		} else {
			num = adh->num_requests;
			(void) pthread_mutex_unlock(&adh->lock);
			logger(LOG_DEBUG,
			    "AD cannot find message ID (%d) "
			    "- %d queued requests",
			    msgid, num);
		}
		(void) ldap_msgfree(res);
		ret = 0;
		break;

	case LDAP_RES_SEARCH_ENTRY:
		msgid = ldap_msgid(res);
		if (msgid2query(adh, msgid, &query_state, &qid)) {
			if (query_state->ldap_res_search_cb != NULL) {
				/*
				 * We use the caller-provided callback
				 * to process the entry.
				 */
				query_state->ldap_res_search_cb(
				    adh->ld, &res, rc, qid,
				    query_state->ldap_res_search_argp);
				(void) pthread_mutex_unlock(&adh->lock);
			} else {
				/*
				 * No callback. We fallback to our
				 * default behaviour. This entry
				 * will be added to the result list.
				 */
				que = &(query_state->queries[qid]);
				rc = add_entry(adh, que, res);
				(void) pthread_mutex_unlock(&adh->lock);
				if (rc < 0) {
					logger(LOG_DEBUG,
					    "Failed to queue entry by "
					    "message ID (%d) "
					    "- %d queued requests",
					    msgid, num);
				}
			}
			adutils_lookup_batch_unlock(&query_state);
		} else {
			num = adh->num_requests;
			(void) pthread_mutex_unlock(&adh->lock);
			logger(LOG_DEBUG,
			    "AD cannot find message ID (%d) "
			    "- %d queued requests",
			    msgid, num);
		}
		(void) ldap_msgfree(res);
		ret = 0;
		break;

	case LDAP_RES_SEARCH_REFERENCE:
		/*
		 * We have no need for these at the moment.  Eventually,
		 * when we query things that we can't expect to find in
		 * the Global Catalog then we'll need to learn to follow
		 * references.
		 */
		(void) pthread_mutex_unlock(&adh->lock);
		(void) ldap_msgfree(res);
		ret = 0;
		break;

	default:
		/* timeout or error; treat the same */
		(void) pthread_mutex_unlock(&adh->lock);
		ret = -1;
		break;
	}

	return (ret);
}

/*
 * This routine decreament the reference count of the
 * adutils_query_state_t
 */
static void
adutils_lookup_batch_unlock(adutils_query_state_t **state)
{
	/*
	 * Decrement reference count with qstatelock locked
	 */
	(void) pthread_mutex_lock(&qstatelock);
	(*state)->ref_cnt--;
	/*
	 * If there are no references wakup the allocating thread
	 */
	if ((*state)->ref_cnt <= 1)
		(void) pthread_cond_signal(&(*state)->cv);
	(void) pthread_mutex_unlock(&qstatelock);
	*state = NULL;
}

/*
 * This routine frees the adutils_query_state_t structure
 * If the reference count is greater than 1 it waits
 * for the other threads to finish using it.
 */
void
adutils_lookup_batch_release(adutils_query_state_t **state)
{
	adutils_query_state_t **p;
	int			i;

	if (state == NULL || *state == NULL)
		return;

	/*
	 * Set state to dead to stop further operations.
	 * Wait for reference count with qstatelock locked
	 * to get to one.
	 */
	(void) pthread_mutex_lock(&qstatelock);
	(*state)->qdead = 1;
	while ((*state)->ref_cnt > 1) {
		(void) pthread_cond_wait(&(*state)->cv, &qstatelock);
	}

	/* Remove this state struct from the list of state structs */
	for (p = &qstatehead; *p != NULL; p = &(*p)->next) {
		if (*p == (*state)) {
			*p = (*state)->next;
			break;
		}
	}
	(void) pthread_mutex_unlock(&qstatelock);
	(void) pthread_cond_destroy(&(*state)->cv);
	release_conn((*state)->qadh);

	/* Clear results for queries that failed */
	for (i = 0; i < (*state)->qcount; i++) {
		if (*(*state)->queries[i].rc != ADUTILS_SUCCESS) {
			adutils_freeresult((*state)->queries[i].result);
		}
	}
	free(*state);
	*state = NULL;
}


/*
 * This routine waits for other threads using the
 * adutils_query_state_t structure to finish.
 * If the reference count is greater than 1 it waits
 * for the other threads to finish using it.
 */
static
void
adutils_lookup_batch_wait(adutils_query_state_t *state)
{
	/*
	 * Set state to dead to stop further operation.
	 * stating.
	 * Wait for reference count to get to one
	 * with qstatelock locked.
	 */
	(void) pthread_mutex_lock(&qstatelock);
	state->qdead = 1;
	while (state->ref_cnt > 1) {
		(void) pthread_cond_wait(&state->cv, &qstatelock);
	}
	(void) pthread_mutex_unlock(&qstatelock);
}

/*
 * Process active queries in the AD lookup batch and then finalize the
 * result.
 */
adutils_rc
adutils_lookup_batch_end(adutils_query_state_t **state)
{
	int		    rc = LDAP_SUCCESS;
	adutils_rc	    ad_rc = ADUTILS_SUCCESS;
	struct timeval	    tv;

	tv.tv_sec = ADUTILS_SEARCH_TIMEOUT;
	tv.tv_usec = 0;

	/* Process results until done or until timeout, if given */
	while ((*state)->qinflight > 0) {
		if ((rc = get_adobject_batch((*state)->qadh,
		    &tv)) != 0)
			break;
	}
	(*state)->qdead = 1;
	/* Wait for other threads processing search result to finish */
	adutils_lookup_batch_wait(*state);
	if (rc == -1 || (*state)->qinflight != 0)
		ad_rc = ADUTILS_ERR_RETRIABLE_NET_ERR;
	adutils_lookup_batch_release(state);
	return (ad_rc);
}

/*
 * Send one prepared search, queue up msgid, process what results are
 * available
 */
adutils_rc
adutils_lookup_batch_add(adutils_query_state_t *state,
    const char *filter, const char * const *attrs, const char *edomain,
    adutils_result_t **result, adutils_rc *rc)
{
	adutils_rc	retcode = ADUTILS_SUCCESS;
	int		lrc, qid;
	int		num;
	int		dead;
	struct timeval	tv;
	adutils_q_t	*q;

	qid = atomic_inc_32_nv(&state->qcount) - 1;
	q = &(state->queries[qid]);

	assert(qid < state->qsize);

	/*
	 * Remember the expected domain so we can check the results
	 * against it
	 */
	q->edomain = edomain;

	/* Remember where to put the results */
	q->result = result;
	q->rc = rc;

	/*
	 * Provide sane defaults for the results in case we never hear
	 * back from the DS before closing the connection.
	 */
	*rc = ADUTILS_ERR_RETRIABLE_NET_ERR;
	if (result != NULL)
		*result = NULL;

	/* Check the number of queued requests first */
	tv.tv_sec = ADUTILS_SEARCH_TIMEOUT;
	tv.tv_usec = 0;
	while (!state->qadh->dead &&
	    state->qadh->num_requests > state->qadh->max_requests) {
		if (get_adobject_batch(state->qadh, &tv) != 0)
			break;
	}

	/* Send this lookup, don't wait for a result here */
	lrc = LDAP_SUCCESS;
	(void) pthread_mutex_lock(&state->qadh->lock);

	if (!state->qadh->dead) {
		state->qadh->idletime = time(NULL);

		lrc = ldap_search_ext(state->qadh->ld,
		    state->qadh->owner->basedn,
		    LDAP_SCOPE_SUBTREE, filter, (char **)attrs,
		    0, NULL, NULL, NULL, -1, &q->msgid);

		if (lrc == LDAP_SUCCESS) {
			state->qadh->num_requests++;
		} else if (lrc == LDAP_BUSY || lrc == LDAP_UNAVAILABLE ||
		    lrc == LDAP_CONNECT_ERROR || lrc == LDAP_SERVER_DOWN ||
		    lrc == LDAP_UNWILLING_TO_PERFORM) {
			retcode = ADUTILS_ERR_RETRIABLE_NET_ERR;
			state->qadh->dead = 1;
		} else {
			retcode = ADUTILS_ERR_OTHER;
			state->qadh->dead = 1;
		}
	}
	dead = state->qadh->dead;
	num = state->qadh->num_requests;
	(void) pthread_mutex_unlock(&state->qadh->lock);

	if (dead) {
		if (lrc != LDAP_SUCCESS)
			logger(LOG_DEBUG,
			    "AD ldap_search_ext error (%s) "
			    "- %d queued requests",
			    ldap_err2string(lrc), num);
		return (retcode);
	}

	atomic_inc_32(&state->qinflight);

	/*
	 * Reap as many requests as we can _without_ waiting to prevent
	 * any possible TCP socket buffer starvation deadlocks.
	 */
	(void) memset(&tv, 0, sizeof (tv));
	while (get_adobject_batch(state->qadh, &tv) == 0)
		;

	return (ADUTILS_SUCCESS);
}

/*
 * Single AD lookup request implemented on top of the batch API.
 */
adutils_rc
adutils_lookup(adutils_ad_t *ad, const char *filter, const char **attrs,
    const char *domain, adutils_result_t **result)
{
	adutils_rc		rc, brc;
	adutils_query_state_t	*qs;

	rc = adutils_lookup_batch_start(ad, 1, NULL, NULL, &qs);
	if (rc != ADUTILS_SUCCESS)
		return (rc);

	rc = adutils_lookup_batch_add(qs, filter, attrs, domain, result, &brc);
	if (rc != ADUTILS_SUCCESS) {
		adutils_lookup_batch_release(&qs);
		return (rc);
	}

	rc = adutils_lookup_batch_end(&qs);
	if (rc != ADUTILS_SUCCESS)
		return (rc);
	return (brc);
}

boolean_t
domain_eq(const char *a, const char *b)
{
	int err;

	return (u8_strcmp(a, b, 0, U8_STRCMP_CI_LOWER, U8_UNICODE_LATEST, &err)
	    == 0 && err == 0);
}

void
adutils_set_debug(enum ad_debug item, int value)
{
	if (item >= 0 && item <= AD_DEBUG_MAX)
		ad_debug[item] = value;
}
