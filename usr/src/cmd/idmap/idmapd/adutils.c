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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Processes name2sid & sid2name batched lookups for a given user or
 * computer from an AD Directory server using GSSAPI authentication
 */

#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>
#include <string.h>
#include <strings.h>
#include <lber.h>
#include <ldap.h>
#include <sasl/sasl.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <synch.h>
#include <atomic.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#include <sys/u8_textprep.h>
#include "idmapd.h"

/*
 * Internal data structures for this code
 */

/* Attribute names and filter format strings */
#define	SAN		"sAMAccountName"
#define	OBJSID		"objectSid"
#define	OBJCLASS	"objectClass"
#define	SANFILTER	"(sAMAccountName=%.*s)"
#define	OBJSIDFILTER	"(objectSid=%s)"

/*
 * This should really be in some <sys/sid.h> file or so; we have a
 * private version of sid_t, and so must other components of ON until we
 * rationalize this.
 */
typedef struct sid {
	uchar_t		version;
	uchar_t		sub_authority_count;
	uint64_t	authority;  /* really, 48-bits */
	rid_t		sub_authorities[SID_MAX_SUB_AUTHORITIES];
} sid_t;

/* A single DS */
typedef struct ad_host {
	struct ad_host		*next;
	ad_t			*owner;		/* ad_t to which this belongs */
	pthread_mutex_t		lock;
	LDAP			*ld;		/* LDAP connection */
	uint32_t		ref;		/* ref count */
	time_t			idletime;	/* time since last activity */
	int			dead;		/* error on LDAP connection */
	/*
	 * Used to distinguish between different instances of LDAP
	 * connections to this same DS.  We need this so we never mix up
	 * results for a given msgID from one connection with those of
	 * another earlier connection where two batch state structures
	 * share this ad_host object but used different LDAP connections
	 * to send their LDAP searches.
	 */
	uint64_t		generation;

	/* LDAP DS info */
	char			*host;
	int			port;

	/* hardwired to SASL GSSAPI only for now */
	char			*saslmech;
	unsigned		saslflags;
} ad_host_t;

/* A set of DSs for a given AD partition; ad_t typedef comes from  adutil.h */
struct ad {
	char			*dflt_w2k_dom;	/* used to qualify bare names */
	pthread_mutex_t		lock;
	uint32_t		ref;
	ad_host_t		*last_adh;
	idmap_ad_partition_t	partition;	/* Data or global catalog? */
};

/*
 * A place to put the results of a batched (async) query
 *
 * There is one of these for every query added to a batch object
 * (idmap_query_state, see below).
 */
typedef struct idmap_q {
	/*
	 * data used for validating search result entries for name->SID
	 * lookups
	 */
	char			*ecanonname;	/* expected canon name */
	char			*edomain;	/* expected domain name */
	int			eunixtype;	/* expected unix type */
	/* results */
	char			**canonname;	/* actual canon name */
	char			**domain;	/* name of domain of object */
	char			**sid;		/* stringified SID */
	rid_t			*rid;		/* RID */
	int			*sid_type;	/* user or group SID? */
	char			**unixname;	/* unixname for name mapping */
	char			**dn;		/* DN of entry */
	char			**attr;		/* Attr for name mapping */
	char			**value;	/* value for name mapping */
	idmap_retcode		*rc;

	/* lookup state */
	int			msgid;		/* LDAP message ID */
} idmap_q_t;

/* Batch context structure; typedef is in header file */
struct idmap_query_state {
	idmap_query_state_t	*next;
	int			qcount;		/* how many queries */
	int			ref_cnt;	/* reference count */
	pthread_cond_t		cv;		/* Condition wait variable */
	uint32_t		qlastsent;
	uint32_t		qinflight;	/* how many queries in flight */
	uint16_t		qdead;		/* oops, lost LDAP connection */
	ad_host_t		*qadh;		/* LDAP connection */
	uint64_t		qadh_gen;	/* same as qadh->generation */
	const char		*ad_unixuser_attr;
	const char		*ad_unixgroup_attr;
	idmap_q_t		queries[1];	/* array of query results */
};

/*
 * List of query state structs -- needed so we can "route" LDAP results
 * to the right context if multiple threads should be using the same
 * connection concurrently
 */
static idmap_query_state_t	*qstatehead = NULL;
static pthread_mutex_t		qstatelock = PTHREAD_MUTEX_INITIALIZER;

/*
 * List of DSs, needed by the idle connection reaper thread
 */
static ad_host_t	*host_head = NULL;
static pthread_t	reaperid = 0;
static pthread_mutex_t	adhostlock = PTHREAD_MUTEX_INITIALIZER;


static void
idmap_lookup_unlock_batch(idmap_query_state_t **state);

static void
delete_ds(ad_t *ad, const char *host, int port);

/*ARGSUSED*/
static int
idmap_saslcallback(LDAP *ld, unsigned flags, void *defaults, void *prompts)
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


/*
 * Turn "dc=foo,dc=bar,dc=com" into "foo.bar.com"; ignores any other
 * attributes (CN, etc...).  We don't need the reverse, for now.
 */
static
char *
dn2dns(const char *dn)
{
	char **rdns = NULL;
	char **attrs = NULL;
	char **labels = NULL;
	char *dns = NULL;
	char **rdn, **attr, **label;
	int maxlabels = 5;
	int nlabels = 0;
	int dnslen;

	/*
	 * There is no reverse of ldap_dns_to_dn() in our libldap, so we
	 * have to do the hard work here for now.
	 */

	/*
	 * This code is much too liberal: it looks for "dc" attributes
	 * in all RDNs of the DN.  In theory this could cause problems
	 * if people were to use "dc" in nodes other than the root of
	 * the tree, but in practice noone, least of all Active
	 * Directory, does that.
	 *
	 * On the other hand, this code is much too conservative: it
	 * does not make assumptions about ldap_explode_dn(), and _that_
	 * is the true for looking at every attr of every RDN.
	 *
	 * Since we only ever look at dc and those must be DNS labels,
	 * at least until we get around to supporting IDN here we
	 * shouldn't see escaped labels from AD nor from libldap, though
	 * the spec (RFC2253) does allow libldap to escape things that
	 * don't need escaping -- if that should ever happen then
	 * libldap will need a spanking, and we can take care of that.
	 */

	/* Explode a DN into RDNs */
	if ((rdns = ldap_explode_dn(dn, 0)) == NULL)
		return (NULL);

	labels = calloc(maxlabels + 1, sizeof (char *));
	label = labels;

	for (rdn = rdns; *rdn != NULL; rdn++) {
		if (attrs != NULL)
			ldap_value_free(attrs);

		/* Explode each RDN, look for DC attr, save val as DNS label */
		if ((attrs = ldap_explode_rdn(rdn[0], 0)) == NULL)
			goto done;

		for (attr = attrs; *attr != NULL; attr++) {
			if (strncasecmp(*attr, "dc=", 3) != 0)
				continue;

			/* Found a DNS label */
			labels[nlabels++] = strdup((*attr) + 3);

			if (nlabels == maxlabels) {
				char **tmp;
				tmp = realloc(labels,
				    sizeof (char *) * (maxlabels + 1));

				if (tmp == NULL)
					goto done;

				labels = tmp;
				labels[nlabels] = NULL;
			}

			/* There should be just one DC= attr per-RDN */
			break;
		}
	}

	/*
	 * Got all the labels, now join with '.'
	 *
	 * We need room for nlabels - 1 periods ('.'), one nul
	 * terminator, and the strlen() of each label.
	 */
	dnslen = nlabels;
	for (label = labels; *label != NULL; label++)
		dnslen += strlen(*label);

	if ((dns = malloc(dnslen)) == NULL)
		goto done;

	*dns = '\0';

	for (label = labels; *label != NULL; label++) {
		(void) strlcat(dns, *label, dnslen);
		/*
		 * NOTE: the last '.' won't be appended -- there's no room
		 * for it!
		 */
		(void) strlcat(dns, ".", dnslen);
	}

done:
	if (labels != NULL) {
		for (label = labels; *label != NULL; label++)
			free(*label);
		free(labels);
	}
	if (attrs != NULL)
		ldap_value_free(attrs);
	if (rdns != NULL)
		ldap_value_free(rdns);

	return (dns);
}

/*
 * Keep connection management simple for now, extend or replace later
 * with updated libsldap code.
 */
#define	ADREAPERSLEEP	60
#define	ADCONN_TIME	300

/*
 * Idle connection reaping side of connection management
 *
 * Every minute wake up and look for connections that have been idle for
 * five minutes or more and close them.
 */
/*ARGSUSED*/
static
void
adreaper(void *arg)
{
	ad_host_t	*adh;
	time_t		now;
	timespec_t	ts;

	ts.tv_sec = ADREAPERSLEEP;
	ts.tv_nsec = 0;

	for (;;) {
		/*
		 * nanosleep(3RT) is thead-safe (no SIGALRM) and more
		 * portable than usleep(3C)
		 */
		(void) nanosleep(&ts, NULL);
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
}

int
idmap_ad_alloc(ad_t **new_ad, const char *default_domain,
		idmap_ad_partition_t part)
{
	ad_t *ad;

	*new_ad = NULL;

	if ((default_domain == NULL || *default_domain == '\0') &&
	    part != IDMAP_AD_GLOBAL_CATALOG)
		return (-1);

	if ((ad = calloc(1, sizeof (ad_t))) == NULL)
		return (-1);

	ad->ref = 1;
	ad->partition = part;

	if (default_domain == NULL)
		default_domain = "";

	if ((ad->dflt_w2k_dom = strdup(default_domain)) == NULL)
		goto err;

	if (pthread_mutex_init(&ad->lock, NULL) != 0)
		goto err;

	*new_ad = ad;

	return (0);
err:
	if (ad->dflt_w2k_dom != NULL)
		free(ad->dflt_w2k_dom);
	free(ad);
	return (-1);
}


void
idmap_ad_free(ad_t **ad)
{
	ad_host_t *p;
	ad_host_t *prev;

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

	free((*ad)->dflt_w2k_dom);
	free(*ad);

	*ad = NULL;
}


static
int
idmap_open_conn(ad_host_t *adh, int timeoutsecs)
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

	atomic_inc_64(&adh->generation);

	/* Open and bind an LDAP connection */
	adh->ld = ldap_init(adh->host, adh->port);
	if (adh->ld == NULL) {
		idmapdlog(LOG_INFO, "ldap_init() to server "
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
	rc = ldap_sasl_interactive_bind_s(adh->ld, "" /* binddn */,
	    adh->saslmech, NULL, NULL, adh->saslflags, &idmap_saslcallback,
	    NULL);

	if (rc != LDAP_SUCCESS) {
		(void) ldap_unbind(adh->ld);
		adh->ld = NULL;
		idmapdlog(LOG_INFO, "ldap_sasl_interactive_bind_s() to server "
		    "%s port %d failed. (%s)", adh->host, adh->port,
		    ldap_err2string(rc));
	}

	idmapdlog(LOG_DEBUG, "Using global catalog server %s:%d",
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
ad_host_t *
idmap_get_conn(ad_t *ad)
{
	ad_host_t	*adh = NULL;
	int		tries;
	int		dscount = 0;
	int		timeoutsecs = IDMAPD_LDAP_OPEN_TIMEOUT;

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
		if (adh != NULL && adh->ld != NULL && !adh->dead)
			break;
		if (adh == NULL || (adh = adh->next) == NULL)
			adh = host_head;
		if (adh->owner == ad)
			break;
	}

	ad->last_adh = adh;
	(void) pthread_mutex_unlock(&adhostlock);


	/* Found suitable DS, open it if not already opened */
	if (idmap_open_conn(adh, timeoutsecs))
		return (adh);

	tries--;

	if ((tries % dscount) == 0)
		timeoutsecs *= 2;

	if (tries > 0)
		goto retry;

out:
	idmapdlog(LOG_NOTICE, "Couldn't open an LDAP connection to any global "
	    "catalog server!");

	return (NULL);
}

static
void
idmap_release_conn(ad_host_t *adh)
{
	(void) pthread_mutex_lock(&adh->lock);
	if (atomic_dec_32_nv(&adh->ref) == 0)
		adh->idletime = time(NULL);
	(void) pthread_mutex_unlock(&adh->lock);
}

/*
 * Take ad_host_config_t information, create a ad_host_t,
 * populate it and add it to the list of hosts.
 */

int
idmap_add_ds(ad_t *ad, const char *host, int port)
{
	ad_host_t	*p;
	ad_host_t	*new = NULL;
	int		ret = -1;

	if (port == 0)
		port = (int)ad->partition;

	(void) pthread_mutex_lock(&adhostlock);
	for (p = host_head; p != NULL; p = p->next) {
		if (p->owner != ad)
			continue;

		if (strcmp(host, p->host) == 0 && p->port == port) {
			/* already added */
			ret = 0;
			goto err;
		}
	}

	/* add new entry */
	new = (ad_host_t *)calloc(1, sizeof (ad_host_t));
	if (new == NULL)
		goto err;
	new->owner = ad;
	new->port = port;
	new->dead = 0;
	if ((new->host = strdup(host)) == NULL)
		goto err;

	/* default to SASL GSSAPI only for now */
	new->saslflags = LDAP_SASL_INTERACTIVE;
	new->saslmech = "GSSAPI";

	if ((ret = pthread_mutex_init(&new->lock, NULL)) != 0) {
		free(new->host);
		new->host = NULL;
		errno = ret;
		ret = -1;
		goto err;
	}

	/* link in */
	new->next = host_head;
	host_head = new;

	/* Start reaper if it doesn't exist */
	if (reaperid == 0)
		(void) pthread_create(&reaperid, NULL,
		    (void *(*)(void *))adreaper, (void *)NULL);

err:
	(void) pthread_mutex_unlock(&adhostlock);

	if (ret != 0 && new != NULL) {
		if (new->host != NULL) {
			(void) pthread_mutex_destroy(&new->lock);
			free(new->host);
		}
		free(new);
	}

	return (ret);
}

/*
 * Free a DS configuration.
 * Caller must lock the adhostlock mutex
 */
static void
delete_ds(ad_t *ad, const char *host, int port)
{
	ad_host_t	**p, *q;

	for (p = &host_head; *p != NULL; p = &((*p)->next)) {
		if ((*p)->owner != ad || strcmp(host, (*p)->host) != 0 ||
		    (*p)->port != port)
			continue;
		/* found */
		if ((*p)->ref > 0)
			break;	/* still in use */

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
 * Convert a binary SID in a BerValue to a sid_t
 */
static
int
idmap_getsid(BerValue *bval, sid_t *sidp)
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
 * Convert a sid_t to S-1-...
 */
static
char *
idmap_sid2txt(sid_t *sidp)
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
 * Convert a sid_t to on-the-wire encoding
 */
static
int
idmap_sid2binsid(sid_t *sid, uchar_t *binsid, int binsidlen)
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
static
int
idmap_txtsid2hexbinsid(const char *txt, const rid_t *rid,
	char *hexbinsid, int hexbinsidlen)
{
	sid_t		sid = { 0 };
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
	    sid.sub_authority_count > SID_MAX_SUB_AUTHORITIES)
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
	(void) idmap_sid2binsid(&sid, binsid, j);

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
convert_bval2sid(BerValue *bval, rid_t *rid)
{
	sid_t	sid;

	if (idmap_getsid(bval, &sid) < 0)
		return (NULL);

	/*
	 * If desired and if the SID is what should be a domain/computer
	 * user or group SID (i.e., S-1-5-w-x-y-z-<user/group RID>) then
	 * save the last RID and truncate the SID
	 */
	if (rid != NULL && sid.authority == 5 && sid.sub_authority_count == 5)
		*rid = sid.sub_authorities[--sid.sub_authority_count];
	return (idmap_sid2txt(&sid));
}


idmap_retcode
idmap_lookup_batch_start(ad_t *ad, int nqueries, idmap_query_state_t **state)
{
	idmap_query_state_t *new_state;
	ad_host_t	*adh = NULL;

	*state = NULL;

	if (ad == NULL)
		return (IDMAP_ERR_INTERNAL);

	adh = idmap_get_conn(ad);
	if (adh == NULL)
		return (IDMAP_ERR_RETRIABLE_NET_ERR);

	new_state = calloc(1, sizeof (idmap_query_state_t) +
	    (nqueries - 1) * sizeof (idmap_q_t));

	if (new_state == NULL)
		return (IDMAP_ERR_MEMORY);

	new_state->ref_cnt = 1;
	new_state->qadh = adh;
	new_state->qcount = nqueries;
	new_state->qadh_gen = adh->generation;
	/* should be -1, but the atomic routines want unsigned */
	new_state->qlastsent = 0;
	(void) pthread_cond_init(&new_state->cv, NULL);

	(void) pthread_mutex_lock(&qstatelock);
	new_state->next = qstatehead;
	qstatehead = new_state;
	(void) pthread_mutex_unlock(&qstatelock);

	*state = new_state;

	return (IDMAP_SUCCESS);
}

/*
 * Set unixuser_attr and unixgroup_attr for AD-based name mapping
 */
void
idmap_lookup_batch_set_unixattr(idmap_query_state_t *state,
		const char *unixuser_attr, const char *unixgroup_attr)
{
	state->ad_unixuser_attr = unixuser_attr;
	state->ad_unixgroup_attr = unixgroup_attr;
}

/*
 * Find the idmap_query_state_t to which a given LDAP result msgid on a
 * given connection belongs. This routine increaments the reference count
 * so that the object can not be freed. idmap_lookup_unlock_batch()
 * must be called to decreament the reference count.
 */
static
int
idmap_msgid2query(ad_host_t *adh, int msgid,
	idmap_query_state_t **state, int *qid)
{
	idmap_query_state_t *p;
	int		    i;

	(void) pthread_mutex_lock(&qstatelock);
	for (p = qstatehead; p != NULL; p = p->next) {
		if (p->qadh != adh || adh->generation != p->qadh_gen)
			continue;
		for (i = 0; i < p->qcount; i++) {
			if ((p->queries[i]).msgid == msgid) {
				p->ref_cnt++;
				*state = p;
				*qid = i;
				(void) pthread_mutex_unlock(&qstatelock);
				return (1);
			}
		}
	}
	(void) pthread_mutex_unlock(&qstatelock);
	return (0);
}

/*
 * Take parsed attribute values from a search result entry and check if
 * it is the result that was desired and, if so, set the result fields
 * of the given idmap_q_t.
 *
 * Frees the unused char * values.
 */
static
void
idmap_setqresults(idmap_q_t *q, char *san, char *dn, const char *attr,
	char *sid, rid_t rid, int sid_type, char *unixname)
{
	char *domain;
	int err1, err2;

	assert(dn != NULL);

	if ((domain = dn2dns(dn)) == NULL)
		goto out;

	if (q->ecanonname != NULL && san != NULL) {
		/* Check that this is the canonname that we were looking for */
		if (u8_strcmp(q->ecanonname, san, 0,
		    U8_STRCMP_CI_LOWER, /* no normalization, for now */
		    U8_UNICODE_LATEST, &err1) != 0 || err1 != 0)
			goto out;
	}

	if (q->edomain != NULL) {
		/* Check that this is the domain that we were looking for */
		if (u8_strcmp(q->edomain, domain, 0, U8_STRCMP_CI_LOWER,
		    U8_UNICODE_LATEST, &err2) != 0 || err2 != 0)
			goto out;
	}

	/* Copy the DN and attr and value */
	if (q->dn != NULL)
		*q->dn = strdup(dn);

	if (q->attr != NULL && attr != NULL)
		*q->attr = strdup(attr);

	if (q->value != NULL && unixname != NULL)
		*q->value = strdup(unixname);

	/* Set results */
	if (q->sid) {
		*q->sid = sid;
		sid = NULL;
	}
	if (q->rid)
		*q->rid = rid;
	if (q->sid_type)
		*q->sid_type = sid_type;
	if (q->unixname) {
		*q->unixname = unixname;
		unixname = NULL;
	}
	if (q->domain != NULL) {
		*q->domain = domain;
		domain = NULL;
	}
	if (q->canonname != NULL) {
		*q->canonname = san;
		san = NULL;
	}

	/* Always have q->rc; idmap_extract_object() asserts this */
	*q->rc = IDMAP_SUCCESS;

out:
	/* Free unused attribute values */
	free(san);
	free(sid);
	free(domain);
	free(unixname);
}

/*
 * The following three functions extract objectSid, sAMAccountName and
 * objectClass attribute values and, in the case of objectSid and
 * objectClass, parse them.
 *
 * idmap_setqresults() takes care of dealing with the result entry's DN.
 */

/*
 * Return a NUL-terminated stringified SID from the value of an
 * objectSid attribute and put the last RID in *rid.
 */
static
char *
idmap_bv_objsid2sidstr(BerValue **bvalues, rid_t *rid)
{
	char *sid;

	if (bvalues == NULL)
		return (NULL);
	/* objectSid is single valued */
	if ((sid = convert_bval2sid(bvalues[0], rid)) == NULL)
		return (NULL);
	return (sid);
}

/*
 * Return a NUL-terminated string from the value of a sAMAccountName
 * or unixname attribute.
 */
static
char *
idmap_bv_name2str(BerValue **bvalues)
{
	char *s;

	if (bvalues == NULL || bvalues[0] == NULL ||
	    bvalues[0]->bv_val == NULL)
		return (NULL);

	if ((s = malloc(bvalues[0]->bv_len + 1)) == NULL)
		return (NULL);

	(void) snprintf(s, bvalues[0]->bv_len + 1, "%.*s", bvalues[0]->bv_len,
	    bvalues[0]->bv_val);

	return (s);
}


#define	BVAL_CASEEQ(bv, str) \
		(((*(bv))->bv_len == (sizeof (str) - 1)) && \
		    strncasecmp((*(bv))->bv_val, str, (*(bv))->bv_len) == 0)

/*
 * Extract the class of the result entry.  Returns 1 on success, 0 on
 * failure.
 */
static
int
idmap_bv_objclass2sidtype(BerValue **bvalues, int *sid_type)
{
	BerValue	**cbval;

	*sid_type = _IDMAP_T_OTHER;
	if (bvalues == NULL)
		return (0);

	/*
	 * We iterate over all the values because computer is a
	 * sub-class of user.
	 */
	for (cbval = bvalues; *cbval != NULL; cbval++) {
		if (BVAL_CASEEQ(cbval, "Computer")) {
			*sid_type = _IDMAP_T_COMPUTER;
			break;
		} else if (BVAL_CASEEQ(cbval, "Group")) {
			*sid_type = _IDMAP_T_GROUP;
			break;
		} else if (BVAL_CASEEQ(cbval, "USER")) {
			*sid_type = _IDMAP_T_USER;
			/* Continue looping -- this may be a computer yet */
		}
		/*
		 * "else if (*sid_type = _IDMAP_T_USER)" then this is a
		 * new sub-class of user -- what to do with it??
		 */
	}

	return (1);
}

/*
 * Handle a given search result entry
 */
static
void
idmap_extract_object(idmap_query_state_t *state, int qid, LDAPMessage *res)
{
	BerElement		*ber = NULL;
	BerValue		**bvalues;
	ad_host_t		*adh;
	idmap_q_t		*q;
	char			*attr;
	const char		*unixuser_attr = NULL;
	const char		*unixgroup_attr = NULL;
	char			*unixuser = NULL;
	char			*unixgroup = NULL;
	char			*dn = NULL;
	char			*san = NULL;
	char			*sid = NULL;
	rid_t			rid = 0;
	int			sid_type = _IDMAP_T_UNDEF;
	int			has_class, has_san, has_sid;
	int			has_unixuser, has_unixgroup;

	adh = state->qadh;

	(void) pthread_mutex_lock(&adh->lock);

	q = &(state->queries[qid]);

	assert(q->rc != NULL);

	if (*q->rc == IDMAP_SUCCESS || adh->dead ||
	    (dn = ldap_get_dn(adh->ld, res)) == NULL) {
		(void) pthread_mutex_unlock(&adh->lock);
		return;
	}

	assert(q->domain == NULL || *q->domain == NULL);

	/*
	 * If the caller has requested unixname then determine the
	 * AD attribute name that will have the unixname.
	 */
	if (q->unixname != NULL) {
		if (q->eunixtype == _IDMAP_T_USER)
			unixuser_attr = state->ad_unixuser_attr;
		else if (q->eunixtype == _IDMAP_T_GROUP)
			unixgroup_attr = state->ad_unixgroup_attr;
		else if (q->eunixtype == _IDMAP_T_UNDEF) {
			/*
			 * This is the case where we don't know
			 * before hand whether we need unixuser
			 * or unixgroup. This will be determined
			 * by the "sid_type" (i.e whether the given
			 * winname is user or group). If sid_type
			 * turns out to be user we will return
			 * unixuser (if found) and if it is a group
			 * we will return unixgroup (if found). We
			 * lookup for both ad_unixuser_attr and
			 * ad_unixgroup_attr and discard one of them
			 * after we know the "sidtype". This
			 * supports the following type of lookups.
			 *
			 * Example:
			 *   $idmap show -c winname:foo
			 * In the above example, idmap will
			 * return uid if winname is winuser
			 * and gid if winname is wingroup.
			 */
			unixuser_attr = state->ad_unixuser_attr;
			unixgroup_attr = state->ad_unixgroup_attr;
		}
	}

	has_class = has_san = has_sid = has_unixuser = has_unixgroup = 0;
	for (attr = ldap_first_attribute(adh->ld, res, &ber); attr != NULL;
	    attr = ldap_next_attribute(adh->ld, res, ber)) {
		bvalues = NULL;	/* for memory management below */

		/*
		 * If this is an attribute we are looking for and
		 * haven't seen it yet, parse it
		 */
		if (q->sid != NULL && !has_sid &&
		    strcasecmp(attr, OBJSID) == 0) {
			bvalues = ldap_get_values_len(adh->ld, res, attr);
			sid = idmap_bv_objsid2sidstr(bvalues, &rid);
			has_sid = (sid != NULL);
		} else if (!has_san && strcasecmp(attr, SAN) == 0) {
			bvalues = ldap_get_values_len(adh->ld, res, attr);
			san = idmap_bv_name2str(bvalues);
			has_san = (san != NULL);
		} else if (!has_class && strcasecmp(attr, OBJCLASS) == 0) {
			bvalues = ldap_get_values_len(adh->ld, res, attr);
			has_class = idmap_bv_objclass2sidtype(bvalues,
			    &sid_type);
			if (has_class && q->unixname != NULL &&
			    q->eunixtype == _IDMAP_T_UNDEF) {
				/*
				 * This is the case where we didn't
				 * know whether we wanted unixuser or
				 * unixgroup as described above.
				 * Now since we know the "sid_type"
				 * we discard the unwanted value
				 * if it was retrieved before we
				 * got here.
				 */
				if (sid_type == _IDMAP_T_USER) {
					free(unixgroup);
					unixgroup_attr = unixgroup = NULL;
				} else if (sid_type == _IDMAP_T_GROUP) {
					free(unixuser);
					unixuser_attr = unixuser = NULL;
				} else {
					free(unixuser);
					free(unixgroup);
					unixuser_attr = unixuser = NULL;
					unixgroup_attr = unixgroup = NULL;
				}
			}
		} else if (!has_unixuser && unixuser_attr != NULL &&
		    strcasecmp(attr, unixuser_attr) == 0) {
			bvalues = ldap_get_values_len(adh->ld, res, attr);
			unixuser = idmap_bv_name2str(bvalues);
			has_unixuser = (unixuser != NULL);

		} else if (!has_unixgroup && unixgroup_attr != NULL &&
		    strcasecmp(attr, unixgroup_attr) == 0) {
			bvalues = ldap_get_values_len(adh->ld, res, attr);
			unixgroup = idmap_bv_name2str(bvalues);
			has_unixgroup = (unixgroup != NULL);
		}

		if (bvalues != NULL)
			ldap_value_free_len(bvalues);
		ldap_memfree(attr);

		if (has_class && has_san &&
		    (q->sid == NULL || has_sid) &&
		    (unixuser_attr == NULL || has_unixuser) &&
		    (unixgroup_attr == NULL || has_unixgroup)) {
			/* Got what we need */
			break;
		}
	}

	if (!has_class) {
		/*
		 * Didn't find objectclass. Something's wrong with our
		 * AD data.
		 */
		free(san);
		free(sid);
		free(unixuser);
		free(unixgroup);
	} else {
		/*
		 * Either we got what we needed and came out of the loop
		 * early OR we completed the loop in which case we didn't
		 * find some attributes that we were looking for. In either
		 * case set the result with what we got.
		 */
		idmap_setqresults(q, san, dn,
		    (unixuser != NULL) ? unixuser_attr : unixgroup_attr,
		    sid, rid, sid_type,
		    (unixuser != NULL) ? unixuser : unixgroup);
	}

	(void) pthread_mutex_unlock(&adh->lock);

	if (ber != NULL)
		ber_free(ber, 0);

	ldap_memfree(dn);
}

/*
 * Try to get a result; if there is one, find the corresponding
 * idmap_q_t and process the result.
 */
static
int
idmap_get_adobject_batch(ad_host_t *adh, struct timeval *timeout)
{
	idmap_query_state_t	*query_state;
	LDAPMessage		*res = NULL;
	int			rc, ret, msgid, qid;

	(void) pthread_mutex_lock(&adh->lock);
	if (adh->dead) {
		(void) pthread_mutex_unlock(&adh->lock);
		return (-1);
	}

	/* Get one result */
	rc = ldap_result(adh->ld, LDAP_RES_ANY, 0,
	    timeout, &res);
	if ((timeout != NULL && timeout->tv_sec > 0 && rc == LDAP_SUCCESS) ||
	    rc < 0)
		adh->dead = 1;
	(void) pthread_mutex_unlock(&adh->lock);

	if (adh->dead)
		return (-1);

	switch (rc) {
	case LDAP_RES_SEARCH_RESULT:
		/* We have all the LDAP replies for some search... */
		msgid = ldap_msgid(res);
		if (idmap_msgid2query(adh, msgid,
		    &query_state, &qid)) {
			/* ...so we can decrement qinflight */
			atomic_dec_32(&query_state->qinflight);
			/* We've seen all the result entries we'll see */
			if (*query_state->queries[qid].rc != IDMAP_SUCCESS)
				*query_state->queries[qid].rc =
				    IDMAP_ERR_NOTFOUND;
			idmap_lookup_unlock_batch(&query_state);
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
		(void) ldap_msgfree(res);
		ret = 0;
		break;
	case LDAP_RES_SEARCH_ENTRY:
		/* Got a result */
		msgid = ldap_msgid(res);
		if (idmap_msgid2query(adh, msgid,
		    &query_state, &qid)) {
			idmap_extract_object(query_state, qid, res);
			/* we saw at least one result */
			idmap_lookup_unlock_batch(&query_state);
		}
		(void) ldap_msgfree(res);
		ret = 0;
		break;
	default:
		/* timeout or error; treat the same */
		ret = -1;
		break;
	}

	return (ret);
}

/*
 * This routine decreament the reference count of the
 * idmap_query_state_t
 */
static void
idmap_lookup_unlock_batch(idmap_query_state_t **state)
{
	/*
	 * Decrement reference count with qstatelock locked
	 */
	(void) pthread_mutex_lock(&qstatelock);
	(*state)->ref_cnt--;
	/*
	 * If there are no references wakup the allocating thread
	 */
	if ((*state)->ref_cnt == 0)
		(void) pthread_cond_signal(&(*state)->cv);
	(void) pthread_mutex_unlock(&qstatelock);
	*state = NULL;
}

static
void
idmap_cleanup_batch(idmap_query_state_t *batch)
{
	int i;

	for (i = 0; i < batch->qcount; i++) {
		if (batch->queries[i].ecanonname != NULL)
			free(batch->queries[i].ecanonname);
		batch->queries[i].ecanonname = NULL;
		if (batch->queries[i].edomain != NULL)
			free(batch->queries[i].edomain);
		batch->queries[i].edomain = NULL;
	}
}

/*
 * This routine frees the idmap_query_state_t structure
 * If the reference count is greater than 1 it waits
 * for the other threads to finish using it.
 */
void
idmap_lookup_release_batch(idmap_query_state_t **state)
{
	idmap_query_state_t **p;

	/*
	 * Decrement reference count with qstatelock locked
	 * and wait for reference count to get to zero
	 */
	(void) pthread_mutex_lock(&qstatelock);
	(*state)->ref_cnt--;
	while ((*state)->ref_cnt > 0) {
		(void) pthread_cond_wait(&(*state)->cv, &qstatelock);
	}

	/* Remove this state struct from the list of state structs */
	for (p = &qstatehead; *p != NULL; p = &(*p)->next) {
		if (*p == (*state)) {
			*p = (*state)->next;
			break;
		}
	}

	idmap_cleanup_batch(*state);

	(void) pthread_mutex_unlock(&qstatelock);

	(void) pthread_cond_destroy(&(*state)->cv);

	idmap_release_conn((*state)->qadh);

	free(*state);
	*state = NULL;
}

idmap_retcode
idmap_lookup_batch_end(idmap_query_state_t **state)
{
	int		    rc = LDAP_SUCCESS;
	idmap_retcode	    retcode = IDMAP_SUCCESS;
	struct timeval	    timeout;

	(*state)->qdead = 1;
	timeout.tv_sec = IDMAPD_SEARCH_TIMEOUT;
	timeout.tv_usec = 0;

	/* Process results until done or until timeout, if given */
	while ((*state)->qinflight > 0) {
		if ((rc = idmap_get_adobject_batch((*state)->qadh,
		    &timeout)) != 0)
			break;
	}

	if (rc != 0)
		retcode = IDMAP_ERR_RETRIABLE_NET_ERR;

	idmap_lookup_release_batch(state);

	return (retcode);
}

/*
 * Send one prepared search, queue up msgid, process what results are
 * available
 */
static
idmap_retcode
idmap_batch_add1(idmap_query_state_t *state, const char *filter,
	char *ecanonname, char *edomain, int eunixtype,
	char **dn, char **attr, char **value,
	char **canonname, char **dname,
	char **sid, rid_t *rid, int *sid_type, char **unixname,
	idmap_retcode *rc)
{
	idmap_retcode	retcode = IDMAP_SUCCESS;
	int		lrc, qid, i;
	struct timeval	tv;
	idmap_q_t	*q;
	static char	*attrs[] = {
		SAN,
		OBJSID,
		OBJCLASS,
		NULL,	/* placeholder for unixname attr */
		NULL,	/* placeholder for unixname attr */
		NULL
	};

	qid = atomic_inc_32_nv(&state->qlastsent) - 1;

	q = &(state->queries[qid]);

	/*
	 * Remember the expected canonname so we can check the results
	 * agains it
	 */
	q->ecanonname = ecanonname;
	q->edomain = edomain;
	q->eunixtype = eunixtype;

	/* Remember where to put the results */
	q->canonname = canonname;
	q->sid = sid;
	q->domain = dname;
	q->rid = rid;
	q->sid_type = sid_type;
	q->rc = rc;
	q->unixname = unixname;
	q->dn = dn;
	q->attr = attr;
	q->value = value;

	/* Add unixuser/unixgroup attribute names to the attrs list */
	if (unixname != NULL) {
		i = 3;
		if (eunixtype != _IDMAP_T_GROUP &&
		    state->ad_unixuser_attr != NULL)
			attrs[i++] = (char *)state->ad_unixuser_attr;
		if (eunixtype != _IDMAP_T_USER &&
		    state->ad_unixgroup_attr != NULL)
			attrs[i] = (char *)state->ad_unixgroup_attr;
	}

	/*
	 * Provide sane defaults for the results in case we never hear
	 * back from the DS before closing the connection.
	 *
	 * In particular we default the result to indicate a retriable
	 * error.  The first complete matching result entry will cause
	 * this to be set to IDMAP_SUCCESS, and the end of the results
	 * for this search will cause this to indicate "not found" if no
	 * result entries arrived or no complete ones matched the lookup
	 * we were doing.
	 */
	*rc = IDMAP_ERR_RETRIABLE_NET_ERR;
	if (sid_type != NULL)
		*sid_type = _IDMAP_T_OTHER;
	if (sid != NULL)
		*sid = NULL;
	if (canonname != NULL)
		*canonname = NULL;
	if (dname != NULL)
		*dname = NULL;
	if (rid != NULL)
		*rid = 0;
	if (dn != NULL)
		*dn = NULL;
	if (attr != NULL)
		*attr = NULL;
	if (value != NULL)
		*value = NULL;

	/* Send this lookup, don't wait for a result here */
	(void) pthread_mutex_lock(&state->qadh->lock);

	if (!state->qadh->dead) {
		state->qadh->idletime = time(NULL);
		lrc = ldap_search_ext(state->qadh->ld, "",
		    LDAP_SCOPE_SUBTREE, filter, attrs, 0, NULL, NULL,
		    NULL, -1, &q->msgid);
		if (lrc == LDAP_BUSY || lrc == LDAP_UNAVAILABLE ||
		    lrc == LDAP_CONNECT_ERROR || lrc == LDAP_SERVER_DOWN ||
		    lrc == LDAP_UNWILLING_TO_PERFORM) {
			retcode = IDMAP_ERR_RETRIABLE_NET_ERR;
			state->qadh->dead = 1;
		} else if (lrc != LDAP_SUCCESS) {
			retcode = IDMAP_ERR_OTHER;
			state->qadh->dead = 1;
		}
	}
	(void) pthread_mutex_unlock(&state->qadh->lock);

	if (state->qadh->dead)
		return (retcode);

	atomic_inc_32(&state->qinflight);

	/*
	 * Reap as many requests as we can _without_ waiting
	 *
	 * We do this to prevent any possible TCP socket buffer
	 * starvation deadlocks.
	 */
	(void) memset(&tv, 0, sizeof (tv));
	while (idmap_get_adobject_batch(state->qadh, &tv) == 0)
		;

	return (IDMAP_SUCCESS);
}

idmap_retcode
idmap_name2sid_batch_add1(idmap_query_state_t *state,
	const char *name, const char *dname, int eunixtype,
	char **dn, char **attr, char **value,
	char **canonname, char **sid, rid_t *rid,
	int *sid_type, char **unixname, idmap_retcode *rc)
{
	idmap_retcode	retcode;
	int		len, samAcctNameLen;
	char		*filter = NULL;
	char		*ecanonname, *edomain; /* expected canonname */

	/*
	 * Strategy: search the global catalog for user/group by
	 * sAMAccountName = user/groupname with "" as the base DN and by
	 * userPrincipalName = user/groupname@domain.  The result
	 * entries will be checked to conform to the name and domain
	 * name given here.  The DN, sAMAccountName, userPrincipalName,
	 * objectSid and objectClass of the result entries are all we
	 * need to figure out which entries match the lookup, the SID of
	 * the user/group and whether it is a user or a group.
	 */

	/*
	 * We need the name and the domain name separately and as
	 * name@domain.  We also allow the domain to be provided
	 * separately.
	 */
	samAcctNameLen = strlen(name);

	if ((ecanonname = strdup(name)) == NULL)
		return (IDMAP_ERR_MEMORY);

	if (dname == NULL || *dname == '\0') {
		if ((dname = strchr(name, '@')) != NULL) {
			/* 'name' is qualified with a domain name */
			if ((edomain = strdup(dname + 1)) == NULL) {
				free(ecanonname);
				return (IDMAP_ERR_MEMORY);
			}
			*strchr(ecanonname, '@') = '\0';
		} else {
			/*
			 * 'name' not qualified and dname not given
			 *
			 * Note: ad->dflt_w2k_dom cannot be NULL - see
			 * idmap_ad_alloc()
			 */
			if (*state->qadh->owner->dflt_w2k_dom == '\0') {
				free(ecanonname);
				return (IDMAP_ERR_DOMAIN);
			}
			edomain = strdup(state->qadh->owner->dflt_w2k_dom);
			if (edomain == NULL) {
				free(ecanonname);
				return (IDMAP_ERR_MEMORY);
			}
		}
	} else {
		if ((edomain = strdup(dname)) == NULL) {
			free(ecanonname);
			return (IDMAP_ERR_MEMORY);
		}
	}

	/* Assemble filter */
	len = snprintf(NULL, 0, SANFILTER, samAcctNameLen, name) + 1;
	if ((filter = (char *)malloc(len)) == NULL) {
		free(ecanonname);
		return (IDMAP_ERR_MEMORY);
	}
	(void) snprintf(filter, len, SANFILTER, samAcctNameLen, name);

	retcode = idmap_batch_add1(state, filter, ecanonname, edomain,
	    eunixtype, dn, attr, value, canonname, NULL, sid, rid, sid_type,
	    unixname, rc);

	free(filter);

	return (retcode);
}

idmap_retcode
idmap_sid2name_batch_add1(idmap_query_state_t *state,
	const char *sid, const rid_t *rid, int eunixtype,
	char **dn, char **attr, char **value,
	char **name, char **dname, int *sid_type,
	char **unixname, idmap_retcode *rc)
{
	idmap_retcode	retcode;
	int		flen, ret;
	char		*filter = NULL;
	char		cbinsid[MAXHEXBINSID + 1];

	/*
	 * Strategy: search [the global catalog] for user/group by
	 * objectSid = SID with empty base DN.  The DN, sAMAccountName
	 * and objectClass of the result are all we need to figure out
	 * the name of the SID and whether it is a user, a group or a
	 * computer.
	 */

	ret = idmap_txtsid2hexbinsid(sid, rid, &cbinsid[0], sizeof (cbinsid));
	if (ret != 0)
		return (IDMAP_ERR_SID);

	/* Assemble filter */
	flen = snprintf(NULL, 0, OBJSIDFILTER, cbinsid) + 1;
	if ((filter = (char *)malloc(flen)) == NULL)
		return (IDMAP_ERR_MEMORY);
	(void) snprintf(filter, flen, OBJSIDFILTER, cbinsid);

	retcode = idmap_batch_add1(state, filter, NULL, NULL, eunixtype,
	    dn, attr, value, name, dname, NULL, NULL, sid_type, unixname, rc);

	free(filter);

	return (retcode);
}

idmap_retcode
idmap_unixname2sid_batch_add1(idmap_query_state_t *state,
	const char *unixname, int is_user, int is_wuser,
	char **dn, char **attr, char **value,
	char **sid, rid_t *rid, char **name,
	char **dname, int *sid_type, idmap_retcode *rc)
{
	idmap_retcode	retcode;
	int		len, ulen;
	char		*filter = NULL;
	const char	*attrname = NULL;

	/* Get unixuser or unixgroup AD attribute name */
	attrname = (is_user) ?
	    state->ad_unixuser_attr : state->ad_unixgroup_attr;
	if (attrname == NULL)
		return (IDMAP_ERR_NOTFOUND);

	/*  Assemble filter */
	ulen = strlen(unixname);
	len = snprintf(NULL, 0, "(&(objectclass=%s)(%s=%.*s))",
	    is_wuser ? "user" : "group", attrname, ulen, unixname) + 1;
	if ((filter = (char *)malloc(len)) == NULL)
		return (IDMAP_ERR_MEMORY);
	(void) snprintf(filter, len, "(&(objectclass=%s)(%s=%.*s))",
	    is_wuser ? "user" : "group", attrname, ulen, unixname);

	retcode = idmap_batch_add1(state, filter, NULL, NULL,
	    _IDMAP_T_UNDEF, dn, NULL, NULL, name, dname, sid, rid, sid_type,
	    NULL, rc);

	if (retcode == IDMAP_SUCCESS && attr != NULL) {
		if ((*attr = strdup(attrname)) == NULL)
			retcode = IDMAP_ERR_MEMORY;
	}

	if (retcode == IDMAP_SUCCESS && value != NULL) {
		if (ulen > 0) {
			if ((*value = strdup(unixname)) == NULL)
				retcode = IDMAP_ERR_MEMORY;
		}
		else
			*value = NULL;
	}

	free(filter);

	return (retcode);
}
