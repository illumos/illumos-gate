/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * mech_krb5/krb5/rcache/rc_mem.c
 *
 * This file of the Kerberos V5 software is derived from public-domain code
 * contributed by Daniel J. Bernstein, <brnstnd@acf10.nyu.edu>.
 */

/*
 * Solaris Kerberos:
 * An implementation for the memory only (mem) replay cache type.
 */
#include "rc_common.h"
#include "rc_mem.h"

/*
 * We want the replay cache to hang around for the entire life span of the
 * process, regardless if the auth_context or acceptor_cred handles are
 * destroyed.
 */
struct global_rcache grcache = {K5_MUTEX_PARTIAL_INITIALIZER, NULL};

/*
 * of course, list is backwards
 * hash could be forwards since we have to search on match, but naaaah
 */
static int
rc_store(krb5_context context, krb5_rcache id, krb5_donot_replay *rep)
{
	struct mem_data *t = (struct mem_data *)id->data;
	int rephash;
	struct authlist *ta, *pta = NULL, *head;
	krb5_int32 time;

	rephash = hash(rep, t->hsize);

	/* Solaris: calling krb_timeofday() here, once for better perf. */
	krb5_timeofday(context, &time);

	/*
	 * Solaris: calling alive() on rep since it doesn't make sense to store
	 * an expired replay.
	 */
	if (alive(context, rep, t->lifespan, time) == CMP_EXPIRED)
		return (CMP_EXPIRED);

	for (ta = t->h[rephash]; ta; ta = ta->nh) {
		switch (cmp(&ta->rep, rep)) {
			case CMP_REPLAY:
				return (CMP_REPLAY);
			case CMP_HOHUM:
				if (alive(context, &ta->rep, t->lifespan, time)
				    == CMP_EXPIRED) {
					free(ta->rep.client);
					free(ta->rep.server);
					if (pta) {
						pta->nh = ta->nh;
						free(ta);
						ta = pta;
					} else {
						head = t->h[rephash];
						t->h[rephash] = ta->nh;
						free(head);
					}
					continue;
				}
		}
		pta = ta;
	}

	if (!(ta = (struct authlist *)malloc(sizeof (struct authlist))))
		return (CMP_MALLOC);
	ta->rep = *rep;
	if (!(ta->rep.client = strdup(rep->client))) {
		free(ta);
		return (CMP_MALLOC);
	}
	if (!(ta->rep.server = strdup(rep->server))) {
		free(ta->rep.client);
		free(ta);
		return (CMP_MALLOC);
	}
	ta->nh = t->h[rephash];
	t->h[rephash] = ta;

	return (CMP_HOHUM);
}

/*ARGSUSED*/
char *KRB5_CALLCONV
krb5_rc_mem_get_name(krb5_context context, krb5_rcache id)
{
	return (((struct mem_data *)(id->data))->name);
}

/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_rc_mem_get_span(
	krb5_context context,
	krb5_rcache id,
	krb5_deltat *lifespan)
{
    krb5_error_code err;
    struct mem_data *t;

    err = k5_mutex_lock(&id->lock);
    if (err)
	return err;

    if (err = k5_mutex_lock(&grcache.lock)) {
	k5_mutex_unlock(&id->lock);
	return (err);
    }
    t = (struct mem_data *) id->data;
    *lifespan = t->lifespan;
    k5_mutex_unlock(&grcache.lock);

    k5_mutex_unlock(&id->lock);
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_rc_mem_init_locked(krb5_context context, krb5_rcache id, krb5_deltat lifespan)
{
	struct mem_data *t = (struct mem_data *)id->data;
	krb5_error_code retval;

	t->lifespan = lifespan ? lifespan : context->clockskew;
	/* default to clockskew from the context */
	return (0);
}

krb5_error_code KRB5_CALLCONV
krb5_rc_mem_init(krb5_context context, krb5_rcache id, krb5_deltat lifespan)
{
    krb5_error_code retval;

    retval = k5_mutex_lock(&id->lock);
    if (retval)
	return retval;
    retval = k5_mutex_lock(&grcache.lock);
    if (retval) {
	k5_mutex_unlock(&id->lock);
	return (retval);
    }

    retval = krb5_rc_mem_init_locked(context, id, lifespan);

    k5_mutex_unlock(&grcache.lock);
    k5_mutex_unlock(&id->lock);
    return retval;
}

/*
 * We want the replay cache to be persistent since we can't
 * read from a file to retrieve the rcache, so we must not free
 * here.  Just return success.
 */
krb5_error_code KRB5_CALLCONV
krb5_rc_mem_close(krb5_context context, krb5_rcache id)
{
	return (0);
}

krb5_error_code KRB5_CALLCONV
krb5_rc_mem_destroy(krb5_context context, krb5_rcache id)
{
	return (krb5_rc_mem_close(context, id));
}

/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_rc_mem_resolve(krb5_context context, krb5_rcache id, char *name)
{
	struct mem_data *t = 0;
	krb5_error_code retval;

	retval = k5_mutex_lock(&grcache.lock);
	if (retval)
		return (retval);

	/*
	 * If the global rcache has already been initialized through a prior
	 * call to this function then just set the rcache to point to it for
	 * any subsequent operations.
	 */
	if (grcache.data != NULL) {
		id->data = (krb5_pointer)grcache.data;
		k5_mutex_unlock(&grcache.lock);
		return (0);
	}
	/* allocate id? no */
	if (!(t = (struct mem_data *)malloc(sizeof (struct mem_data)))) {
		k5_mutex_unlock(&grcache.lock);
		return (KRB5_RC_MALLOC);
	}
	grcache.data = id->data = (krb5_pointer)t;
	memset(t, 0, sizeof (struct mem_data));
	if (name) {
		t->name = malloc(strlen(name)+1);
		if (!t->name) {
			retval = KRB5_RC_MALLOC;
			goto cleanup;
		}
		strcpy(t->name, name);
	} else
		t->name = 0;
	t->hsize = HASHSIZE; /* no need to store---it's memory-only */
	t->h = (struct authlist **)malloc(t->hsize*sizeof (struct authlist *));
	if (!t->h) {
		retval = KRB5_RC_MALLOC;
		goto cleanup;
	}
	memset(t->h, 0, t->hsize*sizeof (struct authlist *));
	k5_mutex_unlock(&grcache.lock);
	return (0);

cleanup:
	if (t) {
		if (t->name)
			krb5_xfree(t->name);
		if (t->h)
			krb5_xfree(t->h);
		krb5_xfree(t);
		grcache.data = NULL; 
		id->data = NULL;
	}
	k5_mutex_unlock(&grcache.lock);
	return (retval);
}

/*
 * Recovery (retrieval) of the replay cache occurred during
 * krb5_rc_resolve().  So we just return error here.
 */
krb5_error_code KRB5_CALLCONV
krb5_rc_mem_recover(krb5_context context, krb5_rcache id)
{
	/* SUNW14resync - No need for locking here, just returning RC_NOIO */
	return (KRB5_RC_NOIO);
}

krb5_error_code KRB5_CALLCONV
krb5_rc_mem_recover_or_init(krb5_context context, krb5_rcache id,
			    krb5_deltat lifespan)
{
    krb5_error_code retval;

    retval = krb5_rc_mem_recover(context, id); 
    if (retval)
	retval = krb5_rc_mem_init(context, id, lifespan);

    return retval;
}

krb5_error_code KRB5_CALLCONV
krb5_rc_mem_store(krb5_context context, krb5_rcache id, krb5_donot_replay *rep)
{
	krb5_error_code ret;

	ret = k5_mutex_lock(&id->lock);
	if (ret)
		return (ret);
	ret = k5_mutex_lock(&grcache.lock);
	if (ret) {
		k5_mutex_unlock(&id->lock);
		return (ret);
	}

	switch (rc_store(context, id, rep)) {
		case CMP_MALLOC:
			k5_mutex_unlock(&grcache.lock);
			k5_mutex_unlock(&id->lock);
			return (KRB5_RC_MALLOC);
		case CMP_REPLAY:
			k5_mutex_unlock(&grcache.lock);
			k5_mutex_unlock(&id->lock);
			return (KRB5KRB_AP_ERR_REPEAT);
		case CMP_EXPIRED:
			k5_mutex_unlock(&grcache.lock);
			k5_mutex_unlock(&id->lock);
			return (KRB5KRB_AP_ERR_SKEW);
		case CMP_HOHUM:
			break;
	}

	k5_mutex_unlock(&grcache.lock);
	k5_mutex_unlock(&id->lock);
	return (0);
}
