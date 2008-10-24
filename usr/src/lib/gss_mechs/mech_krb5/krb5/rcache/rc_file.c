/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * lib/krb5/rcache/rc_file.c
 *
 * This file of the Kerberos V5 software is derived from public-domain code
 * contributed by Daniel J. Bernstein, <brnstnd@acf10.nyu.edu>.
 *
 */


/*
 * An implementation for the default replay cache type.
 */
/* Solaris Kerberos */
#define FREE_RC(x) ((void) free((char *) (x)))
#include "rc_common.h"
#include "rc_file.h"

/*
 * Solaris: The NOIOSTUFF macro has been taken out for the Solaris version
 * of this module, because this has been split into a separate mem rcache.
 */

/* of course, list is backwards from file */
/* hash could be forwards since we have to search on match, but naaaah */

static int
rc_store(krb5_context context, krb5_rcache id, krb5_donot_replay *rep)
{
    struct file_data *t = (struct file_data *)id->data;
    int rephash;
    struct authlist *ta;
    krb5_int32 time;

    rephash = hash(rep, t->hsize);

    /* Solaris: calling krb_timeofday() here, once for better perf. */
    krb5_timeofday(context, &time);

    /* Solaris: calling alive() on rep since it doesn't make sense to store an
     * expired replay. 
     */
    if (alive(context, rep, t->lifespan, time) == CMP_EXPIRED){
	return CMP_EXPIRED;
    }

    for (ta = t->h[rephash]; ta; ta = ta->nh) {
	switch(cmp(&ta->rep, rep))
	{
	case CMP_REPLAY:
	    return CMP_REPLAY;
	case CMP_HOHUM:
	    if (alive(context, &ta->rep, t->lifespan, time) == CMP_EXPIRED)
		t->nummisses++;
	    else
		t->numhits++;
	    break;
	default:
	    ; /* wtf? */
	}
    }

    if (!(ta = (struct authlist *) malloc(sizeof(struct authlist))))
	return CMP_MALLOC;
    ta->rep = *rep;
    if (!(ta->rep.client = strdup(rep->client))) {
	FREE_RC(ta);
	return CMP_MALLOC;
    }
    if (!(ta->rep.server = strdup(rep->server))) {
	FREE_RC(ta->rep.client);
	FREE_RC(ta);
	return CMP_MALLOC;
    }
    ta->na = t->a; t->a = ta;
    ta->nh = t->h[rephash]; t->h[rephash] = ta;

    return CMP_HOHUM;
}

/*ARGSUSED*/
char * KRB5_CALLCONV
krb5_rc_file_get_name(krb5_context context, krb5_rcache id)
{
 return ((struct file_data *) (id->data))->name;
}

/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_rc_file_get_span(krb5_context context, krb5_rcache id,
		     krb5_deltat *lifespan)
{
    krb5_error_code err;
    struct file_data *t;

    err = k5_mutex_lock(&id->lock);
    if (err)
	return err;
    t = (struct file_data *) id->data;
    *lifespan = t->lifespan;
    k5_mutex_unlock(&id->lock);
    return 0;
}

static krb5_error_code KRB5_CALLCONV
krb5_rc_file_init_locked(krb5_context context, krb5_rcache id, krb5_deltat lifespan)
{
    struct file_data *t = (struct file_data *)id->data;
    krb5_error_code retval;

    t->lifespan = lifespan ? lifespan : context->clockskew;
    /* default to clockskew from the context */
    if ((retval = krb5_rc_io_creat(context, &t->d, &t->name))) {
	return retval;
    }
    if ((krb5_rc_io_write(context, &t->d,
			  (krb5_pointer) &t->lifespan, sizeof(t->lifespan))
	 || krb5_rc_io_sync(context, &t->d))) {
	return KRB5_RC_IO;
    }
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_rc_file_init(krb5_context context, krb5_rcache id, krb5_deltat lifespan)
{
    krb5_error_code retval;

    retval = k5_mutex_lock(&id->lock);
    if (retval)
	return retval;
    retval = krb5_rc_file_init_locked(context, id, lifespan);
    k5_mutex_unlock(&id->lock);
    return retval;
}

/* Called with the mutex already locked.  */
krb5_error_code
krb5_rc_file_close_no_free(krb5_context context, krb5_rcache id)
{
    struct file_data *t = (struct file_data *)id->data;
    struct authlist *q;

    if (t->h)
	FREE_RC(t->h);
    if (t->name)
	FREE_RC(t->name);
    while ((q = t->a))
    {
	t->a = q->na;
	FREE_RC(q->rep.client);
	FREE_RC(q->rep.server);
	FREE_RC(q);
    }
 if (t->d.fd >= 0)
    (void) krb5_rc_io_close(context, &t->d);
    FREE_RC(t);
    id->data = NULL;
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_rc_file_close(krb5_context context, krb5_rcache id)
{
    krb5_error_code retval;
    retval = k5_mutex_lock(&id->lock);
    if (retval)
	return retval;
    krb5_rc_file_close_no_free(context, id);
    k5_mutex_unlock(&id->lock);
    k5_mutex_destroy(&id->lock);
    free(id);
    return 0;
}

krb5_error_code KRB5_CALLCONV
krb5_rc_file_destroy(krb5_context context, krb5_rcache id)
{
 if (krb5_rc_io_destroy(context, &((struct file_data *) (id->data))->d))
   return KRB5_RC_IO;
 return krb5_rc_file_close(context, id);
}

/*ARGSUSED*/
krb5_error_code KRB5_CALLCONV
krb5_rc_file_resolve(krb5_context context, krb5_rcache id, char *name)
{
    struct file_data *t = 0;
    krb5_error_code retval;

    /* allocate id? no */
    if (!(t = (struct file_data *) malloc(sizeof(struct file_data))))
	return KRB5_RC_MALLOC;
    id->data = (krb5_pointer) t;
    memset(t, 0, sizeof(struct file_data));
    if (name) {
	t->name = malloc(strlen(name)+1);
	if (!t->name) {
	    retval = KRB5_RC_MALLOC;
	    goto cleanup;
	}
	strcpy(t->name, name);
    } else
	t->name = 0;
    t->numhits = t->nummisses = 0;
    t->hsize = HASHSIZE; /* no need to store---it's memory-only */
    t->h = (struct authlist **) malloc(t->hsize*sizeof(struct authlist *));
    if (!t->h) {
	retval = KRB5_RC_MALLOC;
	goto cleanup;
    }
    memset(t->h, 0, t->hsize*sizeof(struct authlist *));
    t->a = (struct authlist *) 0;
    t->d.fd = -1;
    t->recovering = 0;
    return 0;

cleanup:
    if (t) {
	if (t->name)
	    krb5_xfree(t->name);
	if (t->h)
	    krb5_xfree(t->h);
	krb5_xfree(t);
	id->data = NULL;
    }
    return retval;
}

/*ARGSUSED*/
void
krb5_rc_free_entry(krb5_context context, krb5_donot_replay **rep)
{
    krb5_donot_replay *rp = *rep;

    *rep = NULL;
    if (rp)
    {
	if (rp->client)
	    free(rp->client);

	if (rp->server)
	    free(rp->server);
	rp->client = NULL;
	rp->server = NULL;
	free(rp);
    }
}

static krb5_error_code
krb5_rc_io_fetch(krb5_context context, struct file_data *t,
		 krb5_donot_replay *rep, int maxlen)
{
    unsigned int len;
    krb5_error_code retval;

    rep->client = rep->server = 0;

    retval = krb5_rc_io_read(context, &t->d, (krb5_pointer) &len,
			     sizeof(len));
    if (retval)
	return retval;

    if ((len <= 0) || (len >= maxlen))
	return KRB5_RC_IO_EOF;

    rep->client = malloc (len);
    if (!rep->client)
	return KRB5_RC_MALLOC;

    retval = krb5_rc_io_read(context, &t->d, (krb5_pointer) rep->client, len);
    if (retval)
	goto errout;

    retval = krb5_rc_io_read(context, &t->d, (krb5_pointer) &len, 
			     sizeof(len));
    if (retval)
	goto errout;

    if ((len <= 0) || (len >= maxlen)) {
	retval = KRB5_RC_IO_EOF;
	goto errout;
    }

    rep->server = malloc (len);
    if (!rep->server) {
	retval = KRB5_RC_MALLOC;
	goto errout;
    }

    retval = krb5_rc_io_read(context, &t->d, (krb5_pointer) rep->server, len);
    if (retval)
	goto errout;

    retval = krb5_rc_io_read(context, &t->d, (krb5_pointer) &rep->cusec,
			     sizeof(rep->cusec));
    if (retval)
	goto errout;

    retval = krb5_rc_io_read(context, &t->d, (krb5_pointer) &rep->ctime,
			     sizeof(rep->ctime));
    if (retval)
	goto errout;

    return 0;

errout:
    if (rep->client)
	krb5_xfree(rep->client);
    if (rep->server)
	krb5_xfree(rep->server);
    rep->client = rep->server = 0;
    return retval;
}


static krb5_error_code
krb5_rc_file_expunge_locked(krb5_context context, krb5_rcache id);

static krb5_error_code
krb5_rc_file_recover_locked(krb5_context context, krb5_rcache id)
{
    struct file_data *t = (struct file_data *)id->data;
    krb5_donot_replay *rep = 0;
    krb5_error_code retval;
    long max_size;
    int expired_entries = 0;

    if ((retval = krb5_rc_io_open(context, &t->d, t->name))) {
	return retval;
    }

    t->recovering = 1;

    max_size = krb5_rc_io_size(context, &t->d);

    rep = NULL;
    if (krb5_rc_io_read(context, &t->d, (krb5_pointer) &t->lifespan,
			sizeof(t->lifespan))) {
	retval = KRB5_RC_IO;
	goto io_fail;
    }

    if (!(rep = (krb5_donot_replay *) malloc(sizeof(krb5_donot_replay)))) {
	retval = KRB5_RC_MALLOC;
	goto io_fail;
    }
    rep->client = NULL;
    rep->server = NULL;

    /* now read in each auth_replay and insert into table */
    for (;;) {
	if (krb5_rc_io_mark(context, &t->d)) {
	    retval = KRB5_RC_IO;
	    goto io_fail;
	}
	
	retval = krb5_rc_io_fetch (context, t, rep, (int) max_size);

	if (retval == KRB5_RC_IO_EOF)
	    break;
	else if (retval != 0)
	    goto io_fail;

	/* Solaris: made the change below for better perf. */
	switch (rc_store(context, id, rep)) {
	    case CMP_EXPIRED:
		expired_entries++;
		break;
	    case CMP_MALLOC:
		retval = KRB5_RC_MALLOC;
		goto io_fail;
		break;
	}
	/*
	 *  free fields allocated by rc_io_fetch
	 */
	FREE_RC(rep->server);
	FREE_RC(rep->client);
	rep->server = 0;
	rep->client = 0;
    }
    retval = 0;
    krb5_rc_io_unmark(context, &t->d);
    /*
     *  An automatic expunge here could remove the need for
     *  mark/unmark but that would be inefficient.
     */
io_fail:
    krb5_rc_free_entry(context, &rep);
    if (retval)
	krb5_rc_io_close(context, &t->d);
    else if (expired_entries > EXCESSREPS)
	retval = krb5_rc_file_expunge_locked(context, id);
    t->recovering = 0;
    return retval;
}

krb5_error_code KRB5_CALLCONV
krb5_rc_file_recover(krb5_context context, krb5_rcache id)
{
    krb5_error_code ret;
    ret = k5_mutex_lock(&id->lock);
    if (ret)
	return ret;
    ret = krb5_rc_file_recover_locked(context, id);
    k5_mutex_unlock(&id->lock);
    return ret;
}

krb5_error_code KRB5_CALLCONV
krb5_rc_file_recover_or_init(krb5_context context, krb5_rcache id,
			    krb5_deltat lifespan)
{
    krb5_error_code retval;

    retval = k5_mutex_lock(&id->lock);
    if (retval)
	return retval;
    retval = krb5_rc_file_recover_locked(context, id);
    if (retval)
	retval = krb5_rc_file_init_locked(context, id, lifespan);
    k5_mutex_unlock(&id->lock);
    return retval;
}

static krb5_error_code
krb5_rc_io_store(krb5_context context, struct file_data *t,
		 krb5_donot_replay *rep)
{
    int clientlen, serverlen, len;
    char *buf, *ptr;
    krb5_error_code ret;

    clientlen = strlen(rep->client) + 1;
    serverlen = strlen(rep->server) + 1;
    len = sizeof(clientlen) + clientlen + sizeof(serverlen) + serverlen +
	sizeof(rep->cusec) + sizeof(rep->ctime);
    buf = malloc(len);
    if (buf == 0)
	return KRB5_RC_MALLOC;
    ptr = buf;
    memcpy(ptr, &clientlen, sizeof(clientlen)); ptr += sizeof(clientlen);
    memcpy(ptr, rep->client, clientlen); ptr += clientlen;
    memcpy(ptr, &serverlen, sizeof(serverlen)); ptr += sizeof(serverlen);
    memcpy(ptr, rep->server, serverlen); ptr += serverlen;
    memcpy(ptr, &rep->cusec, sizeof(rep->cusec)); ptr += sizeof(rep->cusec);
    memcpy(ptr, &rep->ctime, sizeof(rep->ctime)); ptr += sizeof(rep->ctime);

    ret = krb5_rc_io_write(context, &t->d, buf, len);
    free(buf);
    return ret;
}

static krb5_error_code krb5_rc_file_expunge_locked(krb5_context, krb5_rcache);

krb5_error_code KRB5_CALLCONV
krb5_rc_file_store(krb5_context context, krb5_rcache id, krb5_donot_replay *rep)
{
    krb5_error_code ret;
    struct file_data *t;

    ret = k5_mutex_lock(&id->lock);
    if (ret)
	return ret;

    t = (struct file_data *)id->data;

    switch(rc_store(context, id,rep)) {
    case CMP_MALLOC:
	k5_mutex_unlock(&id->lock);
	return KRB5_RC_MALLOC;
    case CMP_REPLAY:
	k5_mutex_unlock(&id->lock);
	return KRB5KRB_AP_ERR_REPEAT;
    case CMP_EXPIRED:
	k5_mutex_unlock(&id->lock);
	return KRB5KRB_AP_ERR_SKEW;
    case CMP_HOHUM: break;
    default: /* wtf? */ ;
    }
    ret = krb5_rc_io_store (context, t, rep);
    if (ret) {
	k5_mutex_unlock(&id->lock);
	return ret;
    }
    /* Shall we automatically expunge? */
    if (t->nummisses > t->numhits + EXCESSREPS)
    {
	ret = krb5_rc_file_expunge_locked(context, id);
	k5_mutex_unlock(&id->lock);
	return ret;
    }
    else
    {
	if (krb5_rc_io_sync(context, &t->d)) {
	    k5_mutex_unlock(&id->lock);
	    return KRB5_RC_IO;
	}
    }
    k5_mutex_unlock(&id->lock);
    return 0;
}

static krb5_error_code
krb5_rc_file_expunge_locked(krb5_context context, krb5_rcache id)
{
    struct file_data *t = (struct file_data *)id->data;
    struct authlist *q;
    char *name;
    krb5_error_code retval = 0;
    krb5_rcache tmp;
    krb5_deltat lifespan = t->lifespan;  /* save original lifespan */

    if (! t->recovering) {
	name = t->name;
	t->name = 0;		/* Clear name so it isn't freed */
	(void) krb5_rc_file_close_no_free(context, id);
	retval = krb5_rc_file_resolve(context, id, name);
	free(name);
	if (retval)
	    return retval;
	retval = krb5_rc_file_recover_locked(context, id);
	if (retval)
	    return retval;
	t = (struct file_data *)id->data; /* point to recovered cache */
    }

    tmp = (krb5_rcache) malloc(sizeof(*tmp));
    if (!tmp)
	return ENOMEM;

    retval = k5_mutex_init(&tmp->lock);
    if (retval) {
        free(tmp);
        return retval;
    }

    tmp->ops = &krb5_rc_file_ops;
    if ((retval = krb5_rc_file_resolve(context, tmp, 0)) != 0)
	goto out;
    if ((retval = krb5_rc_initialize(context, tmp, lifespan)) != 0)
	goto out;
    for (q = t->a;q;q = q->na) {
	if (krb5_rc_io_store (context, (struct file_data *)tmp->data, &q->rep)) {
		retval = KRB5_RC_IO;
		goto out;
	}
    }
    if (krb5_rc_io_sync(context, &t->d)) {
	retval = KRB5_RC_IO;
	goto out;
    }
    if (krb5_rc_io_move(context, &t->d, &((struct file_data *)tmp->data)->d))
	retval = KRB5_RC_IO;

out:
    /*
     * krb5_rc_file_close() will free the tmp struct and it's members that the
     * previous functions had allocated.
     */
     (void) krb5_rc_file_close(context, tmp);

    return (retval);
}

krb5_error_code KRB5_CALLCONV
krb5_rc_file_expunge(krb5_context context, krb5_rcache id)
{
    krb5_error_code ret;
    ret = k5_mutex_lock(&id->lock);
    if (ret)
	return ret;
    ret = krb5_rc_file_expunge_locked(context, id);
    k5_mutex_unlock(&id->lock);
    return ret;
}
