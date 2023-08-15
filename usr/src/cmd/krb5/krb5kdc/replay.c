/*
 * kdc/replay.c
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 *
 * Replay lookaside cache for the KDC, to avoid extra work.
 *
 */



#include "k5-int.h"
#include "kdc_util.h"
#include "extern.h"

#ifndef NOCACHE

typedef struct _krb5_kdc_replay_ent {
    struct _krb5_kdc_replay_ent *next;
    int num_hits;
    krb5_int32 timein;
    time_t db_age;
    krb5_data *req_packet;
    krb5_data *reply_packet;
} krb5_kdc_replay_ent;

static krb5_kdc_replay_ent root_ptr = {0};

static int hits = 0;
static int calls = 0;
static int max_hits_per_entry = 0;
static int num_entries = 0;

#define STALE_TIME	2*60		/* two minutes */
#define STALE(ptr) ((abs((ptr)->timein - timenow) >= STALE_TIME) ||	\
		    ((ptr)->db_age != db_age))

#define MATCH(ptr) (((ptr)->req_packet->length == inpkt->length) &&	\
		    !memcmp((ptr)->req_packet->data, inpkt->data,	\
			    inpkt->length) &&				\
		    ((ptr)->db_age == db_age))
/* XXX
   Todo:  quench the size of the queue...
 */

/* return TRUE if outpkt is filled in with a packet to reply with,
   FALSE if the caller should do the work */

krb5_boolean
kdc_check_lookaside(krb5_data *inpkt, krb5_data **outpkt)
{
    krb5_int32 timenow;
    register krb5_kdc_replay_ent *eptr, *last, *hold;
    time_t db_age;

    if (krb5_timeofday(kdc_context, &timenow) ||
	krb5_db_get_age(kdc_context, 0, &db_age))
	return FALSE;

    calls++;

    /* search for a replay entry in the queue, possibly removing
       stale entries while we're here */

    if (root_ptr.next) {
	for (last = &root_ptr, eptr = root_ptr.next;
	     eptr;
	     eptr = eptr->next) {
	    if (MATCH(eptr)) {
		eptr->num_hits++;
		hits++;

		if (krb5_copy_data(kdc_context, eptr->reply_packet, outpkt))
		    return FALSE;
		else
		    return TRUE;
		/* return here, don't bother flushing even if it is stale.
		   if we just matched, we may get another retransmit... */
	    }
	    if (STALE(eptr)) {
		/* flush it and collect stats */
		max_hits_per_entry = max(max_hits_per_entry, eptr->num_hits);
		krb5_free_data(kdc_context, eptr->req_packet);
		krb5_free_data(kdc_context, eptr->reply_packet);
		hold = eptr;
		last->next = eptr->next;
		eptr = last;
		free(hold);
	    } else {
		/* this isn't it, just move along */
		last = eptr;
	    }
	}
    }
    return FALSE;
}

/* insert a request & reply into the lookaside queue.  assumes it's not
   already there, and can fail softly due to other weird errors. */

void
kdc_insert_lookaside(krb5_data *inpkt, krb5_data *outpkt)
{
    register krb5_kdc_replay_ent *eptr;
    krb5_int32 timenow;
    time_t db_age;

    if (krb5_timeofday(kdc_context, &timenow) ||
	krb5_db_get_age(kdc_context, 0, &db_age))
	return;

    /* this is a new entry */
    eptr = (krb5_kdc_replay_ent *)calloc(1, sizeof(*eptr));
    if (!eptr)
	return;
    eptr->timein = timenow;
    eptr->db_age = db_age;
    /*
     * This is going to hurt a lot malloc()-wise due to the need to
     * allocate memory for the krb5_data and krb5_address elements.
     * ARGH!
     */
    if (krb5_copy_data(kdc_context, inpkt, &eptr->req_packet)) {
	free(eptr);
	return;
    }
    if (krb5_copy_data(kdc_context, outpkt, &eptr->reply_packet)) {
	krb5_free_data(kdc_context, eptr->req_packet);
	free(eptr);
	return;
    }
    eptr->next = root_ptr.next;
    root_ptr.next = eptr;
    num_entries++;
    return;
}

/* frees memory associated with the lookaside queue for memory profiling */
void
kdc_free_lookaside(krb5_context kcontext)
{
    register krb5_kdc_replay_ent *eptr, *last, *hold;
    if (root_ptr.next) {
        for (last = &root_ptr, eptr = root_ptr.next;
	     eptr; eptr = eptr->next) {
		krb5_free_data(kcontext, eptr->req_packet);
		krb5_free_data(kcontext, eptr->reply_packet);
		hold = eptr;
		last->next = eptr->next;
		eptr = last;
		free(hold);
	}
    }
}

#endif /* NOCACHE */
