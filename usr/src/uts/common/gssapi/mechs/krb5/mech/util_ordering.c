/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 * 
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * $Id: util_ordering.c,v 1.4 1996/10/21 20:17:11 tytso Exp $
 */

/*
 * functions to check sequence numbers for replay and sequencing
 */

#include <mechglueP.h>
#include <gssapiP_generic.h>

#define QUEUE_LENGTH 20

typedef struct _queue {
   int do_replay;
   int do_sequence;
   int start;
   int length;
   gssint_uint64 firstnum;
   gssint_uint64 elem[QUEUE_LENGTH];
   gssint_uint64 mask;
} queue;

/* rep invariant:
 *  - the queue is a circular queue.  The first element (q->elem[q->start])
 * is the oldest.  The last element is the newest.
 */

#define QSIZE(q) (sizeof((q)->elem)/sizeof((q)->elem[0]))
#define QELEM(q,i) ((q)->elem[(i)%QSIZE(q)])

static void
queue_insert(queue *q, int after, gssint_uint64 seqnum)
{
   /* insert.  this is not the fastest way, but it's easy, and it's
      optimized for insert at end, which is the common case */
   int i;

   /* common case: at end, after == q->start+q->length-1 */

   /* move all the elements (after,last] up one slot */

   for (i=q->start+q->length-1; i>after; i--)
      QELEM(q,i+1) = QELEM(q,i);

   /* fill in slot after+1 */

   QELEM(q,after+1) = seqnum;

   /* Either increase the length by one, or move the starting point up
      one (deleting the first element, which got bashed above), as
      appropriate. */

   if (q->length == QSIZE(q)) {
      q->start++;
      if (q->start == QSIZE(q))
	 q->start = 0;
   } else {
      q->length++;
   }
}
   
gss_int32
g_order_init(void **vqueue, gssint_uint64 seqnum,
	     int do_replay, int do_sequence, int wide_nums)
{
   queue *q;

   if ((q = (queue *) MALLOC(sizeof(queue))) == NULL)
      return(ENOMEM);

   q->do_replay = do_replay;
   q->do_sequence = do_sequence;
   q->mask = wide_nums ? ~(gssint_uint64)0 : 0xffffffffUL;

   q->start = 0;
   q->length = 1;
   q->firstnum = seqnum;
   q->elem[q->start] = ((gssint_uint64)0 - 1) & q->mask;

   *vqueue = (void *) q;
   return(0);
}

gss_int32
g_order_check(void **vqueue, gssint_uint64 seqnum)
{
   queue *q;
   int i;
   gssint_uint64 expected;
   
   q = (queue *) (*vqueue);

   if (!q->do_replay && !q->do_sequence)
      return(GSS_S_COMPLETE);

   /* All checks are done relative to the initial sequence number, to
	avoid (or at least put off) the pain of wrapping.	 */

   /* wraparound case */
   if (seqnum < q->firstnum) {
	/* if 32 bit, put seqnum into 64 bit range */	
	if (q->mask != ~(gssint_uint64)0) {
		seqnum |= 0x100000000ULL;
		seqnum -= q->firstnum;
	} else {
		/*
		 * 64 bit wraparound, just add the number of
		 * elements before the wraparound point
		 * to get the normalized seqnum.
		 */
		seqnum += (~(gssint_uint64)0) - q->firstnum;
	}
   } else {
	/*
	 * Normally (as long as seqnum >= firstnum), just subtract
	 * the firstnum to get the relative 'seqnum'.
	 */
	seqnum -= q->firstnum;
   }

   /* rule 1: expected sequence number */

   expected = (QELEM(q,q->start+q->length-1)+1) & q->mask;
   if (seqnum == expected) {
	queue_insert(q, q->start+q->length-1, seqnum);
	return(GSS_S_COMPLETE);
   }

   /* rule 2: > expected sequence number */

   if ((seqnum > expected)) {
	queue_insert(q, q->start+q->length-1, seqnum);
	if (q->do_replay && !q->do_sequence)
	 return(GSS_S_COMPLETE);
	else
         return(GSS_S_GAP_TOKEN);
   }

   /* rule 3: seqnum < seqnum(first) */
   if (seqnum < QELEM(q,q->start)) {
      if (q->do_replay)
	    return(GSS_S_OLD_TOKEN);
      else
	    return(GSS_S_UNSEQ_TOKEN);
   }

   /* rule 4+5: seqnum in [seqnum(first),seqnum(last)]  */

   else {
      if (seqnum == QELEM(q,q->start+q->length-1))
	 return(GSS_S_DUPLICATE_TOKEN);

      for (i=q->start; i<q->start+q->length-1; i++) {
	 if (seqnum == QELEM(q,i))
	    return(GSS_S_DUPLICATE_TOKEN);
	 if ((seqnum > QELEM(q,i)) && (seqnum < QELEM(q,i+1))) {
	    queue_insert(q, i, seqnum);
	    if (q->do_replay && !q->do_sequence)
	       return(GSS_S_COMPLETE);
	    else
	       return(GSS_S_UNSEQ_TOKEN);
	 }
      }
   }

   /* this should never happen */
   return(GSS_S_FAILURE);
}

void
g_order_free(void **vqueue)
{
   queue *q;
   
   q = (queue *) (*vqueue);

   FREE (q, sizeof (queue));

   *vqueue = NULL;
}

/*
 * These support functions are for the serialization routines
 */

/*ARGSUSED*/
gss_uint32
g_queue_size(void *vqueue, size_t *sizep)
{
    *sizep += sizeof(queue);
    return 0;
}

gss_uint32
g_queue_externalize(void *vqueue, unsigned char **buf, size_t *lenremain)
{
    (void) memcpy(*buf, vqueue, sizeof(queue));
    *buf += sizeof(queue);
    *lenremain -= sizeof(queue);
    
    return 0;
}

gss_uint32
g_queue_internalize(void **vqueue, unsigned char **buf, size_t *lenremain)
{
    void *q;

    if ((q = (void *) MALLOC(sizeof(queue))) == 0)
	return ENOMEM;
    (void) memcpy(q, *buf, sizeof(queue));
    *buf += sizeof(queue);
    *lenremain -= sizeof(queue);
    *vqueue = q;
    return 0;
}
