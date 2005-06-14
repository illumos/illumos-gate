/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The functions in this file used to reside in nis_subr_proc.c. In order
 * to simplify building nislog(1M) (which links in some but not all of the
 * rpc.nisd object files), it was convenient to move the functions to their
 * own file.
 */

#include <syslog.h>
#include <rpcsvc/nis.h>
#include "nis_proc.h"

extern FILE *cons;

void
free_abort(p)
	char *p;
{
	syslog(LOG_CRIT, "Attempting to free a free rag!");
	syslog(LOG_ERR, "Attempting to free a free rag!");
	abort();
}

/*
 * These functions are used to clean up after ourselves when we return
 * a result. The primary client are the svc functions which malloc
 * their data and then put it on the cleanup list when they return.
 * this allows them to be reentrant.
 */
void
do_cleanup(stuff)
	cleanup	*stuff;
{
	cleanup	*this, *nextrag;
	nis_tsd_t	*tsd;

	if (stuff == 0)
		return;

	tsd = __nis_get_tsd();

	for (this = stuff; this; this = nextrag) {
		nextrag = this->next;
#ifdef DEBUG
		if ((this->tag) && verbose)
			syslog(LOG_INFO, "do_cleanup : '%s'", this->tag);
#endif
		(*(this->func))(this->data);
		this->func = free_abort;
		this->data = NULL;
		this->tag = NULL;
		this->next = tsd->free_rags;
		tsd->free_rags = this;
	}
}

/*
 * The non-MT code allocates space for 1024 rags. Because the auto-MT
 * mode of RPC usually creates a new thread for every RPC request,
 * and since each thread has its own rags list, we only need enough
 * for one NIS+ operation. Testing showed that handling a nis_list()
 * (without callback) used seven rags, so 16 seems a good choice,
 * making it unlikely that a thread will need to allocate rags more
 * than once.
 */
#define	RAGCHUNK	16

void
add_cleanup(clean_func, clean_data, ragtag)
	void	(*clean_func)();
	void	*clean_data;
	char	*ragtag;
{
	register cleanup *newrag;
	int	i;
	nis_tsd_t	*tsd;

	if ((! clean_func) || (! clean_data)) {
		if (cons)
			fprintf(cons, "no func or data : %s\n", ragtag);
		return;
	}

	tsd = __nis_get_tsd();

	if (! tsd->free_rags) {
		if (verbose)
			syslog(LOG_DEBUG,
			"add_cleanup: Low on rags, allocating some more.");
		/* Allocate extra space to keep track of the newrag block */
#define	newragoffset	(1+(sizeof (cleanupblock_t)/sizeof (cleanup)))
		newrag = (cleanup *)XCALLOC((RAGCHUNK + newragoffset),
					sizeof (cleanup));
		if (! newrag) {
			syslog(LOG_CRIT,
				"add_cleanup: Can't allocate more rags.");
			return;
		}

		/*
		 * Use the first 'newragoffset' element(s) of the 'newrag'
		 * array for housekeeping that enables us to free the array
		 * on thread exit.
		 */
		{
			cleanupblock_t	**b = &(tsd->ragblocks);
			cleanupblock_t	*n = (cleanupblock_t *)newrag;

			n->next = *b;
			*b = n;
#ifdef	NIS_MT_DEBUG
			printf("%d: newrag 0x%x (%d bytes)\n",
				pthread_self(), n,
				(RAGCHUNK+newragoffset)*sizeof (cleanup));
#endif	/* NIS_MT_DEBUG */
		}
		for (i = newragoffset; i < RAGCHUNK + newragoffset; i++) {
			newrag[i].next = tsd->free_rags;
			tsd->free_rags = &(newrag[i]);
		}
	}

	newrag = tsd->free_rags;
	tsd->free_rags = tsd->free_rags->next;

	newrag->func = clean_func;
	newrag->data = clean_data;
	newrag->tag  = ragtag;
	newrag->next = tsd->looseends;
	newrag->id = tsd->cleanup_tag;
#ifdef DEBUG
	if (verbose)
		syslog(LOG_INFO, "add_cleanup (thread # %d: tag # %d '%s'",
			pthread_self(), tsd->cleanup_tag, ragtag);
#endif	/* DEBUG */
	tsd->cleanup_tag++;
	tsd->looseends = newrag;
}

void
do_xdr_cleanup(data)
	xdr_clean_data *data;
{
	if (! data)
		return;

	xdr_free(data->xdr_func, data->xdr_data);
	XFREE(data->xdr_data);
	XFREE(data);
}

void
add_xdr_cleanup(func, data, t)
	bool_t	(*func)();
	char	*data;
	char	*t;
{
	xdr_clean_data	*dat = NULL;

	dat = (xdr_clean_data *)XCALLOC(1, sizeof (xdr_clean_data));
	if (! dat)
		return;

	dat->xdr_func = func;
	dat->xdr_data = (void *)data;
	add_cleanup(do_xdr_cleanup, dat, t);
}
