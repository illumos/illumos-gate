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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/



/* ********************************************************************** */
/* *		General-Purpose Event List Manager			* */
/* ********************************************************************** */
/*
 *	description:	These routines maintain a time-ordered list of events.
 *	functions available:
 *		init :	Creates and initializes the data structure.
 *			See the reference for parameters to init.
 *		add(&event, time, id) :	Adds an event to the list.
 *					Returns: 0 if success,
 *						-2 if event time is lower
 *						   than Lower Bound time LB
 *						-1 else
 *		remove(id) :	Removes events (with appropriate id).
 *		empty : Returns true if the list is empty, false otherwise.
 *		first :	Removes the element at the head of the list.
 *			Returns a pointer to the event.
 *		delete : Frees up all allocated storage associated
 *			 with the event list.
 *	reference:	Franta, W. R. and Maly, K.,
 *			"An efficient data structure for the
 *			simulation event set ", CACM Vol. 20(8),
 *			Aug 1977, pp. 596-602.
 *	machine dependant:	the constant INFINITY
 */
/* ********************************************************************** */


#include <sys/types.h>
#include <stdlib.h>

extern	void *xmalloc(size_t);

#define	INFINITY	2147483647L	/* upper bound on time	*/
#define	TRUE		1
#define	FALSE		0

/* the following parameters are set in init	*/
static int	DU;		/* number of time intervals	*/
static time_t	LB;		/* lower bound on time	*/
static time_t	DT;		/* width of interval	*/
static int	NLIM;		/* max notices per sublist	*/

/*
 * a notice points to an event.  a notice has the following fields:
 *	time = time of the event.
 *	id = identifier for an event or class of events that may need
 *		to be removed (other than at the front of the list).
 *	event = pointer to the event.
 *	isdummy = tells whether this notice points to a real event or
 *		is just a dummy notice (one that is used to "mark off"
 *		the time intervals that the user specifies in init).
 *	key = points back to the key that points to this notice,
 *		if there is one.
 *	left = points to the notice immediately preceding this one.
 *	right = points to the notice immediately following this one.
 */
struct notice {	time_t	time;
		int	id;
		void	*event;
		short int	isdummy;
		struct key	*key;
		struct notice	*left;
		struct notice	*right; };

/* current points to the front of the list of notices (events)	*/
struct notice	*current = NULL;

/*
 * a key points to a sublist of notices.  a key has the following fields:
 *	time = max time of notices in sublist.
 *	numnote = number of notices in sublist.
 *	notice = pointer to the notice with max time.
 *	left = points to the key immediately preceding this one.
 *	right = points to the key immediately following this one.
 */
struct key {	time_t	time;
		int	numnote;
		struct notice	*notice;
		struct key	*left;
		struct key	*right; };

/*
 * the index list breaks the keys into time intervals as specified in init.
 * the index is "shifted" one time interval whenever el_first returns an
 * event with a time greater than the max time of the first interval
 * (eg. with intervals of a day which span one week (MTWTFSS),
 * if el_first finds the next event is on tuesday, then
 * the intervals of the event list get shifted (TWTFSSM).
 */
struct index {	struct key *key;
		struct index *right; };

/* index pts to the front of the index list */
static struct index *index = NULL;

/* ******************* */
void
el_init(du, lb, dt, nlim)
/* ******************* */
int du, nlim;
time_t lb, dt;
{
	int	i;
	time_t	t;
	struct index *indprev, *ind;
	struct key *kprev, *k;
	struct notice *nprev, *n;

	if ((du < 1) || (dt < 1) || (nlim < 1))
		return;
	DU = du + 1;
	LB = lb;
	DT = dt;
	NLIM = nlim;

	/*
	 * initialize index, keys, and notices
	 */

	/* create first dummy notice */
	n = (struct notice *)xmalloc(sizeof (struct notice));
	n->time = LB;
	n->isdummy = TRUE;
	n->left = NULL;
	nprev = n;
	/* create first dummy key */
	k = (struct key *)xmalloc(sizeof (struct key));
	k->time = LB;
	k->numnote = 1;
	k->notice = n;
	k->left = NULL;
	kprev = k;
	/* make notice point to key */
	n->key = k;
	/* no index element to allocate this time */
	indprev = NULL;
	/* create dummy notices, dummy keys, and index elements */
	t = LB;
	for (i = 1; i < DU; i++) {
		t = t + DT;
		n = (struct notice *)xmalloc(sizeof (struct notice));
		n->time = t;
		n->isdummy = TRUE;
		n->left = nprev;
		nprev->right = n;
		nprev = n;
		k = (struct key *)xmalloc(sizeof (struct key));
		k->time = t;
		k->numnote = 1;
		k->notice = n;
		k->left = kprev;
		kprev->right = k;
		kprev = k;
		n->key = k;
		ind = (struct index *)xmalloc(sizeof (struct index));
		ind->key = k;
		if (indprev == NULL)
			index = ind;
		else
			indprev->right = ind;
		indprev = ind; }
	/* create last dummy notice */
	n = (struct notice *)xmalloc(sizeof (struct notice));
	n->time = INFINITY;
	n->isdummy = TRUE;
	n->left = nprev;
	n->right = NULL;
	nprev->right = n;
	/* create last dummy key */
	k = (struct key *)xmalloc(sizeof (struct key));
	k->time = INFINITY;
	k->numnote = 1;
	k->notice = n;
	k->left = kprev;
	k->right = NULL;
	kprev->right = k;
	n->key = k;
	/* create last index element */
	ind = (struct index *)xmalloc(sizeof (struct index));
	ind->key = k;
	ind->right = NULL;
	indprev->right = ind;

	current = NULL;
}


/* ********************** */
int
el_add(event, time, id)
/* ********************** */
void	*event;
int	id;
time_t	time;
{
	/*
	 * add works slightly differently than in the reference.  if the
	 * sublist to be inserted into is full (numnote = NLIM),
	 * the sublist is split in half.  thus the size of the sublists
	 * in this implementation normally ranges from NLIM/2 to NLIM.
	 */

	struct index *ind;
	struct key *k, *k2;
	struct notice *n, *n2;
	int i;

	/*
	 * time may be 0 when set by next_time() on error or an
	 * invalid time specification of job
	 */
	if ((index == NULL) || (time <= 0)) {
		return (-1);
	}
	if (time < LB) {
		return (-2);
	}

	/* allocate new notice */
	n = (struct notice *)xmalloc(sizeof (struct notice));
	n->time = time;
	n->id = id;
	n->event = event;
	n->isdummy = FALSE;
	n->key = NULL;

	/* find the right interval */
	ind = index;
	while ((ind->key)->time <= time) ind = ind->right;

	/* find the right key */
	k = (ind->key)->left;
	while (k->time > time) k = k->left;
	k = k->right;

	/* (k->time>time) and ((k->left)->time<=time) */
	if (k->numnote == NLIM) {
		/* k's sublist is full, so split it */
		k->numnote = NLIM / 2;
		n2 = k->notice;
		for (i = 1; i <= NLIM/2; i++) n2 = n2->left;
		/* create a key which will point to notice n2 */
		k2 = (struct key *)xmalloc(sizeof (struct key));
		k2->time = n2->time;
		k2->numnote = NLIM - NLIM/2;
		k2->notice = n2;
		k2->right = k;
		k2->left = k->left;
		k->left = k2;
		(k2->left)->right = k2;
		n2->key = k2;	/* have n2 point back to k2 */
		/* which of the new sublists will hold the new notice? */
		if (k2->time > time) k = k2; }

	/*
	 * the new notice n is ready to be inserted
	 * k points to the appropriate sublist
	 */
	k->numnote = k->numnote + 1;
	n2 = k->notice;
	while (n2->time > time) n2 = n2->left;
	n->right = n2->right;
	n->left = n2;
	(n2->right)->left = n;
	n2->right = n;

	if ((current == NULL) || (current->time > time))
		current = n;

	return (0);
}


/* ******************** */
void
el_remove(id, flag)
/* ******************** */
int	id, flag;
{
	/*
	 * remove finds notices n that need to be removed by traversing thru
	 * the notice list.  if n is the sole element of a sublist, the
	 * sublist is deleted.  if not, an adjacent sublist is merged with
	 * n's sublist, if that is possible.  after these checks, n is removed.
	 */

	struct notice *n, *n2;
	struct key *k, *kl, *kr;

	if ((index == NULL) || (current == NULL))
		return;

	n = current;
	while (n != NULL) {
		while ((n != NULL) && ((n->isdummy) || (n->id != id)))
			n = n->right;
		if (n != NULL) {
			/* n should be deleted */
			if ((n->key != NULL) && ((n->key)->numnote == 1)) {
				/* n = sole element of a sublist */
				k = n->key;
				(k->left)->right = k->right;
				(k->right)->left = k->left;
				free(k);
			} else { if (n->key != NULL) {
					/* n has a key pointing to it */
					(n->left)->key = n->key;
					(n->key)->time = (n->left)->time;
					(n->key)->notice = n->left; }
				/* find the key that points to this sublist */
				n2 = n;
				while (n2->key == NULL) n2 = n2->right;
				k = n2->key;
				k->numnote = k->numnote - 1;
				/*
				 * check if two adjacent sublists can be merged
				 * first check left, then check right
				 */
				kl = k->left;
				kr = k->right;
				if ((!(kl->notice)->isdummy) &&
				    ((kl->numnote+k->numnote) <= NLIM)) {
					/* delete the key to the left */
					(kl->notice)->key = NULL;
					k->numnote += kl->numnote;
					(kl->left)->right = k;
					k->left = kl->left;
					free(kl);
				} else if ((!(k->notice)->isdummy) &&
					    ((kr->numnote+k->numnote)
					    <= NLIM)) {
					/* delete this key */
					(k->notice)->key = NULL;
					kr->numnote += k->numnote;
					(k->left)->right = kr;
					kr->left = k->left;
					free(k); }
				}
			/* delete n, then advance n down the list */
			(n->left)->right = n->right;
			(n->right)->left = n->left;
			n2 = n->right;
			free(n);
			n = n2;
			}
		if (flag) break;
		}
	/* now reset current */
	k = (index->key)->left;
	while (k->left != NULL) k = k->left;
	n = (k->notice)->right;
	while ((n != NULL) && (n->isdummy)) n = n->right;
	current = n;
}


/* ********************* */
int
el_empty(void)
/* ********************* */
{
	if (current == NULL)
		return (1);
	else
		return (0);
}


/* ********************* */
void *
el_first(void)
/* ********************* */
{
	struct notice *n, *fn;
	struct key *k, *fk;
	struct index *ind, *fi;
	int ctr, *val;
	time_t next_int;

	if ((index == NULL) || (current == NULL))
		return (NULL);

	while ((index->key)->time < current->time) {
		if (DU == 2) {
			/* only two intervals, so relabel first one */
			k = index->key;
			k->time += DT;
			(k->notice)->time += DT;
			continue; }
		/*
		 * remove the notice, key, and index corresponding
		 * to the first time interval.  Then split the
		 * overflow interval into a normal interval
		 * plus an overflow interval.
		 */
		fi = index;
		fk = fi->key;
		fn = fk->notice;
		(fn->left)->right = fn->right;
		(fn->right)->left = fn->left;
		(fk->left)->right = fk->right;
		(fk->right)->left = fk->left;
		index = index->right;
		/* find where to split	*/
		ind = index;
		while ((ind->right)->right != NULL) ind = ind->right;
		/* ind points to the next to last index interval	*/
		k = ind->key;
		next_int = k->time + DT;	/* upper bound on new inter.  */
		while (k->time < next_int) k = k->right;
		/* k points to the appropriate sublist of notices	*/
		n = (k->notice)->left;
		ctr = 1;
		while (n->time >= next_int) {
			ctr++;
			n = n->left; }
		n = n->right;
		/*
		 * n points to first notice of the new overflow interval
		 * ctr tells how many notices are in the first sublist
		 *	of the new overflow interval
		 * insert the new index element
		 */
		fi->right = ind->right;
		ind->right = fi;
		/* insert the new dummy key	*/
		fk->time = next_int;
		fk->numnote = k->numnote - ctr + 1;
		fk->left = k->left;
		fk->right = k;
		(k->left)->right = fk;
		k->left = fk;
		k->numnote = ctr;
		/* insert the new dummy notice	*/
		fn->time = next_int;
		fn->left = n->left;
		fn->right = n;
		(n->left)->right = fn;
		n->left = fn; }

	/* remove the first element of the list */
	(current->left)->right = current->right;
	(current->right)->left = current->left;
	/* now update the numnote field in the appropriate key */
	n = current;
	while (n->key == NULL) n = n->right;
	k = n->key;
	k->numnote = k->numnote - 1;
	/* if numnote = 0 then this key must be removed */
	if (k->numnote == 0) {
		(k->left)->right = k->right;
		(k->right)->left = k->left;
		free(k); }

	/* now set current to be the head of the list */
	fn = current->right;
	while ((fn != NULL) && (fn->isdummy))
		fn = fn->right;
	val = current->event;
	free(current);
	current = fn;

	return (val);
}


/* ************** */
void
el_delete(void)
/* ************** */
{
	/* el_delete frees up all the space associated with the event list */

	struct index *ind, *ind2;
	struct key *k, *k2;
	struct notice *n, *n2;

	if (index == NULL)
		return;
	ind = index;
	k = ind->key;
	while (k->left != NULL) k = k->left;
	n = k->notice;
	while (n != NULL) {
		n2 = n->right;
		free(n);
		n = n2; }
	while (k != NULL) {
		k2 = k->right;
		free(k);
		k = k2; }
	while (ind != NULL) {
		ind2 = ind->right;
		free(ind);
		ind = ind2; }

	index = NULL;
	current = NULL;
}
