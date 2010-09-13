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
 * Copyright (c) 1997, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <netinet/tcp.h>
#include <sys/systm.h>
#include <sys/stropts.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/tcp.h>

/* kmem cache for notsack_blk_t */
kmem_cache_t	*tcp_notsack_blk_cache;

/*
 * To insert a new blk to the array of SACK blk in receiver.
 *
 * Parameters:
 *	sack_blk_t *head: pointer to the array of SACK blks.
 *	tcp_seq begin: starting seq num of the new blk.
 *	tcp_seq end: ending seq num of the new blk.
 *	int32_t *num: (referenced) total num of SACK blks on the list.
 */
void
tcp_sack_insert(sack_blk_t *head, tcp_seq begin, tcp_seq end, int32_t *num)
{
	int32_t	i, j, old_num, new_num;
	sack_blk_t tmp[MAX_SACK_BLK - 1];

	/* The array is empty, just add the new one. */
	if (*num == 0) {
		head[0].begin = begin;
		head[0].end = end;
		*num = 1;
		return;
	}

	/*
	 * Check for overlap.  There are five cases.
	 *
	 * 1. there is no overlap with any other SACK blks.
	 * 2. new SACK blk is completely contained in another blk.
	 * 3. tail part of new SACK blk overlaps with another blk.
	 * 4. head part of new SACK blk overlaps with another blk.
	 * 5. new SACK blk completely contains another blk.
	 *
	 * Use tmp to hold old SACK blks.  After the loop, copy them back
	 * to head.
	 */
	old_num = *num;
	if (old_num > MAX_SACK_BLK - 1) {
		old_num = MAX_SACK_BLK - 1;
	}
	new_num = old_num;
	j = 0;
	for (i = 0; i < old_num; i++) {
		if (SEQ_LT(end, head[i].begin) || SEQ_GT(begin, head[i].end)) {
			/* Case 1: continue to check. */
			tmp[j].begin = head[i].begin;
			tmp[j].end = head[i].end;
			j++;
			continue;
		} else if (SEQ_GEQ(begin, head[i].begin) &&
		    SEQ_LEQ(end, head[i].end)) {
			/* Case 2: re-insert the old blk to the head. */
			begin = head[i].begin;
			end = head[i].end;
		} else if (SEQ_LEQ(end, head[i].end) &&
		    SEQ_GEQ(end, head[i].begin)) {
			/*
			 * Case 3: Extend the new blk, remove the old one
			 * and continue to check.
			 */
			end = head[i].end;
		} else if (SEQ_GEQ(begin, head[i].begin) &&
		    SEQ_LEQ(begin, head[i].end)) {
			/* Case 4 */
			begin = head[i].begin;
		}
		/*
		 * Common code for all cases except the first one, which
		 * copies the original SACK blk into the tmp storage.  Other
		 * cases remove the original SACK blk by not copying into
		 * tmp storage.
		 */
		new_num--;
	}

	head[0].begin = begin;
	head[0].end = end;
	for (i = 0; i < new_num; i++) {
		head[i+1].begin = tmp[i].begin;
		head[i+1].end = tmp[i].end;
	}
	*num = new_num + 1;
}


/*
 * To remove a SACK block.
 *
 * Parameters:
 *	sack_blk_t *head: pointer to the array of SACK blks.
 *	tcp_seq end: to remove all sack blk with seq num less than end.
 *	int32_t *num: (referenced) total num of SACK blks in the array.
 */
void
tcp_sack_remove(sack_blk_t *head, tcp_seq end, int32_t *num)
{
	sack_blk_t tmp[MAX_SACK_BLK];
	int32_t i, j, old_num, new_num;

	if (*num == 0)
		return;

	old_num = *num;
	new_num = old_num;
	j = 0;
	/* Walk thru the whole list and copy the new list to tmp[]. */
	for (i = 0; i < old_num; i++) {
		if (SEQ_GT(end, head[i].begin)) {
			/*
			 * Check to see if the old SACK blk needs to be
			 * removed or updated.  If the old blk is just
			 * partially covered, update begin and continue.
			 * If the old blk is completely covered, remove it
			 * and continue to check.
			 */
			if (SEQ_GEQ(end, head[i].end)) {
				new_num--;
				continue;
			} else {
				tmp[j].begin = end;
				tmp[j].end = head[i].end;
			}
		} else {
			tmp[j].begin = head[i].begin;
			tmp[j].end = head[i].end;
		}
		j++;
	}
	/* Copy tmp[] back to the original list. */
	for (i = 0; i < new_num; i++) {
		head[i].begin = tmp[i].begin;
		head[i].end = tmp[i].end;
	}
	*num = new_num;
}


/*
 * Use the SACK info to insert a "notsack'ed" blk.  The notsack'ed blk list
 * contains the list of blks which have not been selectively acknowledged
 * by the receiver.  The SACK info is a blk which is being selectively
 * acknowledged by the receiver.
 *
 * Parameters:
 *	notsack_blk_t **head: address of the pointer to the list of notsack'ed
 *		blks.
 *	tcp_seq begin: starting seq num of the SACK info.
 *	tcp_seq end: ending seq num of the SACK info.
 *	int32_t *num: (referenced) total num of notsack'ed blk on the list.
 *	uint32_t *sum: (referenced) total num of bytes of all the notsack'ed
 *		blks.
 */
void
tcp_notsack_insert(notsack_blk_t **head, tcp_seq begin, tcp_seq end,
    int32_t *num, uint32_t *sum)
{
	notsack_blk_t *prev, *tmp, *new;
	uint32_t tmp_sum, tmp_num;

	if (*head == NULL) {
		return;
	}

	tmp = *head;
	prev = NULL;
	/* Find the right place of updating the list. */
	while ((tmp != NULL) && SEQ_LEQ(tmp->end, begin)) {
		prev = tmp;
		(tmp->sack_cnt)++;
		tmp = tmp->next;
	}

	/*
	 * This can happen only when TCP sends new data but the notsack list
	 * is not updated.
	 */
	if (tmp == NULL) {
		return;
	}

	/*
	 * This means the new SACK info covers something that is not on
	 * the list anymore.
	 */
	if (SEQ_LEQ(end, tmp->begin)) {
		return;
	}

	/* The SACK info covers up to this blk.  So just check for this blk. */
	if (SEQ_LEQ(end, tmp->end)) {
		/*
		 * Only this notsack'ed blk is completely covered.  Delete
		 * it and return.
		 */
		if (end == tmp->end && SEQ_LEQ(begin, tmp->begin)) {
			if (prev != NULL) {
				prev->next = tmp->next;
			} else {
				*head = tmp->next;
			}
			(*num)--;
			*sum -= tmp->end - tmp->begin;
			kmem_cache_free(tcp_notsack_blk_cache, tmp);
			return;
		}
		/* This blk is partially covered. */
		if (SEQ_GEQ(begin, tmp->begin)) {
			/* Check what needs to be updated. */
			if (begin == tmp->begin) {
				*sum -= end - tmp->begin;
				tmp->begin = end;
			} else if (end == tmp->end) {
				*sum -= tmp->end - begin;
				tmp->end = begin;
				(tmp->sack_cnt)++;
			} else {
				/* Split the notsack blk. */
				if ((new = kmem_cache_alloc(
				    tcp_notsack_blk_cache, KM_NOSLEEP)) ==
				    NULL) {
					return;
				}
				new->end = tmp->end;
				new->begin = end;
				new->next = tmp->next;
				new->sack_cnt = 0;
				tmp->end = begin;
				tmp->next = new;
				(tmp->sack_cnt)++;
				(*num)++;
				*sum -= end - begin;
			}
		} else {
			*sum -= end - tmp->begin;
			tmp->begin = end;
		}
		return;
	}

	/* Need to check for coverage of this blk and later blks. */
	tmp_sum = *sum;
	tmp_num = *num;
	if (SEQ_LT(tmp->begin, begin)) {
		tmp_sum -= tmp->end - begin;
		tmp->end = begin;
		(tmp->sack_cnt)++;
		prev = tmp;
		tmp = tmp->next;
	}

	while (tmp != NULL) {
		/* The coverage stops here. */
		if (SEQ_GT(tmp->begin, end)) {
			break;
		} else {
			/* Is the blk completely or partially covered? */
			if (SEQ_LEQ(tmp->end, end)) {
				tmp_num--;
				tmp_sum -= tmp->end - tmp->begin;
				if (prev != NULL) {
					prev->next = tmp->next;
					kmem_cache_free(tcp_notsack_blk_cache,
					    tmp);
					tmp = prev->next;
				} else {
					*head = tmp->next;
					kmem_cache_free(tcp_notsack_blk_cache,
					    tmp);
					tmp = *head;
				}
			} else {
				/*
				 * This blk is partially covered.  It also
				 * means it should be the end of coverage.
				 */
				tmp_sum -= end - tmp->begin;
				tmp->begin = end;
				break;
			}
		}
	}
	*num = tmp_num;
	*sum = tmp_sum;
}


/*
 * To remove notsack'ed blks.
 *
 * Parameters:
 *	notsack_blk_t **head: address of the pointer to the list of notsack'ed
 *		blks.
 *	tcp_seq end: to remove all notsack'ed blk with seq num less than end.
 *	int32_t *num: (referenced) total num of notsack'ed blks.
 *	uint32_t *sum: (referenced) total num of bytes of all the notsack'ed
 *		blks.
 */
void
tcp_notsack_remove(notsack_blk_t **head, tcp_seq end, int32_t *num,
    uint32_t *sum)
{
	notsack_blk_t *prev, *tmp;
	uint32_t tmp_sum = *sum;

	if (*head == NULL)
		return;

	prev = NULL;
	tmp = *head;
	while (tmp != NULL) {
		/* There is nothing to discard. */
		if (SEQ_GT(tmp->begin, end)) {
			break;
		}

		/* Is the blk completely or partially covered? */
		if (SEQ_GEQ(end, tmp->end)) {
			(*num)--;
			tmp_sum -= tmp->end - tmp->begin;
			if (prev == NULL) {
				*head = tmp->next;
				kmem_cache_free(tcp_notsack_blk_cache, tmp);
				tmp = *head;
			} else {
				prev->next = tmp->next;
				kmem_cache_free(tcp_notsack_blk_cache, tmp);
				tmp = prev->next;
			}
		} else {
			tmp_sum -= end - tmp->begin;
			tmp->begin = end;
			break;
		}
	}
	*sum = tmp_sum;
}


/*
 * To update the notsack'ed list when new data is sent.
 *
 * Assumption: this should only be called when new notsack blk is to be added.
 *
 * Parameters:
 *	notsack_blk_t **head: address of the pointer to the list of notsack'ed
 *		blks.
 *	tcp_seq begin: beginning seq num of new data.
 *	tcp_seq end: ending seq num of new data.
 *	int32_t *num: (referenced) total num of notsack'ed blks.
 *	uint32_t *sum: (referenced) total num of bytes of all the notsack'ed
 *		blks.
 */
void tcp_notsack_update(notsack_blk_t **head, tcp_seq begin, tcp_seq end,
    int32_t *num, uint32_t *sum)
{
	notsack_blk_t *tmp;

	tmp = *head;
	/* If the list is empty, create a new one. */
	if (tmp == NULL) {
		if ((tmp = kmem_cache_alloc(tcp_notsack_blk_cache,
		    KM_NOSLEEP)) == NULL) {
			return;
		}
		tmp->begin = begin;
		tmp->end = end;
		tmp->next = NULL;
		tmp->sack_cnt = 0;
		*head = tmp;
		*num = 1;
		*sum = end - begin;
		return;
	}

	/*
	 * Find the place to add the new blk.  This assumes that new data
	 * is being sent, so the place to insert the new notsack blk is at
	 * the end of the list.
	 */
	while (tmp->next != NULL) {
		tmp = tmp->next;
	}

	/* Does the new blk overlap with old one? */
	if (SEQ_GEQ(tmp->end, begin)) {
		*sum += end - tmp->end;
		tmp->end = end;
	} else {
		/* No.  Need to create a new notsack blk. */
		tmp->next = kmem_cache_alloc(tcp_notsack_blk_cache, KM_NOSLEEP);
		if (tmp->next != NULL) {
			tmp = tmp->next;
			tmp->begin = begin;
			tmp->end = end;
			tmp->next = NULL;
			tmp->sack_cnt = 0;
			(*num)++;
			*sum += end - begin;
		}
	}
}
