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

#ifndef	_INET_TCP_SACK_H
#define	_INET_TCP_SACK_H

#ifdef	__cplusplus
extern "C" {
#endif

/* Maximum num of receiver's SACK blocks */
#define	MAX_SACK_BLK	5

/* Receiver's SACK blk structure */
typedef struct sack_blk
{
	tcp_seq	begin;
	tcp_seq	end;
} sack_blk_t;

/* Sender's notsack'ed blk structure */
typedef struct notsack_blk
{
	struct notsack_blk	*next;
	tcp_seq			begin;
	tcp_seq			end;
	uint32_t		sack_cnt; /* Dup SACK count */
} notsack_blk_t;


/* SACK information in the tcp_t structure. */
typedef struct
{
	int32_t	tcp_pipe;	/* # of bytes in network */
	tcp_seq	tcp_fack;	/* highest sack'ed seq num */
	tcp_seq	tcp_sack_snxt;	/* next seq num to be rexmited using SACK. */

	int32_t	tcp_max_sack_blk; /* max # of SACK info blk in a segment */
	int32_t	tcp_num_sack_blk; /* num of blks in sack list */
	sack_blk_t	tcp_sack_list[MAX_SACK_BLK]; /* the sack list */

	/* num of blks in notsack list */
	int32_t		tcp_num_notsack_blk;
	/* # of bytes represented in blks in notsack list */
	uint32_t	tcp_cnt_notsack_list;
	/* the notsack list */
	notsack_blk_t	*tcp_notsack_list;
} tcp_sack_info_t;

extern void tcp_sack_insert(sack_blk_t *, tcp_seq, tcp_seq, int32_t *);
extern void tcp_sack_remove(sack_blk_t *, tcp_seq, int32_t *);
extern void tcp_notsack_insert(notsack_blk_t **, tcp_seq, tcp_seq,
    int32_t *, uint32_t *);
extern void tcp_notsack_remove(notsack_blk_t **, tcp_seq, int32_t *,
    uint32_t *);
extern void tcp_notsack_update(notsack_blk_t **, tcp_seq, tcp_seq,
    int32_t *, uint32_t *);

/* Defined in tcp_sack.c */
extern kmem_cache_t	*tcp_notsack_blk_cache;

/*
 * Macro to remove all the notsack'ed blks in sender.
 *
 * Param:
 * notsack_blk_t *head: pointer to the head of the list of notsack'ed blks.
 */
#define	TCP_NOTSACK_REMOVE_ALL(head, tcp)			\
{								\
	if ((head) != NULL) {					\
		notsack_blk_t *prev, *tmp;			\
		tmp = (head);					\
		do  {						\
			prev = tmp;				\
			tmp = tmp->next;			\
			kmem_cache_free(tcp_notsack_blk_cache, prev); \
		} while (tmp != NULL);				\
		(head) = NULL;					\
		(tcp)->tcp_cnt_notsack_list = 0;		\
		(tcp)->tcp_num_notsack_blk = 0;			\
	} else {						\
		ASSERT((tcp)->tcp_cnt_notsack_list == 0);	\
		ASSERT((tcp)->tcp_num_notsack_blk == 0);	\
	}							\
}

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_TCP_SACK_H */
