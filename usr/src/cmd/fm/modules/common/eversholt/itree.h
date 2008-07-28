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
 *
 * itree.h -- public definitions for itree module
 *
 */

#ifndef	_EFT_ITREE_H
#define	_EFT_ITREE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* the "fault" field in the event struct requires the definition of nvlist_t */
#include <sys/fm/protocol.h>
#include <fm/fmd_api.h>

/* Numerical representation of propagation N value (A), short for All */
#define	N_IS_ALL	-1

/*
 * effects_test event cached_state bits
 * - reset on each call to effects_test()
 */
#define	CREDIBLE_EFFECT 1
#define	WAIT_EFFECT 2
#define	PARENT_WAIT 4

/*
 * arrow mark bits (for K-count)
 */
#define	EFFECTS_COUNTER 8
#define	REQMNTS_COUNTER 16

/*
 * requirements_test event cached_state bits
 */
#define	REQMNTS_CREDIBLE 32
#define	REQMNTS_DISPROVED 64
#define	REQMNTS_WAIT 128

/*
 * requirements_test bubble mark bits
 */
#define	BUBBLE_ELIDED 256
#define	BUBBLE_OK 512

/*
 * causes_test event cached_state bits
 */
#define	CAUSES_TESTED 1024

struct event {
	struct event *suspects;
	struct event *psuspects;
	struct event *observations;	/* for lists like suspect list */
	fmd_event_t *ffep;
	nvlist_t *nvp;			/* payload nvp for ereports */
	struct node *enode;		/* event node in parse tree */
	const struct ipath *ipp;	/* instanced version of event */
	struct lut *props;		/* instanced version of nvpairs */
	struct lut *payloadprops;	/* nvpairs for problem payload */
	struct lut *serdprops;		/* nvpairs for dynamic serd args */
	int count;			/* for reports, number seen */
	enum nametype t:3;		/* defined in tree.h */
	int is_suspect:1;		/* true if on suspect list */
	int keep_in_tree:1;
	int cached_state:11;
	unsigned long long cached_delay;
	struct bubble {
		struct bubble *next;
		struct event *myevent;
		int gen;		/* generation # */
		int nork;
		int mark:11;
		enum bubbletype {
			B_FROM,
			B_TO,
			B_INHIBIT
		} t:2;
		struct arrowlist {
			struct arrowlist *next;
			struct arrow {
				struct bubble *head;
				struct bubble *tail;
				/* prop node in parse tree */
				struct node *pnode;
				struct constraintlist {
					struct constraintlist *next;
					/* deferred constraints */
					struct node *cnode;
				} *constraints;
				int forever_false:1;
				int forever_true:1;
				int arrow_marked:1;
				int mark:11;
				unsigned long long mindelay;
				unsigned long long maxdelay;
			} *arrowp;
		} *arrows;
	} *bubbles;
};

/*
 * struct iterinfo is the stuff we store in the dictionary of iterators
 * when we assign a value to an iterator.  it not only contains the value
 * we assigned to the iterator, it contains a node pointer which we use to
 * determine if we're the one that defined the value when popping [vh]match()
 * recursion.
 */
struct iterinfo {
	int num;
	struct node *np;
};

struct lut *itree_create(struct config *croot);
void itree_free(struct lut *itp);
void itree_prune(struct lut *itp);
struct event *itree_lookup(struct lut *itp,
    const char *ename, const struct ipath *ipp);

struct arrowlist *itree_next_arrow(struct bubble *bubblep,
    struct arrowlist *last);
struct bubble *itree_next_bubble(struct event *eventp, struct bubble *last);
struct constraintlist *itree_next_constraint(struct arrow *arrowp,
    struct constraintlist *last);

void itree_pevent_brief(int flags, struct event *eventp);
void itree_ptree(int flags, struct lut *itp);

const char *itree_bubbletype2str(enum bubbletype t);

void itree_fini(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _EFT_ITREE_H */
