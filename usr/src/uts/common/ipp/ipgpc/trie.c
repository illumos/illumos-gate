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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ipp/ipgpc/trie.h>
#include <ipp/ipgpc/filters.h>
#include <ipp/ipgpc/classifier.h>
#include <inet/ip6.h>

/* trie data structure used for classifying IP addresses and TCP/UDP ports */

#define	ZERO	0
#define	ONE	1


/* Statics */
static void t_split(node_t **, uint8_t, uint8_t);
static boolean_t t_traverse_delete(node_t **, uint8_t, key_t, uint32_t,
    uint32_t, trie_id_t **);

/*
 * create_node(flag)
 *
 * generates a pointer to a new trie node
 * flag is passed to kmem_alloc
 * returns NULL to signify memory error
 */
node_t *
create_node(int flag)
{
	node_t *buf = kmem_cache_alloc(trie_node_cache, flag);

	if (buf == NULL) {
		return (NULL);
	}
	buf->elements = NULL;
	buf->zero = NULL;
	buf->one = NULL;
	buf->pos = 0;
	buf->bits = 0;
	buf->val = 0;
	buf->mask = 0;
	buf->isroot = 0;
	return (buf);
}


/*
 * t_split(c_node, pos, key_len)
 *
 * performs a split on c_node for the following three cases:
 * 1 a mismatch occured between the insert key and the value at the node
 * 2 the insert key specifies a shorter key than the one at the node
 * 3 the insert key specifies a longer key than the one at the node
 * cases 1 and 2 are handled in the same way
 * when t_split returns, c_node->one and c_node->zero must != NULL
 *
 * (note: we assume a key_len = n (where in the real world n = 16 | 32),
 *  and a "key" in this example is actaully some value of key_len n that
 *  has its high order bits masked.
 *  For example: key = 1011 with key_len = 8, would actaully be the key:mask
 *  combo 1011xxxx:11110000.  I am using short keys for ease of example)
 * Case 1 and 2:
 *
 * assume 8 bit keys for all examples
 *
 * trie A contains keys 111011, 0, 10
 *       *
 *      / \
 *         *
 *        / \
 *        *  * bits = 4 pos = 5 val = 1011 mask = 00111100
 * inserting 111100 would result in the following split
 *                       *
 *                      / \
 *                         *
 *                        / \
 *                           *  bits = 1 pos = 5 val = 1 mask = 00100000
 *                          / \
 *  bits = 2 pos = 3 val=11*   * (to be inserted: (bits = 2 pos = 3 val = 00
 *  mask = 00001100                               mask = 00001100))
 *
 * Case 3:
 *
 * trie A same as above, before insert
 * inserting key 11101111 would results in the following split
 *       *
 *      / \
 *         *
 *        / \
 *        *  * bits = 4 pos = 5 val = 1011 mask = 00111100
 *          / \
 *         *   *  (to be inserted: bits = 1 pos = 0 val = 1 mask = 00000001)
 */
/* ARGSUSED */
static void
t_split(node_t **c_node, uint8_t pos, uint8_t key_len)
{
	uint8_t old_bits = 0;
	uint8_t i;
	int bit;
	node_t *nodep = *c_node;
	node_t *tnodep = NULL;

	/* check if case is that the mask is longer */
	if (pos == (nodep->pos - nodep->bits)) {
		/* pos is past the last bit covered at this node */
		ASSERT(nodep->one == NULL);
		ASSERT(nodep->zero == NULL);
		nodep->one = create_node(KM_SLEEP);
		nodep->zero = create_node(KM_SLEEP);
	} else {		/* pos > (nodep->pos - nodep->bits) */
		old_bits = nodep->bits; /* save old bits entry */
		/* nodep->pos will remain the same */
		nodep->bits = nodep->pos - pos;
		/* find the mismatch bit */
		bit = EXTRACTBIT(nodep->val, pos, key_len);
		if (bit == ZERO) {
			if ((nodep->one == NULL) && (nodep->zero == NULL)) {
				nodep->one = create_node(KM_SLEEP);
				nodep->zero = create_node(KM_SLEEP);
			} else {
				tnodep = create_node(KM_SLEEP);
				tnodep->one = nodep->one;
				tnodep->zero = nodep->zero;
				nodep->zero = tnodep;
				nodep->one = create_node(KM_SLEEP);
			}
			/* pos is before the last bit covered at this node */
			nodep->zero->pos = pos - 1; /* link is one bit */
			/* bits gets remaining bits minus the link */
			nodep->zero->bits = (old_bits - nodep->bits) - 1;
			/* set bits that are covered by this node */
			for (i = 0; i < nodep->zero->bits; ++i) {
				SETBIT(nodep->zero->val,
				    (nodep->zero->pos - i),
				    EXTRACTBIT(nodep->val,
					(nodep->zero->pos - i), key_len),
				    key_len);
				SETBIT(nodep->zero->mask,
				    (nodep->zero->pos - i), 1, key_len);
			}
			nodep->zero->elements = nodep->elements;
			nodep->elements = NULL;
		} else {	/* bit == ONE */
			if ((nodep->one == NULL) && (nodep->zero == NULL)) {
				nodep->one = create_node(KM_SLEEP);
				nodep->zero = create_node(KM_SLEEP);
			} else {
				tnodep = create_node(KM_SLEEP);
				tnodep->one = nodep->one;
				tnodep->zero = nodep->zero;
				nodep->one = tnodep;
				nodep->zero = create_node(KM_SLEEP);
			}
			/* pos is before the last bit covered at this node */
			nodep->one->pos = pos - 1; /* link is one bit */
			/* bits gets remaining bits minus the link */
			nodep->one->bits = (old_bits - nodep->bits) - 1;
			/* set bits that are covered by this node */
			for (i = 0; i < nodep->one->bits; ++i) {
				SETBIT(nodep->one->val, (nodep->one->pos - i),
				    EXTRACTBIT(nodep->val,
					(nodep->one->pos - i), key_len),
				    key_len);
				SETBIT(nodep->one->mask,
				    (nodep->one->pos - i), 1, key_len);
			}
			nodep->one->elements = nodep->elements;
			nodep->elements = NULL;
		}

		/* clear bits no longer covered by this node, from pos=>0 */
		for (i = 0; i <= pos; ++i) {
			UNSETBIT(nodep->val, i, key_len);
			UNSETBIT(nodep->mask, i, key_len);
		}
	}
}

/*
 * t_insert(tid, id, key, mask)
 *
 * inserts a new value, id, into the trie, tid->trie with the input key
 * - if node exists, id is appended to element list at the node, if id does
 *   not already exist.
 * - if node does not exist, a new node is created and id is the head of a new
 *   element list
 * return DONTCARE_VALUE if mask == 0, otherwise NORMAL_VALUE
 */
int
t_insert(trie_id_t *tid, key_t id, uint32_t key, uint32_t mask)
{
	node_t *c_node;
	int bit;
	uint8_t pos;
	uint8_t key_len = (uint8_t)tid->key_len;

	/* don't insert if don't care */
	if (mask == 0) {
		++tid->stats.num_dontcare;
		return (DONTCARE_VALUE);
	}

	rw_enter(&tid->rw_lock, RW_WRITER);
	c_node = tid->trie;	/* point at trie root */
	key &= mask;		/* apply mask */
	/* traverse trie to the correct position */
	for (pos = key_len; pos > 0; --pos) {
		/* check if bit is significant */
		/* bit in key is significant if it is covered by the mask */
		if (EXTRACTBIT(mask, (pos - 1), key_len) != 1) {
			/* check if this is a path compressed internal node */
			if (c_node->bits > 0) {
				/* check if split is needed */
				if ((pos - 1) > (c_node->pos - c_node->bits)) {
					t_split(&c_node, (pos - 1), key_len);
					ASSERT(c_node->one != NULL);
					ASSERT(c_node->zero != NULL);
				}
			}
			break;
		}
		/* extra bit at current position */
		bit = EXTRACTBIT(key, (pos - 1), key_len);
		/* check if this is a path compressed internal node */
		if (c_node->bits > 0) { /* path compressed node */
			/* check if split is needed */
			if ((pos - 1) > (c_node->pos - c_node->bits)) {
				/* testing for mismatch */
				if (bit != EXTRACTBIT(c_node->val, (pos - 1),
				    key_len)) {
					t_split(&c_node, (pos - 1), key_len);
					ASSERT(c_node->one != NULL);
					ASSERT(c_node->zero != NULL);
				} else {
					continue; /* bits match, so go on */
				}
			} else if ((pos - 1) == (c_node->pos - c_node->bits)) {
				/* check if at a leaf node with elements */
				if ((c_node->one == NULL) &&
				    (c_node->zero == NULL) &&
				    (c_node->elements != NULL)) {
					/*
					 * this case occurs when mask for key
					 * is longer than mask for key at
					 * current node
					 */
					t_split(&c_node, (pos - 1), key_len);
					ASSERT(c_node->one != NULL);
					ASSERT(c_node->zero != NULL);
				}
			} /* else continue onto child */
		}
		if (bit == ZERO) {
			if (c_node->zero == NULL) { /* leaf node */
				if (c_node->bits == 0) {
					c_node->pos = (pos - 1);
				}
				c_node->bits++;
				/* bit at pos for node value should be 0 */
				UNSETBIT(c_node->val, (pos - 1), key_len);
				SETBIT(c_node->mask, (pos - 1), 1, key_len);
			} else {
				/* assert that trie is path compressed */
				ASSERT(c_node->one != NULL);
				c_node = c_node->zero; /* internal node */
			}
		} else {	/* ONE bit */
			if (c_node->one == NULL) { /* leaf node */
				if (c_node->bits == 0) {
					c_node->pos = (pos - 1);
				}
				c_node->bits++;
				/* bit at pos for node value should be 1 */
				SETBIT(c_node->val, (pos - 1), 1, key_len);
				SETBIT(c_node->mask, (pos - 1), 1, key_len);
			} else {
				/* assert that trie is path compressed */
				ASSERT(c_node->zero != NULL);
				c_node = c_node->one; /* internal node */
			}
		}
	}
	/* insert at node */
	(void) ipgpc_list_insert(&c_node->elements, id);
	/* update stats */
	++tid->stats.num_inserted;
	/*
	 * check if this is the first key to be inserted that is not a
	 * don't care (*)
	 */
	if (tid->info.dontcareonly == B_TRUE) {
		tid->info.dontcareonly = B_FALSE;
	}
	rw_exit(&tid->rw_lock);
	return (NORMAL_VALUE);
}

/*
 * t_insert6(tid, id, key, mask)
 *
 * specific to inserting keys of 128 bits in length
 */
int
t_insert6(trie_id_t *tid, key_t id, in6_addr_t key, in6_addr_t mask)
{
	node_t *c_node;
	int bit, i;
	uint8_t pos;
	uint8_t type_len = IP_ABITS;
	in6_addr_t zero_addr = IN6ADDR_ANY_INIT;

	/* don't insert if don't care */
	if (IN6_ARE_ADDR_EQUAL(&mask, &zero_addr)) {
		++tid->stats.num_dontcare;
		return (DONTCARE_VALUE);
	}

	rw_enter(&tid->rw_lock, RW_WRITER);
	c_node = tid->trie;	/* point at root of trie */
	V6_MASK_COPY(key, mask, key); /* apply mask to key */
	/*
	 * A IPv6 address is structured as an array of four uint32_t
	 * values.  The highest order of the bits are located in array[0]
	 */
	for (i = 0; i < 4; ++i) {
		/* traverse trie to the correct position */
		for (pos = type_len; pos > 0; --pos) {
			/* check if bit is significant */
			if (EXTRACTBIT(mask.s6_addr32[i], (pos - 1), type_len)
			    != ONE) {
				break;
			}
			bit = EXTRACTBIT(key.s6_addr32[i], (pos - 1), type_len);
			if (bit == ZERO) {
				if (c_node->zero == NULL) {
					c_node->zero = create_node(KM_SLEEP);
				}
				c_node = c_node->zero;
			} else {	/* ONE bit */
				if (c_node->one == NULL) {
					c_node->one = create_node(KM_SLEEP);
				}
				c_node = c_node->one;
			}

		}
	}
	/* insert at node */
	(void) ipgpc_list_insert(&c_node->elements, id);
	/* update stats */
	++tid->stats.num_inserted;
	/*
	 * check if this is the first key to be inserted that is not a
	 * don't care (*)
	 */
	if (tid->info.dontcareonly == B_TRUE) {
		tid->info.dontcareonly = B_FALSE;
	}
	rw_exit(&tid->rw_lock);
	return (NORMAL_VALUE);
}

/*
 * t_traverse_delete(in_node, pos, id, key, mask, tid)
 *
 * used to traverse to the node containing id, as found under key
 * once id is found, it is removed from the trie.
 * Upon removing the id from a given node in the trie, path compression
 * will be applied to nodes that are no longer compressed.
 * If the id is successfully removed, tid->stats are updated
 */
static boolean_t
t_traverse_delete(node_t **in_node, uint8_t pos, key_t id, uint32_t key,
    uint32_t mask, trie_id_t **tid)
{
	node_t *c_node = *in_node;
	node_t *t_node;
	int bit;

	if (c_node == NULL) {
		return (B_FALSE); /* base failure case */
	}

	/* we've found the node the id is probably at */
	if ((pos == 0) ||
	    (EXTRACTBIT(mask, (pos - 1), (uint8_t)(*tid)->key_len) != 1)) {
		if (ipgpc_list_remove(&c_node->elements, id) == B_FALSE) {
			ipgpc0dbg(("t_traverse_delete: id %d does not " \
			    "exist in trie\n", id));
			return (B_FALSE); /* key does not exist at node */
		} else {
			/* update stats */
			--(*tid)->stats.num_inserted;
			/* check if 0 values are inserted in this trie */
			if ((*tid)->stats.num_inserted == 0) {
				/* update dontcareonly boolean */
				(*tid)->info.dontcareonly = B_TRUE;
			}
		}
		/* check if node has zero elements, is a LEAF node */
		if ((c_node->elements == NULL) &&
		    ((c_node->one == NULL) && (c_node->zero == NULL))) {
			/* make sure we don't delete the root */
			if (c_node->isroot != 1) {
				kmem_cache_free(trie_node_cache, c_node);
				return (B_TRUE);
			} else {
				/* this is the root, just zero out the info */
				c_node->pos = 0;
				c_node->bits = 0;
				c_node->val = 0;
				c_node->mask = 0;
			}
		}
		return (B_FALSE);
	}

	/* check to see if node describes bits to skip */
	if (c_node->bits > 0) {
		if ((key & c_node->mask) != c_node->val) {
			ipgpc0dbg(("t_traverse_delete: id %d does not " \
			    "exist in trie\n", id));
			return (B_FALSE); /* key does not exist at node */
		}
		pos = (c_node->pos - c_node->bits) + 1;
		/* search should continue if mask and pos are valid */
		if ((pos == 0) ||
		    (EXTRACTBIT(mask, (pos - 1), (uint8_t)(*tid)->key_len)
			!= 1)) {
			/* this node probably contains the id */
			if (ipgpc_list_remove(&c_node->elements,
			    id) == B_FALSE) {
				ipgpc0dbg(("t_traverse_delete: id %d does" \
				    "not exist in trie\n", id));
				return (B_FALSE);
			} else {
				/* update stats */
				--(*tid)->stats.num_inserted;
				/* check if 0 values are inserted */
				if ((*tid)->stats.num_inserted == 0) {
					/* update dontcare boolean */
					(*tid)->info.dontcareonly = B_TRUE;
				}
			}
			/* check if node has zero elements & is a LEAF node */
			if ((c_node->elements == NULL) &&
			    ((c_node->one == NULL) &&
				(c_node->zero == NULL))) {
				/* make sure we don't delete the root */
				if (c_node->isroot != 1) {
					kmem_cache_free(trie_node_cache,
					    c_node);
					return (B_TRUE);
				} else {
					/* this is the root, zero out info */
					c_node->pos = 0;
					c_node->bits = 0;
					c_node->val = 0;
					c_node->mask = 0;
				}
			}
			return (B_FALSE);
		}
	}
	/* extract next bit and test */
	bit = EXTRACTBIT(key, (pos - 1), (uint8_t)(*tid)->key_len);
	if (bit == ZERO) {
		if (t_traverse_delete(&c_node->zero, (pos - 1), id, key, mask,
		    tid) == B_TRUE) {
			c_node->zero = NULL;
		}
	} else {	/* ONE bit */
		if (t_traverse_delete(&c_node->one, (pos - 1), id, key, mask,
		    tid) == B_TRUE) {
			c_node->one = NULL;
		}
	}
	/*
	 * non path-compressed nodes will contain one child and no elements
	 * what occurs here:
	 *	  *
	 *	 / \
	 *	*   *  <-- p_node->elements == NULL
	 *	   /
	 *	  *  <-- c_node->elements = foo
	 *	 / \
	 *	*   *  <-- children of c_node
	 * after:
	 *	  *
	 *	 / \
	 *	*   *   <-- p_node->elements = foo
	 *	   / \
	 *	  *   *  <-- p_node adopts children of c_node
	 */
	if ((c_node->one == NULL) && (c_node->zero != NULL)) {
		if (c_node->elements == NULL) {
			/* move child elements to parent */
			c_node->elements = c_node->zero->elements;
			/* be sure to include the link in the bits */
			c_node->bits += c_node->zero->bits + 1;
			/* c_node->pos will remain the same */
			c_node->mask |= c_node->zero->mask;
			/* don't forget to mark the link */
			SETBIT(c_node->mask, (pos - 1), 1,
			    (uint8_t)(*tid)->key_len);
			c_node->val |= c_node->zero->val;
			/* don't forget to mark the link  */
			UNSETBIT(c_node->val, (pos - 1),
			    (uint8_t)(*tid)->key_len);
			/* adopt children */
			t_node = c_node->zero;
			c_node->one = c_node->zero->one;
			c_node->zero = c_node->zero->zero;
			kmem_cache_free(trie_node_cache, t_node);
		} else {
			ASSERT(c_node->zero->one == NULL);
			ASSERT(c_node->zero->zero == NULL);
			kmem_cache_free(trie_node_cache, c_node->zero);
			c_node->zero = NULL;
		}
	} else if ((c_node->one != NULL) && (c_node->zero == NULL)) {
		if (c_node->elements == NULL) {
			/* move child elements to parent */
			c_node->elements = c_node->one->elements;
			/* be sure to include the link in the bits */
			c_node->bits += c_node->one->bits + 1;
			/* c_node->pos will remain the same */
			c_node->mask |= c_node->one->mask;
			/* don't forget to mark the link */
			SETBIT(c_node->mask, (pos - 1), 1,
			    (uint8_t)(*tid)->key_len);
			c_node->val |= c_node->one->val;
			/* don't forget to mark the link  */
			SETBIT(c_node->val, (pos - 1), 1,
			    (uint8_t)(*tid)->key_len);
			/* adopt children */
			t_node = c_node->one;
			c_node->zero = c_node->one->zero;
			c_node->one = c_node->one->one;
			kmem_cache_free(trie_node_cache, t_node);
		} else {
			ASSERT(c_node->one->one == NULL);
			ASSERT(c_node->one->zero == NULL);
			kmem_cache_free(trie_node_cache, c_node->one);
			c_node->one = NULL;
		}
	}
	/* check if node has zero elements, is a LEAF node */
	if ((c_node->elements == NULL) &&
	    ((c_node->one == NULL) && (c_node->zero == NULL))) {
		/* make sure we don't delete the root */
		if (c_node->isroot != 1) {
			kmem_cache_free(trie_node_cache, c_node);
			return (B_TRUE);
		} else {
			/* this is the root, just zero out the info */
			c_node->pos = 0;
			c_node->bits = 0;
			c_node->val = 0;
			c_node->mask = 0;
		}
	}
	return (B_FALSE);
}



/*
 * t_remove(tid, id, key, mask)
 *
 * removes a value associated with an id from the trie
 * - if the item does not exist, nothing is removed
 * - if more than one id share the same key, only the id specified is removed
 */
void
t_remove(trie_id_t *tid, key_t id, uint32_t key, uint32_t mask)
{
	node_t *c_node;

	/* don't cares are not inserted */
	if (mask == 0) {
		--tid->stats.num_dontcare;
		return;
	}

	key &= mask;		/* apply mask */
	/* traverse to node containing id and remove the id from the trie */
	rw_enter(&tid->rw_lock, RW_WRITER);
	c_node = tid->trie;
	(void) t_traverse_delete(&c_node, (uint8_t)tid->key_len, id, key, mask,
	    &tid);
	rw_exit(&tid->rw_lock);
}

/*
 * t_remove6(tid, id, key, mask)
 *
 * specific to removing key of 128 bits in length
 */
void
t_remove6(trie_id_t *tid, key_t id, in6_addr_t key, in6_addr_t mask)
{
	node_t *c_node;
	int bit, i;
	uint8_t pos;
	uint8_t type_len = IP_ABITS;
	in6_addr_t zero_addr = IN6ADDR_ANY_INIT;

	/* don't cares are not inserted */
	if (IN6_ARE_ADDR_EQUAL(&mask, &zero_addr)) {
		--tid->stats.num_dontcare;
		return;
	}

	rw_enter(&tid->rw_lock, RW_WRITER);
	c_node = tid->trie;	/* point at root of trie */
	V6_MASK_COPY(key, mask, key);
	/*
	 * A IPv6 address is structured as an array of four uint32_t
	 * values.  The higest order of the bits are located in array[0]
	 */
	for (i = 0; i < 4; ++i) {
		/* traverse trie to the correct position */
		for (pos = type_len; pos > 0; --pos) {
			/* check if bit is significant */
			if (EXTRACTBIT(mask.s6_addr32[i], (pos - 1), type_len)
			    != ONE) {
				break;
			}
			bit = EXTRACTBIT(key.s6_addr32[i], (pos - 1), type_len);
			if (bit == ZERO) {
				if (c_node->zero == NULL) {
					break;
				}
				c_node = c_node->zero;
			} else {	/* ONE bit */
				if (c_node->one == NULL) {
					break;
				}
				c_node = c_node->one;
			}

		}
	}
	if (c_node != NULL) {
		if (ipgpc_list_remove(&c_node->elements, id)) {
			/* update stats */
			--tid->stats.num_inserted;
			/*
			 * check to see if only dontcare's are inserted
			 */
			if (tid->stats.num_inserted <= 0) {
				tid->info.dontcareonly = B_TRUE;
			}
		}
	}
	rw_exit(&tid->rw_lock);
}


/*
 * t_retrieve(tid, key, fid_table)
 *
 * returns the number of found filters that match the input key
 * - each value that matches either a partial or exact match on the key
 *   is inserted into the fid_table
 * - some nodes may contain multiple id's, all items will be inserted
 *   into the fid_table
 * - the find stops when an edge node is reached, the left and right nodes
 *   for the current node are null
 * - 0 is returned if no matches are found, otherwise the number of matches
 *   is returned
 * - (-1) is returned if a memory error occurred
 */
int
t_retrieve(trie_id_t *tid, uint32_t key, ht_match_t *fid_table)
{
	int bit;
	uint8_t pos;
	int num_found = 0;
	int ret;
	node_t *c_node;

	rw_enter(&tid->rw_lock, RW_READER);
	c_node = tid->trie;	/* point at root of trie */

	/* ensure trie structure is allocated */
	if (c_node == NULL) {
		rw_exit(&tid->rw_lock);
		return (num_found);
	}
	/*
	 * foreach node encountered in the search, collect elements and append
	 * to a list to be returned
	 */
	for (pos = (uint8_t)tid->key_len; pos > 0; --pos) {
		/* check node for bits to check */
		if (c_node->bits > 0) {
			if ((key & c_node->mask) != c_node->val) {
				rw_exit(&tid->rw_lock);
				return (num_found); /* search is done */
			}
			/* pos is set to next bit not covered by node */
			if ((pos = (c_node->pos - c_node->bits) + 1) == 0) {
				/* if node covers rest of bits in key */
				break;
			}
		}
		/* check node for elements */
		if (c_node->elements != NULL) {
			if ((ret = ipgpc_mark_found(tid->info.mask,
			    c_node->elements, fid_table)) == -1) {
				/* signifies a memory error */
				rw_exit(&tid->rw_lock);
				return (-1);
			}
			num_found += ret; /* increment num_found */
		}

		bit = EXTRACTBIT(key, (pos - 1), (uint8_t)tid->key_len);
		if (bit == ZERO) { /* choose leaf */
			c_node = c_node->zero;

		} else {	/* bit == ONE */
			c_node = c_node->one;

		}
		if (c_node == NULL) {
			/* search is finished, edge node reached */
			rw_exit(&tid->rw_lock);
			return (num_found);
		}
	}
	/* see if current node contains elements */
	if (c_node->elements != NULL) {
		if ((ret = ipgpc_mark_found(tid->info.mask, c_node->elements,
		    fid_table)) == -1) {
			rw_exit(&tid->rw_lock);
			return (-1); /* signifies a memory error */
		}
		num_found += ret; /* increment num_found */
	}
	rw_exit(&tid->rw_lock);
	return (num_found);
}

/*
 * t_retrieve6(tid, key, fid_table)
 *
 * specific to retrieving keys of 128 bits in length
 */
int
t_retrieve6(trie_id_t *tid, in6_addr_t key, ht_match_t *fid_table)
{
	int bit, i;
	uint8_t pos;
	int num_found = 0;
	int ret;
	node_t *c_node;
	uint8_t type_len = IP_ABITS;

	rw_enter(&tid->rw_lock, RW_READER);
	c_node = tid->trie;

	/* ensure trie structure is allocated */
	if (c_node == NULL) {
		rw_exit(&tid->rw_lock);
		return (num_found);
	}
	/*
	 * A IPv6 address is structured as an array of four uint32_t
	 * values.  The higest order of the bits are located in array[0]
	 */
	for (i = 0; i < 4; ++i) {
		/*
		 * foreach node encountered in the search, collect elements
		 * and append to a list to be returned
		 */
		for (pos = type_len; pos > 0; --pos) {
			/* extract bit at pos */
			bit =
			    EXTRACTBIT(key.s6_addr32[i], (pos - 1), type_len);
			if (bit == ZERO) { /* choose leaf */
				c_node = c_node->zero;

			} else {
				c_node = c_node->one;

			}
			if (c_node == NULL) {
				/* search is finished, edge node reached */
				rw_exit(&tid->rw_lock);
				return (num_found);
			}
			/* see if current node contains elements */
			if (c_node->elements != NULL) {
				if ((ret = ipgpc_mark_found(tid->info.mask,
				    c_node->elements, fid_table)) == -1) {
					/* signifies a memory error */
					rw_exit(&tid->rw_lock);
					return (-1);
				}
				num_found += ret; /* increment num_found */
			}
		}
	}
	rw_exit(&tid->rw_lock);
	return (num_found);
}
