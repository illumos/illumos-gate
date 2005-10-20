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
 * Copyright 1986 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * file: malloc.c
 * description:
 *	Yet another memory allocator, this one based on a method
 *	described in C.J. Stephenson, "Fast Fits"
 *
 *	The basic data structure is a "Cartesian" binary tree, in which
 *	nodes are ordered by ascending addresses (thus minimizing free
 *	list insertion time) and block sizes decrease with depth in the
 *	tree (thus minimizing search time for a block of a given size).
 *
 *	In other words: for any node s, let D(s) denote the set of
 *	descendents of s; for all x in D(left(s)) and all y in
 *	D(right(s)), we have:
 *
 *	a. addr(x) <  addr(s) <  addr(y)
 *	b. len(x)  <= len(s)  >= len(y)
 */

#include "mallint.h"
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>

/* system interface */

extern	char	*sbrk();
extern	int	getpagesize();

static	int	nbpg = 0;	/* set by calling getpagesize() */
static	bool	morecore(uint);	/* get more memory into free space */

#ifdef	S5EMUL
#define	ptr_t		void *	/* ANSI C says these are voids */
#define	free_t		void	/* ANSI says void free(ptr_t ptr) */
#define	free_return(x)	return
#else
#define	ptr_t		char *	/* BSD still (4.3) wants char*'s */
#define	free_t		int	/* BSD says int free(ptr_t ptr) */
#define	free_return(x)	return(x)
#endif

/* SystemV-compatible information structure */
#define INIT_MXFAST 0
#define INIT_NLBLKS 100
#define INIT_GRAIN ALIGNSIZ

struct	mallinfo __mallinfo = {
	0,0,0,0,0,0,0,0,0,0,			/* basic info */
	INIT_MXFAST, INIT_NLBLKS, INIT_GRAIN,	/* mallopt options */
	0,0,0
};

/* heap data structures */

Freehdr	_root	= NIL;			/* root of free space list */
char	*_lbound = NULL;		/* lower bound of heap */
char	*_ubound = NULL;		/* upper bound of heap */

/* free header list management */

static	Freehdr	getfreehdr(void);
static	void	putfreehdr(Freehdr);
static	Freehdr	freehdrptr = NIL;	/* ptr to block of available headers */
static	int	nfreehdrs = 0;		/* # of headers in current block */
static	Freehdr	freehdrlist = NIL;	/* List of available headers */

/* error checking */
static void	error(char *, ...);
/* sets errno; prints msg and aborts if DEBUG is on */

static int	reclaim(Dblk, uint, int);

#ifdef	DEBUG	/*	>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> */

int	malloc_debug(int);
int	malloc_verify(void);
static	int debug_level = 1;

/*
 * A block with a negative size, a size that is not a multiple
 * of ALIGNSIZ, a size greater than the current extent of the
 * heap, or a size which extends beyond the end of the heap is
 * considered bad.
 */

#define badblksize(p,size)\
( (size) < SMALLEST_BLK \
	|| (size) & (ALIGNSIZ-1) \
	|| (size) > heapsize() \
	|| ((char*)(p))+(size) > _ubound )

#else	/* !DEBUG	================================================= */

#define malloc_debug(level) 0
#define malloc_verify() 1
#define debug_level 0
#define badblksize(p,size) 0

#endif	/* !DEBUG	<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< */


/*
 * insert (newblk, len)
 *	Inserts a new node in the free space tree, placing it
 *	in the correct position with respect to the existing nodes.
 *
 * algorithm:
 *	Starting from the root, a binary search is made for the new
 *	node. If this search were allowed to continue, it would
 *	eventually fail (since there cannot already be a node at the
 *	given address); but in fact it stops when it reaches a node in
 *	the tree which has a length less than that of the new node (or
 *	when it reaches a null tree pointer).
 *
 *	The new node is then inserted at the root of the subtree for
 *	which the shorter node forms the old root (or in place of the
 *	null pointer).
 *
 * Arguments
 *	newblk:	Ptr to the block to insert
 *	len:	Length of new node
 */

static void
insert(Dblk newblk, uint len)
{
	Freehdr *fpp;		/* Address of ptr to subtree */
	Freehdr x;
	Freehdr *left_hook;	/* Temp for insertion */
	Freehdr *right_hook;	/* Temp for insertion */
	Freehdr newhdr;

	/*
	 * check for bad block size.
	 */
	if ( badblksize(newblk,len) ) {
		error("insert: bad block size (%d) at %#x\n", len, newblk);
		return;
	}

	/*
	 * Search for the first node which has a weight less
	 *	than that of the new node; this will be the
	 *	point at which we insert the new node.
	 */
	fpp = &_root;
	x = *fpp;
	while (weight(x) >= len) {	
		if (newblk < x->block)
			fpp = &x->left;
		else
			fpp = &x->right;
		x = *fpp;
	}

	/*
	 * Perform root insertion. The variable x traces a path through
	 *	the fpp, and with the help of left_hook and right_hook,
	 *	rewrites all links that cross the territory occupied
	 *	by newblk.
	 */ 

	if ((newhdr = getfreehdr()) == NIL) {
		/* Error message returned by getfreehdr() */
		return;
	}
	*fpp = newhdr;

	newhdr->left = NIL;
	newhdr->right = NIL;
	newhdr->block = newblk;
	newhdr->size = len;

	/*
	 * set length word in the block for consistency with the header.
	 */

	newblk->size = len;

	left_hook = &newhdr->left;
	right_hook = &newhdr->right;

	while (x != NIL) {
		/*
		 * Remark:
		 *	The name 'left_hook' is somewhat confusing, since
		 *	it is always set to the address of a .right link
		 *	field.  However, its value is always an address
		 *	below (i.e., to the left of) newblk. Similarly
		 *	for right_hook. The values of left_hook and
		 *	right_hook converge toward the value of newblk,
		 *	as in a classical binary search.
		 */
		if (x->block < newblk) {
			/*
			 * rewrite link crossing from the left
			 */
			*left_hook = x;
			left_hook = &x->right;
			x = x->right;
		} else {
			/*
			 * rewrite link crossing from the right
			 */
			*right_hook = x;
			right_hook = &x->left;
			x = x->left;
		} /*else*/
	} /*while*/

	*left_hook = *right_hook = NIL;		/* clear remaining hooks */

} /*insert*/

/*
 * delete(p)
 *	deletes a node from a cartesian tree. p is the address of
 *	a pointer to the node which is to be deleted.
 *
 * algorithm:
 *	The left and right branches of the node to be deleted define two
 *	subtrees which are to be merged and attached in place of the
 *	deleted node.  Each node on the inside edges of these two
 *	subtrees is examined and longer nodes are placed above the
 *	shorter ones.
 *
 * On entry:
 *	*p is assumed to be non-null.
 */
static void
delete(Freehdr *p)
{
	Freehdr x;
	Freehdr left_branch;	/* left subtree of deleted node */
	Freehdr right_branch;	/* right subtree of deleted node */
	uint left_weight;
	uint right_weight;

	x = *p;
	left_branch = x->left;
	left_weight = weight(left_branch);
	right_branch = x->right;
	right_weight = weight(right_branch);

	while (left_branch != right_branch) {	
		/*
		 * iterate until left branch and right branch are
		 * both NIL.
		 */
		if ( left_weight >= right_weight ) {
			/*
			 * promote the left branch
			 */
			if (left_branch != NIL) {
				if (left_weight == 0) {
					/* zero-length block */
					error("blocksize=0 at %#x\n",
						(int)left_branch->block->data);
					break;
				}
				*p = left_branch;
				p = &left_branch->right;
				left_branch = *p;
				left_weight = weight(left_branch);
			}
		} else {
			/*
			 * promote the right branch
			 */
			if (right_branch != NIL) {
				if (right_weight == 0) {
					/* zero-length block */
					error("blocksize=0 at %#x\n",
						(int)right_branch->block->data);
					break;
				}
				*p = right_branch;
				p = &right_branch->left;
				right_branch = *p;
				right_weight = weight(right_branch);
			}
		}/*else*/
	}/*while*/
	*p = NIL;
	putfreehdr(x);
} /*delete*/


/*
 * demote(p)
 *	Demotes a node in a cartesian tree, if necessary, to establish
 *	the required vertical ordering.
 *
 * algorithm:
 *	The left and right subtrees of the node to be demoted are to
 *	be partially merged and attached in place of the demoted node.
 *	The nodes on the inside edges of these two subtrees are
 *	examined and the longer nodes are placed above the shorter
 *	ones, until a node is reached which has a length no greater
 *	than that of the node being demoted (or until a null pointer
 *	is reached).  The node is then attached at this point, and
 *	the remaining subtrees (if any) become its descendants.
 *
 * on entry:
 *   a. All the nodes in the tree, including the one to be demoted,
 *	must be correctly ordered horizontally;
 *   b. All the nodes except the one to be demoted must also be
 *	correctly positioned vertically.  The node to be demoted
 *	may be already correctly positioned vertically, or it may
 *	have a length which is less than that of one or both of
 *	its progeny.
 *   c. *p is non-null
 */

static void
demote(Freehdr *p)
{
	Freehdr x;		/* addr of node to be demoted */
	Freehdr left_branch;
	Freehdr right_branch;
	uint	left_weight;
	uint	right_weight;
	uint	x_weight;

	x = *p;
	x_weight = weight(x);
	left_branch = x->left;
	right_branch = x->right;
	left_weight = weight(left_branch);
	right_weight = weight(right_branch);

	while (left_weight > x_weight || right_weight > x_weight) {
		/*
		 * select a descendant branch for promotion
		 */
		if (left_weight >= right_weight) {
			/*
			 * promote the left branch
			 */
			*p = left_branch;
			p = &left_branch->right;
			left_branch = *p;
			left_weight = weight(left_branch);
		} else {
			/*
			 * promote the right branch
			 */
			*p = right_branch;
			p = &right_branch->left;
			right_branch = *p;
			right_weight = weight(right_branch);
		} /*else*/
	} /*while*/

	*p = x;				/* attach demoted node here */
	x->left = left_branch;
	x->right = right_branch;

} /*demote*/


/*
 * char*
 * malloc(nbytes)
 *	Allocates a block of length specified in bytes.  If nbytes is
 *	zero, a valid pointer (that should not be dereferenced) is returned.
 *
 * algorithm:
 *	The freelist is searched by descending the tree from the root
 *	so that at each decision point the "better fitting" branch node
 *	is chosen (i.e., the shorter one, if it is long enough, or
 *	the longer one, otherwise).  The descent stops when both
 *	branch nodes are too short.
 *
 * function result:
 *	Malloc returns a pointer to the allocated block. A null
 *	pointer indicates an error.
 *
 * diagnostics:
 *
 *	ENOMEM: storage could not be allocated.
 *
 *	EINVAL: either the argument was invalid, or the heap was found
 *	to be in an inconsistent state.  More detailed information may
 *	be obtained by enabling range checks (cf., malloc_debug()).
 *
 * Note: In this implementation, each allocated block includes a
 *	length word, which occurs before the address seen by the caller.
 *	Allocation requests are rounded up to a multiple of wordsize.
 */

ptr_t
malloc(uint nbytes)
{
	Freehdr allocp;	/* ptr to node to be allocated */
	Freehdr *fpp;		/* for tree modifications */
	Freehdr left_branch;
	Freehdr right_branch;
	uint	 left_weight;
	uint	 right_weight;
	Dblk	 retblk;		/* block returned to the user */

	/*
	 * if rigorous checking was requested, do it.
	 */
	if (debug_level >= 2) {
		malloc_verify();
	}

	/*
	 * add the size of a length word to the request, and
	 * guarantee at least one word of usable data.
	 */
	nbytes += ALIGNSIZ;
	if (nbytes < SMALLEST_BLK) {
		nbytes = SMALLEST_BLK;
	} else {
		nbytes = roundup(nbytes, ALIGNSIZ);
	}

	/*
	 * ensure that at least one block is big enough to satisfy
	 *	the request.
	 */

	if (weight(_root) < nbytes) {
		/*
		 * the largest block is not enough. 
		 */
		if(!morecore(nbytes))
			return 0;
	}

	/*
	 * search down through the tree until a suitable block is
	 *	found.  At each decision point, select the better
	 *	fitting node.
	 */

	fpp = &_root;
	allocp = *fpp;
	left_branch = allocp->left;
	right_branch = allocp->right;
	left_weight = weight(left_branch);
	right_weight = weight(right_branch);

	while (left_weight >= nbytes || right_weight >= nbytes) {
		if (left_weight <= right_weight) {
			if (left_weight >= nbytes) {
				fpp = &allocp->left;
				allocp = left_branch;
			} else {
				fpp = &allocp->right;
				allocp = right_branch;
			}
		} else {
			if (right_weight >= nbytes) {
				fpp = &allocp->right;
				allocp = right_branch;
			} else {
				fpp = &allocp->left;
				allocp = left_branch;
			}
		}
		left_branch = allocp->left;
		right_branch = allocp->right;
		left_weight = weight(left_branch);
		right_weight = weight(right_branch);
	} /*while*/	

	/*
	 * allocate storage from the selected node.
	 */
	
	if (allocp->size - nbytes <= SMALLEST_BLK) {
		/*
		 * not big enough to split; must leave at least
		 * a dblk's worth of space.
		 */
		retblk = allocp->block;
		delete(fpp);
	} else {

		/*
		 * Split the selected block n bytes from the top. The
		 * n bytes at the top are returned to the caller; the
		 * remainder of the block goes back to free space.
		 */
		Dblk nblk;

		retblk = allocp->block;
		nblk = nextblk(retblk, nbytes);		/* ^next block */
		nblk->size =  allocp->size = retblk->size - nbytes; 
		__mallinfo.ordblks++;			/* count fragments */

		/*
		 * Change the selected node to point at the newly split
		 * block, and move the node to its proper place in
		 * the free space list.
		 */
		allocp->block = nblk;
		demote(fpp);

		/*
		 * set the length field of the allocated block; we need
		 * this because free() does not specify a length.
		 */
		retblk->size = nbytes;
	}
	/* maintain statistics */
	__mallinfo.uordbytes += retblk->size;		/* bytes allocated */
	__mallinfo.allocated++;				/* frags allocated */
	if (nbytes < __mallinfo.mxfast)
		__mallinfo.smblks++;	/* kludge to pass the SVVS */

	return((ptr_t)retblk->data);

} /*malloc*/

/*
 * free(p)
 *	return a block to the free space tree.
 * 
 * algorithm:
 *	Starting at the root, search for and coalesce free blocks
 *	adjacent to one given.  When the appropriate place in the
 *	tree is found, insert the given block.
 *
 * Some sanity checks to avoid total confusion in the tree.
 *	If the block has already been freed, return.
 *	If the ptr is not from the sbrk'ed space, return.
 *	If the block size is invalid, return.
 */
free_t
free(ptr_t ptr)
{
	uint 	 nbytes;	/* Size of node to be released */
	Freehdr *fpp;		/* For deletion from free list */
	Freehdr neighbor;	/* Node to be coalesced */
	Dblk	 neighbor_blk;	/* Ptr to potential neighbor */
	uint	 neighbor_size;	/* Size of potential neighbor */
	Dblk	 oldblk;	/* Ptr to block to be freed */

	/*
	 * if rigorous checking was requested, do it.
	 */
	if (debug_level >= 2) {
		malloc_verify();
	}

	/*
	 * Check the address of the old block.
	 */
	if ( misaligned(ptr) ) {
		error("free: illegal address (%#x)\n", ptr);
		free_return(0);
	}

	/*
	 * Freeing something that wasn't allocated isn't
	 * exactly kosher, but fclose() does it routinely.
	 */
	if( ptr < (ptr_t)_lbound || ptr > (ptr_t)_ubound ) {
		errno = EINVAL;
		free_return(0);
	}

	/*
	 * Get node length by backing up by the size of a header.
	 * Check for a valid length.  It must be a positive 
	 * multiple of ALIGNSIZ, at least as large as SMALLEST_BLK,
	 * no larger than the extent of the heap, and must not
	 * extend beyond the end of the heap.
	 */
	oldblk = (Dblk)((char*)ptr - ALIGNSIZ);
	nbytes = oldblk->size;
	if (badblksize(oldblk,nbytes)) {
		error("free: bad block size (%d) at %#x\n",
			(int)nbytes, (int)oldblk );
		free_return(0);
	}

	/* maintain statistics */
	__mallinfo.uordbytes -= nbytes;		/* bytes allocated */
	__mallinfo.allocated--;			/* frags allocated */

	/*
	 * Search the tree for the correct insertion point for this
	 *	node, coalescing adjacent free blocks along the way.
	 */
	fpp = &_root;
	neighbor = *fpp;
	while (neighbor != NIL) {
		neighbor_blk = neighbor->block;
		neighbor_size = neighbor->size;
		if (oldblk < neighbor_blk) {
			Dblk nblk = nextblk(oldblk,nbytes);
			if (nblk == neighbor_blk) {
				/*
				 * Absorb and delete right neighbor
				 */
				nbytes += neighbor_size;
				__mallinfo.ordblks--;
				delete(fpp);
			} else if (nblk > neighbor_blk) {
				/*
				 * The block being freed overlaps
				 * another block in the tree.  This
				 * is bad news.  Return to avoid
				 * further fouling up the the tree.
				 */
				 error("free: blocks %#x, %#x overlap\n",
						(int)oldblk, (int)neighbor_blk);
				 free_return(0);
			} else {
				/*
				 * Search to the left
			 	 */
				fpp = &neighbor->left;
			}
		} else if (oldblk > neighbor_blk) {
			Dblk nblk = nextblk(neighbor_blk, neighbor_size);
			if (nblk == oldblk) {
				/*
				 * Absorb and delete left neighbor
				 */
				oldblk = neighbor_blk;
				nbytes += neighbor_size;
				__mallinfo.ordblks--;
				delete(fpp);
			} else if (nblk > oldblk) {
				/*
				 * This block has already been freed
				 */
				error("free: block %#x was already free\n",
					(int)ptr);
				free_return(0);
			} else {
				/*
				 * search to the right
				 */
				fpp = &neighbor->right;
			}
		} else {
			/*
			 * This block has already been freed
			 * as "oldblk == neighbor_blk"
			 */
			error("free: block %#x was already free\n", (int)ptr);
			free_return(0);
		} /*else*/

		/*
		 * Note that this depends on a side effect of
		 * delete(fpp) in order to terminate the loop!
		 */
		neighbor = *fpp;

	} /*while*/

	/*
	 * Insert the new node into the free space tree
	 */
	insert( oldblk, nbytes );
	free_return(1);

} /*free*/


/*
 * char*
 * shrink(oldblk, oldsize, newsize)
 *	Decreases the size of an old block to a new size.
 *	Returns the remainder to free space.  Returns the
 *	truncated block to the caller.
 */

static char *
shrink(Dblk oldblk, uint oldsize, uint newsize)
{
	Dblk remainder;
	if (oldsize - newsize >= SMALLEST_BLK) {
		/*
		 * Block is to be contracted. Split the old block
		 * and return the remainder to free space.
		 */
		remainder = nextblk(oldblk, newsize);
		remainder->size = oldsize - newsize;
		oldblk->size = newsize;

		/* maintain statistics */
		__mallinfo.ordblks++;		/* count fragments */
		__mallinfo.allocated++;		/* negate effect of free() */

		free(remainder->data);
	}
	return(oldblk->data);
}

/*
 * char*
 * realloc(ptr, nbytes)
 *
 * Reallocate an old block with a new size, returning the old block
 * if possible. The block returned is guaranteed to preserve the
 * contents of the old block up to min(size(old block), newsize).
 *
 * For backwards compatibility, ptr is allowed to reference
 * a block freed since the LAST call of malloc().  Thus the old
 * block may be busy, free, or may even be nested within a free
 * block. 
 *
 * Some old programs have been known to do things like the following,
 * which is guaranteed not to work:
 *
 *	free(ptr);
 *	free(dummy);
 *	dummy = malloc(1);
 *	ptr = realloc(ptr,nbytes);
 *
 * This atrocity was found in the source for diff(1).
 */
ptr_t
realloc(ptr_t ptr, uint nbytes)
{
	Freehdr *fpp;
	Freehdr fp;
	Dblk	oldblk;
	Dblk	freeblk;
	Dblk	oldneighbor;
	uint	oldsize;
	uint	newsize;
	uint	oldneighborsize;

	/*
	 * Add SVR4 semantics for OS 5.x so /usr/lib librarys
	 * work correctly when running in BCP mode
	 */
	if (ptr == NULL) {
		return (malloc(nbytes));
	}

	/*
	 * if rigorous checking was requested, do it.
	 */
	if (debug_level >= 2) {
		malloc_verify();
	}

	/*
	 * Check the address of the old block.
	 */
	if ( misaligned(ptr) || 
	    ptr < (ptr_t)_lbound || 
	    ptr > (ptr_t)_ubound ) {
		error("realloc: illegal address (%#x)\n", ptr);
		return(NULL);
	}

	/*
	 * check location and size of the old block and its
	 * neighboring block to the right.  If the old block is
	 * at end of memory, the neighboring block is undefined.
	 */
	oldblk = (Dblk)((char*)ptr - ALIGNSIZ);
	oldsize = oldblk->size;
	if (badblksize(oldblk,oldsize)) {
		error("realloc: bad block size (%d) at %#x\n",
			oldsize, oldblk);
		return(NULL);
	}
	oldneighbor = nextblk(oldblk,oldsize);

	/* *** tree search code pulled into separate subroutine *** */
	if (reclaim(oldblk, oldsize, 1) == -1) {
		return(NULL);		/* internal error */
	}

	/*
	 * At this point, we can guarantee that oldblk is out of free
	 * space. What we do next depends on a comparison of the size
	 * of the old block and the requested new block size.  To do
	 * this, first round up the new size request.
	 */
	newsize = nbytes + ALIGNSIZ;		/* add size of a length word */
	if (newsize < SMALLEST_BLK) {
		newsize = SMALLEST_BLK;
	} else {
		newsize = roundup(newsize, ALIGNSIZ);
	}

	/*
	 * Next, examine the size of the old block, and compare it
	 * with the requested new size.
	 */

	if (oldsize >= newsize) {
		/*
		 * Block is to be made smaller.
		 */
		return(shrink(oldblk, oldsize, newsize));
	}

	/*
	 * Block is to be expanded.  Look for adjacent free memory.
	 */
	if ( oldneighbor < (Dblk)_ubound ) {
		/*
		 * Search for the adjacent block in the free
		 * space tree.  Note that the tree may have been
		 * modified in the earlier loop.
		 */
		fpp = &_root;
		fp = *fpp;
		oldneighborsize = oldneighbor->size;
		if ( badblksize(oldneighbor, oldneighborsize) ) {
			error("realloc: bad blocksize(%d) at %#x\n",
				oldneighborsize, oldneighbor);
			return(NULL);
		}
		while ( weight(fp) >= oldneighborsize ) {
			freeblk = fp->block;
			if (oldneighbor < freeblk) {
				/*
				 * search to the left
				 */
				fpp = &(fp->left);
				fp = *fpp;
			}
			else if (oldneighbor > freeblk) {
				/*
				 * search to the right
				 */
				fpp = &(fp->right);
				fp = *fpp;
			}
			else {		/* oldneighbor == freeblk */
				/*
				 * neighboring block is free; is it big enough?
				 */
				if (oldsize + oldneighborsize >= newsize) {
					/*
					 * Big enough. Delete freeblk, join
					 * oldblk to neighbor, return newsize
					 * bytes to the caller, and return the
					 * remainder to free storage.
					 */
					delete(fpp);

					/* maintain statistics */
					__mallinfo.ordblks--;
					__mallinfo.uordbytes += oldneighborsize;

					oldsize += oldneighborsize;
					oldblk->size = oldsize;
					return(shrink(oldblk, oldsize, newsize));
				} else {
					/*
					 * Not big enough. Stop looking for a
					 * free lunch.
					 */
					break;
				} /*else*/
			} /*else*/
		}/*while*/
	} /*if*/

	/*
	 * At this point, we know there is no free space in which to
	 * expand. Malloc a new block, copy the old block to the new,
	 * and free the old block, IN THAT ORDER.
	 */
	ptr = malloc(nbytes);
	if (ptr != NULL) {
		bcopy(oldblk->data, ptr, oldsize-ALIGNSIZ);
		free(oldblk->data);
	}
	return(ptr);

} /* realloc */


/*
 * *** The following code was pulled out of realloc() ***
 *
 * int
 * reclaim(oldblk, oldsize, flag)
 *	If a block containing 'oldsize' bytes from 'oldblk'
 *	is in the free list, remove it from the free list.
 *	'oldblk' and 'oldsize' are assumed to include the free block header.
 *
 *	Returns 1 if block was successfully removed.
 *	Returns 0 if block was not in free list.
 *	Returns -1 if block spans a free/allocated boundary (error() called
 *						if 'flag' == 1).
 */
static int
reclaim(Dblk oldblk, uint oldsize, int flag)
{
	Dblk oldneighbor;
	Freehdr	*fpp;
	Freehdr	fp;
	Dblk		freeblk;
	uint		size;

	/*
	 * Search the free space list for a node describing oldblk,
	 * or a node describing a block containing oldblk.  Assuming
	 * the size of blocks decreases monotonically with depth in
	 * the tree, the loop may terminate as soon as a block smaller
	 * than oldblk is encountered.
	 */

	oldneighbor = nextblk(oldblk, oldsize);

	fpp = &_root;
	fp = *fpp;
	while ( (size = weight(fp)) >= oldsize ) {
		freeblk = fp->block;
		if (badblksize(freeblk,size)) {
			error("realloc: bad block size (%d) at %#x\n",
				size, freeblk);
			return(-1);
		}
		if ( oldblk == freeblk ) {
			/*
			 * |<-- freeblk ...
			 * _________________________________
			 * |<-- oldblk ...
			 * ---------------------------------
			 * Found oldblk in the free space tree; delete it.
			 */
			delete(fpp);

			/* maintain statistics */
			__mallinfo.uordbytes += oldsize;
			__mallinfo.allocated++;
			return(1);
		}
		else if (oldblk < freeblk) {
			/*
			 * 		|<-- freeblk ...
			 * _________________________________
			 * |<--oldblk ...
			 * ---------------------------------
			 * Search to the left for oldblk
			 */
			fpp = &fp->left;
			fp = *fpp;
		}
		else { 
			/*
			 * |<-- freeblk ...
			 * _________________________________
			 * |     		|<--oldblk--->|<--oldneighbor
			 * ---------------------------------
			 * oldblk is somewhere to the right of freeblk.
			 * Check to see if it lies within freeblk.
			 */
			Dblk freeneighbor;
			freeneighbor =  nextblk(freeblk, freeblk->size); 
			if (oldblk >= freeneighbor) {
				/*
				 * |<-- freeblk--->|<--- freeneighbor ...
				 * _________________________________
				 * |  		      |<--oldblk--->|
				 * ---------------------------------
				 * no such luck; search to the right.
				 */
				fpp =  &fp->right;
				fp = *fpp;
			}
			else { 
				/*
				 * freeblk < oldblk < freeneighbor;
				 * i.e., oldblk begins within freeblk.
				 */
				if (oldneighbor > freeneighbor) {
					/*
					 * |<-- freeblk--->|<--- freeneighbor
					 * _________________________________
					 * |     |<--oldblk--->|<--oldneighbor
					 * ---------------------------------
					 * oldblk straddles a block boundary!
					 */
					if (flag) {
	    error("realloc: block %#x straddles free block boundary\n", oldblk);
					}
					return(-1);
				}
				else if (  oldneighbor == freeneighbor ) {
					/*
					 * |<-------- freeblk------------->|
					 * _________________________________
					 * |                 |<--oldblk--->|
					 * ---------------------------------
					 * Oldblk is on the right end of
					 * freeblk. Delete freeblk, split
					 * into two fragments, and return
					 * the one on the left to free space.
					 */
					delete(fpp);

					/* maintain statistics */
					__mallinfo.ordblks++;
					__mallinfo.uordbytes += oldsize;
					__mallinfo.allocated += 2;

					freeblk->size -= oldsize;
					free(freeblk->data);
					return(1);
				}
				else {
					/*
					 * |<-------- freeblk------------->|
					 * _________________________________
					 * |        |oldblk  | oldneighbor |
					 * ---------------------------------
					 * Oldblk is in the middle of freeblk.
					 * Delete freeblk, split into three
					 * fragments, and return the ones on
					 * the ends to free space.
					 */
					delete(fpp);

					/* maintain statistics */
					__mallinfo.ordblks += 2;
					__mallinfo.uordbytes += freeblk->size;
					__mallinfo.allocated += 3;

					/*
					 * split the left fragment by
					 * subtracting the size of oldblk
					 * and oldblk's neighbor
					 */
					freeblk->size -=
						( (char*)freeneighbor
							- (char*)oldblk );
					/*
					 * split the right fragment by
					 * setting oldblk's neighbor's size
					 */
					oldneighbor->size = 
						(char*)freeneighbor
							- (char*)oldneighbor;
					/*
					 * return the fragments to free space
					 */
					free(freeblk->data);
					free(oldneighbor->data);
					return(1);
				} /*else*/
			} /*else*/
		} /* else */
	} /*while*/

	return(0);		/* free block not found */
}

/*
 * bool
 * morecore(nbytes)
 *	Add a block of at least nbytes from end-of-memory to the
 *	free space tree.
 *
 * return value:
 *	true	if at least n bytes can be allocated
 *	false	otherwise
 *
 * remarks:
 *
 *   -- free space (delimited by the extern variable _ubound) is 
 *	extended by an amount determined by rounding nbytes up to
 *	a multiple of the system page size.
 *
 *   -- The lower bound of the heap is determined the first time
 *	this routine is entered. It does NOT necessarily begin at
 *	the end of static data space, since startup code (e.g., for
 *	profiling) may have invoked sbrk() before we got here. 
 */

static bool
morecore(uint nbytes)
{
	Dblk p;
	Freehdr newhdr;

	if (nbpg == 0) {
		nbpg = getpagesize();
		/* hack to avoid fragmenting the heap with the first
		   freehdr page */
		if ((newhdr = getfreehdr()) == NIL) {
			/* Error message returned by getfreehdr() */
			return(false);
		}
		(void)putfreehdr(newhdr);
	}
	nbytes = roundup(nbytes, nbpg);
	p = (Dblk) sbrk((int)nbytes);
	if (p == (Dblk) -1) {
		if (errno == EAGAIN) errno = ENOMEM;
		return(false);	/* errno = ENOMEM */
	}
	if (_lbound == NULL)	/* set _lbound the first time through */
		_lbound = (char*) p;
	_ubound = (char *) p + nbytes;
	p->size = nbytes;

	/* maintain statistics */
	__mallinfo.arena = _ubound - _lbound;
	__mallinfo.uordbytes += nbytes;
	__mallinfo.ordblks++;
	__mallinfo.allocated++;

	free(p->data);
	return(true);

} /*morecore*/


/*
 * Get a free block header from the free header list.
 * When the list is empty, allocate an array of headers.
 * When the array is empty, allocate another one.
 * When we can't allocate another array, we're in deep weeds.
 */
static	Freehdr
getfreehdr(void)
{
	Freehdr	r;
	Dblk	blk;
	uint	size;

	if (freehdrlist != NIL) {
		r = freehdrlist;
		freehdrlist = freehdrlist->left;
		return(r);
	}
	if (nfreehdrs <= 0) {
		size = NFREE_HDRS*sizeof(struct freehdr) + ALIGNSIZ;
		blk = (Dblk) sbrk(size);
		if ((int)blk == -1) {
			malloc_debug(1);
			error("getfreehdr: out of memory");
			if (errno == EAGAIN) errno = ENOMEM;
			return(NIL);
		}
		if (_lbound == NULL)	/* set _lbound on first allocation */
			_lbound = (char*)blk;
		blk->size = size;
		freehdrptr = (Freehdr)blk->data;
		nfreehdrs = NFREE_HDRS;
		_ubound = (char*) nextblk(blk,size);

		/* maintain statistics */
		__mallinfo.arena = _ubound - _lbound;
		__mallinfo.treeoverhead += size;
	}
	nfreehdrs--;
	return(freehdrptr++);
}

/*
 * Free a free block header
 * Add it to the list of available headers.
 */
static void
putfreehdr(Freehdr p)
{
	p->left = freehdrlist;
	freehdrlist = p;
}

#ifndef DEBUG	/*	>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> */

/*
 * stubs for error handling and diagnosis routines. These are what
 * you get in the standard C library; for non-placebo diagnostics
 * load /usr/lib/malloc.debug.o with your program.
 */
/*ARGSUSED*/
static void
error(char *fmt, ...)
{
	errno = EINVAL;
}

#endif	/* !DEBUG	<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< */


#ifdef	DEBUG	/*	>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> */

/*
 * malloc_debug(level)
 *
 * description:
 *
 *	Controls the level of error diagnosis and consistency checking
 *	done by malloc() and free(). level is interpreted as follows:
 *
 *	0:  malloc() and free() return 0 if error detected in arguments
 *	    (errno is set to EINVAL)
 *	1:  malloc() and free() abort if errors detected in arguments
 *	2:  same as 1, but scan entire heap for errors on every call
 *	    to malloc() or free()
 *
 * function result:
 *	returns the previous level of error reporting.
 */
int
malloc_debug(int level)
{
	int old_level;
	old_level = debug_level;
	debug_level = level;
	return (old_level);
}

/*
 * check a free space tree pointer. Should be in
 * the static free pool or somewhere in the heap.
 */

#define chkblk(p)\
	if ( misaligned(p)\
		|| ((Dblk)(p) < (Dblk)_lbound || (Dblk)(p) > (Dblk)_ubound)){\
		blkerror(p);\
		return 0;\
	}

#define chkhdr(p) chkblk(p)

static
blkerror(Freehdr p)
{
	error("Illegal block address (%#x)\n", (p));
}

/*
 * cartesian(p)
 *	returns 1 if free space tree p satisfies internal consistency
 *	checks.
 */

static int
cartesian(Freehdr p)
{
	Freehdr probe;
	Dblk db,pdb;

	if (p == NIL)				/* no tree to test */
		return 1;
	/*
	 * check that root has a data block
	 */
	chkhdr(p);
	pdb = p->block;
	chkblk(pdb);

	/*
	 * check that the child blocks are no larger than the parent block.
	 */
	probe = p->left;
	if (probe != NIL) {
		chkhdr(probe);
		db = probe->block;
		chkblk(db);
		if (probe->size > p->size)	/* child larger than parent */
			return 0;
	}
	probe = p->right;
	if (probe != NIL) {
		chkhdr(probe);
		db = probe->block;
		chkblk(db);
		if (probe->size > p->size)	/* child larger than parent */
			return 0;
	}
	/*
	 * test data addresses in the left subtree,
	 * starting at the left subroot and probing to
	 * the right.  All data addresses must be < p->block.
	 */
	probe = p->left;
	while (probe != NIL) {
		chkhdr(probe);
		db = probe->block;
		chkblk(db);
		if ( nextblk(db, probe->size) >= pdb )	/* overlap */
			return 0;
		probe = probe->right;
	}
	/*
	 * test data addresses in the right subtree,
	 * starting at the right subroot and probing to
	 * the left.  All addresses must be > nextblk(p->block).
	 */
	pdb = nextblk(pdb, p->size);
	probe = p->right;
	while (probe != NIL) {
		chkhdr(probe);
		db = probe->block;
		chkblk(db);
		if (db == NULL || db <= pdb)		/* overlap */
			return 0;
		probe = probe->left;
	}
	return (cartesian(p->left) && cartesian(p->right));
}

/*
 * malloc_verify()
 *
 * This is a verification routine.  It walks through all blocks
 * in the heap (both free and busy) and checks for bad blocks.
 * malloc_verify returns 1 if the heap contains no detectably bad
 * blocks; otherwise it returns 0.
 */

int
malloc_verify(void)
{
	int	maxsize;
	int	hdrsize;
	int	size;
	Dblk	p;
	uint	lb,ub;

	extern  char	end[];

	if (_lbound == NULL)	/* no allocation yet */
		return 1;

	/*
	 * first check heap bounds pointers
	 */
	lb = (uint)end;
	ub = (uint)sbrk(0);

	if ((uint)_lbound < lb || (uint)_lbound > ub) {
		error("malloc_verify: illegal heap lower bound (%#x)\n",
			_lbound);
		return 0;
	}
	if ((uint)_ubound < lb || (uint)_ubound > ub) {
		error("malloc_verify: illegal heap upper bound (%#x)\n",
			_ubound);
		return 0;
	}
	maxsize = heapsize();
	p = (Dblk)_lbound;
	while (p < (Dblk) _ubound) {
		size = p->size;
		if ( (size) < SMALLEST_BLK 
			|| (size) & (ALIGNSIZ-1)
			|| (size) > heapsize()
			|| ((char*)(p))+(size) > _ubound ) {
			error("malloc_verify: bad block size (%d) at %#x\n",
				size, p);
			return(0);		/* Badness */
		}
		p = nextblk(p, size);
	}
	if (p > (Dblk) _ubound) {
		error("malloc_verify: heap corrupted\n");
		return(0);
	}
	if (!cartesian(_root)){
		error("malloc_verify: free space tree corrupted\n");
		return(0);
	}
	return(1);
}

/*
 * The following is a kludge to avoid dependency on stdio, which
 * uses malloc() and free(), one of which probably got us here in
 * the first place.
 */

#define putchar(c) (*buf++ = (c))
extern	int	fileno();	/*bletch*/
#define stderr 2		/*bletch*/
#define	LBUFSIZ	256

static	char	stderrbuf[LBUFSIZ];

/*
 * Error routine.
 * If debug_level == 0, does nothing except set errno = EINVAL.
 * Otherwise, prints an error message to stderr and generates a
 * core image.
 */
static void
error(char *fmt, ...)
{
	static int n = 0; /* prevents infinite recursion when using stdio */
	int nbytes;
	va_list ap;

	errno = EINVAL;
	if (debug_level == 0)
		return;
	if (!n++) {
		va_start(ap, fmt);
		nbytes = vsprintf(stderrbuf, fmt, ap);
		va_end(ap);
		stderrbuf[nbytes++] = '\n';
		stderrbuf[nbytes] = '\0';
		write(fileno(stderr), stderrbuf, nbytes);
	}
	abort();
}

#endif	/* DEBUG	<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< */
