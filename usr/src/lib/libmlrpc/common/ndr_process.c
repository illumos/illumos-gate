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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Network Data Representation (NDR) is a compatible subset of the DCE RPC
 * and MSRPC NDR.  NDR is used to move parameters consisting of
 * complicated trees of data constructs between an RPC client and server.
 */

#include <sys/byteorder.h>
#include <strings.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <libmlrpc.h>
#include <ndr_wchar.h>

#define	NDR_IS_UNION(T)	\
	(((T)->type_flags & NDR_F_TYPEOP_MASK) == NDR_F_UNION)
#define	NDR_IS_STRING(T)	\
	(((T)->type_flags & NDR_F_TYPEOP_MASK) == NDR_F_STRING)

extern ndr_typeinfo_t ndt_s_wchar;

/*
 * The following synopsis describes the terms TOP-MOST, OUTER and INNER.
 *
 * Each parameter (call arguments and return values) is a TOP-MOST item.
 * A TOP-MOST item consists of one or more OUTER items.  An OUTER item
 * consists of one or more INNER items.  There are important differences
 * between each kind, which, primarily, have to do with the allocation
 * of memory to contain data structures and the order of processing.
 *
 * This is most easily demonstrated with a short example.
 * Consider these structures:
 *
 *	struct top_param {
 *		long		level;
 *		struct list *	head;
 *		long		count;
 *	};
 *
 *	struct list {
 *		struct list *	next;
 *		char *		str; // a string
 *	};
 *
 * Now, consider an instance tree like this:
 *
 *	+---------+       +-------+       +-------+
 *	|top_param|  +--->|list #1|  +--->|list #2|
 *	+---------+  |    +-------+  |    +-------+
 *	| level   |  |    | next ----+    | next --->(NULL)
 *	| head   ----+    | str  -->"foo" | str  -->"bar"
 *	| count   |       | flag  |       | flag  |
 *	+---------+       +-------+       +-------+
 *
 * The DCE(MS)/RPC Stub Data encoding for the tree is the following.
 * The vertical bars (|) indicate OUTER construct boundaries.
 *
 *   +-----+----------------------+----------------------+-----+-----+-----+
 *   |level|#1.next #1.str #1.flag|#2.next #2.str #2.flag|"bar"|"foo"|count|
 *   +-----+----------------------+----------------------+-----+-----+-----+
 *   level |<----------------------- head -------------------------->|count
 *   TOP    TOP                                                       TOP
 *
 * Here's what to notice:
 *
 * - The members of the TOP-MOST construct are scattered through the Stub
 *   Data in the order they occur.  This example shows a TOP-MOST construct
 *   consisting of atomic types (pointers and integers).  A construct
 *   (struct) within the TOP-MOST construct would be contiguous and not
 *   scattered.
 *
 * - The members of OUTER constructs are contiguous, which allows for
 *   non-copied relocated (fixed-up) data structures at the packet's
 *   destination.  We don't do fix-ups here.  The pointers within the
 *   OUTER constructs are processed depth-first in the order that they
 *   occur.  If they were processed breadth first, the sequence would
 *   be #1,"foo",#2,"bar".  This is tricky because OUTER constructs may
 *   be variable length, and pointers are often encountered before the
 *   size(s) is known.
 *
 * - The INNER constructs are simply the members of an OUTER construct.
 *
 * For comparison, consider how ONC RPC would handle the same tree of
 * data.  ONC requires very little buffering, while DCE requires enough
 * buffer space for the entire message.  ONC does atom-by-atom depth-first
 * (de)serialization and copy, while DCE allows for constructs to be
 * "fixed-up" (relocated) in place at the destination.  The packet data
 * for the same tree processed by ONC RPC would look like this:
 *
 *   +---------------------------------------------------------------------+
 *   |level #1.next #2.next #2.str "bar" #2.flag #1.str "foo" #1.flag count|
 *   +---------------------------------------------------------------------+
 *   TOP    #1      #2      #2     bar   #2      #1     foo   #1      TOP
 *
 * More details about each TOP-MOST, OUTER, and INNER constructs appear
 * throughout this source file near where such constructs are processed.
 *
 * NDR_REFERENCE
 *
 * The primary object for NDR is the ndr_ref_t.
 *
 * An ndr reference indicates the local datum (i.e. native "C" data
 * format), and the element within the Stub Data (contained within the
 * RPC PDU (protocol data unit).  An ndr reference also indicates,
 * largely as a debugging aid, something about the type of the
 * element/datum, and the enclosing construct for the element. The
 * ndr reference's are typically allocated on the stack as locals,
 * and the chain of ndr-reference.enclosing references is in reverse
 * order of the call graph.
 *
 * The ndr-reference.datum is a pointer to the local memory that
 * contains/receives the value. The ndr-reference.pdu_offset indicates
 * where in the Stub Data the value is to be stored/retrieved.
 *
 * The ndr-reference also contains various parameters to the NDR
 * process, such as ndr-reference.size_is, which indicates the size
 * of variable length data, or ndr-reference.switch_is, which
 * indicates the arm of a union to use.
 *
 * QUEUE OF OUTER REFERENCES
 *
 * Some OUTER constructs are variable size.  Sometimes (often) we don't
 * know the size of the OUTER construct until after pointers have been
 * encountered. Hence, we can not begin processing the referent of the
 * pointer until after the referring OUTER construct is completely
 * processed, i.e. we don't know where to find/put the referent in the
 * Stub Data until we know the size of all its predecessors.
 *
 * This is managed using the queue of OUTER references.  The queue is
 * anchored in ndr_stream.outer_queue_head.  At any time,
 * ndr_stream.outer_queue_tailp indicates where to put the
 * ndr-reference for the next encountered pointer.
 *
 * Refer to the example above as we illustrate the queue here.  In these
 * illustrations, the queue entries are not the data structures themselves.
 * Rather, they are ndr-reference entries which **refer** to the data
 * structures in both the PDU and local memory.
 *
 * During some point in the processing, the queue looks like this:
 *
 *   outer_current -------v
 *   outer_queue_head --> list#1 --0
 *   outer_queue_tailp ---------&
 *
 * When the pointer #1.next is encountered, and entry is added to the
 * queue,
 *
 *   outer_current -------v
 *   outer_queue_head --> list#1 --> list#2 --0
 *   outer_queue_tailp --------------------&
 *
 * and the members of #1 continue to be processed, which encounters
 * #1.str:
 *
 *   outer_current -------v
 *   outer_queue_head --> list#1 --> list#2 --> "foo" --0
 *   outer_queue_tailp ------------------------------&
 *
 * Upon the completion of list#1, the processing continues by moving to
 * ndr_stream.outer_current->next, and the tail is set to this outer member:
 *
 *   outer_current ------------------v
 *   outer_queue_head --> list#1 --> list#2 --> "foo" --0
 *   outer_queue_tailp --------------------&
 *
 * Space for list#2 is allocated, either in the Stub Data or of local
 * memory.  When #2.next is encountered, it is found to be the null
 * pointer and no reference is added to the queue.  When #2.str is
 * encountered, it is found to be valid, and a reference is added:
 *
 *   outer_current ------------------v
 *   outer_queue_head --> list#1 --> list#2 --> "bar" --> "foo" --0
 *   outer_queue_tailp ------------------------------&
 *
 * Processing continues in a similar fashion with the string "bar",
 * which is variable-length.  At this point, memory for "bar" may be
 * malloc()ed during NDR_M_OP_UNMARSHALL:
 *
 *   outer_current -----------------------------v
 *   outer_queue_head --> list#1 --> list#2 --> "bar" --> "foo" --0
 *   outer_queue_tailp ------------------------------&
 *
 * And finishes on string "foo".  Notice that because "bar" is a
 * variable length string, and we don't know the PDU offset for "foo"
 * until we reach this point.
 *
 * When the queue is drained (current->next==0), processing continues
 * with the next TOP-MOST member.
 *
 * The queue of OUTER constructs manages the variable-length semantics
 * of OUTER constructs and satisfies the depth-first requirement.
 * We allow the queue to linger until the entire TOP-MOST structure is
 * processed as an aid to debugging.
 */

static ndr_ref_t *ndr_enter_outer_queue(ndr_ref_t *);
extern int ndr__ulong(ndr_ref_t *);

/*
 * TOP-MOST ELEMENTS
 *
 * This is fundamentally the first OUTER construct of the parameter,
 * possibly followed by more OUTER constructs due to pointers.  The
 * datum (local memory) for TOP-MOST constructs (structs) is allocated
 * by the caller of NDR.
 *
 * After the element is transferred, the outer_queue is drained.
 *
 * All we have to do is add an entry to the outer_queue for this
 * top-most member, and commence the outer_queue processing.
 */
int
ndo_process(ndr_stream_t *nds, ndr_typeinfo_t *ti, char *datum)
{
	ndr_ref_t	myref;

	bzero(&myref, sizeof (myref));
	myref.stream = nds;
	myref.datum = datum;
	myref.name = "PROCESS";
	myref.ti = ti;

	return (ndr_topmost(&myref));
}

int
ndo_operation(ndr_stream_t *nds, ndr_typeinfo_t *ti, int opnum, char *datum)
{
	ndr_ref_t	myref;

	bzero(&myref, sizeof (myref));
	myref.stream = nds;
	myref.datum = datum;
	myref.name = "OPERATION";
	myref.ti = ti;
	myref.inner_flags = NDR_F_SWITCH_IS;
	myref.switch_is = opnum;

	if (ti->type_flags != NDR_F_INTERFACE) {
		NDR_SET_ERROR(&myref, NDR_ERR_NOT_AN_INTERFACE);
		return (0);
	}

	return ((*ti->ndr_func)(&myref));
}

int
ndr_params(ndr_ref_t *params_ref)
{
	ndr_typeinfo_t *ti = params_ref->ti;

	if (ti->type_flags == NDR_F_OPERATION)
		return (*ti->ndr_func) (params_ref);
	else
		return (ndr_topmost(params_ref));
}

int
ndr_topmost(ndr_ref_t *top_ref)
{
	ndr_stream_t *nds;
	ndr_typeinfo_t *ti;
	ndr_ref_t *outer_ref = 0;
	int	is_varlen;
	int	is_string;
	int	error;
	int	rc;
	unsigned n_fixed;
	int	params;

	assert(top_ref);
	assert(top_ref->stream);
	assert(top_ref->ti);

	nds = top_ref->stream;
	ti = top_ref->ti;

	is_varlen = ti->pdu_size_variable_part;
	is_string = NDR_IS_STRING(ti);

	assert(nds->outer_queue_tailp && !*nds->outer_queue_tailp);
	assert(!nds->outer_current);

	params = top_ref->inner_flags & NDR_F_PARAMS_MASK;

	switch (params) {
	case NDR_F_NONE:
	case NDR_F_SWITCH_IS:
		if (is_string || is_varlen) {
			error = NDR_ERR_TOPMOST_VARLEN_ILLEGAL;
			NDR_SET_ERROR(outer_ref, error);
			return (0);
		}
		n_fixed = ti->pdu_size_fixed_part;
		break;

	case NDR_F_SIZE_IS:
		error = NDR_ERR_TOPMOST_VARLEN_ILLEGAL;
		NDR_SET_ERROR(outer_ref, error);
		return (0);

	case NDR_F_DIMENSION_IS:
		if (is_varlen) {
			error = NDR_ERR_ARRAY_VARLEN_ILLEGAL;
			NDR_SET_ERROR(outer_ref, error);
			return (0);
		}
		n_fixed = ti->pdu_size_fixed_part * top_ref->dimension_is;
		break;

	case NDR_F_IS_POINTER:
	case NDR_F_IS_POINTER+NDR_F_SIZE_IS:
		n_fixed = 4;
		break;

	case NDR_F_IS_REFERENCE:
	case NDR_F_IS_REFERENCE+NDR_F_SIZE_IS:
		n_fixed = 0;
		break;

	default:
		error = NDR_ERR_OUTER_PARAMS_BAD;
		NDR_SET_ERROR(outer_ref, error);
		return (0);
	}

	outer_ref = ndr_enter_outer_queue(top_ref);
	if (!outer_ref)
		return (0);	/* error already set */

	/*
	 * Hand-craft the first OUTER construct and directly call
	 * ndr_inner(). Then, run the outer_queue. We do this
	 * because ndr_outer() wants to malloc() memory for
	 * the construct, and we already have the memory.
	 */

	/* move the flags, etc, around again, undoes enter_outer_queue() */
	outer_ref->inner_flags = top_ref->inner_flags;
	outer_ref->outer_flags = 0;
	outer_ref->datum = top_ref->datum;

	/* All outer constructs start on a mod4 (longword) boundary */
	if (!ndr_outer_align(outer_ref))
		return (0);		/* error already set */

	/* Regardless of what it is, this is where it starts */
	outer_ref->pdu_offset = nds->pdu_scan_offset;

	rc = ndr_outer_grow(outer_ref, n_fixed);
	if (!rc)
		return (0);		/* error already set */

	outer_ref->pdu_end_offset = outer_ref->pdu_offset + n_fixed;

	/* set-up outer_current, as though run_outer_queue() was doing it */
	nds->outer_current = outer_ref;
	nds->outer_queue_tailp = &nds->outer_current->next;
	nds->pdu_scan_offset = outer_ref->pdu_end_offset;

	/* do the topmost member */
	rc = ndr_inner(outer_ref);
	if (!rc)
		return (0);		/* error already set */

	nds->pdu_scan_offset = outer_ref->pdu_end_offset;

	/* advance, as though run_outer_queue() was doing it */
	nds->outer_current = nds->outer_current->next;
	return (ndr_run_outer_queue(nds));
}

static ndr_ref_t *
ndr_enter_outer_queue(ndr_ref_t *arg_ref)
{
	ndr_stream_t	*nds = arg_ref->stream;
	ndr_ref_t	*outer_ref;

	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	outer_ref = (ndr_ref_t *)NDS_MALLOC(nds, sizeof (*outer_ref), arg_ref);
	if (!outer_ref) {
		NDR_SET_ERROR(arg_ref, NDR_ERR_MALLOC_FAILED);
		return (0);
	}

	*outer_ref = *arg_ref;

	/* move advice in inner_flags to outer_flags */
	outer_ref->outer_flags = arg_ref->inner_flags & NDR_F_PARAMS_MASK;
	outer_ref->inner_flags = 0;
	outer_ref->enclosing = nds->outer_current;
	outer_ref->backptr = 0;
	outer_ref->datum = 0;

	assert(nds->outer_queue_tailp);

	outer_ref->next = *nds->outer_queue_tailp;
	*nds->outer_queue_tailp = outer_ref;
	nds->outer_queue_tailp = &outer_ref->next;
	return (outer_ref);
}

int
ndr_run_outer_queue(ndr_stream_t *nds)
{
	while (nds->outer_current) {
		nds->outer_queue_tailp = &nds->outer_current->next;

		if (!ndr_outer(nds->outer_current))
			return (0);

		nds->outer_current = nds->outer_current->next;
	}

	return (1);
}

/*
 * OUTER CONSTRUCTS
 *
 * OUTER constructs are where the real work is, which stems from the
 * variable-length potential.
 *
 * DCE(MS)/RPC VARIABLE LENGTH -- CONFORMANT, VARYING, VARYING/CONFORMANT
 *
 * DCE(MS)/RPC provides for three forms of variable length: CONFORMANT,
 * VARYING, and VARYING/CONFORMANT.
 *
 * What makes this so tough is that the variable-length array may be well
 * encapsulated within the outer construct.  Further, because DCE(MS)/RPC
 * tries to keep the constructs contiguous in the data stream, the sizing
 * information precedes the entire OUTER construct.  The sizing information
 * must be used at the appropriate time, which can be after many, many,
 * many fixed-length elements.  During IDL type analysis, we know in
 * advance constructs that encapsulate variable-length constructs.  So,
 * we know when we have a sizing header and when we don't.  The actual
 * semantics of the header are largely deferred.
 *
 * Currently, VARYING constructs are not implemented but they are described
 * here in case they have to be implemented in the future.  Similarly,
 * DCE(MS)/RPC provides for multi-dimensional arrays, which are currently
 * not implemented.  Only one-dimensional, variable-length arrays are
 * supported.
 *
 * CONFORMANT CONSTRUCTS -- VARIABLE LENGTH ARRAYS START THE SHOW
 *
 * All variable-length values are arrays.  These arrays may be embedded
 * well within another construct.  However, a variable-length construct
 * may ONLY appear as the last member of an enclosing construct.  Example:
 *
 *	struct credentials {
 *		ulong	uid, gid;
 *		ulong	n_gids;
 *	    [size_is(n_gids)]
 *		ulong	gids[*];    // variable-length.
 *	};
 *
 * CONFORMANT constructs have a dynamic size in local memory and in the
 * PDU.  The CONFORMANT quality is indicated by the [size_is()] advice.
 * CONFORMANT constructs have the following header:
 *
 *	struct conformant_header {
 *		ulong		size_is;
 *	};
 *
 * (Multi-dimensional CONFORMANT arrays have a similar header for each
 * dimension - not implemented).
 *
 * Example CONFORMANT construct:
 *
 *	struct user {
 *		char *			name;
 *		struct credentials	cred;	// see above
 *	};
 *
 * Consider the data tree:
 *
 *    +--------+
 *    |  user  |
 *    +--------+
 *    | name  ----> "fred" (the string is a different OUTER)
 *    | uid    |
 *    | gid    |
 *    | n_gids |    for example, 3
 *    | gids[0]|
 *    | gids[1]|
 *    | gids[2]|
 *    +--------+
 *
 * The OUTER construct in the Stub Data would be:
 *
 *    +---+---------+---------------------------------------------+
 *    |pad|size_is=3 name uid gid n_gids=3 gids[0] gids[1] gids[2]|
 *    +---+---------+---------------------------------------------+
 *         szing hdr|user |<-------------- user.cred ------------>|
 *                  |<--- fixed-size ---->|<----- conformant ---->|
 *
 * The ndr_typeinfo for struct user will have:
 *	pdu_fixed_size_part = 16	four long words (name uid gid n_gids)
 *	pdu_variable_size_part = 4	per element, sizeof gids[0]
 *
 * VARYING CONSTRUCTS -- NOT IMPLEMENTED
 *
 * VARYING constructs have the following header:
 *
 *	struct varying_header {
 *		ulong		first_is;
 *		ulong		length_is;
 *	};
 *
 * This indicates which interval of an array is significant.
 * Non-intersecting elements of the array are undefined and usually
 * zero-filled.  The first_is parameter for C arrays is always 0 for
 * the first element.
 *
 * N.B. Constructs may contain one CONFORMANT element, which is always
 * last, but may contain many VARYING elements, which can be anywhere.
 *
 * VARYING CONFORMANT constructs have the sizing headers arranged like
 * this:
 *
 *	struct conformant_header	all_conformant[N_CONFORMANT_DIM];
 *	struct varying_header		all_varying[N_VARYING_ELEMS_AND_DIMS];
 *
 * The sizing header is immediately followed by the values for the
 * construct.  Again, we don't support more than one dimension and
 * we don't support VARYING constructs at this time.
 *
 * A good example of a VARYING/CONFORMANT data structure is the UNIX
 * directory entry:
 *
 *	struct dirent {
 *		ushort		reclen;
 *		ushort		namlen;
 *		ulong		inum;
 *	    [size_is(reclen-8) length_is(namlen+1)] // -(2+2+4), +1 for NUL
 *		uchar		name[*];
 *	};
 *
 *
 * STRINGS ARE A SPECIAL CASE
 *
 * Strings are handled specially.  MS/RPC uses VARYING/CONFORMANT structures
 * for strings.  This is a simple one-dimensional variable-length array,
 * typically with its last element all zeroes.  We handle strings with the
 * header:
 *
 *	struct string_header {
 *		ulong		size_is;
 *		ulong		first_is;	// always 0
 *		ulong		length_is;	// always same as size_is
 *	};
 *
 * If general support for VARYING and VARYING/CONFORMANT mechanisms is
 * implemented, we probably won't need the strings special case.
 */
int
ndr_outer(ndr_ref_t *outer_ref)
{
	ndr_stream_t 	*nds = outer_ref->stream;
	ndr_typeinfo_t	*ti = outer_ref->ti;
	int	is_varlen = ti->pdu_size_variable_part;
	int	is_union = NDR_IS_UNION(ti);
	int	is_string = NDR_IS_STRING(ti);
	int	error = NDR_ERR_OUTER_PARAMS_BAD;
	int	params;

	params = outer_ref->outer_flags & NDR_F_PARAMS_MASK;

	NDR_TATTLE(outer_ref, "--OUTER--");

	/* All outer constructs start on a mod4 (longword) boundary */
	if (!ndr_outer_align(outer_ref))
		return (0);		/* error already set */

	/* Regardless of what it is, this is where it starts */
	outer_ref->pdu_offset = nds->pdu_scan_offset;

	if (is_union) {
		error = NDR_ERR_OUTER_UNION_ILLEGAL;
		NDR_SET_ERROR(outer_ref, error);
		return (0);
	}

	switch (params) {
	case NDR_F_NONE:
		if (is_string)
			return (ndr_outer_string(outer_ref));
		if (is_varlen)
			return (ndr_outer_conformant_construct(outer_ref));

		return (ndr_outer_fixed(outer_ref));

	case NDR_F_SIZE_IS:
	case NDR_F_DIMENSION_IS:
	case NDR_F_IS_POINTER+NDR_F_SIZE_IS:
	case NDR_F_IS_REFERENCE+NDR_F_SIZE_IS:
		if (is_varlen) {
			error = NDR_ERR_ARRAY_VARLEN_ILLEGAL;
			break;
		}

		if (params & NDR_F_SIZE_IS)
			return (ndr_outer_conformant_array(outer_ref));
		else
			return (ndr_outer_fixed_array(outer_ref));

	default:
		error = NDR_ERR_OUTER_PARAMS_BAD;
		break;
	}

	/*
	 * If we get here, something is wrong. Most likely,
	 * the params flags do not match.
	 */
	NDR_SET_ERROR(outer_ref, error);
	return (0);
}

int
ndr_outer_fixed(ndr_ref_t *outer_ref)
{
	ndr_stream_t	*nds = outer_ref->stream;
	ndr_typeinfo_t	*ti = outer_ref->ti;
	ndr_ref_t	myref;
	char 		*valp = NULL;
	int		is_varlen = ti->pdu_size_variable_part;
	int		is_union = NDR_IS_UNION(ti);
	int		is_string = NDR_IS_STRING(ti);
	int		rc;
	unsigned	n_hdr;
	unsigned	n_fixed;
	unsigned	n_variable;
	unsigned	n_alloc;
	unsigned	n_pdu_total;
	int		params;

	params = outer_ref->outer_flags & NDR_F_PARAMS_MASK;

	assert(!is_varlen && !is_string && !is_union);
	assert(params == NDR_F_NONE);

	/* no header for this */
	n_hdr = 0;

	/* fixed part -- exactly one of these */
	n_fixed = ti->pdu_size_fixed_part;
	assert(n_fixed > 0);

	/* variable part -- exactly none of these */
	n_variable = 0;

	/* sum them up to determine the PDU space required */
	n_pdu_total = n_hdr + n_fixed + n_variable;

	/* similar sum to determine how much local memory is required */
	n_alloc = n_fixed + n_variable;

	rc = ndr_outer_grow(outer_ref, n_pdu_total);
	if (!rc)
		return (rc);		/* error already set */

	switch (nds->m_op) {
	case NDR_M_OP_MARSHALL:
		valp = outer_ref->datum;
		if (!valp) {
			NDR_SET_ERROR(outer_ref, NDR_ERR_OUTER_PARAMS_BAD);
			return (0);
		}
		if (outer_ref->backptr)
			assert(valp == *outer_ref->backptr);
		break;

	case NDR_M_OP_UNMARSHALL:
		valp = NDS_MALLOC(nds, n_alloc, outer_ref);
		if (!valp) {
			NDR_SET_ERROR(outer_ref, NDR_ERR_MALLOC_FAILED);
			return (0);
		}
		if (outer_ref->backptr)
			*outer_ref->backptr = valp;
		outer_ref->datum = valp;
		break;

	default:
		NDR_SET_ERROR(outer_ref, NDR_ERR_M_OP_INVALID);
		return (0);
	}

	bzero(&myref, sizeof (myref));
	myref.stream = nds;
	myref.enclosing = outer_ref;
	myref.ti = outer_ref->ti;
	myref.datum = outer_ref->datum;
	myref.name = "FIXED-VALUE";
	myref.outer_flags = NDR_F_NONE;
	myref.inner_flags = NDR_F_NONE;

	myref.pdu_offset = outer_ref->pdu_offset;
	outer_ref->pdu_end_offset = outer_ref->pdu_offset + n_pdu_total;

	rc = ndr_inner(&myref);
	if (!rc)
		return (rc);		/* error already set */

	nds->pdu_scan_offset = outer_ref->pdu_end_offset;
	return (1);
}

int
ndr_outer_fixed_array(ndr_ref_t *outer_ref)
{
	ndr_stream_t	*nds = outer_ref->stream;
	ndr_typeinfo_t	*ti = outer_ref->ti;
	ndr_ref_t	myref;
	char 		*valp = NULL;
	int		is_varlen = ti->pdu_size_variable_part;
	int		is_union = NDR_IS_UNION(ti);
	int		is_string = NDR_IS_STRING(ti);
	int		rc;
	unsigned	n_hdr;
	unsigned	n_fixed;
	unsigned	n_variable;
	unsigned	n_alloc;
	unsigned	n_pdu_total;
	int		params;

	params = outer_ref->outer_flags & NDR_F_PARAMS_MASK;

	assert(!is_varlen && !is_string && !is_union);
	assert(params == NDR_F_DIMENSION_IS);

	/* no header for this */
	n_hdr = 0;

	/* fixed part -- exactly dimension_is of these */
	n_fixed = ti->pdu_size_fixed_part * outer_ref->dimension_is;
	assert(n_fixed > 0);

	/* variable part -- exactly none of these */
	n_variable = 0;

	/* sum them up to determine the PDU space required */
	n_pdu_total = n_hdr + n_fixed + n_variable;

	/* similar sum to determine how much local memory is required */
	n_alloc = n_fixed + n_variable;

	rc = ndr_outer_grow(outer_ref, n_pdu_total);
	if (!rc)
		return (rc);		/* error already set */

	switch (nds->m_op) {
	case NDR_M_OP_MARSHALL:
		valp = outer_ref->datum;
		if (!valp) {
			NDR_SET_ERROR(outer_ref, NDR_ERR_OUTER_PARAMS_BAD);
			return (0);
		}
		if (outer_ref->backptr)
			assert(valp == *outer_ref->backptr);
		break;

	case NDR_M_OP_UNMARSHALL:
		valp = NDS_MALLOC(nds, n_alloc, outer_ref);
		if (!valp) {
			NDR_SET_ERROR(outer_ref, NDR_ERR_MALLOC_FAILED);
			return (0);
		}
		if (outer_ref->backptr)
			*outer_ref->backptr = valp;
		outer_ref->datum = valp;
		break;

	default:
		NDR_SET_ERROR(outer_ref, NDR_ERR_M_OP_INVALID);
		return (0);
	}

	bzero(&myref, sizeof (myref));
	myref.stream = nds;
	myref.enclosing = outer_ref;
	myref.ti = outer_ref->ti;
	myref.datum = outer_ref->datum;
	myref.name = "FIXED-ARRAY";
	myref.outer_flags = NDR_F_NONE;
	myref.inner_flags = NDR_F_DIMENSION_IS;
	myref.dimension_is = outer_ref->dimension_is;

	myref.pdu_offset = outer_ref->pdu_offset;
	outer_ref->pdu_end_offset = outer_ref->pdu_offset + n_pdu_total;

	rc = ndr_inner(&myref);
	if (!rc)
		return (rc);		/* error already set */

	nds->pdu_scan_offset = outer_ref->pdu_end_offset;
	return (1);
}

int
ndr_outer_conformant_array(ndr_ref_t *outer_ref)
{
	ndr_stream_t	*nds = outer_ref->stream;
	ndr_typeinfo_t	*ti = outer_ref->ti;
	ndr_ref_t	myref;
	char 		*valp = NULL;
	int		is_varlen = ti->pdu_size_variable_part;
	int		is_union = NDR_IS_UNION(ti);
	int		is_string = NDR_IS_STRING(ti);
	unsigned long	size_is;
	int		rc;
	unsigned	n_hdr;
	unsigned	n_fixed;
	unsigned	n_variable;
	unsigned	n_alloc;
	unsigned	n_pdu_total;
	unsigned	n_ptr_offset;
	int		params;

	params = outer_ref->outer_flags & NDR_F_PARAMS_MASK;

	assert(!is_varlen && !is_string && !is_union);
	assert(params & NDR_F_SIZE_IS);

	/* conformant header for this */
	n_hdr = 4;

	/* fixed part -- exactly none of these */
	n_fixed = 0;

	/* variable part -- exactly size_of of these */
	/* notice that it is the **fixed** size of the ti */
	n_variable = ti->pdu_size_fixed_part * outer_ref->size_is;

	/* sum them up to determine the PDU space required */
	n_pdu_total = n_hdr + n_fixed + n_variable;

	/* similar sum to determine how much local memory is required */
	n_alloc = n_fixed + n_variable;

	rc = ndr_outer_grow(outer_ref, n_pdu_total);
	if (!rc)
		return (rc);		/* error already set */

	switch (nds->m_op) {
	case NDR_M_OP_MARSHALL:
		size_is = outer_ref->size_is;
		rc = ndr_outer_poke_sizing(outer_ref, 0, &size_is);
		if (!rc)
			return (0);	/* error already set */

		valp = outer_ref->datum;
		if (!valp) {
			NDR_SET_ERROR(outer_ref, NDR_ERR_OUTER_PARAMS_BAD);
			return (0);
		}
		if (outer_ref->backptr)
			assert(valp == *outer_ref->backptr);
		n_ptr_offset = 4;
		break;

	case NDR_M_OP_UNMARSHALL:
		if (params & NDR_F_IS_REFERENCE) {
			size_is = outer_ref->size_is;
			n_ptr_offset = 0;
		} else {
			/* NDR_F_IS_POINTER */
			rc = ndr_outer_peek_sizing(outer_ref, 0, &size_is);
			if (!rc)
				return (0);	/* error already set */

			if (size_is != outer_ref->size_is) {
				NDR_SET_ERROR(outer_ref,
				    NDR_ERR_SIZE_IS_MISMATCH_PDU);
				return (0);
			}

			n_ptr_offset = 4;
		}

		if (size_is > 0) {
			valp = NDS_MALLOC(nds, n_alloc, outer_ref);
			if (!valp) {
				NDR_SET_ERROR(outer_ref, NDR_ERR_MALLOC_FAILED);
				return (0);
			}
		}

		if (outer_ref->backptr)
			*outer_ref->backptr = valp;
		outer_ref->datum = valp;
		break;

	default:
		NDR_SET_ERROR(outer_ref, NDR_ERR_M_OP_INVALID);
		return (0);
	}

	outer_ref->pdu_end_offset = outer_ref->pdu_offset + n_pdu_total;
	outer_ref->type_flags = NDR_F_NONE;
	outer_ref->inner_flags = NDR_F_NONE;

	if (size_is > 0) {
		bzero(&myref, sizeof (myref));
		myref.stream = nds;
		myref.enclosing = outer_ref;
		myref.ti = outer_ref->ti;
		myref.datum = outer_ref->datum;
		myref.name = "CONFORMANT-ARRAY";
		myref.outer_flags = NDR_F_NONE;
		myref.inner_flags = NDR_F_SIZE_IS;
		myref.size_is = outer_ref->size_is;

		myref.inner_flags = NDR_F_DIMENSION_IS;		/* convenient */
		myref.dimension_is = outer_ref->size_is;	/* convenient */

		myref.pdu_offset = outer_ref->pdu_offset + n_ptr_offset;

		rc = ndr_inner(&myref);
		if (!rc)
			return (rc);		/* error already set */
	}

	nds->pdu_scan_offset = outer_ref->pdu_end_offset;
	return (1);
}

int
ndr_outer_conformant_construct(ndr_ref_t *outer_ref)
{
	ndr_stream_t	*nds = outer_ref->stream;
	ndr_typeinfo_t	*ti = outer_ref->ti;
	ndr_ref_t	myref;
	char 		*valp = NULL;
	int		is_varlen = ti->pdu_size_variable_part;
	int		is_union = NDR_IS_UNION(ti);
	int		is_string = NDR_IS_STRING(ti);
	unsigned long	size_is;
	int		rc;
	unsigned	n_hdr;
	unsigned	n_fixed;
	unsigned	n_variable;
	unsigned	n_alloc;
	unsigned	n_pdu_total;
	int		params;

	params = outer_ref->outer_flags & NDR_F_PARAMS_MASK;

	assert(is_varlen && !is_string && !is_union);
	assert(params == NDR_F_NONE);

	/* conformant header for this */
	n_hdr = 4;

	/* fixed part -- exactly one of these */
	n_fixed = ti->pdu_size_fixed_part;

	/* variable part -- exactly size_of of these */
	n_variable = 0;		/* 0 for the moment */

	/* sum them up to determine the PDU space required */
	n_pdu_total = n_hdr + n_fixed + n_variable;

	/* similar sum to determine how much local memory is required */
	n_alloc = n_fixed + n_variable;

	/* For the moment, grow enough for the fixed-size part */
	rc = ndr_outer_grow(outer_ref, n_pdu_total);
	if (!rc)
		return (rc);		/* error already set */

	switch (nds->m_op) {
	case NDR_M_OP_MARSHALL:
		/*
		 * We don't know the size yet. We have to wait for
		 * it. Proceed with the fixed-size part, and await
		 * the call to ndr_size_is().
		 */
		size_is = 0;
		rc = ndr_outer_poke_sizing(outer_ref, 0, &size_is);
		if (!rc)
			return (0);	/* error already set */

		valp = outer_ref->datum;
		if (!valp) {
			NDR_SET_ERROR(outer_ref, NDR_ERR_OUTER_PARAMS_BAD);
			return (0);
		}
		if (outer_ref->backptr)
			assert(valp == *outer_ref->backptr);
		break;

	case NDR_M_OP_UNMARSHALL:
		/*
		 * We know the size of the variable part because
		 * of the CONFORMANT header. We will verify
		 * the header against the [size_is(X)] advice
		 * later when ndr_size_is() is called.
		 */
		rc = ndr_outer_peek_sizing(outer_ref, 0, &size_is);
		if (!rc)
			return (0);	/* error already set */

		/* recalculate metrics */
		n_variable = size_is * ti->pdu_size_variable_part;
		n_pdu_total = n_hdr + n_fixed + n_variable;
		n_alloc = n_fixed + n_variable;

		rc = ndr_outer_grow(outer_ref, n_pdu_total);
		if (!rc)
			return (rc);		/* error already set */

		outer_ref->size_is = size_is; /* verified later */

		valp = NDS_MALLOC(nds, n_alloc, outer_ref);
		if (!valp) {
			NDR_SET_ERROR(outer_ref, NDR_ERR_MALLOC_FAILED);
			return (0);
		}
		if (outer_ref->backptr)
			*outer_ref->backptr = valp;
		outer_ref->datum = valp;
		break;

	default:
		NDR_SET_ERROR(outer_ref, NDR_ERR_M_OP_INVALID);
		return (0);
	}

	outer_ref->pdu_end_offset = outer_ref->pdu_offset + n_pdu_total;
	outer_ref->type_flags = NDR_F_SIZE_IS; /* indicate pending */
	outer_ref->inner_flags = NDR_F_NONE;   /* indicate pending */

	bzero(&myref, sizeof (myref));
	myref.stream = nds;
	myref.enclosing = outer_ref;
	myref.ti = outer_ref->ti;
	myref.datum = outer_ref->datum;
	myref.name = "CONFORMANT-CONSTRUCT";
	myref.outer_flags = NDR_F_NONE;
	myref.inner_flags = NDR_F_NONE;
	myref.size_is = outer_ref->size_is;

	myref.pdu_offset = outer_ref->pdu_offset + 4;

	rc = ndr_inner(&myref);
	if (!rc)
		return (rc);		/* error already set */

	nds->pdu_scan_offset = outer_ref->pdu_end_offset;

	if (outer_ref->inner_flags != NDR_F_SIZE_IS) {
		NDR_SET_ERROR(&myref, NDR_ERR_SIZE_IS_MISMATCH_AFTER);
		return (0);
	}

	return (1);
}

int
ndr_size_is(ndr_ref_t *ref)
{
	ndr_stream_t 		*nds = ref->stream;
	ndr_ref_t 		*outer_ref = nds->outer_current;
	ndr_typeinfo_t		*ti = outer_ref->ti;
	unsigned long		size_is;
	int			rc;
	unsigned		n_hdr;
	unsigned		n_fixed;
	unsigned		n_variable;
	unsigned		n_pdu_total;

	assert(ref->inner_flags & NDR_F_SIZE_IS);
	size_is = ref->size_is;

	if (outer_ref->type_flags != NDR_F_SIZE_IS) {
		NDR_SET_ERROR(ref, NDR_ERR_SIZE_IS_UNEXPECTED);
		return (0);
	}

	if (outer_ref->inner_flags & NDR_F_SIZE_IS) {
		NDR_SET_ERROR(ref, NDR_ERR_SIZE_IS_DUPLICATED);
		return (0);
	}

	/* repeat metrics, see ndr_conformant_construct() above */
	n_hdr = 4;
	n_fixed = ti->pdu_size_fixed_part;
	n_variable = size_is * ti->pdu_size_variable_part;
	n_pdu_total = n_hdr + n_fixed + n_variable;

	rc = ndr_outer_grow(outer_ref, n_pdu_total);
	if (!rc)
		return (rc);		/* error already set */

	switch (nds->m_op) {
	case NDR_M_OP_MARSHALL:
		/*
		 * We have to set the sizing header and extend
		 * the size of the PDU (already done).
		 */
		rc = ndr_outer_poke_sizing(outer_ref, 0, &size_is);
		if (!rc)
			return (0);	/* error already set */
		break;

	case NDR_M_OP_UNMARSHALL:
		/*
		 * Allocation done during ndr_conformant_construct().
		 * All we are doing here is verifying that the
		 * intended size (ref->size_is) matches the sizing header.
		 */
		if (size_is != outer_ref->size_is) {
			NDR_SET_ERROR(ref, NDR_ERR_SIZE_IS_MISMATCH_PDU);
			return (0);
		}
		break;

	default:
		NDR_SET_ERROR(outer_ref, NDR_ERR_M_OP_INVALID);
		return (0);
	}

	outer_ref->inner_flags |= NDR_F_SIZE_IS;
	outer_ref->size_is = ref->size_is;
	return (1);
}

int
ndr_outer_string(ndr_ref_t *outer_ref)
{
	ndr_stream_t	*nds = outer_ref->stream;
	ndr_typeinfo_t 	*ti = outer_ref->ti;
	ndr_ref_t	myref;
	char 		*valp = NULL;
	unsigned	is_varlen = ti->pdu_size_variable_part;
	int		is_union = NDR_IS_UNION(ti);
	int		is_string = NDR_IS_STRING(ti);
	int		rc;
	unsigned	n_zeroes;
	unsigned	ix;
	unsigned long	size_is;
	unsigned long	first_is;
	unsigned long	length_is;
	unsigned	n_hdr;
	unsigned	n_fixed;
	unsigned	n_variable;
	unsigned	n_alloc;
	unsigned	n_pdu_total;
	int		params;

	params = outer_ref->outer_flags & NDR_F_PARAMS_MASK;

	assert(is_varlen && is_string && !is_union);
	assert(params == NDR_F_NONE);

	/* string header for this: size_is first_is length_is */
	n_hdr = 12;

	/* fixed part -- exactly none of these */
	n_fixed = 0;

	if (!ndr_outer_grow(outer_ref, n_hdr))
		return (0);		/* error already set */

	switch (nds->m_op) {
	case NDR_M_OP_MARSHALL:
		valp = outer_ref->datum;
		if (!valp) {
			NDR_SET_ERROR(outer_ref, NDR_ERR_OUTER_PARAMS_BAD);
			return (0);
		}

		if (outer_ref->backptr)
			assert(valp == *outer_ref->backptr);

		if (ti == &ndt_s_wchar) {
			/*
			 * size_is is the number of characters in the
			 * (multibyte) string, including the null.
			 * In other words, symbols, not bytes.
			 */
			size_t wlen;
			wlen = ndr__mbstowcs(NULL, valp, NDR_STRING_MAX);
			if (wlen == (size_t)-1) {
				/* illegal sequence error? */
				NDR_SET_ERROR(outer_ref, NDR_ERR_STRLEN);
				return (0);
			}
			if ((nds->flags & NDS_F_NONULL) == 0)
				wlen++;
			if (wlen > NDR_STRING_MAX) {
				NDR_SET_ERROR(outer_ref, NDR_ERR_STRLEN);
				return (0);
			}
			size_is = wlen;
		} else {
			valp = outer_ref->datum;
			n_zeroes = 0;
			for (ix = 0; ix < NDR_STRING_MAX; ix++) {
				if (valp[ix] == 0) {
					n_zeroes++;
					if (n_zeroes >= is_varlen &&
					    ix % is_varlen == 0) {
						break;
					}
				} else {
					n_zeroes = 0;
				}
			}
			if (ix >= NDR_STRING_MAX) {
				NDR_SET_ERROR(outer_ref, NDR_ERR_STRLEN);
				return (0);
			}
			size_is = ix+1;
		}

		first_is = 0;

		if (nds->flags & NDS_F_NOTERM)
			length_is = size_is - 1;
		else
			length_is = size_is;

		if (!ndr_outer_poke_sizing(outer_ref, 0, &size_is) ||
		    !ndr_outer_poke_sizing(outer_ref, 4, &first_is) ||
		    !ndr_outer_poke_sizing(outer_ref, 8, &length_is))
			return (0);		/* error already set */
		break;

	case NDR_M_OP_UNMARSHALL:
		if (!ndr_outer_peek_sizing(outer_ref, 0, &size_is) ||
		    !ndr_outer_peek_sizing(outer_ref, 4, &first_is) ||
		    !ndr_outer_peek_sizing(outer_ref, 8, &length_is))
			return (0);		/* error already set */

		/*
		 * In addition to the first_is check, we used to check that
		 * size_is or size_is-1 was equal to length_is but Windows95
		 * doesn't conform to this "rule" (see variable part below).
		 * The srvmgr tool for Windows95 sent the following values
		 * for a path string:
		 *
		 *	size_is   = 261 (0x105)
		 *	first_is  = 0
		 *	length_is = 53  (0x35)
		 *
		 * The length_is was correct (for the given path) but the
		 * size_is was the maximum path length rather than being
		 * related to length_is.
		 */
		if (first_is != 0) {
			NDR_SET_ERROR(outer_ref, NDR_ERR_STRING_SIZING);
			return (0);
		}

		if (ti == &ndt_s_wchar) {
			/*
			 * Decoding Unicode to UTF-8; we need to allow
			 * for the maximum possible char size. It would
			 * be nice to use mbequiv_strlen but the string
			 * may not be null terminated.
			 */
			n_alloc = (size_is + 1) * NDR_MB_CHAR_MAX;
		} else {
			n_alloc = (size_is + 1) * is_varlen;
		}

		valp = NDS_MALLOC(nds, n_alloc, outer_ref);
		if (!valp) {
			NDR_SET_ERROR(outer_ref, NDR_ERR_MALLOC_FAILED);
			return (0);
		}

		bzero(valp, (size_is+1) * is_varlen);

		if (outer_ref->backptr)
			*outer_ref->backptr = valp;
		outer_ref->datum = valp;
		break;

	default:
		NDR_SET_ERROR(outer_ref, NDR_ERR_M_OP_INVALID);
		return (0);
	}

	/*
	 * Variable part - exactly length_is of these.
	 *
	 * Usually, length_is is same as size_is and includes nul.
	 * Some protocols use length_is = size_is-1, and length_is does
	 * not include the nul (which is more consistent with DCE spec).
	 * If the length_is is 0, there is no data following the
	 * sizing header, regardless of size_is.
	 */
	n_variable = length_is * is_varlen;

	/* sum them up to determine the PDU space required */
	n_pdu_total = n_hdr + n_fixed + n_variable;

	/* similar sum to determine how much local memory is required */
	n_alloc = n_fixed + n_variable;

	rc = ndr_outer_grow(outer_ref, n_pdu_total);
	if (!rc)
		return (rc);		/* error already set */

	if (length_is > 0) {
		bzero(&myref, sizeof (myref));
		myref.stream = nds;
		myref.enclosing = outer_ref;
		myref.ti = outer_ref->ti;
		myref.datum = outer_ref->datum;
		myref.name = "OUTER-STRING";
		myref.outer_flags = NDR_F_IS_STRING;
		myref.inner_flags = NDR_F_NONE;

		/*
		 * Set up size_is and strlen_is for ndr_s_wchar.
		 */
		myref.size_is = size_is;
		myref.strlen_is = length_is;
	}

	myref.pdu_offset = outer_ref->pdu_offset + 12;

	/*
	 * Don't try to decode empty strings.
	 */
	if ((size_is == 0) && (first_is == 0) && (length_is == 0)) {
		nds->pdu_scan_offset = outer_ref->pdu_end_offset;
		return (1);
	}

	if ((size_is != 0) && (length_is != 0)) {
		rc = ndr_inner(&myref);
		if (!rc)
			return (rc);		/* error already set */
	}

	nds->pdu_scan_offset = outer_ref->pdu_end_offset;
	return (1);
}

int
ndr_outer_peek_sizing(ndr_ref_t *outer_ref, unsigned offset,
    unsigned long *sizing_p)
{
	ndr_stream_t 	*nds = outer_ref->stream;
	unsigned long	pdu_offset;
	int		rc;

	pdu_offset = outer_ref->pdu_offset + offset;

	if (pdu_offset < nds->outer_current->pdu_offset ||
	    pdu_offset > nds->outer_current->pdu_end_offset ||
	    pdu_offset+4 > nds->outer_current->pdu_end_offset) {
		NDR_SET_ERROR(outer_ref, NDR_ERR_BOUNDS_CHECK);
		return (0);
	}

	switch (nds->m_op) {
	case NDR_M_OP_MARSHALL:
		NDR_SET_ERROR(outer_ref, NDR_ERR_UNIMPLEMENTED);
		return (0);

	case NDR_M_OP_UNMARSHALL:
		rc = NDS_GET_PDU(nds, pdu_offset, 4, (char *)sizing_p,
		    nds->swap, outer_ref);
		break;

	default:
		NDR_SET_ERROR(outer_ref, NDR_ERR_M_OP_INVALID);
		return (0);
	}

	return (rc);
}

int
ndr_outer_poke_sizing(ndr_ref_t *outer_ref, unsigned offset,
    unsigned long *sizing_p)
{
	ndr_stream_t 	*nds = outer_ref->stream;
	unsigned long	pdu_offset;
	int		rc;

	pdu_offset = outer_ref->pdu_offset + offset;

	if (pdu_offset < nds->outer_current->pdu_offset ||
	    pdu_offset > nds->outer_current->pdu_end_offset ||
	    pdu_offset+4 > nds->outer_current->pdu_end_offset) {
		NDR_SET_ERROR(outer_ref, NDR_ERR_BOUNDS_CHECK);
		return (0);
	}

	switch (nds->m_op) {
	case NDR_M_OP_MARSHALL:
		rc = NDS_PUT_PDU(nds, pdu_offset, 4, (char *)sizing_p,
		    nds->swap, outer_ref);
		break;

	case NDR_M_OP_UNMARSHALL:
		NDR_SET_ERROR(outer_ref, NDR_ERR_UNIMPLEMENTED);
		return (0);

	default:
		NDR_SET_ERROR(outer_ref, NDR_ERR_M_OP_INVALID);
		return (0);
	}

	return (rc);
}

/*
 * All OUTER constructs begin on a mod4 (dword) boundary - except
 * for the ones that don't: some MSRPC calls appear to use word or
 * packed alignment.  Strings appear to be dword aligned.
 */
int
ndr_outer_align(ndr_ref_t *outer_ref)
{
	ndr_stream_t 	*nds = outer_ref->stream;
	int		rc;
	unsigned	n_pad;
	unsigned	align;

	if (outer_ref->packed_alignment && outer_ref->ti != &ndt_s_wchar) {
		align = outer_ref->ti->alignment;
		n_pad = ((align + 1) - nds->pdu_scan_offset) & align;
	} else {
		n_pad = NDR_ALIGN4(nds->pdu_scan_offset);
	}

	if (n_pad == 0)
		return (1);	/* already aligned, often the case */

	if (!ndr_outer_grow(outer_ref, n_pad))
		return (0);	/* error already set */

	switch (nds->m_op) {
	case NDR_M_OP_MARSHALL:
		rc = NDS_PAD_PDU(nds, nds->pdu_scan_offset, n_pad, outer_ref);
		if (!rc) {
			NDR_SET_ERROR(outer_ref, NDR_ERR_PAD_FAILED);
			return (0);
		}
		break;

	case NDR_M_OP_UNMARSHALL:
		break;

	default:
		NDR_SET_ERROR(outer_ref, NDR_ERR_M_OP_INVALID);
		return (0);
	}

	nds->pdu_scan_offset += n_pad;
	return (1);
}

int
ndr_outer_grow(ndr_ref_t *outer_ref, unsigned n_total)
{
	ndr_stream_t 	*nds = outer_ref->stream;
	unsigned long	pdu_want_size;
	int		rc, is_ok = 0;

	pdu_want_size = nds->pdu_scan_offset + n_total;

	if (pdu_want_size <= nds->pdu_max_size) {
		is_ok = 1;
	}

	switch (nds->m_op) {
	case NDR_M_OP_MARSHALL:
		if (is_ok)
			break;
		rc = NDS_GROW_PDU(nds, pdu_want_size, outer_ref);
		if (!rc) {
			NDR_SET_ERROR(outer_ref, NDR_ERR_GROW_FAILED);
			return (0);
		}
		break;

	case NDR_M_OP_UNMARSHALL:
		if (is_ok)
			break;
		NDR_SET_ERROR(outer_ref, NDR_ERR_UNDERFLOW);
		return (0);

	default:
		NDR_SET_ERROR(outer_ref, NDR_ERR_M_OP_INVALID);
		return (0);
	}

	if (nds->pdu_size < pdu_want_size)
		nds->pdu_size = pdu_want_size;

	outer_ref->pdu_end_offset = pdu_want_size;
	return (1);
}

/*
 * INNER ELEMENTS
 *
 * The local datum (arg_ref->datum) already exists, there is no need to
 * malloc() it.  The datum should point at a member of a structure.
 *
 * For the most part, ndr_inner() and its helpers are just a sanity
 * check.  The underlying ti->ndr_func() could be called immediately
 * for non-pointer elements.  For the sake of robustness, we detect
 * run-time errors here.  Most of the situations this protects against
 * have already been checked by the IDL compiler.  This is also a
 * common point for processing of all data, and so is a convenient
 * place to work from for debugging.
 */
int
ndr_inner(ndr_ref_t *arg_ref)
{
	ndr_typeinfo_t 	*ti = arg_ref->ti;
	int	is_varlen = ti->pdu_size_variable_part;
	int	is_union = NDR_IS_UNION(ti);
	int	error = NDR_ERR_INNER_PARAMS_BAD;
	int	params;

	params = arg_ref->inner_flags & NDR_F_PARAMS_MASK;

	switch (params) {
	case NDR_F_NONE:
		if (is_union) {
			error = NDR_ERR_SWITCH_VALUE_MISSING;
			break;
		}
		return (*ti->ndr_func)(arg_ref);

	case NDR_F_SIZE_IS:
	case NDR_F_DIMENSION_IS:
	case NDR_F_IS_POINTER+NDR_F_SIZE_IS:   /* pointer to something */
	case NDR_F_IS_REFERENCE+NDR_F_SIZE_IS: /* pointer to something */
		if (is_varlen) {
			error = NDR_ERR_ARRAY_VARLEN_ILLEGAL;
			break;
		}
		if (is_union) {
			error = NDR_ERR_ARRAY_UNION_ILLEGAL;
			break;
		}
		if (params & NDR_F_IS_POINTER)
			return (ndr_inner_pointer(arg_ref));
		else if (params & NDR_F_IS_REFERENCE)
			return (ndr_inner_reference(arg_ref));
		else
			return (ndr_inner_array(arg_ref));

	case NDR_F_IS_POINTER:	/* type is pointer to one something */
		if (is_union) {
			error = NDR_ERR_ARRAY_UNION_ILLEGAL;
			break;
		}
		return (ndr_inner_pointer(arg_ref));

	case NDR_F_IS_REFERENCE:	/* type is pointer to one something */
		if (is_union) {
			error = NDR_ERR_ARRAY_UNION_ILLEGAL;
			break;
		}
		return (ndr_inner_reference(arg_ref));

	case NDR_F_SWITCH_IS:
		if (!is_union) {
			error = NDR_ERR_SWITCH_VALUE_ILLEGAL;
			break;
		}
		return (*ti->ndr_func)(arg_ref);

	default:
		error = NDR_ERR_INNER_PARAMS_BAD;
		break;
	}

	/*
	 * If we get here, something is wrong. Most likely,
	 * the params flags do not match
	 */
	NDR_SET_ERROR(arg_ref, error);
	return (0);
}

int
ndr_inner_pointer(ndr_ref_t *arg_ref)
{
	ndr_stream_t	*nds = arg_ref->stream;
	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	char 		**valpp = (char **)arg_ref->datum;
	ndr_ref_t 	*outer_ref;

	if (!ndr__ulong(arg_ref))
		return (0);	/* error */
	if (!*valpp)
		return (1);	/* NULL pointer */

	outer_ref = ndr_enter_outer_queue(arg_ref);
	if (!outer_ref)
		return (0);	/* error already set */

	/*
	 * Move advice in inner_flags to outer_flags.
	 * Retain pointer flag for conformant arrays.
	 */
	outer_ref->outer_flags = arg_ref->inner_flags & NDR_F_PARAMS_MASK;
	if ((outer_ref->outer_flags & NDR_F_SIZE_IS) == 0)
		outer_ref->outer_flags &= ~NDR_F_IS_POINTER;
#ifdef NDR_INNER_PTR_NOT_YET
	outer_ref->outer_flags |= NDR_F_BACKPTR;
	if (outer_ref->outer_flags & NDR_F_SIZE_IS) {
		outer_ref->outer_flags |= NDR_F_ARRAY+NDR_F_CONFORMANT;
	}
#endif /* NDR_INNER_PTR_NOT_YET */

	outer_ref->backptr = valpp;

	switch (nds->m_op) {
	case NDR_M_OP_MARSHALL:
		outer_ref->datum = *valpp;
		break;

	case NDR_M_OP_UNMARSHALL:
		/*
		 * This is probably wrong if the application allocated
		 * memory in advance.  Indicate no value for now.
		 * ONC RPC handles this case.
		 */
		*valpp = 0;
		outer_ref->datum = 0;
		break;
	}

	return (1);		/* pointer dereference scheduled */
}

int
ndr_inner_reference(ndr_ref_t *arg_ref)
{
	ndr_stream_t	*nds = arg_ref->stream;
	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	char		**valpp = (char **)arg_ref->datum;
	ndr_ref_t	*outer_ref;

	outer_ref = ndr_enter_outer_queue(arg_ref);
	if (!outer_ref)
		return (0);	/* error already set */

	/*
	 * Move advice in inner_flags to outer_flags.
	 * Retain reference flag for conformant arrays.
	 */
	outer_ref->outer_flags = arg_ref->inner_flags & NDR_F_PARAMS_MASK;
	if ((outer_ref->outer_flags & NDR_F_SIZE_IS) == 0)
		outer_ref->outer_flags &= ~NDR_F_IS_REFERENCE;
#ifdef NDR_INNER_REF_NOT_YET
	outer_ref->outer_flags |= NDR_F_BACKPTR;
	if (outer_ref->outer_flags & NDR_F_SIZE_IS) {
		outer_ref->outer_flags |= NDR_F_ARRAY+NDR_F_CONFORMANT;
	}
#endif /* NDR_INNER_REF_NOT_YET */

	outer_ref->backptr = valpp;

	switch (nds->m_op) {
	case NDR_M_OP_MARSHALL:
		outer_ref->datum = *valpp;
		break;

	case NDR_M_OP_UNMARSHALL:
		/*
		 * This is probably wrong if the application allocated
		 * memory in advance.  Indicate no value for now.
		 * ONC RPC handles this case.
		 */
		*valpp = 0;
		outer_ref->datum = 0;
		break;
	}

	return (1);		/* pointer dereference scheduled */
}

int
ndr_inner_array(ndr_ref_t *encl_ref)
{
	ndr_typeinfo_t		*ti = encl_ref->ti;
	ndr_ref_t		myref;
	unsigned long		pdu_offset = encl_ref->pdu_offset;
	unsigned long		n_elem;
	unsigned long		i;
	char			name[30];

	if (encl_ref->inner_flags & NDR_F_SIZE_IS) {
		/* now is the time to check/set size */
		if (!ndr_size_is(encl_ref))
			return (0);	/* error already set */
		n_elem = encl_ref->size_is;
	} else {
		assert(encl_ref->inner_flags & NDR_F_DIMENSION_IS);
		n_elem = encl_ref->dimension_is;
	}

	bzero(&myref, sizeof (myref));
	myref.enclosing = encl_ref;
	myref.stream = encl_ref->stream;
	myref.packed_alignment = 0;
	myref.ti = ti;
	myref.inner_flags = NDR_F_NONE;

	for (i = 0; i < n_elem; i++) {
		(void) snprintf(name, sizeof (name), "[%lu]", i);
		myref.name = name;
		myref.pdu_offset = pdu_offset + i * ti->pdu_size_fixed_part;
		myref.datum = encl_ref->datum + i * ti->c_size_fixed_part;

		if (!ndr_inner(&myref))
			return (0);
	}

	return (1);
}


/*
 * BASIC TYPES
 */
#define	MAKE_BASIC_TYPE_BASE(TYPE, SIZE) \
    extern int ndr_##TYPE(struct ndr_reference *encl_ref); \
    ndr_typeinfo_t ndt_##TYPE = { \
	1,		/* NDR version */ \
	(SIZE)-1,	/* alignment */ \
	NDR_F_NONE,	/* flags */ \
	ndr_##TYPE,	/* ndr_func */ \
	SIZE,		/* pdu_size_fixed_part */ \
	0,		/* pdu_size_variable_part */ \
	SIZE,		/* c_size_fixed_part */ \
	0,		/* c_size_variable_part */ \
	}; \
    int ndr_##TYPE(struct ndr_reference *ref) { \
	return (ndr_basic_integer(ref, SIZE)); \
}

#define	MAKE_BASIC_TYPE_STRING(TYPE, SIZE) \
    extern int ndr_s##TYPE(struct ndr_reference *encl_ref); \
    ndr_typeinfo_t ndt_s##TYPE = { \
	1,		/* NDR version */ \
	(SIZE)-1,	/* alignment */ \
	NDR_F_STRING,	/* flags */ \
	ndr_s##TYPE,	/* ndr_func */ \
	0,		/* pdu_size_fixed_part */ \
	SIZE,		/* pdu_size_variable_part */ \
	0,		/* c_size_fixed_part */ \
	SIZE,		/* c_size_variable_part */ \
	}; \
    int ndr_s##TYPE(struct ndr_reference *ref) { \
	return (ndr_string_basic_integer(ref, &ndt_##TYPE)); \
}

#define	MAKE_BASIC_TYPE(TYPE, SIZE) \
	MAKE_BASIC_TYPE_BASE(TYPE, SIZE) \
	MAKE_BASIC_TYPE_STRING(TYPE, SIZE)

int ndr_basic_integer(ndr_ref_t *, unsigned);
int ndr_string_basic_integer(ndr_ref_t *, ndr_typeinfo_t *);

/* Comments to be nice to those searching for these types. */
MAKE_BASIC_TYPE(_char, 1)	/* ndt__char,  ndt_s_char */
MAKE_BASIC_TYPE(_uchar, 1)	/* ndt__uchar, ndt_s_uchar */
MAKE_BASIC_TYPE(_short, 2)	/* ndt__short, ndt_s_short */
MAKE_BASIC_TYPE(_ushort, 2)	/* ndt__ushort, ndt_s_ushort */
MAKE_BASIC_TYPE(_long, 4)	/* ndt__long,  ndt_s_long */
MAKE_BASIC_TYPE(_ulong, 4)	/* ndt__ulong, ndt_s_ulong */

MAKE_BASIC_TYPE_BASE(_wchar, 2)	/* ndt__wchar, ndt_s_wchar */

int
ndr_basic_integer(ndr_ref_t *ref, unsigned size)
{
	ndr_stream_t	*nds = ref->stream;
	char 		*valp = (char *)ref->datum;
	int		rc;

	switch (nds->m_op) {
	case NDR_M_OP_MARSHALL:
		rc = NDS_PUT_PDU(nds, ref->pdu_offset, size,
		    valp, nds->swap, ref);
		break;

	case NDR_M_OP_UNMARSHALL:
		rc = NDS_GET_PDU(nds, ref->pdu_offset, size,
		    valp, nds->swap, ref);
		break;

	default:
		NDR_SET_ERROR(ref, NDR_ERR_M_OP_INVALID);
		return (0);
	}

	return (rc);
}

int
ndr_string_basic_integer(ndr_ref_t *encl_ref, ndr_typeinfo_t *type_under)
{
	unsigned long		pdu_offset = encl_ref->pdu_offset;
	unsigned		size = type_under->pdu_size_fixed_part;
	char			*valp;
	ndr_ref_t		myref;
	unsigned long		i;
	long			sense = 0;
	char			name[30];

	assert(size != 0);

	bzero(&myref, sizeof (myref));
	myref.enclosing = encl_ref;
	myref.stream = encl_ref->stream;
	myref.packed_alignment = 0;
	myref.ti = type_under;
	myref.inner_flags = NDR_F_NONE;
	myref.name = name;

	for (i = 0; i < NDR_STRING_MAX; i++) {
		(void) snprintf(name, sizeof (name), "[%lu]", i);
		myref.pdu_offset = pdu_offset + i * size;
		valp = encl_ref->datum + i * size;
		myref.datum = valp;

		if (!ndr_inner(&myref))
			return (0);

		switch (size) {
		case 1:		sense = *valp; break;
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		case 2:		sense = *(short *)valp; break;
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		case 4:		sense = *(long *)valp; break;
		}

		if (!sense)
			break;
	}

	return (1);
}


extern int ndr_s_wchar(ndr_ref_t *encl_ref);
ndr_typeinfo_t ndt_s_wchar = {
	1,		/* NDR version */
	2-1,		/* alignment */
	NDR_F_STRING,	/* flags */
	ndr_s_wchar,	/* ndr_func */
	0,		/* pdu_size_fixed_part */
	2,		/* pdu_size_variable_part */
	0,		/* c_size_fixed_part */
	1,		/* c_size_variable_part */
};


/*
 * Hand coded wchar function because all strings are transported
 * as wide characters. During NDR_M_OP_MARSHALL, we convert from
 * multi-byte to wide characters. During NDR_M_OP_UNMARSHALL, we
 * convert from wide characters to multi-byte.
 *
 * The most critical thing to get right in this function is to
 * marshall or unmarshall _exactly_ the number of elements the
 * OtW length specifies, as saved by the caller in: strlen_is.
 * Doing otherwise would leave us positioned at the wrong place
 * in the data stream for whatever follows this.  Note that the
 * string data covered by strlen_is may or may not include any
 * null termination, but the converted string provided by the
 * caller or returned always has a null terminator.
 */
int
ndr_s_wchar(ndr_ref_t *encl_ref)
{
	ndr_stream_t		*nds = encl_ref->stream;
	char			*valp = encl_ref->datum;
	ndr_ref_t		myref;
	char			name[30];
	ndr_wchar_t		wcs[NDR_STRING_MAX+1];
	size_t			i, slen, wlen;

	/* This is enforced in ndr_outer_string() */
	assert(encl_ref->strlen_is <= NDR_STRING_MAX);

	if (nds->m_op == NDR_M_OP_UNMARSHALL) {
		/*
		 * To avoid problems with zero length strings
		 * we can just null terminate here and be done.
		 */
		if (encl_ref->strlen_is == 0) {
			encl_ref->datum[0] = '\0';
			return (1);
		}
	}

	/*
	 * If we're marshalling, convert the given string
	 * from UTF-8 into a local UCS-2 string.
	 */
	if (nds->m_op == NDR_M_OP_MARSHALL) {
		wlen = ndr__mbstowcs(wcs, valp, NDR_STRING_MAX);
		if (wlen == (size_t)-1)
			return (0);
		/*
		 * Add a nulls to make strlen_is.
		 * (always zero or one of them)
		 * Then null terminate at wlen,
		 * just for debug convenience.
		 */
		while (wlen < encl_ref->strlen_is)
			wcs[wlen++] = 0;
		wcs[wlen] = 0;
	}

	/*
	 * Copy wire data to or from the local wc string.
	 * Always exactly strlen_is elements.
	 */
	bzero(&myref, sizeof (myref));
	myref.enclosing = encl_ref;
	myref.stream = encl_ref->stream;
	myref.packed_alignment = 0;
	myref.ti = &ndt__wchar;
	myref.inner_flags = NDR_F_NONE;
	myref.name = name;
	myref.pdu_offset = encl_ref->pdu_offset;
	myref.datum = (char *)wcs;
	wlen = encl_ref->strlen_is;

	for (i = 0; i < wlen; i++) {
		(void) snprintf(name, sizeof (name), "[%lu]", i);
		if (!ndr_inner(&myref))
			return (0);
		myref.pdu_offset += sizeof (ndr_wchar_t);
		myref.datum	 += sizeof (ndr_wchar_t);
	}

	/*
	 * If this is unmarshall, convert the local UCS-2 string
	 * into a UTF-8 string in the caller's buffer.  The caller
	 * previously determined the space required and provides a
	 * buffer of sufficient size.
	 */
	if (nds->m_op == NDR_M_OP_UNMARSHALL) {
		wcs[wlen] = 0;
		slen = encl_ref->size_is * NDR_MB_CHAR_MAX;
		slen = ndr__wcstombs(valp, wcs, slen);
		if (slen == (size_t)-1)
			return (0);
		valp[slen] = '\0';
	}

	return (1);
}

/*
 * Converts a multibyte character string to a little-endian, wide-char
 * string.  No more than nwchars wide characters are stored.
 * A terminating null wide character is appended if there is room.
 *
 * Returns the number of wide characters converted, not counting
 * any terminating null wide character.  Returns -1 if an invalid
 * multibyte character is encountered.
 */
/* ARGSUSED */
size_t
ndr_mbstowcs(ndr_stream_t *nds, ndr_wchar_t *wcs, const char *mbs,
    size_t nwchars)
{
	size_t len;

#ifdef _BIG_ENDIAN
	if (nds == NULL || NDR_MODE_MATCH(nds, NDR_MODE_RETURN_SEND)) {
		/* Make WC string in LE order. */
		len = ndr__mbstowcs_le(wcs, mbs, nwchars);
	} else
#endif
		len = ndr__mbstowcs(wcs, mbs, nwchars);

	return (len);
}
