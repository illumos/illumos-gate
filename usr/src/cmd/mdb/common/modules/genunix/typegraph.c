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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2025 Oxide Computer Company
 */

/*
 * Postmortem type identification
 * ------------------------------
 *
 * When debugging kernel memory corruption problems, one often determines that
 * the corrupted buffer has been erroneously written to by a user of an
 * adjacent buffer -- determining the specifics of the adjacent buffer can
 * therefore offer insight into the cause of the corruption.  To determine the
 * type of an arbitrary memory buffer, however, one has historically been
 * forced to use dcmds ::kgrep and ::whatis in alternating succession; when an
 * object of known type is finally reached, types can be back-propagated to
 * determine the type of the unknown object.
 *
 * This process is labor-intensive and error-prone.  Using CTF data and a
 * collection of heuristics, we would like to both automate this process and
 * improve on it.
 *
 * We start by constructing the pointer graph.  Each node in the graph is
 * a memory object (either a static object from module data, or a dynamically
 * allocated memory object); the node's outgoing edges represent pointers from
 * the object to other memory objects in the system.
 *
 * Once the graph is constructed, we start at nodes of known type, and use the
 * type information to determine the type of each pointer represented by an
 * outgoing edge.  Determining the pointer type allows us to determine the
 * type of the edge's destination node, and therefore to iteratively continue
 * the process of type identification.  This process works as long as all
 * pointed-to objects are exactly the size of their inferred types.
 *
 * Unfortunately, pointed-to objects are often _not_ the size of the pointed-to
 * type.  This is largely due to three phenomena:
 *
 * (a)	C makes no distinction between a pointer to a single object and a
 *	pointer to some number of objects of like type.
 *
 * (b)	C performs no bounds checking on array indexing, allowing declarations
 *	of structures that are implicitly followed by arrays of the type of the
 *	structure's last member.  These declarations most often look like:
 *
 *	    typedef struct foo {
 *	            int       foo_bar;
 *	            int       foo_baz;
 *	            mumble_t  foo_mumble[1];
 *	    } foo_t;
 *
 *	When a foo_t is allocated, the size of n - 1 mumble_t's is added to the
 *	size of a foo_t to derive the size of the allocation; this allows for
 *	the n trailing mumble_t's to be referenced from the allocated foo_t
 *	using C's convenient array syntax -- without requiring an additional
 *	memory dereference.  ISO C99 calls the last member in such a structure
 *	the "flexible array member" (FAM); we adhere to this terminology.
 *
 * (c)	It is not uncommon for structures to embed smaller structures, and
 *	to pass pointers to these smaller structures to routines that track
 *	the structures only by the smaller type.  This can be thought of as
 *	a sort of crude-but-efficient polymorphism; see e.g., struct seg and
 *	its embedded avl_node_t.  It is less common (but by no means unheard
 *	of) for the smaller structures to be used as place holders in data
 *	structures consisting of the larger structure.  That is, instead of an
 *	instance of the larger structure being pointed to by the smaller
 *	structure pointer, an instance of the smaller structure is pointed to
 *	the larger structure pointer; see e.g., struct buf and struct hbuf or
 *	struct seg_pcache and struct seg_phash.  This construct is particularly
 *	important to identify when the smaller structures are in a contiguous
 *	array (as they are in each of the two examples provided):  by examining
 *	only the data structure of larger structures, one would erroneously
 *	assume that the array of the smaller structure is actually an array of
 *	the larger structure.
 *
 * Taken together, these three phenomena imply that if we have a pointer to
 * an object that is larger than the pointed-to type, we don't know if the
 * object is an array of objects of the pointed-to type, the pointed-to type
 * followed by an array of that type's last member, or some other larger type
 * that we haven't yet discovered.
 *
 * Differentiating these three situations is the focus of many of the
 * type graph heuristics.  Type graph processing is performed in an initial
 * pass, four type-determining passes, and a final, post-pass:
 *
 * Initial: Graph construction
 *
 * The initial pass constructs the nodes from the kmem caches and module data,
 * and constructs the edges by propagating out from module data.  Nodes that
 * are in module data or known kmem caches (see tg_cachetab[], below) are
 * marked with their known type.  This pass takes the longest amount of
 * wall-clock time, for it frequently induces I/O to read the postmortem image
 * into memory from permanent storage.
 *
 * pass1: Conservative propagation
 *
 * In pass1, we propagate types out from the known nodes, adding types to
 * nodes' tgn_typelists as they are inferred.  Nodes are marked as they are
 * processed to guarantee halting.  We proceed as conservatively as possible
 * in this pass; if we discover that a node is larger than twice its inferred
 * type (that is, we've run into one of the three phenomena described above),
 * we add the inferred type to the node's tgn_typelist, but we don't descend.
 *
 * pass2: Array determination
 *
 * In pass2, we visit those nodes through which we refused to descend in pass1.
 * If we find one (and only one) structural interpretation for the object, we
 * have determined that -- to the best of our knowledge -- we are not seeing
 * phenomenon (c).  To further differentiate (a) from (b), we check if the
 * structure ends with an array of size one; if it does, we assume that it has
 * a flexible array member.  Otherwise, we perform an additional check:  we
 * calculate the size of the object modulo the size of the inferred type and
 * subtract it from the size of the object.  If this value is less than or
 * equal to the size of the next-smaller kmem cache, we know that it's not an
 * array of the inferred type -- if it were an array of the inferred type, it
 * would have been instead allocated out of the next-smaller cache.
 *
 * In either case (FAM or no FAM), we iterate through each element of the
 * hypothesised array, checking that each pointer member points to either NULL
 * or valid memory.  If pointer members do not satisfy these criteria, it is
 * assumed that we have not satisfactorily determined that the given object is
 * an array of the inferred type, and we abort processing of the node.  Note
 * that uninitialized pointers can potentially prevent an otherwise valid
 * array from being interpreted as such.  Because array misinterpretation
 * can induce substantial cascading type misinterpretation, it is preferred to
 * be conservative and accurate in such cases -- even if it means a lower type
 * recognition rate.
 *
 * pass3: Type coalescence
 *
 * pass3 coalesces type possibilities by preferring structural possibilities
 * over non-structural ones.  For example, if an object is either of type
 * "char" (pointed to by a caddr_t) or type "struct frotz", the possibilities
 * will be coalesced into just "struct frotz."
 *
 * pass4: Non-array type inference
 *
 * pass4 is the least conservative:  it is assumed that phenomenon (c) has been
 * completely ferreted out by prior passes.  All unknown types are visited, and
 * incoming edges are checked.  If there is only one possible structural
 * inference for the unknown type, the node is inferred to be of that type, and
 * the type is propagated.  This pass picks up those nodes that are larger than
 * their inferred type, but for which the inferred type is likely accurate.
 * (struct dcentry, with its FAM of characters, is an example type that is
 * frequently determined by this pass.)
 *
 * Post-pass: Greatest unknown reach
 *
 * If recognition rate is low (or, from a more practical perspective, if the
 * object of interest is not automatically identified), it can be useful
 * to know which node is the greatest impediment to further recognition.
 * If the user can -- by hook or by crook -- determine the true type of this
 * node (and set it with ::istype), much more type identification should be
 * possible.  To facilitate this, we therefore define the _reach_ of a node to
 * be the number of unknown nodes that could potentially be identified were the
 * node's type better known.  We determine the reach by performing a
 * depth-first pass through the graph.  The node of greatest reach (along with
 * the reach itself) are reported upon completion of the post-pass.
 */

#include <mdb/mdb_param.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ctf.h>
#include <sys/sysmacros.h>
#include <sys/kmem_impl.h>
#include <sys/vmem_impl.h>
#include <sys/modctl.h>
#include <sys/kobj.h>
#include <stdio.h>
#include "kmem.h"

struct tg_node;

typedef struct tg_edge {
	struct tg_node	*tge_src;	/* source node */
	struct tg_node	*tge_dest;	/* destination node */
	uintptr_t	tge_srcoffs;	/* offset in source node */
	uintptr_t	tge_destoffs;	/* offset in destination node */
	struct tg_edge	*tge_nextin;	/* next incoming edge */
	struct tg_edge	*tge_nextout;	/* next outgoing edge */
	int		tge_marked;	/* mark */
} tg_edge_t;

typedef struct tg_type {
	mdb_ctf_id_t	tgt_type;	/* CTF type */
	mdb_ctf_id_t	tgt_utype;	/* unresolved CTF type */
	mdb_ctf_id_t	tgt_rtype;	/* referring type */
	size_t		tgt_roffs;	/* referring offset */
	const char	*tgt_rmember;	/* referring member */
	tg_edge_t	*tgt_redge;	/* referring edge */
	struct tg_type	*tgt_next;	/* next type */
	int		tgt_flags;	/* flags */
} tg_type_t;

#define	TG_TYPE_ARRAY		0x0001
#define	TG_TYPE_NOTARRAY	0x0002
#define	TG_TYPE_HASFAM		0x0004

typedef struct tg_node {
	uintptr_t	tgn_base;	/* address base of object */
	uintptr_t	tgn_limit;	/* address limit of object */
	tg_edge_t	*tgn_incoming;	/* incoming edges */
	tg_edge_t	*tgn_outgoing;	/* outgoing edges */
	tg_type_t	*tgn_typelist;	/* conjectured typelist */
	tg_type_t	*tgn_fraglist;	/* type fragment list */
	char		tgn_marked;	/* marked */
	char		tgn_postmarked;	/* marked in postpass */
	int		tgn_smaller;	/* size of next-smaller cache */
	int		tgn_reach;	/* number of reachable unknown nodes */
	mdb_ctf_id_t	tgn_type;	/* known type */
} tg_node_t;

#define	TG_NODE_SIZE(n)		((n)->tgn_limit - (n)->tgn_base)

typedef struct tg_stats {
	size_t	tgs_buffers;
	size_t	tgs_nodes;
	size_t	tgs_unmarked;
	size_t	tgs_known;
	size_t	tgs_typed;
	size_t	tgs_conflicts;
	size_t	tgs_frag;
	size_t	tgs_candidates;
} tg_stats_t;

typedef struct tg_typeoffs {
	mdb_ctf_id_t		tgto_type;	/* found type */
	ulong_t			tgto_offs;	/* offset of interest */
	const char		**tgto_memberp;	/* referring member name */
	tg_edge_t		*tgto_edge;	/* outbound edge */
} tg_typeoffs_t;

typedef struct tg_buildstate {
	uintptr_t		tgbs_addr;	/* address of region */
	uintptr_t		*tgbs_buf;	/* in-core copy of region */
	size_t			tgbs_ndx;	/* current pointer index */
	size_t			tgbs_nptrs;	/* number of pointers */
	tg_node_t		*tgbs_src;	/* corresponding node */
	struct tg_buildstate	*tgbs_next;	/* next stacked or free */
} tg_buildstate_t;

typedef struct tg_poststate {
	tg_node_t		*tgps_node;	/* current node */
	tg_edge_t		*tgps_edge;	/* current edge */
	size_t			tgps_total;	/* current total */
	struct tg_poststate	*tgps_next;	/* next stacked or free */
} tg_poststate_t;

typedef struct tg_todo {
	tg_node_t		*tgtd_node;	/* node to process */
	uintptr_t		tgtd_offs;	/* offset within node */
	mdb_ctf_id_t		tgtd_type;	/* conjectured type */
	struct tg_todo		*tgtd_next;	/* next todo */
} tg_todo_t;

typedef struct tg_nodedata {
	tg_node_t		*tgd_next;	/* next node to fill in */
	size_t			tgd_size;	/* size of this node */
} tg_nodedata_t;

/*
 * Some caches can be pretty arduous to identify (or are rife with conflicts).
 * To assist type identification, specific caches are identified with the
 * types of their contents.  Each cache need _not_ be listed here; in general,
 * a cache should only be added to the tg_cachetab[] if the identification rate
 * for the cache is less than 95%Every .  (The identification rate for a
 * specific cache can be quickly determined by specifying the cache to
 * ::typegraph.)
 */
struct {
	char *tgc_name;
	char *tgc_type;
} tg_cachetab[] = {
	{ "streams_mblk",	"mblk_t" },
	{ "seg_cache",		"struct seg" },
	{ "segvn_cache",	"struct segvn_data" },
	{ "anon_cache",		"struct anon" },
	{ "ufs_inode_cache",	"inode_t" },
	{ "hme_cache",		"struct hment" },
	{ "queue_cache",	"queinfo_t" },
	{ "sock_cache",		"struct sonode" },
	{ "ire_cache",		"ire_t" },
	{ NULL,			NULL }
};

/*
 * Some types are only known by their opaque handles.  While this is a good way
 * to keep interface clients from eating the Forbidden Fruit, it can make type
 * identification difficult -- which can be especially important for big
 * structures like dev_info_t.  To assist type identification, we keep a table
 * to translate from opaque handles to their underlying structures.  A
 * translation should only be added to the tg_typetab[] if the lack of
 * translation is preventing substantial type identification.  (This can be
 * determined by using the "typeunknown" walker on a dump with bufctl auditing
 * enabled, and using "::whatis -b" to determine the types of unknown buffers;
 * if many of these unknown types are structures behind an opaque handle, a
 * new entry in tg_typetab[] is likely warranted.)
 */
struct {
	char		*tgt_type_name;		/* filled in statically */
	char		*tgt_actual_name;	/* filled in statically */
	mdb_ctf_id_t	tgt_type;		/* determined dynamically */
	mdb_ctf_id_t	tgt_actual_type;	/* determined dynamically */
} tg_typetab[] = {
	{ "dev_info_t",		"struct dev_info" },
	{ "ddi_dma_handle_t",	"ddi_dma_impl_t *" },
	{ NULL,			NULL }
};

static enum {
	TG_PASS1 = 1,
	TG_PASS2,
	TG_PASS3,
	TG_PASS4
} tg_pass;

static size_t tg_nnodes;	/* number of nodes */
static size_t tg_nanchored;	/* number of anchored nodes */
static tg_node_t *tg_node;	/* array of nodes */
static tg_node_t **tg_sorted;	/* sorted array of pointers into tg_node */
static size_t tg_nsorted;	/* number of pointers in tg_sorted */
static int *tg_sizes;		/* copy of kmem_alloc_sizes[] array */
static int tg_nsizes;		/* number of sizes in tg_sizes */
static hrtime_t tg_start;	/* start time */
static int tg_improved;		/* flag indicating that we have improved */
static int tg_built;		/* flag indicating that type graph is built */
static uint_t tg_verbose;	/* flag to increase verbosity */

struct typegraph_ctf_module {
	unsigned int nsyms;
	char *data;
	uintptr_t bss;
	size_t data_size;
	size_t bss_size;
};

static mdb_ctf_id_t typegraph_type_offset(mdb_ctf_id_t, size_t,
    tg_edge_t *, const char **);

static void
typegraph_typetab_init(void)
{
	int i;

	for (i = 0; tg_typetab[i].tgt_type_name != NULL; i++) {
		if (mdb_ctf_lookup_by_name(tg_typetab[i].tgt_type_name,
		    &tg_typetab[i].tgt_type) == -1) {
			mdb_warn("can't find type '%s'\n",
			    tg_typetab[i].tgt_type_name);
			mdb_ctf_type_invalidate(&tg_typetab[i].tgt_type);
			continue;
		}

		if (mdb_ctf_lookup_by_name(tg_typetab[i].tgt_actual_name,
		    &tg_typetab[i].tgt_actual_type) == -1) {
			mdb_warn("can't find type '%s'\n",
			    tg_typetab[i].tgt_actual_name);
			mdb_ctf_type_invalidate(&tg_typetab[i].tgt_actual_type);
		}
	}
}

/*
 * A wrapper around mdb_ctf_type_resolve() that first checks the type
 * translation table.
 */
static mdb_ctf_id_t
typegraph_resolve(mdb_ctf_id_t type)
{
	int i;
	mdb_ctf_id_t ret;

	/*
	 * This could be _much_ more efficient...
	 */
	for (i = 0; tg_typetab[i].tgt_type_name != NULL; i++) {
		if (mdb_ctf_type_cmp(type, tg_typetab[i].tgt_type) == 0) {
			type = tg_typetab[i].tgt_actual_type;
			break;
		}
	}

	(void) mdb_ctf_type_resolve(type, &ret);
	return (ret);
}

/*
 * A wrapper around mdb_ctf_type_name() that deals with anonymous structures.
 * Anonymous structures are those that have no name associated with them.
 * Nearly always, these structures are referred to by a typedef (e.g.
 * "typedef struct { int bar } foo_t"); we expect the unresolved type to
 * be passed as utype.
 */
static char *
typegraph_type_name(mdb_ctf_id_t type, mdb_ctf_id_t utype)
{
	static char buf[MDB_SYM_NAMLEN];

	if (mdb_ctf_type_name(type, buf, sizeof (buf)) == NULL) {
		(void) strcpy(buf, "<unknown>");
	} else {
		/*
		 * Perhaps a CTF interface would be preferable to this kludgey
		 * strcmp()?  Perhaps.
		 */
		if (strcmp(buf, "struct ") == 0)
			(void) mdb_ctf_type_name(utype, buf, sizeof (buf));
	}

	return (buf);
}

/*
 * A wrapper around mdb_ctf_type_size() that accurately accounts for arrays.
 */
static ssize_t
typegraph_size(mdb_ctf_id_t type)
{
	mdb_ctf_arinfo_t arr;
	ssize_t size;

	if (!mdb_ctf_type_valid(type))
		return (-1);

	if (mdb_ctf_type_kind(type) != CTF_K_ARRAY)
		return (mdb_ctf_type_size(type));

	if (mdb_ctf_array_info(type, &arr) == -1)
		return (-1);

	type = typegraph_resolve(arr.mta_contents);

	if (!mdb_ctf_type_valid(type))
		return (-1);

	if ((size = mdb_ctf_type_size(type)) == -1)
		return (-1);

	return (size * arr.mta_nelems);
}

/*
 * The mdb_ctf_member_iter() callback for typegraph_type_offset().
 */
static int
typegraph_offiter(const char *name, mdb_ctf_id_t type,
    ulong_t off, tg_typeoffs_t *toffs)
{
	int kind;
	ssize_t size;
	mdb_ctf_arinfo_t arr;

	off /= NBBY;

	if (off > toffs->tgto_offs) {
		/*
		 * We went past it; return failure.
		 */
		return (1);
	}

	if (!mdb_ctf_type_valid(type = typegraph_resolve(type)))
		return (0);

	if ((size = mdb_ctf_type_size(type)) == -1)
		return (0);

	if (off < toffs->tgto_offs &&
	    size != 0 && off + size <= toffs->tgto_offs) {
		/*
		 * Haven't reached it yet; continue looking.
		 */
		return (0);
	}

	/*
	 * If the base type is not a structure, an array or a union, and
	 * the offset equals the desired offset, we have our type.
	 */
	if ((kind = mdb_ctf_type_kind(type)) != CTF_K_STRUCT &&
	    kind != CTF_K_UNION && kind != CTF_K_ARRAY) {
		if (off == toffs->tgto_offs)
			toffs->tgto_type = type;

		if (toffs->tgto_memberp != NULL)
			*(toffs->tgto_memberp) = name;

		return (1);
	}

	/*
	 * If the type is an array, see if we fall within the bounds.
	 */
	if (kind == CTF_K_ARRAY) {
		if (mdb_ctf_array_info(type, &arr) == -1)
			return (0);

		type = typegraph_resolve(arr.mta_contents);

		if (!mdb_ctf_type_valid(type))
			return (0);

		size = mdb_ctf_type_size(type) * arr.mta_nelems;

		if (off < toffs->tgto_offs && off + size <= toffs->tgto_offs) {
			/*
			 * Nope, haven't found it yet; continue looking.
			 */
			return (0);
		}
	}

	toffs->tgto_type = typegraph_type_offset(type,
	    toffs->tgto_offs - off, toffs->tgto_edge, toffs->tgto_memberp);

	return (1);
}

/*
 * The mdb_ctf_member_iter() callback for typegraph_type_offset() when the type
 * is found to be of kind CTF_K_UNION.  With unions, we attempt to do better
 * than just completely punting:  if all but one of the members is impossible
 * (due to, say, size constraints on the destination node), we can propagate
 * the valid member.
 */
static int
typegraph_union(const char *name, mdb_ctf_id_t type, ulong_t off,
    tg_typeoffs_t *toffs)
{
	const char *member = name;
	tg_edge_t *e = toffs->tgto_edge;
	mdb_ctf_id_t rtype;
	size_t rsize;
	int kind;

	if (!mdb_ctf_type_valid(type = typegraph_resolve(type)))
		return (0);

	kind = mdb_ctf_type_kind(type);

	if (kind == CTF_K_STRUCT || kind != CTF_K_UNION ||
	    kind != CTF_K_ARRAY) {
		type = typegraph_type_offset(type,
		    toffs->tgto_offs - off, e, &member);
	}

	if (!mdb_ctf_type_valid(type))
		return (0);

	if (mdb_ctf_type_kind(type) != CTF_K_POINTER)
		return (0);

	/*
	 * Now figure out what exactly we're pointing to.
	 */
	if (mdb_ctf_type_reference(type, &rtype) == -1)
		return (0);

	if (!mdb_ctf_type_valid(rtype = typegraph_resolve(rtype)))
		return (0);

	rsize = mdb_ctf_type_size(rtype);

	/*
	 * Compare this size to the size of the thing we're pointing to --
	 * if it's larger than the node that we're pointing to, we know that
	 * the alleged pointer type must be an invalid interpretation of the
	 * union.
	 */
	if (rsize > TG_NODE_SIZE(e->tge_dest) - e->tge_destoffs) {
		/*
		 * We're in luck -- it's not possibly this pointer.
		 */
		return (0);
	}

	/*
	 * This looks like it could be legit.  If the type hasn't been
	 * specified, we could be in business.
	 */
	if (mdb_ctf_type_valid(toffs->tgto_type)) {
		/*
		 * There are two potentially valid interpretations for this
		 * union.  Invalidate the type.
		 */
		mdb_ctf_type_invalidate(&toffs->tgto_type);
		return (1);
	}

	toffs->tgto_type = type;

	if (toffs->tgto_memberp != NULL)
		*(toffs->tgto_memberp) = member;

	return (0);
}

/*ARGSUSED*/
static int
typegraph_lastmember(const char *name,
    mdb_ctf_id_t type, ulong_t off, void *last)
{
	*((mdb_ctf_id_t *)last) = type;

	return (0);
}

/*
 * To determine if a structure is has a flexible array member, we iterate over
 * the members; if the structure has more than one member, and the last member
 * is an array of size 1, we're going to assume that this structure has a
 * flexible array member.  Yes, this heuristic is a little sloppy -- but cut me
 * some slack:  why the hell else would you have an array of size 1?  (Don't
 * answer that.)
 */
static int
typegraph_hasfam(mdb_ctf_id_t type, mdb_ctf_id_t *atype)
{
	mdb_ctf_arinfo_t arr;
	mdb_ctf_id_t last;
	int kind;

	if (!mdb_ctf_type_valid(type))
		return (0);

	if ((kind = mdb_ctf_type_kind(type)) != CTF_K_STRUCT)
		return (0);

	mdb_ctf_type_invalidate(&last);
	mdb_ctf_member_iter(type, typegraph_lastmember, &last, 0);

	if (!mdb_ctf_type_valid(last))
		return (0);

	if ((kind = mdb_ctf_type_kind(last)) == CTF_K_STRUCT)
		return (typegraph_hasfam(last, atype));

	if (kind != CTF_K_ARRAY)
		return (0);

	if (typegraph_size(last) == typegraph_size(type)) {
		/*
		 * This structure has only one member; even if that member is
		 * an array of size 1, we'll assume that there is something
		 * stranger going on than a run-of-the-mill FAM (e.g., a
		 * kmutex_t).
		 */
		return (0);
	}

	if (mdb_ctf_array_info(last, &arr) == -1)
		return (0);

	if (arr.mta_nelems != 1)
		return (0);

	if (atype != NULL)
		*atype = typegraph_resolve(arr.mta_contents);

	return (1);
}

/*
 * This routine takes a type and offset, and returns the type at the specified
 * offset.  It additionally takes an optional edge to help bust unions, and
 * an optional address of a character pointer to set to the name of the member
 * found at the specified offset.
 */
static mdb_ctf_id_t
typegraph_type_offset(mdb_ctf_id_t type, size_t offset, tg_edge_t *e,
    const char **member)
{
	mdb_ctf_arinfo_t arr;
	uint_t kind;
	mdb_ctf_id_t last;
	ssize_t size;
	ssize_t lsize;
	tg_typeoffs_t toffs;
	mdb_ctf_id_t inval;

	mdb_ctf_type_invalidate(&inval);

	if (member != NULL)
		*member = NULL;

	/*
	 * Resolve type to its base type.
	 */
	type = typegraph_resolve(type);
	kind = mdb_ctf_type_kind(type);

	switch (kind) {
	case CTF_K_ARRAY:
		/*
		 * If this is an array, we need to figure out what it's an
		 * array _of_.  We must then figure out the size of the array
		 * structure, and then determine our offset within that type.
		 * From there, we can recurse.
		 */
		if (mdb_ctf_array_info(type, &arr) == -1)
			return (inval);

		type = typegraph_resolve(arr.mta_contents);

		if (!mdb_ctf_type_valid(type))
			return (inval);

		/*
		 * If the type is not a structure/union, then check that the
		 * offset doesn't point to the middle of the base type and
		 * return it.
		 */
		kind = mdb_ctf_type_kind(type);
		size = mdb_ctf_type_size(type);

		if (kind != CTF_K_STRUCT && kind != CTF_K_UNION) {
			if (offset % size) {
				/*
				 * The offset is pointing to the middle of a
				 * type; return failure.
				 */
				return (inval);
			}

			return (type);
		}

		return (typegraph_type_offset(type, offset % size, e, member));

	case CTF_K_STRUCT:
		/*
		 * If the offset is larger than the size, we need to figure
		 * out what exactly we're looking at.  There are several
		 * possibilities:
		 *
		 * (a)	A structure that has this type as its first member.
		 *
		 * (b)	An array of structures of this type.
		 *
		 * (c)	A structure has a flexible array member.
		 *
		 * The differentiation between (a) and (b) has hopefully
		 * happened before entering this function.  To differentiate
		 * between (b) and (c), we call typegraph_hasfam().
		 */
		size = mdb_ctf_type_size(type);

		if (offset >= size) {
			if (typegraph_hasfam(type, &last)) {
				/*
				 * We have a live one.  Take the size, subtract
				 * the size of the last element, and recurse.
				 */
				if (!mdb_ctf_type_valid(last))
					return (inval);

				lsize = mdb_ctf_type_size(last);

				return (typegraph_type_offset(last,
				    offset - size - lsize, e, member));
			}

			offset %= size;
		}

		toffs.tgto_offs = offset;
		toffs.tgto_memberp = member;
		toffs.tgto_edge = e;
		mdb_ctf_type_invalidate(&toffs.tgto_type);

		mdb_ctf_member_iter(type,
		    (mdb_ctf_member_f *)typegraph_offiter, &toffs, 0);

		return (toffs.tgto_type);

	case CTF_K_POINTER:
		if (!mdb_ctf_type_valid(type = typegraph_resolve(type)))
			return (inval);

		size = mdb_ctf_type_size(type);

		if (offset % size) {
			/*
			 * The offset is pointing to the middle of a type;
			 * return failure.
			 */
			return (inval);
		}

		return (type);

	case CTF_K_UNION:
		if (e == NULL) {
			/*
			 * We've been given no outbound edge -- we have no way
			 * of figuring out what the hell this union is.
			 */
			return (inval);
		}

		toffs.tgto_offs = offset;
		toffs.tgto_memberp = member;
		toffs.tgto_edge = e;
		mdb_ctf_type_invalidate(&toffs.tgto_type);

		/*
		 * Try to bust the union...
		 */
		if (mdb_ctf_member_iter(type,
		    (mdb_ctf_member_f *)typegraph_union, &toffs, 0) != 0) {
			/*
			 * There was at least one valid pointer in there.
			 * Return "void *".
			 */
			(void) mdb_ctf_lookup_by_name("void *", &type);

			return (type);
		}

		return (toffs.tgto_type);

	default:
		/*
		 * If the offset is anything other than zero, no dice.
		 */
		if (offset != 0)
			return (inval);

		return (type);
	}
}

/*
 * This routine takes an address and a type, and determines if the memory
 * pointed to by the specified address could be of the specified type.
 * This could become significantly more sophisticated, but for now it's pretty
 * simple:  this is _not_ of the specified type if it's a pointer, and either:
 *
 *  (a)	The alignment is not correct given the type that is pointed to.
 *
 *  (b)	The memory pointed to is invalid.  Note that structures that have
 *	uninitialized pointers may cause us to erroneously fail -- but these
 *	structures are a bug anyway (uninitialized pointers can confuse many
 *	analysis tools, including ::findleaks).
 */
static int
typegraph_couldbe(uintptr_t addr, mdb_ctf_id_t type)
{
	int rkind;
	mdb_ctf_id_t rtype;
	uintptr_t val, throwaway;
	size_t rsize;
	char buf[MDB_SYM_NAMLEN];

	if (mdb_ctf_type_kind(type) != CTF_K_POINTER)
		return (1);

	if (mdb_ctf_type_reference(type, &rtype) == -1)
		return (1);

	if (!mdb_ctf_type_valid(rtype = typegraph_resolve(rtype)))
		return (1);

	if (mdb_vread(&val, sizeof (val), addr) == -1) {
		/*
		 * This is definitely unexpected.  We should not be getting
		 * back an error on a node that was successfully read in.
		 * Lacking something better to do, we'll print an error
		 * and return.
		 */
		mdb_warn("failed to evaluate pointer type at address %p", addr);
		return (1);
	}

	rkind = mdb_ctf_type_kind(rtype);

	if (rkind == CTF_K_STRUCT || rkind == CTF_K_UNION) {
		/*
		 * If it's a pointer to a structure or union, it must be
		 * aligned to sizeof (uintptr_t).
		 */
		if (val & (sizeof (uintptr_t) - 1)) {
			if (tg_verbose) {
				mdb_printf("typegraph: pass %d: rejecting "
				    "*%p (%p) as %s: misaligned pointer\n",
				    tg_pass, addr, val,
				    mdb_ctf_type_name(type, buf, sizeof (buf)));
			}

			return (0);
		}
	}

	rsize = mdb_ctf_type_size(rtype);

	if (val == 0 || rsize == 0)
		return (1);

	/*
	 * For our speculative read, we're going to clamp the referenced size
	 * at the size of a pointer.
	 */
	if (rsize > sizeof (uintptr_t))
		rsize = sizeof (uintptr_t);

	if (mdb_vread(&throwaway, rsize, val) == -1) {
		if (tg_verbose) {
			mdb_printf("typegraph: pass %d: rejecting *%p (%p) as"
			    " %s: bad pointer\n", tg_pass, addr, val,
			    mdb_ctf_type_name(type, buf, sizeof (buf)));
		}
		return (0);
	}

	return (1);
}

static int
typegraph_nodecmp(const void *l, const void *r)
{
	tg_node_t *lhs = *(tg_node_t **)l;
	tg_node_t *rhs = *(tg_node_t **)r;

	if (lhs->tgn_base < rhs->tgn_base)
		return (-1);
	if (lhs->tgn_base > rhs->tgn_base)
		return (1);

	return (0);
}

static tg_node_t *
typegraph_search(uintptr_t addr)
{
	ssize_t left = 0, right = tg_nnodes - 1, guess;

	while (right >= left) {
		guess = (right + left) >> 1;

		if (addr < tg_sorted[guess]->tgn_base) {
			right = guess - 1;
			continue;
		}

		if (addr >= tg_sorted[guess]->tgn_limit) {
			left = guess + 1;
			continue;
		}

		return (tg_sorted[guess]);
	}

	return (NULL);
}

static int
typegraph_interested(const kmem_cache_t *c)
{
	vmem_t vmem;

	if (mdb_vread(&vmem, sizeof (vmem), (uintptr_t)c->cache_arena) == -1) {
		mdb_warn("cannot read arena %p for cache '%s'",
		    (uintptr_t)c->cache_arena, c->cache_name);
		return (0);
	}

	/*
	 * If this cache isn't allocating from the kmem_default or the
	 * kmem_firewall vmem arena, we're not interested.
	 */
	if (strcmp(vmem.vm_name, "kmem_default") != 0 &&
	    strcmp(vmem.vm_name, "kmem_firewall") != 0)
		return (0);

	return (1);
}

static int
typegraph_estimate(uintptr_t addr, const kmem_cache_t *c, size_t *est)
{
	if (!typegraph_interested(c))
		return (WALK_NEXT);

	*est += kmem_estimate_allocated(addr, c);

	return (WALK_NEXT);
}

static int
typegraph_estimate_modctl(uintptr_t addr, const struct modctl *m, size_t *est)
{
	struct typegraph_ctf_module mod;

	if (m->mod_mp == NULL)
		return (WALK_NEXT);

	if (mdb_ctf_vread(&mod, "struct module", "struct typegraph_ctf_module",
	    (uintptr_t)m->mod_mp, 0) == -1) {
		mdb_warn("couldn't read modctl %p's module", addr);
		return (WALK_NEXT);
	}

	(*est) += mod.nsyms;

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
typegraph_estimate_vmem(uintptr_t addr, const vmem_t *vmem, size_t *est)
{
	if (strcmp(vmem->vm_name, "kmem_oversize") != 0)
		return (WALK_NEXT);

	*est += (size_t)(vmem->vm_kstat.vk_alloc.value.ui64 -
	    vmem->vm_kstat.vk_free.value.ui64);

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
typegraph_buf(uintptr_t addr, void *ignored, tg_nodedata_t *tgd)
{
	tg_node_t *node = tgd->tgd_next++;
	uintptr_t limit = addr + tgd->tgd_size;

	node->tgn_base = addr;
	node->tgn_limit = limit;

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
typegraph_kmem(uintptr_t addr, const kmem_cache_t *c, tg_node_t **tgp)
{
	tg_node_t *node = *tgp;
	tg_nodedata_t tgd;
	mdb_ctf_id_t type;
	int i, smaller;

	mdb_ctf_type_invalidate(&type);

	if (!typegraph_interested(c))
		return (WALK_NEXT);

	tgd.tgd_size = c->cache_bufsize;
	tgd.tgd_next = *tgp;

	if (mdb_pwalk("kmem", (mdb_walk_cb_t)typegraph_buf, &tgd, addr) == -1) {
		mdb_warn("can't walk kmem for cache %p (%s)", addr,
		    c->cache_name);
		return (WALK_DONE);
	}

	*tgp = tgd.tgd_next;

	for (i = 0; tg_cachetab[i].tgc_name != NULL; i++) {
		if (strcmp(tg_cachetab[i].tgc_name, c->cache_name) != 0)
			continue;

		if (mdb_ctf_lookup_by_name(tg_cachetab[i].tgc_type,
		    &type) == -1) {
			mdb_warn("could not find type '%s', allegedly type "
			    "for cache %s", tg_cachetab[i].tgc_type,
			    c->cache_name);
			break;
		}

		break;
	}

	/*
	 * If this is a named cache (i.e., not from a kmem_alloc_[n] cache),
	 * the nextsize is 0.
	 */
	if (strncmp(c->cache_name, "kmem_alloc_", strlen("kmem_alloc_")) == 0) {
		GElf_Sym sym;
		GElf_Sym sym2;

		if (tg_sizes == NULL) {
			size_t nsizes = 0;
			size_t nsizes_reg = 0;
			size_t nsizes_big = 0;

			if (mdb_lookup_by_name("kmem_alloc_sizes",
			    &sym) == -1) {
				mdb_warn("failed to find 'kmem_alloc_sizes'");
				return (WALK_ERR);
			}
			nsizes_reg = sym.st_size / sizeof (int);

			if (mdb_lookup_by_name("kmem_big_alloc_sizes",
			    &sym2) != -1) {
				nsizes_big = sym2.st_size / sizeof (int);
			}

			nsizes = nsizes_reg + nsizes_big;

			tg_sizes = mdb_zalloc(nsizes * sizeof (int), UM_SLEEP);
			tg_nsizes = nsizes;

			if (mdb_vread(tg_sizes, sym.st_size,
			    (uintptr_t)sym.st_value) == -1) {
				mdb_warn("failed to read kmem_alloc_sizes");
				return (WALK_ERR);
			}
			if (nsizes_big > 0 &&
			    mdb_vread(&tg_sizes[nsizes_reg], sym2.st_size,
			    (uintptr_t)sym2.st_value) == -1) {
				mdb_warn("failed to read kmem_big_alloc_sizes");
				return (WALK_ERR);
			}
		}

		/*
		 * Yes, this is a linear search -- but we're talking about
		 * a pretty small array (38 elements as of this writing), and
		 * only executed a handful of times (for each sized kmem
		 * cache).
		 */
		for (i = 0; i < tg_nsizes; i++) {
			if (tg_sizes[i] == c->cache_bufsize)
				break;
		}

		if (i == tg_nsizes) {
			/*
			 * Something is wrong -- this appears to be a sized
			 * kmem cache, but we can't find its size in the
			 * kmem_alloc_sizes array.  Emit a warning and return
			 * failure.
			 */
			mdb_warn("couldn't find buffer size for %s (%d)"
			    " in kmem_alloc_sizes array\n", c->cache_name,
			    c->cache_bufsize);

			return (WALK_ERR);
		}

		if (i == 0) {
			smaller = 1;
		} else {
			smaller = tg_sizes[i - 1];
		}
	} else {
		smaller = 0;
	}

	for (; node < *tgp; node++) {
		node->tgn_type = type;
		node->tgn_smaller = smaller;
	}

	*tgp = tgd.tgd_next;

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
typegraph_seg(uintptr_t addr, const vmem_seg_t *seg, tg_node_t **tgp)
{
	tg_nodedata_t tgd;

	tgd.tgd_next = *tgp;
	tgd.tgd_size = seg->vs_end - seg->vs_start;

	typegraph_buf(seg->vs_start, NULL, &tgd);

	*tgp = tgd.tgd_next;
	return (WALK_NEXT);
}

static int
typegraph_vmem(uintptr_t addr, const vmem_t *vmem, tg_node_t **tgp)
{
	if (strcmp(vmem->vm_name, "kmem_oversize") != 0)
		return (WALK_NEXT);

	if (mdb_pwalk("vmem_alloc",
	    (mdb_walk_cb_t)typegraph_seg, tgp, addr) == -1)
		mdb_warn("can't walk vmem for arena %p", addr);

	return (WALK_NEXT);
}

static void
typegraph_build_anchored(uintptr_t addr, size_t size, mdb_ctf_id_t type)
{
	uintptr_t *buf;
	tg_buildstate_t *state = NULL, *new_state, *free = NULL;
	tg_node_t *node, *src;
	tg_edge_t *edge;
	size_t nptrs, ndx;
	uintptr_t min = tg_sorted[0]->tgn_base;
	uintptr_t max = tg_sorted[tg_nnodes - 1]->tgn_limit;
	ssize_t rval;
	int mask = sizeof (uintptr_t) - 1;

	if (addr == 0 || size < sizeof (uintptr_t))
		return;

	/*
	 * Add an anchored node.
	 */
	src = &tg_node[tg_nnodes + tg_nanchored++];
	src->tgn_base = addr;
	src->tgn_limit = addr + size;
	src->tgn_type = type;

push:
	/*
	 * If our address isn't pointer-aligned, we need to align it and
	 * whack the size appropriately.
	 */
	if (addr & mask) {
		if ((mask + 1) - (addr & mask) >= size)
			goto out;

		size -= (mask + 1) - (addr & mask);
		addr += (mask + 1) - (addr & mask);
	}

	nptrs = size / sizeof (uintptr_t);
	buf = mdb_alloc(size, UM_SLEEP);
	ndx = 0;

	if ((rval = mdb_vread(buf, size, addr)) != size) {
		mdb_warn("couldn't read ptr at %p (size %ld); rval is %d",
		    addr, size, rval);
		goto out;
	}
pop:
	for (; ndx < nptrs; ndx++) {
		uintptr_t ptr = buf[ndx];

		if (ptr < min || ptr >= max)
			continue;

		if ((node = typegraph_search(ptr)) == NULL)
			continue;

		/*
		 * We need to record an edge to us.
		 */
		edge = mdb_zalloc(sizeof (tg_edge_t), UM_SLEEP);

		edge->tge_src = src;
		edge->tge_dest = node;
		edge->tge_nextout = src->tgn_outgoing;
		src->tgn_outgoing = edge;

		edge->tge_srcoffs += ndx * sizeof (uintptr_t);
		edge->tge_destoffs = ptr - node->tgn_base;
		edge->tge_nextin = node->tgn_incoming;
		node->tgn_incoming = edge;

		/*
		 * If this node is marked, we don't need to descend.
		 */
		if (node->tgn_marked)
			continue;

		/*
		 * We need to descend.  To minimize the resource consumption
		 * of type graph construction, we avoid recursing.
		 */
		node->tgn_marked = 1;

		if (free != NULL) {
			new_state = free;
			free = free->tgbs_next;
		} else {
			new_state =
			    mdb_zalloc(sizeof (tg_buildstate_t), UM_SLEEP);
		}

		new_state->tgbs_src = src;
		src = node;

		new_state->tgbs_addr = addr;
		addr = node->tgn_base;
		size = node->tgn_limit - addr;

		new_state->tgbs_next = state;
		new_state->tgbs_buf = buf;
		new_state->tgbs_ndx = ndx + 1;
		new_state->tgbs_nptrs = nptrs;
		state = new_state;
		goto push;
	}

	/*
	 * If we're here, then we have completed this region.  We need to
	 * free our buffer, and update our "resident" counter accordingly.
	 */
	mdb_free(buf, size);

out:
	/*
	 * If we have pushed state, we need to pop it.
	 */
	if (state != NULL) {
		buf = state->tgbs_buf;
		ndx = state->tgbs_ndx;
		src = state->tgbs_src;
		nptrs = state->tgbs_nptrs;
		addr = state->tgbs_addr;

		size = nptrs * sizeof (uintptr_t);

		new_state = state->tgbs_next;
		state->tgbs_next = free;
		free = state;
		state = new_state;

		goto pop;
	}

	while (free != NULL) {
		state = free;
		free = free->tgbs_next;
		mdb_free(state, sizeof (tg_buildstate_t));
	}
}

static void
typegraph_build(uintptr_t addr, size_t size)
{
	uintptr_t limit = addr + size;
	char name[MDB_SYM_NAMLEN];
	GElf_Sym sym;
	mdb_ctf_id_t type;

	do {
		if (mdb_lookup_by_addr(addr, MDB_SYM_EXACT, name,
		    sizeof (name), &sym) == -1) {
			addr++;
			continue;
		}

		if (sym.st_size == 0) {
			addr++;
			continue;
		}

		if (strcmp(name, "kstat_initial") == 0) {
			/*
			 * Yes, this is a kludge.  "kstat_initial" ends up
			 * backing the kstat vmem arena -- so we don't want
			 * to include it as an anchor node.
			 */
			addr += sym.st_size;
			continue;
		}

		/*
		 * We have the symbol; now get its type.
		 */
		if (mdb_ctf_lookup_by_addr(addr, &type) == -1) {
			addr += sym.st_size;
			continue;
		}

		if (!mdb_ctf_type_valid(type)) {
			addr += sym.st_size;
			continue;
		}

		if (!mdb_ctf_type_valid(type = typegraph_resolve(type))) {
			addr += sym.st_size;
			continue;
		}

		typegraph_build_anchored(addr, (size_t)sym.st_size, type);
		addr += sym.st_size;
	} while (addr < limit);
}

/*ARGSUSED*/
static int
typegraph_thread(uintptr_t addr, const kthread_t *t, mdb_ctf_id_t *type)
{
	/*
	 * If this thread isn't already a node, add it as an anchor.  And
	 * regardless, set its type to be the specified type.
	 */
	tg_node_t *node;

	if ((node = typegraph_search(addr)) == NULL) {
		typegraph_build_anchored(addr, mdb_ctf_type_size(*type), *type);
	} else {
		node->tgn_type = *type;
	}

	return (WALK_NEXT);
}

/*ARGSUSED*/
static int
typegraph_kstat(uintptr_t addr, const vmem_seg_t *seg, mdb_ctf_id_t *type)
{
	size_t size = mdb_ctf_type_size(*type);

	typegraph_build_anchored(seg->vs_start, size, *type);

	return (WALK_NEXT);
}

static void
typegraph_node_addtype(tg_node_t *node, tg_edge_t *edge, mdb_ctf_id_t rtype,
    const char *rmember, size_t roffs, mdb_ctf_id_t utype, mdb_ctf_id_t type)
{
	tg_type_t *tp;
	tg_type_t **list;

	if (edge->tge_destoffs == 0) {
		list = &node->tgn_typelist;
	} else {
		list = &node->tgn_fraglist;
	}

	/*
	 * First, search for this type in the type list.
	 */
	for (tp = *list; tp != NULL; tp = tp->tgt_next) {
		if (mdb_ctf_type_cmp(tp->tgt_type, type) == 0)
			return;
	}

	tp = mdb_zalloc(sizeof (tg_type_t), UM_SLEEP);
	tp->tgt_next = *list;
	tp->tgt_type = type;
	tp->tgt_rtype = rtype;
	tp->tgt_utype = utype;
	tp->tgt_redge = edge;
	tp->tgt_roffs = roffs;
	tp->tgt_rmember = rmember;
	*list = tp;

	tg_improved = 1;
}

static void
typegraph_stats_node(tg_node_t *node, tg_stats_t *stats)
{
	tg_edge_t *e;

	stats->tgs_nodes++;

	if (!node->tgn_marked)
		stats->tgs_unmarked++;

	if (mdb_ctf_type_valid(node->tgn_type)) {
		stats->tgs_known++;
		return;
	}

	if (node->tgn_typelist != NULL) {
		stats->tgs_typed++;

		if (node->tgn_typelist->tgt_next)
			stats->tgs_conflicts++;

		return;
	}

	if (node->tgn_fraglist != NULL) {
		stats->tgs_frag++;
		return;
	}

	/*
	 * This node is not typed -- but check if any of its outgoing edges
	 * were successfully typed; such nodes represent candidates for
	 * an exhaustive type search.
	 */
	for (e = node->tgn_outgoing; e != NULL; e = e->tge_nextout) {
		if (e->tge_dest->tgn_typelist) {
			stats->tgs_candidates++;
			break;
		}
	}
}

/*ARGSUSED*/
static int
typegraph_stats_buffer(uintptr_t addr, void *ignored, tg_stats_t *stats)
{
	tg_node_t *node;

	stats->tgs_buffers++;

	if ((node = typegraph_search(addr)) == NULL) {
		return (WALK_NEXT);
	}

	typegraph_stats_node(node, stats);

	return (WALK_NEXT);
}

/*ARGSUSED*/
void
typegraph_stat_print(char *name, size_t stat)
{
	mdb_printf("typegraph: ");

	if (name == NULL) {
		mdb_printf("\n");
		return;
	}

	mdb_printf("%30s => %ld\n", name, stat);
}

static void
typegraph_stat_str(char *name, char *str)
{
	mdb_printf("typegraph: %30s => %s\n", name, str);
}

static void
typegraph_stat_perc(char *name, size_t stat, size_t total)
{
	int perc = (stat * 100) / total;
	int tenths = ((stat * 1000) / total) % 10;

	mdb_printf("typegraph: %30s => %-13ld (%2d.%1d%%)\n", name, stat,
	    perc, tenths);
}

static void
typegraph_stat_time(int last)
{
	static hrtime_t ts;
	hrtime_t pass;

	if (ts == 0) {
		pass = (ts = gethrtime()) - tg_start;
	} else {
		hrtime_t now = gethrtime();

		pass = now - ts;
		ts = now;
	}

	mdb_printf("typegraph: %30s => %lld seconds\n",
	    "time elapsed, this pass", pass / NANOSEC);
	mdb_printf("typegraph: %30s => %lld seconds\n",
	    "time elapsed, total", (ts - tg_start) / NANOSEC);
	mdb_printf("typegraph:\n");

	if (last)
		ts = 0;
}

static void
typegraph_stats(void)
{
	size_t i, n;
	tg_stats_t stats;

	bzero(&stats, sizeof (stats));

	for (i = 0; i < tg_nnodes - tg_nanchored; i++)
		typegraph_stats_node(&tg_node[i], &stats);

	n = stats.tgs_nodes;

	typegraph_stat_print("pass", tg_pass);
	typegraph_stat_print("nodes", n);
	typegraph_stat_perc("unmarked", stats.tgs_unmarked, n);
	typegraph_stat_perc("known", stats.tgs_known, n);
	typegraph_stat_perc("conjectured", stats.tgs_typed, n);
	typegraph_stat_perc("conjectured fragments", stats.tgs_frag, n);
	typegraph_stat_perc("known or conjectured",
	    stats.tgs_known + stats.tgs_typed + stats.tgs_frag, n);
	typegraph_stat_print("conflicts", stats.tgs_conflicts);
	typegraph_stat_print("candidates", stats.tgs_candidates);
	typegraph_stat_time(0);
}

/*
 * This is called both in pass1 and in subsequent passes (to propagate new type
 * inferences).
 */
static void
typegraph_pass1_node(tg_node_t *node, mdb_ctf_id_t type)
{
	tg_todo_t *first = NULL, *last = NULL, *free = NULL, *this = NULL;
	tg_todo_t *todo;
	tg_edge_t *e;
	uintptr_t offs = 0;
	size_t size;
	const char *member;

	if (!mdb_ctf_type_valid(type))
		return;
again:
	/*
	 * For each of the nodes corresponding to our outgoing edges,
	 * determine their type.
	 */
	size = typegraph_size(type);

	for (e = node->tgn_outgoing; e != NULL; e = e->tge_nextout) {
		mdb_ctf_id_t ntype, rtype;
		size_t nsize;
		int kind;

		/*
		 * If we're being called in pass1, we're very conservative:
		 *
		 * (a)	If the outgoing edge is beyond the size of the type
		 *	(and the current node is not the root), we refuse to
		 *	descend.  This situation isn't actually hopeless -- we
		 *	could be looking at array of the projected type -- but
		 *	we'll allow a later phase to pass in that node and its
		 *	conjectured type as the root.
		 *
		 * (b)	If the outgoing edge has a destination offset of
		 *	something other than 0, we'll descend, but we won't
		 *	add the type to the type list of the destination node.
		 *	This allows us to gather information that can later be
		 *	used to perform a more constrained search.
		 */
		if (tg_pass == TG_PASS1 && e->tge_srcoffs - offs > size)
			continue;

		if (offs >= typegraph_size(type))
			continue;

		if (e->tge_srcoffs < offs)
			continue;

		if (e->tge_marked)
			continue;

		ntype = typegraph_type_offset(type,
		    e->tge_srcoffs - offs, e, &member);

		if (!mdb_ctf_type_valid(ntype))
			continue;

		if ((kind = mdb_ctf_type_kind(ntype)) != CTF_K_POINTER)
			continue;

		if (mdb_ctf_type_reference(ntype, &rtype) == -1)
			continue;

		if (!mdb_ctf_type_valid(ntype = typegraph_resolve(rtype)))
			continue;

		kind = mdb_ctf_type_kind(ntype);
		nsize = mdb_ctf_type_size(ntype);

		if (nsize > TG_NODE_SIZE(e->tge_dest) - e->tge_destoffs)
			continue;

		typegraph_node_addtype(e->tge_dest, e, type,
		    member, e->tge_srcoffs - offs, rtype, ntype);

		if (e->tge_dest->tgn_marked)
			continue;

		/*
		 * If our destination offset is 0 and the type that we marked
		 * it with is useful, mark the node that we're
		 * going to visit.  And regardless, mark the edge.
		 */
		if (e->tge_destoffs == 0 && kind == CTF_K_STRUCT)
			e->tge_dest->tgn_marked = 1;

		e->tge_marked = 1;

		/*
		 * If this isn't a structure, it's pointless to descend.
		 */
		if (kind != CTF_K_STRUCT)
			continue;

		if (nsize <= TG_NODE_SIZE(e->tge_dest) / 2) {
			tg_node_t *dest = e->tge_dest;

			/*
			 * If the conjectured type is less than half of the
			 * size of the object, we might be dealing with a
			 * polymorphic type.  It's dangerous to descend in
			 * this case -- if our conjectured type is larger than
			 * the actual type, we will mispropagate.  (See the
			 * description for phenomenon (c) in the block comment
			 * for how this condition can arise.)  We therefore
			 * only descend if we are in pass4 and there is only
			 * one inference for this node.
			 */
			if (tg_pass < TG_PASS4)
				continue;

			if (dest->tgn_typelist == NULL ||
			    dest->tgn_typelist->tgt_next != NULL) {
				/*
				 * There is either no inference for this node,
				 * or more than one -- in either case, chicken
				 * out.
				 */
				continue;
			}
		}

		if (free != NULL) {
			todo = free;
			free = free->tgtd_next;
		} else {
			todo = mdb_alloc(sizeof (tg_todo_t), UM_SLEEP);
		}

		todo->tgtd_node = e->tge_dest;
		todo->tgtd_type = ntype;
		todo->tgtd_offs = e->tge_destoffs;
		todo->tgtd_next = NULL;

		if (last == NULL) {
			first = last = todo;
		} else {
			last->tgtd_next = todo;
			last = todo;
		}
	}

	/*
	 * If this was from a to-do list, it needs to be freed.
	 */
	if (this != NULL) {
		this->tgtd_next = free;
		free = this;
	}

	/*
	 * Now peel something off of the to-do list.
	 */
	if (first != NULL) {
		this = first;
		first = first->tgtd_next;
		if (first == NULL)
			last = NULL;

		node = this->tgtd_node;
		offs = this->tgtd_offs;
		type = this->tgtd_type;
		goto again;
	}

	/*
	 * Nothing more to do -- free the to-do list.
	 */
	while (free != NULL) {
		this = free->tgtd_next;
		mdb_free(free, sizeof (tg_todo_t));
		free = this;
	}
}

static void
typegraph_pass1(void)
{
	int i;

	tg_pass = TG_PASS1;
	for (i = 0; i < tg_nnodes; i++)
		typegraph_pass1_node(&tg_node[i], tg_node[i].tgn_type);
}

static void
typegraph_pass2_node(tg_node_t *node)
{
	mdb_ctf_id_t type, ntype;
	size_t tsize, nsize, rem, offs, limit;
	uintptr_t base, addr;
	int fam, kind;
	tg_type_t *tp, *found = NULL;

	if (mdb_ctf_type_valid(node->tgn_type))
		return;

	for (tp = node->tgn_typelist; tp != NULL; tp = tp->tgt_next) {
		if ((kind = mdb_ctf_type_kind(tp->tgt_type)) == CTF_K_UNION) {
			/*
			 * Fucking unions...
			 */
			found = NULL;
			break;
		}

		if (kind == CTF_K_POINTER || kind == CTF_K_STRUCT) {
			if (found != NULL) {
				/*
				 * There's more than one interpretation for
				 * this structure; for now, we punt.
				 */
				found = NULL;
				break;
			}
			found = tp;
		}
	}

	if (found == NULL ||
	    (found->tgt_flags & (TG_TYPE_ARRAY | TG_TYPE_NOTARRAY)))
		return;

	fam = typegraph_hasfam(type = found->tgt_type, &ntype);

	if (fam) {
		/*
		 * If this structure has a flexible array member, and the
		 * FAM type isn't a struct or pointer, we're going to treat
		 * it as if it did not have a FAM.
		 */
		kind = mdb_ctf_type_kind(ntype);

		if (kind != CTF_K_POINTER && kind != CTF_K_STRUCT)
			fam = 0;
	}

	tsize = typegraph_size(type);
	nsize = TG_NODE_SIZE(node);

	if (!fam) {
		/*
		 * If this doesn't have a flexible array member, and our
		 * preferred type is greater than half the size of the node, we
		 * won't try to treat it as an array.
		 */
		if (tsize > nsize / 2)
			return;

		if ((rem = (nsize % tsize)) != 0) {
			/*
			 * If the next-smaller cache size is zero, we were
			 * expecting the type size to evenly divide the node
			 * size -- we must not have the right type.
			 */
			if (node->tgn_smaller == 0)
				return;

			if (nsize - rem <= node->tgn_smaller) {
				/*
				 * If this were really an array of this type,
				 * we would have allocated it out of a smaller
				 * cache -- it's either not an array (e.g.,
				 * it's a bigger, unknown structure) or it's an
				 * array of some other type.  In either case,
				 * we punt.
				 */
				return;
			}
		}
	}

	/*
	 * So far, this looks like it might be an array.
	 */
	if (node->tgn_smaller != 0) {
		limit = node->tgn_smaller;
	} else {
		limit = TG_NODE_SIZE(node);
	}

	base = node->tgn_base;

	if (fam) {
		found->tgt_flags |= TG_TYPE_HASFAM;

		for (offs = 0; offs < limit; ) {
			ntype = typegraph_type_offset(type, offs, NULL, NULL);

			if (!mdb_ctf_type_valid(ntype)) {
				offs++;
				continue;
			}

			if (!typegraph_couldbe(base + offs, ntype)) {
				found->tgt_flags |= TG_TYPE_NOTARRAY;
				return;
			}

			offs += mdb_ctf_type_size(ntype);
		}
	} else {
		for (offs = 0; offs < tsize; ) {
			ntype = typegraph_type_offset(type, offs, NULL, NULL);

			if (!mdb_ctf_type_valid(ntype)) {
				offs++;
				continue;
			}

			for (addr = base + offs; addr < base + limit;
			    addr += tsize) {
				if (typegraph_couldbe(addr, ntype))
					continue;

				found->tgt_flags |= TG_TYPE_NOTARRAY;
				return;
			}

			offs += mdb_ctf_type_size(ntype);
			continue;
		}
	}

	/*
	 * Now mark this type as an array, and reattempt pass1 from this node.
	 */
	found->tgt_flags |= TG_TYPE_ARRAY;
	typegraph_pass1_node(node, type);
}

static void
typegraph_pass2(void)
{
	int i;

	tg_pass = TG_PASS2;
	do {
		tg_improved = 0;

		for (i = 0; i < tg_nnodes; i++)
			typegraph_pass2_node(&tg_node[i]);
	} while (tg_improved);
}

static void
typegraph_pass3(void)
{
	tg_node_t *node;
	tg_type_t *tp;
	size_t i;
	uintptr_t loffs;

	tg_pass = TG_PASS3;
	loffs = offsetof(tg_node_t, tgn_typelist);

again:
	/*
	 * In this pass, we're going to coalesce types.  We're looking for
	 * nodes where one possible type is a structure, and another is
	 * either a CTF_K_INTEGER variant (e.g. "char", "void") or a
	 * CTF_K_FORWARD (an opaque forward definition).
	 *
	 * N.B.  It might appear to be beneficial to coalesce types when
	 * the possibilities include two structures, and one is contained
	 * within the other (e.g., "door_node" contains a "vnode" as its
	 * first member; "vnode" could be smooshed, leaving just "door_node").
	 * This optimization is overly aggressive, however:  there are too
	 * many places where we pull stunts with structures such that they're
	 * actually polymorphic (e.g., "nc_cache" and "ncache").  Performing
	 * this optimization would run the risk of false propagation --
	 * which we want to avoid if at all possible.
	 */
	for (i = 0; i < tg_nnodes; i++) {
		tg_type_t **list;

		list = (tg_type_t **)((uintptr_t)(node = &tg_node[i]) + loffs);

		if (mdb_ctf_type_valid(node->tgn_type))
			continue;

		if (*list == NULL)
			continue;

		/*
		 * First, scan for type CTF_K_STRUCT.  If we find it, eliminate
		 * everything that's a CTF_K_INTEGER or CTF_K_FORWARD.
		 */
		for (tp = *list; tp != NULL; tp = tp->tgt_next) {
			if (mdb_ctf_type_kind(tp->tgt_type) == CTF_K_STRUCT)
				break;
		}

		if (tp != NULL) {
			tg_type_t *prev = NULL, *next;

			for (tp = *list; tp != NULL; tp = next) {
				int kind = mdb_ctf_type_kind(tp->tgt_type);

				next = tp->tgt_next;

				if (kind == CTF_K_INTEGER ||
				    kind == CTF_K_FORWARD) {
					if (prev == NULL) {
						*list = next;
					} else {
						prev->tgt_next = next;
					}

					mdb_free(tp, sizeof (tg_type_t));
				} else {
					prev = tp;
				}
			}
		}
	}

	if (loffs == offsetof(tg_node_t, tgn_typelist)) {
		loffs = offsetof(tg_node_t, tgn_fraglist);
		goto again;
	}
}

static void
typegraph_pass4_node(tg_node_t *node)
{
	tg_edge_t *e;
	mdb_ctf_id_t type, ntype;
	tg_node_t *src = NULL;
	int kind;

	if (mdb_ctf_type_valid(node->tgn_type))
		return;

	if (node->tgn_typelist != NULL)
		return;

	mdb_ctf_type_invalidate(&type);

	/*
	 * Now we want to iterate over all incoming edges.  If we can find an
	 * incoming edge pointing to offset 0 from a node of known or
	 * conjectured type, check the types of the referring node.
	 */
	for (e = node->tgn_incoming; e != NULL; e = e->tge_nextin) {
		tg_node_t *n = e->tge_src;

		if (e->tge_destoffs != 0)
			continue;

		if (!mdb_ctf_type_valid(ntype = n->tgn_type)) {
			if (n->tgn_typelist != NULL &&
			    n->tgn_typelist->tgt_next == NULL) {
				ntype = n->tgn_typelist->tgt_type;
			}

			if (!mdb_ctf_type_valid(ntype))
				continue;
		}

		kind = mdb_ctf_type_kind(ntype);

		if (kind != CTF_K_STRUCT && kind != CTF_K_POINTER)
			continue;

		if (src != NULL && mdb_ctf_type_cmp(type, ntype) != 0) {
			/*
			 * We have two valid, potentially conflicting
			 * interpretations for this node -- chicken out.
			 */
			src = NULL;
			break;
		}

		src = n;
		type = ntype;
	}

	if (src != NULL)
		typegraph_pass1_node(src, type);
}

static void
typegraph_pass4(void)
{
	size_t i, conjectured[2], gen = 0;

	conjectured[1] = tg_nnodes;

	tg_pass = TG_PASS4;
	do {
		conjectured[gen] = 0;

		for (i = 0; i < tg_nnodes; i++) {
			if (tg_node[i].tgn_typelist != NULL)
				conjectured[gen]++;
			typegraph_pass4_node(&tg_node[i]);
		}

		/*
		 * Perform another pass3 to coalesce any new conflicts.
		 */
		typegraph_pass3();
		tg_pass = TG_PASS4;
		gen ^= 1;
	} while (conjectured[gen ^ 1] < conjectured[gen]);
}

static void
typegraph_postpass_node(tg_node_t *node)
{
	size_t total = 0;
	tg_edge_t *e, *edge = node->tgn_outgoing;
	tg_poststate_t *free = NULL, *stack = NULL, *state;
	tg_node_t *dest;

	if (node->tgn_postmarked)
		return;

push:
	node->tgn_postmarked = 1;
	node->tgn_reach = 0;

pop:
	for (e = edge; e != NULL; e = e->tge_nextout) {
		dest = e->tge_dest;

		if (dest->tgn_postmarked)
			continue;

		/*
		 * Add a new element and descend.
		 */
		if (free == NULL) {
			state = mdb_alloc(sizeof (tg_poststate_t), UM_SLEEP);
		} else {
			state = free;
			free = free->tgps_next;
		}

		state->tgps_node = node;
		state->tgps_edge = e;
		state->tgps_total = total;
		state->tgps_next = stack;
		stack = state;

		node = dest;
		edge = dest->tgn_outgoing;
		goto push;
	}

	if (!mdb_ctf_type_valid(node->tgn_type) &&
	    node->tgn_typelist == NULL && node->tgn_fraglist == NULL) {
		/*
		 * We are an unknown node; our count must reflect this.
		 */
		node->tgn_reach++;
	}

	/*
	 * Now we need to check for state to pop.
	 */
	if ((state = stack) != NULL) {
		edge = state->tgps_edge;
		node = state->tgps_node;
		total = state->tgps_total;
		dest = edge->tge_dest;

		stack = state->tgps_next;
		state->tgps_next = free;
		free = state;

		if (!mdb_ctf_type_valid(dest->tgn_type) &&
		    dest->tgn_typelist == NULL && dest->tgn_fraglist == NULL) {
			/*
			 * We only sum our child's reach into our own if
			 * that child is of unknown type.  This prevents long
			 * chains of non-increasing reach.
			 */
			node->tgn_reach += dest->tgn_reach;
		}

		edge = edge->tge_nextout;
		goto pop;
	}

	/*
	 * We need to free our freelist.
	 */
	while (free != NULL) {
		state = free;
		free = free->tgps_next;
		mdb_free(state, sizeof (tg_poststate_t));
	}
}

static void
typegraph_postpass(void)
{
	int i, max = 0;
	tg_node_t *node, *maxnode = NULL;
	char c[256];

	for (i = 0; i < tg_nnodes; i++)
		tg_node[i].tgn_postmarked = 0;

	/*
	 * From those nodes with unknown type and no outgoing edges, we want
	 * to eminate towards the root.
	 */
	for (i = tg_nnodes - tg_nanchored; i < tg_nnodes; i++) {
		node = &tg_node[i];

		typegraph_postpass_node(node);
	}

	for (i = 0; i < tg_nnodes - tg_nanchored; i++) {
		node = &tg_node[i];

		if (mdb_ctf_type_valid(node->tgn_type))
			continue;

		if (node->tgn_reach < max)
			continue;

		maxnode = node;
		max = node->tgn_reach;
	}

	typegraph_stat_str("pass", "post");

	if (maxnode != NULL) {
		mdb_snprintf(c, sizeof (c), "%p",
		    maxnode->tgn_base, maxnode->tgn_reach);
	} else {
		strcpy(c, "-");
	}

	typegraph_stat_print("nodes", tg_nnodes - tg_nanchored);
	typegraph_stat_str("greatest unknown node reach", c);
	typegraph_stat_perc("reachable unknown nodes",
	    max, tg_nnodes - tg_nanchored);
	typegraph_stat_time(1);
}

static void
typegraph_allpass(int first)
{
	size_t i;
	tg_edge_t *e;

	if (!first)
		tg_start = gethrtime();

	for (i = 0; i < tg_nnodes; i++) {
		tg_node[i].tgn_marked = 0;
		tg_node[i].tgn_postmarked = 0;

		for (e = tg_node[i].tgn_incoming; e != NULL; e = e->tge_nextin)
			e->tge_marked = 0;
	}

	typegraph_pass1();
	typegraph_stats();
	typegraph_pass2();
	typegraph_stats();
	typegraph_pass3();
	typegraph_stats();
	typegraph_pass4();
	typegraph_stats();
	typegraph_postpass();
}

/*ARGSUSED*/
static int
typegraph_modctl(uintptr_t addr, const struct modctl *m, int *ignored)
{
	struct typegraph_ctf_module mod;
	tg_node_t *node;
	mdb_ctf_id_t type;

	if (m->mod_mp == NULL)
		return (WALK_NEXT);

	if (mdb_ctf_vread(&mod, "struct module", "struct typegraph_ctf_module",
	    (uintptr_t)m->mod_mp, 0) == -1) {
		mdb_warn("couldn't read modctl %p's module", addr);
		return (WALK_NEXT);
	}

	/*
	 * As long as we're here, we're going to mark the address pointed
	 * to by mod_mp as a "struct module" (mod_mp is defined to be a
	 * void *).  Yes, this is a horrible kludge -- but it's not like
	 * this code isn't already depending on the fact that mod_mp is
	 * actually a pointer to "struct module" (see the mdb_vread(), above).
	 * Without this, we can't identify any of the objects allocated by
	 * krtld.
	 */
	if ((node = typegraph_search((uintptr_t)m->mod_mp)) != NULL) {
		if (mdb_ctf_lookup_by_name("struct module", &type) != -1)
			node->tgn_type = type;
	}

	typegraph_build((uintptr_t)mod.data, mod.data_size);
	typegraph_build((uintptr_t)mod.bss, mod.bss_size);

	return (WALK_NEXT);
}

static void
typegraph_sort(void)
{
	size_t i;

	if (tg_sorted)
		mdb_free(tg_sorted, tg_nsorted * sizeof (tg_node_t *));

	tg_nsorted = tg_nnodes;
	tg_sorted = mdb_alloc(tg_nsorted * sizeof (tg_node_t *), UM_SLEEP);

	for (i = 0; i < tg_nsorted; i++)
		tg_sorted[i] = &tg_node[i];

	qsort(tg_sorted, tg_nsorted, sizeof (tg_node_t *), typegraph_nodecmp);
}

static void
typegraph_known_node(uintptr_t addr, const char *typename)
{
	tg_node_t *node;
	mdb_ctf_id_t type;

	if ((node = typegraph_search(addr)) == NULL) {
		mdb_warn("couldn't find node corresponding to "
		    "%s at %p\n", typename, addr);
		return;
	}

	if (mdb_ctf_lookup_by_name(typename, &type) == -1) {
		mdb_warn("couldn't find type for '%s'", typename);
		return;
	}

	node->tgn_type = type;
}

/*
 * There are a few important nodes that are impossible to figure out without
 * some carnal knowledge.
 */
static void
typegraph_known_nodes(void)
{
	uintptr_t segkp;

	if (mdb_readvar(&segkp, "segkp") == -1) {
		mdb_warn("couldn't read 'segkp'");
	} else {
		struct seg seg;

		if (mdb_vread(&seg, sizeof (seg), segkp) == -1) {
			mdb_warn("couldn't read seg at %p", segkp);
		} else {
			typegraph_known_node((uintptr_t)seg.s_data,
			    "struct segkp_segdata");
		}
	}
}

/*ARGSUSED*/
int
typegraph(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	size_t est = 0;
	tg_node_t *tgp;
	kmem_cache_t c;
	tg_stats_t stats;
	mdb_ctf_id_t type;
	int wasbuilt = tg_built;
	uintptr_t kstat_arena;
	uint_t perc;
	int i;

	if (!mdb_prop_postmortem) {
		mdb_warn("typegraph: can only be run on a system "
		    "dump; see dumpadm(8)\n");
		return (DCMD_ERR);
	}

	tg_verbose = 0;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &tg_verbose, NULL) != argc)
		return (DCMD_USAGE);

	if (tg_built)
		goto trace;

	tg_start = gethrtime();
	typegraph_stat_str("pass", "initial");
	typegraph_typetab_init();

	/*
	 * First, we need an estimate on the number of buffers.
	 */
	if (mdb_walk("kmem_cache",
	    (mdb_walk_cb_t)typegraph_estimate, &est) == -1) {
		mdb_warn("couldn't walk 'kmem_cache'");
		return (DCMD_ERR);
	}

	if (mdb_walk("modctl",
	    (mdb_walk_cb_t)typegraph_estimate_modctl, &est) == -1) {
		mdb_warn("couldn't walk 'modctl'");
		return (DCMD_ERR);
	}

	if (mdb_walk("vmem",
	    (mdb_walk_cb_t)typegraph_estimate_vmem, &est) == -1) {
		mdb_warn("couldn't walk 'vmem'");
		return (DCMD_ERR);
	}

	typegraph_stat_print("maximum nodes", est);

	tgp = tg_node = mdb_zalloc(sizeof (tg_node_t) * est, UM_SLEEP);
	for (i = 0; i < est; i++)
		mdb_ctf_type_invalidate(&tg_node[i].tgn_type);

	if (mdb_walk("vmem", (mdb_walk_cb_t)typegraph_vmem, &tgp) == -1) {
		mdb_warn("couldn't walk 'vmem'");
		return (DCMD_ERR);
	}

	if (mdb_walk("kmem_cache", (mdb_walk_cb_t)typegraph_kmem, &tgp) == -1) {
		mdb_warn("couldn't walk 'kmem_cache'");
		return (DCMD_ERR);
	}

	tg_nnodes = tgp - tg_node;

	typegraph_stat_print("actual nodes", tg_nnodes);

	typegraph_sort();

	if (mdb_ctf_lookup_by_name("kthread_t", &type) == -1) {
		mdb_warn("couldn't find 'kthread_t'");
		return (DCMD_ERR);
	}

	if (mdb_walk("thread", (mdb_walk_cb_t)typegraph_thread, &type) == -1) {
		mdb_warn("couldn't walk 'thread'");
		return (DCMD_ERR);
	}

	if (mdb_ctf_lookup_by_name("ekstat_t", &type) == -1) {
		mdb_warn("couldn't find 'ekstat_t'");
		return (DCMD_ERR);
	}

	if (mdb_readvar(&kstat_arena, "kstat_arena") == -1) {
		mdb_warn("couldn't read 'kstat_arena'");
		return (DCMD_ERR);
	}

	if (mdb_pwalk("vmem_alloc", (mdb_walk_cb_t)typegraph_kstat,
	    &type, kstat_arena) == -1) {
		mdb_warn("couldn't walk kstat vmem arena");
		return (DCMD_ERR);
	}

	if (mdb_walk("modctl", (mdb_walk_cb_t)typegraph_modctl, NULL) == -1) {
		mdb_warn("couldn't walk 'modctl'");
		return (DCMD_ERR);
	}

	typegraph_stat_print("anchored nodes", tg_nanchored);
	tg_nnodes += tg_nanchored;
	typegraph_sort();
	typegraph_known_nodes();
	typegraph_stat_time(0);
	tg_built = 1;

trace:
	if (!wasbuilt || !(flags & DCMD_ADDRSPEC)) {
		typegraph_allpass(!wasbuilt);
		return (DCMD_OK);
	}

	bzero(&stats, sizeof (stats));

	/*
	 * If we've been given an address, it's a kmem cache.
	 */
	if (mdb_vread(&c, sizeof (c), addr) == -1) {
		mdb_warn("couldn't read kmem_cache at %p", addr);
		return (DCMD_ERR);
	}

	if (mdb_pwalk("kmem",
	    (mdb_walk_cb_t)typegraph_stats_buffer, &stats, addr) == -1) {
		mdb_warn("can't walk kmem for cache %p", addr);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%-25s %7s %7s %7s %7s %7s %7s %5s\n", "NAME",
		    "BUFS", "NODES", "UNMRK", "KNOWN",
		    "INFER", "FRAG", "HIT%");

	if (stats.tgs_nodes) {
		perc = ((stats.tgs_known + stats.tgs_typed +
		    stats.tgs_frag) * 1000) / stats.tgs_nodes;
	} else {
		perc = 0;
	}

	mdb_printf("%-25s %7ld %7ld %7ld %7ld %7ld %7ld %3d.%1d\n",
	    c.cache_name, stats.tgs_buffers, stats.tgs_nodes,
	    stats.tgs_unmarked, stats.tgs_known, stats.tgs_typed,
	    stats.tgs_frag, perc / 10, perc % 10);

	return (DCMD_OK);
}

int
typegraph_built(void)
{
	if (!tg_built) {
		mdb_warn("type graph not yet built; run ::typegraph.\n");
		return (0);
	}

	return (1);
}

int
whattype(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	tg_node_t *node;
	tg_edge_t *e;
	char buf[MDB_SYM_NAMLEN];
	tg_type_t *tp;
	int verbose = 0;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose, NULL) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (!typegraph_built())
		return (DCMD_ABORT);

	if ((node = typegraph_search(addr)) == NULL) {
		mdb_warn("%p does not correspond to a node.\n", addr);
		return (DCMD_OK);
	}

	if (!verbose) {
		mdb_printf("%p is %p+%p, ", addr, node->tgn_base,
		    addr - node->tgn_base);

		if (mdb_ctf_type_valid(node->tgn_type)) {
			mdb_printf("%s\n", mdb_ctf_type_name(node->tgn_type,
			    buf, sizeof (buf)));
			return (DCMD_OK);
		}

		if ((tp = node->tgn_typelist) == NULL) {
			if ((tp = node->tgn_fraglist) == NULL) {
				mdb_printf("unknown type\n");
				return (DCMD_OK);
			}
		}

		if (tp->tgt_next == NULL && mdb_ctf_type_valid(tp->tgt_type)) {
			int kind = mdb_ctf_type_kind(tp->tgt_type);
			size_t offs = tp->tgt_redge->tge_destoffs;

			mdb_printf("possibly %s%s ",
			    tp->tgt_flags & TG_TYPE_ARRAY ? "array of " : "",
			    typegraph_type_name(tp->tgt_type, tp->tgt_utype));

			if (kind != CTF_K_STRUCT && kind != CTF_K_UNION &&
			    mdb_ctf_type_valid(tp->tgt_rtype) &&
			    tp->tgt_rmember != NULL) {
				mdb_printf("(%s.%s) ",
				    mdb_ctf_type_name(tp->tgt_rtype, buf,
				    sizeof (buf)), tp->tgt_rmember);
			}

			if (offs != 0)
				mdb_printf("at %p", node->tgn_base + offs);

			mdb_printf("\n");
			return (DCMD_OK);
		}

		mdb_printf("possibly one of the following:\n");

		for (; tp != NULL; tp = tp->tgt_next) {
			size_t offs = tp->tgt_redge->tge_destoffs;

			mdb_printf("  %s%s ",
			    tp->tgt_flags & TG_TYPE_ARRAY ? "array of " : "",
			    typegraph_type_name(tp->tgt_type, tp->tgt_utype));

			if (offs != 0)
				mdb_printf("at %p ", node->tgn_base + offs);

			mdb_printf("(from %p+%p, type %s)\n",
			    tp->tgt_redge->tge_src->tgn_base,
			    tp->tgt_redge->tge_srcoffs,
			    mdb_ctf_type_name(tp->tgt_rtype,
			    buf, sizeof (buf)) != NULL ? buf : "<unknown>");
		}

		mdb_printf("\n");

		return (DCMD_OK);
	}

	mdb_printf("%-?s %-?s %-29s %5s %5s %s\n", "BASE", "LIMIT", "TYPE",
	    "SIZE", "REACH", "MRK");
	mdb_printf("%-?p %-?p %-29s %5d %5d %s\n",
	    node->tgn_base, node->tgn_limit,
	    mdb_ctf_type_name(node->tgn_type,
	    buf, sizeof (buf)) != NULL ? buf : "<unknown>",
	    typegraph_size(node->tgn_type), node->tgn_reach,
	    node->tgn_marked ? "yes" : "no");

	mdb_printf("\n");
	mdb_printf("  %-20s %?s %8s %-20s %s\n",
	    "INFERENCE", "FROM", "SRCOFFS", "REFTYPE", "REFMEMBER");

	for (tp = node->tgn_typelist; tp != NULL; tp = tp->tgt_next) {
		mdb_printf("  %-20s %?p %8p %-20s %s\n",
		    typegraph_type_name(tp->tgt_type, tp->tgt_utype),
		    tp->tgt_redge->tge_src->tgn_base,
		    tp->tgt_redge->tge_srcoffs,
		    mdb_ctf_type_name(tp->tgt_rtype,
		    buf, sizeof (buf)) != NULL ? buf : "<unknown>",
		    tp->tgt_rmember != NULL ? tp->tgt_rmember : "-");
	}

	mdb_printf("\n");
	mdb_printf("  %-20s %?s %8s %-20s %s\n",
	    "FRAGMENT", "FROM", "SRCOFFS", "REFTYPE", "REFMEMBER");

	for (tp = node->tgn_fraglist; tp != NULL; tp = tp->tgt_next) {
		mdb_printf("  %-20s %?p %8p %-20s %s\n",
		    typegraph_type_name(tp->tgt_type, tp->tgt_utype),
		    tp->tgt_redge->tge_src->tgn_base,
		    tp->tgt_redge->tge_srcoffs,
		    mdb_ctf_type_name(tp->tgt_rtype,
		    buf, sizeof (buf)) != NULL ? buf : "<unknown>",
		    tp->tgt_rmember != NULL ? tp->tgt_rmember : "-");
	}

	mdb_printf("\n");

	mdb_printf("  %?s %8s %8s %6s %6s %5s\n", "FROM", "SRCOFFS", "DESTOFFS",
	    "MARKED", "STATUS", "REACH");

	for (e = node->tgn_incoming; e != NULL; e = e->tge_nextin) {
		tg_node_t *n = e->tge_src;

		mdb_printf("  %?p %8p %8p %6s %6s %ld\n",
		    n->tgn_base, e->tge_srcoffs, e->tge_destoffs,
		    e->tge_marked ? "yes" : "no",
		    mdb_ctf_type_valid(n->tgn_type) ? "known" :
		    n->tgn_typelist != NULL ? "inferd" :
		    n->tgn_fraglist != NULL ? "frgmnt" : "unknwn",
		    n->tgn_reach);
	}

	mdb_printf("\n  %?s %8s %8s %6s %6s %5s\n", "TO", "SRCOFFS", "DESTOFFS",
	    "MARKED", "STATUS", "REACH");

	for (e = node->tgn_outgoing; e != NULL; e = e->tge_nextout) {
		tg_node_t *n = e->tge_dest;

		mdb_printf("  %?p %8p %8p %6s %6s %ld\n",
		    n->tgn_base, e->tge_srcoffs, e->tge_destoffs,
		    e->tge_marked ? "yes" : "no",
		    mdb_ctf_type_valid(n->tgn_type) ? "known" :
		    n->tgn_typelist != NULL ? "inferd" :
		    n->tgn_fraglist != NULL ? "frgmnt" : "unknwn",
		    n->tgn_reach);
	}

	mdb_printf("\n");

	return (DCMD_OK);
}

int
istype(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	tg_node_t *node;
	mdb_ctf_id_t type;

	if (!(flags & DCMD_ADDRSPEC) || argc != 1 ||
	    argv[0].a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	if (!typegraph_built())
		return (DCMD_ABORT);

	/*
	 * Determine the node corresponding to the passed address.
	 */
	if ((node = typegraph_search(addr)) == NULL) {
		mdb_warn("%p not found\n", addr);
		return (DCMD_ERR);
	}

	/*
	 * Now look up the specified type.
	 */
	if (mdb_ctf_lookup_by_name(argv[0].a_un.a_str, &type) == -1) {
		mdb_warn("could not find type %s", argv[0].a_un.a_str);
		return (DCMD_ERR);
	}

	node->tgn_type = type;
	typegraph_allpass(0);

	return (DCMD_OK);
}

/*ARGSUSED*/
int
notype(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	tg_node_t *node;

	if (!(flags & DCMD_ADDRSPEC) || argc != 0)
		return (DCMD_USAGE);

	if (!typegraph_built())
		return (DCMD_ABORT);

	if ((node = typegraph_search(addr)) == NULL) {
		mdb_warn("%p not found\n", addr);
		return (DCMD_ERR);
	}

	mdb_ctf_type_invalidate(&node->tgn_type);
	typegraph_allpass(0);

	return (DCMD_OK);
}

int
typegraph_walk_init(mdb_walk_state_t *wsp)
{
	wsp->walk_data = (void *)0;
	return (WALK_NEXT);
}

int
typeconflict_walk_step(mdb_walk_state_t *wsp)
{
	size_t ndx;
	tg_node_t *node = NULL;

	for (ndx = (size_t)wsp->walk_data; ndx < tg_nnodes; ndx++) {
		node = &tg_node[ndx];

		if (mdb_ctf_type_valid(node->tgn_type))
			continue;

		if (node->tgn_typelist == NULL)
			continue;

		if (node->tgn_typelist->tgt_next == NULL)
			continue;

		break;
	}

	if (ndx == tg_nnodes)
		return (WALK_DONE);

	wsp->walk_data = (void *)++ndx;
	return (wsp->walk_callback(node->tgn_base, NULL, wsp->walk_cbdata));
}

int
typeunknown_walk_step(mdb_walk_state_t *wsp)
{
	size_t ndx;
	tg_node_t *node = NULL;

	for (ndx = (size_t)wsp->walk_data; ndx < tg_nnodes; ndx++) {
		node = &tg_node[ndx];

		if (mdb_ctf_type_valid(node->tgn_type))
			continue;

		if (node->tgn_typelist != NULL)
			continue;

		if (node->tgn_fraglist != NULL)
			continue;

		break;
	}

	if (ndx == tg_nnodes)
		return (WALK_DONE);

	wsp->walk_data = (void *)++ndx;
	return (wsp->walk_callback(node->tgn_base, NULL, wsp->walk_cbdata));
}

#define	FINDLOCKS_DEPTH		32

typedef struct foundlock {
	uintptr_t	fnd_addr;
	uintptr_t	fnd_owner;
	const char	*fnd_member[FINDLOCKS_DEPTH];
	mdb_ctf_id_t	fnd_parent;
	tg_node_t	*fnd_node;
} foundlock_t;

typedef struct findlocks {
	uintptr_t	fl_addr;
	uintptr_t	fl_thread;
	size_t		fl_ndx;
	size_t		fl_nlocks;
	foundlock_t	*fl_locks;
	mdb_ctf_id_t	fl_parent;
	tg_node_t	*fl_node;
	const char	*fl_member[FINDLOCKS_DEPTH - 1];
	int		fl_depth;
} findlocks_t;

/*ARGSUSED*/
static int
findlocks_owner(uintptr_t addr, const void *data, void *owner)
{
	*((uintptr_t *)owner) = addr;

	return (WALK_NEXT);
}

static int
findlocks_findmutex(const char *name, mdb_ctf_id_t type, ulong_t offs,
    findlocks_t *fl)
{
	static int called = 0;
	static mdb_ctf_id_t mutex;
	static mdb_ctf_id_t thread;
	mdb_ctf_id_t parent = fl->fl_parent;
	uintptr_t addr = fl->fl_addr;
	int kind, depth = fl->fl_depth, i;
	foundlock_t *found;

	offs /= NBBY;

	if (!called) {
		if (mdb_ctf_lookup_by_name("kmutex_t", &mutex) == -1) {
			mdb_warn("can't find 'kmutex_t' type");
			return (1);
		}

		if (!mdb_ctf_type_valid(mutex = typegraph_resolve(mutex))) {
			mdb_warn("can't resolve 'kmutex_t' type");
			return (1);
		}

		if (mdb_ctf_lookup_by_name("kthread_t", &thread) == -1) {
			mdb_warn("can't find 'kthread_t' type");
			return (1);
		}

		if (!mdb_ctf_type_valid(thread = typegraph_resolve(thread))) {
			mdb_warn("can't resolve 'kthread_t' type");
			return (1);
		}

		called = 1;
	}

	if (!mdb_ctf_type_valid(type))
		return (0);

	type = typegraph_resolve(type);
	kind = mdb_ctf_type_kind(type);

	if (!mdb_ctf_type_valid(type))
		return (0);

	if (kind == CTF_K_ARRAY) {
		mdb_ctf_arinfo_t arr;
		ssize_t size;

		if (mdb_ctf_array_info(type, &arr) == -1)
			return (0);

		type = typegraph_resolve(arr.mta_contents);

		if (!mdb_ctf_type_valid(type))
			return (0);

		/*
		 * Small optimization:  don't bother running through the array
		 * if we know that we can't process the type.
		 */
		kind = mdb_ctf_type_kind(type);
		size = mdb_ctf_type_size(type);

		if (kind == CTF_K_POINTER || kind == CTF_K_INTEGER)
			return (0);

		for (i = 0; i < arr.mta_nelems; i++) {
			fl->fl_addr = addr + offs + (i * size);
			findlocks_findmutex(name, type, 0, fl);
		}

		fl->fl_addr = addr;

		return (0);
	}

	if (kind != CTF_K_STRUCT)
		return (0);

	if (mdb_ctf_type_cmp(type, mutex) == 0) {
		mdb_ctf_id_t ttype;
		uintptr_t owner = 0;
		tg_node_t *node;

		if (mdb_pwalk("mutex_owner",
		    findlocks_owner, &owner, addr + offs) == -1) {
			return (0);
		}

		/*
		 * Check to see if the owner is a thread.
		 */
		if (owner == 0 || (node = typegraph_search(owner)) == NULL)
			return (0);

		if (!mdb_ctf_type_valid(node->tgn_type))
			return (0);

		ttype = typegraph_resolve(node->tgn_type);

		if (!mdb_ctf_type_valid(ttype))
			return (0);

		if (mdb_ctf_type_cmp(ttype, thread) != 0)
			return (0);

		if (fl->fl_thread != 0 && owner != fl->fl_thread)
			return (0);

		if (fl->fl_ndx >= fl->fl_nlocks) {
			size_t nlocks, osize, size;
			foundlock_t *locks;

			if ((nlocks = (fl->fl_nlocks << 1)) == 0)
				nlocks = 1;

			osize = fl->fl_nlocks * sizeof (foundlock_t);
			size = nlocks * sizeof (foundlock_t);

			locks = mdb_zalloc(size, UM_SLEEP);

			if (fl->fl_locks) {
				bcopy(fl->fl_locks, locks, osize);
				mdb_free(fl->fl_locks, osize);
			}

			fl->fl_locks = locks;
			fl->fl_nlocks = nlocks;
		}

		found = &fl->fl_locks[fl->fl_ndx++];
		found->fnd_addr = (uintptr_t)addr + offs;
		found->fnd_owner = owner;

		for (i = 0; i < fl->fl_depth; i++)
			found->fnd_member[i] = fl->fl_member[i];

		found->fnd_member[i] = name;
		found->fnd_parent = fl->fl_parent;
		found->fnd_node = fl->fl_node;

		return (0);
	}

	fl->fl_addr = (uintptr_t)addr + offs;

	if (name == NULL) {
		fl->fl_parent = type;
	} else if (depth < FINDLOCKS_DEPTH - 1) {
		fl->fl_member[depth] = name;
		fl->fl_depth++;
	}

	mdb_ctf_member_iter(type, (mdb_ctf_member_f *)findlocks_findmutex, fl,
	    0);

	fl->fl_addr = addr;
	fl->fl_parent = parent;
	fl->fl_depth = depth;

	return (0);
}

static void
findlocks_node(tg_node_t *node, findlocks_t *fl)
{
	mdb_ctf_id_t type = node->tgn_type, ntype;
	int kind;
	tg_type_t *tp, *found = NULL;

	if (!mdb_ctf_type_valid(type)) {
		mdb_ctf_type_invalidate(&type);

		for (tp = node->tgn_typelist; tp != NULL; tp = tp->tgt_next) {
			kind = mdb_ctf_type_kind(ntype = tp->tgt_type);

			if (kind == CTF_K_UNION) {
				/*
				 * Insert disparaging comment about unions here.
				 */
				return;
			}

			if (kind != CTF_K_STRUCT && kind != CTF_K_ARRAY)
				continue;

			if (found != NULL) {
				/*
				 * There are multiple interpretations for this
				 * node; we have to punt.
				 */
				return;
			}

			found = tp;
		}
	}

	if (found != NULL)
		type = found->tgt_type;

	fl->fl_parent = type;
	fl->fl_node = node;

	/*
	 * We have our type.  Now iterate for locks.  Note that we don't yet
	 * deal with locks in flexible array members.
	 */
	if (found != NULL && (found->tgt_flags & TG_TYPE_ARRAY) &&
	    !(found->tgt_flags & TG_TYPE_HASFAM)) {
		uintptr_t base, limit = node->tgn_limit;
		size_t size = mdb_ctf_type_size(found->tgt_type);

		for (base = node->tgn_base; base < limit; base += size) {
			fl->fl_addr = base;
			findlocks_findmutex(NULL, type, 0, fl);
		}
	} else {
		fl->fl_addr = node->tgn_base;
		findlocks_findmutex(NULL, type, 0, fl);
	}

	if (mdb_ctf_type_valid(type))
		return;

	for (tp = node->tgn_fraglist; tp != NULL; tp = tp->tgt_next) {
		kind = mdb_ctf_type_kind(ntype = tp->tgt_type);

		if (kind != CTF_K_STRUCT && kind != CTF_K_ARRAY)
			continue;

		fl->fl_addr = node->tgn_base + tp->tgt_redge->tge_destoffs;
		fl->fl_parent = ntype;
		findlocks_findmutex(NULL, ntype, 0, fl);
	}
}

/*ARGSUSED*/
int
findlocks(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	size_t i, j;
	findlocks_t fl;

	if (argc != 0)
		return (DCMD_USAGE);

	if (!typegraph_built())
		return (DCMD_ABORT);

	if (!(flags & DCMD_ADDRSPEC))
		addr = 0;

	bzero(&fl, sizeof (fl));
	fl.fl_thread = addr;

	for (i = 0; i < tg_nnodes; i++) {
		findlocks_node(&tg_node[i], &fl);
	}

	for (i = 0; i < fl.fl_ndx; i++) {
		foundlock_t *found = &fl.fl_locks[i];
		char buf[MDB_SYM_NAMLEN];

		if (found->fnd_member[0] != NULL) {
			mdb_printf("%p (%s",
			    found->fnd_addr,
			    mdb_ctf_type_name(found->fnd_parent, buf,
			    sizeof (buf)));

			for (j = 0; found->fnd_member[j] != NULL; j++)
				mdb_printf(".%s", found->fnd_member[j]);

			mdb_printf(") is owned by %p\n", found->fnd_owner);
		} else {
			if (found->fnd_node->tgn_incoming == NULL) {
				mdb_printf("%p (%a) is owned by %p\n",
				    found->fnd_addr, found->fnd_addr,
				    found->fnd_owner);
			} else {
				mdb_printf("%p is owned by %p\n",
				    found->fnd_addr, found->fnd_owner);
			}
		}
	}

	mdb_printf("findlocks: nota bene: %slocks may be held",
	    fl.fl_nlocks ? "other " : "");

	if (addr == 0) {
		mdb_printf("\n");
	} else {
		mdb_printf(" by %p\n", addr);
	}

	if (fl.fl_nlocks)
		mdb_free(fl.fl_locks, fl.fl_nlocks * sizeof (foundlock_t));

	return (DCMD_OK);
}

/*
 * ::findfalse:  Using type knowledge to detect potential false sharing
 *
 * In caching SMP systems, memory is kept coherent through bus-based snooping
 * protocols.  Under these protocols, only a single cache may have a given line
 * of memory in a dirty state.  If a different cache wishes to write to the
 * dirty line, the new cache must first read-to-own the dirty line from the
 * owning cache.  The size of the line used for coherence (the coherence
 * granularity) has an immediate ramification for parallel software:  because
 * only one cache may own a line at a given time, one wishes to avoid a
 * situation where two or more small, disjoint data structures are both
 * (a) contained within a single line and (b) accessed in parallel on disjoint
 * CPUs.  This situation -- so-called "false sharing" -- can induce suboptimal
 * scalability in otherwise scalable software.
 *
 * Historically, one has been able to find false sharing only with some
 * combination of keen intuition and good luck.  And where false sharing has
 * been discovered, it has almost always been after having induced suboptimal
 * scaling; one has historically not been able to detect false sharing before
 * the fact.
 *
 * Building on the mechanism for postmortem type information, however, we
 * can -- from a system crash dump -- detect the the potentially most egregious
 * cases of false sharing.  Specifically, after having run through the type
 * identification passes described above, we can iterate over all nodes,
 * looking for nodes that satisfy the following criteria:
 *
 *  (a)	The node is an array.  That is, the node was either determined to
 *	be of type CTF_K_ARRAY, or the node was inferred to be an array in
 *	pass2 of type identification (described above).
 *
 *  (b)	Each element of the array is a structure that is smaller than the
 *	coherence granularity.
 *
 *  (c)	The total size of the array is greater than the coherence granularity.
 *
 *  (d)	Each element of the array is a structure that contains within it a
 *	synchronization primitive (mutex, readers/writer lock, condition
 *	variable or semaphore).  We use the presence of a synchronization
 *	primitive as a crude indicator that the disjoint elements of the
 *	array are accessed in parallel.
 *
 * Any node satisfying these criteria is identified as an object that could
 * potentially suffer from false sharing, and the node's address, symbolic
 * name (if any), type, type size and total size are provided as output.
 *
 * While there are some instances of false sharing that do not meet the
 * above criteria (e.g., if the synchronization for each element is handled
 * in a separate structure, or if the elements are only manipulated with
 * atomic memory operations), these criteria yield many examples of false
 * sharing without swamping the user with false positives.
 */
#define	FINDFALSE_COHERENCE_SIZE	64

/*ARGSUSED*/
static int
findfalse_findsync(const char *name, mdb_ctf_id_t type, ulong_t offs,
    void *ignored)
{
	int i, kind;
	static int called = 0;
	static struct {
		char *name;
		mdb_ctf_id_t type;
	} sync[] = {
		{ "kmutex_t" },
		{ "krwlock_t" },
		{ "kcondvar_t" },
		{ "ksema_t" },
		{ NULL }
	};

	if (!called) {
		char *name;

		called = 1;

		for (i = 0; (name = sync[i].name) != NULL; i++) {
			if (mdb_ctf_lookup_by_name(name, &sync[i].type) == -1) {
				mdb_warn("can't find '%s' type", name);
				return (0);
			}

			sync[i].type = typegraph_resolve(sync[i].type);

			if (!mdb_ctf_type_valid(sync[i].type)) {
				mdb_warn("can't resolve '%s' type", name);
				return (0);
			}
		}
	}

	/*
	 * See if this type is any of the synchronization primitives.
	 */
	if (!mdb_ctf_type_valid(type))
		return (0);

	type = typegraph_resolve(type);

	for (i = 0; sync[i].name != NULL; i++) {
		if (mdb_ctf_type_cmp(type, sync[i].type) == 0) {
			/*
			 * We have a winner!
			 */
			return (1);
		}
	}

	if ((kind = mdb_ctf_type_kind(type)) == CTF_K_ARRAY) {
		mdb_ctf_arinfo_t arr;

		if (mdb_ctf_array_info(type, &arr) == -1)
			return (0);

		type = typegraph_resolve(arr.mta_contents);

		return (findfalse_findsync(name, type, 0, NULL));
	}

	if (kind != CTF_K_STRUCT)
		return (0);

	if (mdb_ctf_member_iter(type,
	    (mdb_ctf_member_f *)findfalse_findsync, NULL, 0) != 0)
		return (1);

	return (0);
}

static void
findfalse_node(tg_node_t *node)
{
	mdb_ctf_id_t type = node->tgn_type;
	tg_type_t *tp, *found = NULL;
	ssize_t size;
	int kind;
	char buf[MDB_SYM_NAMLEN + 1];
	GElf_Sym sym;

	if (!mdb_ctf_type_valid(type)) {
		mdb_ctf_type_invalidate(&type);

		for (tp = node->tgn_typelist; tp != NULL; tp = tp->tgt_next) {
			kind = mdb_ctf_type_kind(tp->tgt_type);

			if (kind == CTF_K_UNION) {
				/*
				 * Once again, the unions impede progress...
				 */
				return;
			}

			if (kind != CTF_K_STRUCT && kind != CTF_K_ARRAY)
				continue;

			if (found != NULL) {
				/*
				 * There are multiple interpretations for this
				 * node; we have to punt.
				 */
				return;
			}

			found = tp;
		}
	}

	if (found != NULL)
		type = found->tgt_type;

	if (!mdb_ctf_type_valid(type))
		return;

	kind = mdb_ctf_type_kind(type);

	/*
	 * If this isn't an array (or treated as one), it can't induce false
	 * sharing.  (Or at least, we can't detect it.)
	 */
	if (found != NULL) {
		if (!(found->tgt_flags & TG_TYPE_ARRAY))
			return;

		if (found->tgt_flags & TG_TYPE_HASFAM)
			return;
	} else {
		if (kind != CTF_K_ARRAY)
			return;
	}

	if (kind == CTF_K_ARRAY) {
		mdb_ctf_arinfo_t arr;

		if (mdb_ctf_array_info(type, &arr) == -1)
			return;

		type = typegraph_resolve(arr.mta_contents);

		if (!mdb_ctf_type_valid(type))
			return;

	}

	size = mdb_ctf_type_size(type);

	/*
	 * If the size is greater than or equal to the cache line size, it's
	 * not false sharing.  (Or at least, the false sharing is benign.)
	 */
	if (size >= FINDFALSE_COHERENCE_SIZE)
		return;

	if (TG_NODE_SIZE(node) <= FINDFALSE_COHERENCE_SIZE)
		return;

	/*
	 * This looks like it could be a falsely shared structure.  If this
	 * type contains a mutex, rwlock, semaphore or condition variable,
	 * we're going to report it.
	 */
	if (!findfalse_findsync(NULL, type, 0, NULL))
		return;

	mdb_printf("%?p ", node->tgn_base);

	if (mdb_lookup_by_addr(node->tgn_base, MDB_SYM_EXACT, buf,
	    sizeof (buf), &sym) != -1) {
		mdb_printf("%-28s ", buf);
	} else {
		mdb_printf("%-28s ", "-");
	}

	mdb_printf("%-22s %2d %7ld\n",
	    mdb_ctf_type_name(type, buf, sizeof (buf)), size,
	    TG_NODE_SIZE(node));
}

/*ARGSUSED*/
int
findfalse(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	ssize_t i;

	if (argc != 0 || (flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (!typegraph_built())
		return (DCMD_ABORT);

	mdb_printf("%?s %-28s %-22s %2s %7s\n", "ADDR", "SYMBOL", "TYPE",
	    "SZ", "TOTSIZE");

	/*
	 * We go from the back of the bus and move forward to report false
	 * sharing in named symbols before reporting false sharing in dynamic
	 * structures.
	 */
	for (i = tg_nnodes - 1; i >= 0; i--)
		findfalse_node(&tg_node[i]);

	return (DCMD_OK);
}
