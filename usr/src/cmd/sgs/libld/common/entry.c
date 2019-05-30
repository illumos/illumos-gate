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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#define	ELF_TARGET_AMD64

#include	<stdio.h>
#include	<memory.h>
#include	<debug.h>
#include	"msg.h"
#include	"_libld.h"

/*
 * The link-editor uses a segment descriptor list to describe the program
 * headers, and related output segments, it can potentially create. This
 * list is initially seeded using the templates contained in the sg_desc
 * array below. Additional segments may be added using a mapfile.
 *
 * The entries in sg_desc must be put in the order defined by the
 * Segment_id enum.
 *
 * The entries in sg_desc are initialized using the SG_DESC_INIT macro
 * for two reasons:
 *
 *	1) The first field of the Sg_desc struct is a program header
 *		entry. ELF32_Phdr and ELF64_Phdr have the same fields,
 *		but their order is different. Use of a macro allows us
 *		to handle this transparently.
 *	2) Most of the fields in the Sg_desc entries are set to 0.
 *		Use of a macro allows us to hide the clutter.
 *
 * If a given program header can be referenced via an entrance criteria
 * (i.e. can serve as a segment), then it must be given a unique sg_name.
 * Program headers that cannot be a segment (PHDR, INTERP, DYNAMIC, etc)
 * must have a NULL sg_name --- their program header type identifies them.
 */
#ifdef _ELF64
#define	SG_DESC_INIT(id, p_type, p_flags, sg_name, sg_flags) \
	{ id, { p_type, p_flags, 0, 0, 0, 0, 0, 0}, \
	    sg_name, 0, 0, NULL, NULL, NULL, sg_flags, NULL, 0, NULL}
#else
#define	SG_DESC_INIT(id, p_type, p_flags, sg_name, sg_flags) \
	{ id, { p_type, 0, 0, 0, 0, 0, p_flags, 0}, \
	    sg_name, 0, 0, NULL, NULL, NULL, sg_flags, NULL, 0, NULL}
#endif

/*
 * Predefined segment descriptors:
 *
 * The C language guarantees that a structure containing only fields of
 * identical type is indistinguishable from a simple array containing
 * the same number of items of the same type. They will have the same
 * size, alignment, and internal layout:
 *
 * -	A pointer to one is equivalent to a pointer to the other, and you
 *	can cast safely between them.
 *
 * -	You can put both into a union, and access the elements within
 *	either way (by index, or by name).
 *
 * We use this fact here to create an "array" of predefined segment
 * descriptors, assigning each one a mnemonic name that can be used to point
 * at it from a predefined entrance criteria descriptor (below). These
 * segments are positioned in the default order that will result in the
 * output object, unless a mapfile alters things.
 */
typedef struct {
	Sg_desc	psg_phdr;
	Sg_desc psg_interp;
	Sg_desc psg_sunwcap;
	Sg_desc psg_text;
	Sg_desc psg_data;
	Sg_desc psg_bss;
#if	defined(_ELF64)
	Sg_desc	psg_lrodata;	/* (amd64-only) */
	Sg_desc psg_ldata;	/* (amd64-only) */
#endif
	Sg_desc	psg_dynamic;
	Sg_desc	psg_sunwdtrace;
	Sg_desc	psg_tls;
	Sg_desc	psg_unwind;
	Sg_desc	psg_sunwstack;
	Sg_desc	psg_note;
	Sg_desc	psg_extra;
} predef_seg_t;

static const size_t predef_seg_nelts =
	(sizeof (predef_seg_t) / sizeof (Sg_desc));

static predef_seg_t sg_desc = {
	/* psg_phdr */
	SG_DESC_INIT(SGID_PHDR, PT_PHDR, PF_R + PF_X, NULL,
	    (FLG_SG_P_TYPE | FLG_SG_P_FLAGS)),

	/* psg_interp */
	SG_DESC_INIT(SGID_INTERP, PT_INTERP, PF_R, NULL,
	    (FLG_SG_P_TYPE | FLG_SG_P_FLAGS)),

	/* psg_sunwcap */
	SG_DESC_INIT(SGID_SUNWCAP, PT_SUNWCAP, PF_R, NULL,
	    (FLG_SG_P_TYPE | FLG_SG_P_FLAGS)),

	/* psg_text */
	SG_DESC_INIT(SGID_TEXT, PT_LOAD, PF_R + PF_X, MSG_ORIG(MSG_ENT_TEXT),
	    (FLG_SG_P_TYPE | FLG_SG_P_FLAGS)),

	/* psg_data */
	SG_DESC_INIT(SGID_DATA, PT_LOAD, 0, MSG_ORIG(MSG_ENT_DATA),
	    (FLG_SG_P_TYPE | FLG_SG_P_FLAGS)),

	/* psg_bss */
	SG_DESC_INIT(SGID_BSS, PT_LOAD, 0, MSG_ORIG(MSG_ENT_BSS),
	    (FLG_SG_P_TYPE | FLG_SG_P_FLAGS | FLG_SG_DISABLED)),

#if	defined(_ELF64)
	/* psg_lrodata (amd64-only ) */
	SG_DESC_INIT(SGID_LRODATA, PT_LOAD, PF_R, MSG_ORIG(MSG_ENT_LRODATA),
	    (FLG_SG_P_TYPE | FLG_SG_P_FLAGS)),

	/* psg_ldata (amd64-only ) */
	SG_DESC_INIT(SGID_LDATA, PT_LOAD, 0, MSG_ORIG(MSG_ENT_LDATA),
	    (FLG_SG_P_TYPE | FLG_SG_P_FLAGS)),
#endif
	/* psg_dynamic */
	SG_DESC_INIT(SGID_DYN, PT_DYNAMIC, 0, NULL,
	    (FLG_SG_P_TYPE | FLG_SG_P_FLAGS)),

	/* psg_sunwdtrace */
	SG_DESC_INIT(SGID_DTRACE, PT_SUNWDTRACE, 0, NULL,
	    (FLG_SG_P_TYPE | FLG_SG_P_FLAGS)),

	/* psg_tls */
	SG_DESC_INIT(SGID_TLS, PT_TLS, PF_R, NULL,
	    (FLG_SG_P_TYPE | FLG_SG_P_FLAGS)),

	/* psg_unwind */
	SG_DESC_INIT(SGID_UNWIND, PT_SUNW_UNWIND, PF_R, NULL,
	    (FLG_SG_P_TYPE | FLG_SG_P_FLAGS)),

	/* psg_sunwstack */
	SG_DESC_INIT(SGID_SUNWSTACK, PT_SUNWSTACK, 0, NULL,
	    (FLG_SG_P_TYPE | FLG_SG_P_FLAGS | FLG_SG_DISABLED)),

	/* psg_note */
	SG_DESC_INIT(SGID_NOTE, PT_NOTE, 0, MSG_ORIG(MSG_ENT_NOTE),
	    FLG_SG_P_TYPE),

	/*
	 * psg_extra
	 *
	 * This segment is referenced by the final entrance criteria descriptor
	 * to catch any segment not otherwise placed. It cannot be disabled
	 * via a mapfile.
	 */
	SG_DESC_INIT(SGID_EXTRA, PT_NULL, 0, MSG_ORIG(MSG_ENT_EXTRA),
	    (FLG_SG_P_TYPE | FLG_SG_NODISABLE))
};
#undef SG_DESC_INIT

/*
 * The processing of input files by the link-editor involves matching the
 * input file sections against an ordered list of entrance criteria
 * descriptors. The following template defines the built in entrance criteria
 * list. This list can be augmented using a mapfile. Each entrance criteria
 * is associated with a segment descriptor, providing the means for mapping
 * input sections to output segments.
 *
 * As with the segment descriptors, the EC_DESC_INIT macro is used
 * to reduce boilerplate clutter.
 */
#define	EC_DESC_INIT(ec_is_name, ec_type, ec_attrmask, ec_attrbits, \
    _seg_field, ec_flags) \
	{ NULL, NULL, ec_is_name, ec_type, ec_attrmask, ec_attrbits, \
	    &sg_desc.psg_ ## _seg_field, 0, FLG_EC_BUILTIN | ec_flags }

static const Ent_desc	ent_desc[] = {
	EC_DESC_INIT(NULL, SHT_NOTE, 0, 0, note, 0),

#if	defined(_ELF64)		/* (amd64-only) */
	EC_DESC_INIT(NULL, 0, SHF_ALLOC + SHF_WRITE + SHF_AMD64_LARGE,
	    SHF_ALLOC + SHF_AMD64_LARGE, lrodata, 0),
#endif
	EC_DESC_INIT(NULL, 0, SHF_ALLOC + SHF_WRITE, SHF_ALLOC, text, 0),

	/*
	 * Explicitly assign the .tdata section to bss.  The design of TLS
	 * provides for initialized data being assigned to a .tdata section,
	 * and uninitialized data being assigned to a .tbss section.  These
	 * sections should be laid out adjacent to each other, with little or
	 * no gap between them.  A PT_TLS program header is created that
	 * defines the address range of the two sections.  This header is
	 * passed to libc to instantiate the appropriate thread allocation.
	 *
	 * By default a separate bss segment is disabled, however users can
	 * trigger the creation of a bss segment with a mapfile.  By default,
	 * all bss sections are assigned to the data segment, and the section
	 * identifiers of .tdata and .tbss ensure that these two sections are
	 * adjacent to each other.
	 *
	 * However, if a bss segment is enabled, the adjacency of the .tdata
	 * and .tbss sections can only be retained by having an explicit .tdata
	 * entrance criteria.
	 */
	EC_DESC_INIT(MSG_ORIG(MSG_SCN_TDATA), 0, SHF_ALLOC + SHF_WRITE,
	    SHF_ALLOC + SHF_WRITE, bss, 0),

	EC_DESC_INIT(NULL, SHT_NOBITS, SHF_ALLOC + SHF_WRITE,
	    SHF_ALLOC + SHF_WRITE, bss, 0),

#if	defined(_ELF64)		/* (amd64-only) */
	EC_DESC_INIT(NULL, SHT_NOBITS, SHF_ALLOC + SHF_WRITE + SHF_AMD64_LARGE,
	    SHF_ALLOC + SHF_WRITE + SHF_AMD64_LARGE, data, 0),

	EC_DESC_INIT(NULL, 0, SHF_ALLOC + SHF_WRITE + SHF_AMD64_LARGE,
	    SHF_ALLOC + SHF_WRITE + SHF_AMD64_LARGE, ldata, 0),
#endif
	EC_DESC_INIT(NULL, 0, SHF_ALLOC + SHF_WRITE, SHF_ALLOC + SHF_WRITE,
	    data, 0),

	/*
	 * Final catchall rule sends remaining sections to "extra"
	 * NULL segment, which has been tagged as FLG_SG_NODISABLE,
	 * and which will therefore always accept them.
	 */
	EC_DESC_INIT(NULL, 0, 0, 0, extra, FLG_EC_CATCHALL)
};
#undef EC_DESC_INIT

/*
 * AVL comparison function for Sg_desc items in ofl_segs_avl.
 *
 * entry:
 *	n1, n2 - pointers to nodes to be compared
 *
 * exit:
 *	Returns -1 if (n1 < n2), 0 if they are equal, and 1 if (n1 > n2)
 */
static int
ofl_segs_avl_cmp(const void *n1, const void *n2)
{
	int		rc;

	rc = strcmp(((Sg_desc *)n1)->sg_name, ((Sg_desc *)n2)->sg_name);

	if (rc > 0)
		return (1);
	if (rc < 0)
		return (-1);
	return (0);
}

/*
 * AVL comparison function for Ent_desc items in ofl_ents_avl.
 *
 * entry:
 *	n1, n2 - pointers to nodes to be compared
 *
 * exit:
 *	Returns -1 if (n1 < n2), 0 if they are equal, and 1 if (n1 > n2)
 */
static int
ofl_ents_avl_cmp(const void *n1, const void *n2)
{
	int		rc;

	/*
	 * There are entrance criteria nodes with NULL pointer names,
	 * but they are never entered into the AVL tree. Hence, we can
	 * assume that both nodes have names.
	 */
	rc = strcmp(((Ent_desc *)n1)->ec_name, ((Ent_desc *)n2)->ec_name);

	if (rc > 0)
		return (1);
	if (rc < 0)
		return (-1);
	return (0);
}

/*
 * Lookup a segment descriptor by name.
 *
 * entry:
 *	ofl - Output descriptor
 *	name - Name of desired segment
 *
 * exit:
 *	On success, returns pointer to descriptor. On failure, returns NULL.
 */
Sg_desc *
ld_seg_lookup(Ofl_desc *ofl, const char *name, avl_index_t *where)
{
	Sg_desc		sg;

	sg.sg_name = name;
	return (avl_find(&ofl->ofl_segs_avl, &sg, where));
}


/*
 * Look up an entrance criteria record by name
 *
 * entry:
 *	mf - Mapfile descriptor
 *	name - Name of entrance criteria to locate
 *
 * exit:
 *	On success, a pointer to the entrace criteria record is
 *	returned. On failure, NULL is returned.
 *
 * note:
 *	Entrance criteria are not required to have names. Only
 *	named entrance criteria can be looked up via this method.
 */
Ent_desc *
ld_ent_lookup(Ofl_desc *ofl, const char *name, avl_index_t *where)
{
	Ent_desc	en;

	en.ec_name = name;
	return (avl_find(&ofl->ofl_ents_avl, &en, where));
}

/*
 * Initialize new entrance and segment descriptors and add them as lists to
 * the output file descriptor.
 */
uintptr_t
ld_ent_setup(Ofl_desc *ofl, Xword segalign)
{
	Ent_desc	*enp;
	predef_seg_t	*psegs;
	Sg_desc		*sgp;
	size_t		idx;

	/*
	 * Initialize the elf library.
	 */
	if (elf_version(EV_CURRENT) == EV_NONE) {
		ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_ELF_LIBELF),
		    EV_CURRENT);
		return (S_ERROR);
	}

	/*
	 * Initialize internal Global Symbol Table AVL tree
	 */
	avl_create(&ofl->ofl_symavl, &ld_sym_avl_comp, sizeof (Sym_avlnode),
	    SGSOFFSETOF(Sym_avlnode, sav_node));

	/* Initialize segment AVL tree */
	avl_create(&ofl->ofl_segs_avl, ofl_segs_avl_cmp,
	    sizeof (Sg_desc), SGSOFFSETOF(Sg_desc, sg_avlnode));

	/* Initialize entrance criteria AVL tree */
	avl_create(&ofl->ofl_ents_avl, ofl_ents_avl_cmp, sizeof (Ent_desc),
	    SGSOFFSETOF(Ent_desc, ec_avlnode));


	/*
	 * Allocate and initialize writable copies of both the entrance and
	 * segment descriptors.
	 *
	 * Note that on non-amd64 targets, this allocates a few more
	 * elements than are needed. For now, we are willing to overallocate
	 * a small amount to simplify the code.
	 */
	if ((psegs = libld_malloc(sizeof (sg_desc))) == NULL)
		return (S_ERROR);
	(void) memcpy(psegs, &sg_desc, sizeof (sg_desc));
	sgp = (Sg_desc *) psegs;

	/*
	 * The data segment and stack permissions can differ:
	 *
	 *	- Architectural/ABI per-platform differences
	 *	- Whether the object is built statically or dynamically
	 *
	 * Those segments so affected have their program header flags
	 * set here at runtime, rather than in the sg_desc templates above.
	 */
	psegs->psg_data.sg_phdr.p_flags = ld_targ.t_m.m_dataseg_perm;
	psegs->psg_bss.sg_phdr.p_flags = ld_targ.t_m.m_dataseg_perm;
	psegs->psg_dynamic.sg_phdr.p_flags = ld_targ.t_m.m_dataseg_perm;
	psegs->psg_sunwdtrace.sg_phdr.p_flags = ld_targ.t_m.m_dataseg_perm;
#if	defined(_ELF64)
	psegs->psg_ldata.sg_phdr.p_flags = ld_targ.t_m.m_dataseg_perm;
	psegs->psg_sunwdtrace.sg_phdr.p_flags |= PF_X;
#endif
	psegs->psg_sunwstack.sg_phdr.p_flags = ld_targ.t_m.m_stack_perm;
	if ((ofl->ofl_flags & FLG_OF_DYNAMIC) == 0)
		psegs->psg_data.sg_phdr.p_flags |= PF_X;

	/*
	 * Traverse the new entrance descriptor list converting the segment
	 * pointer entries to the absolute address within the new segment
	 * descriptor list.  Add each entrance descriptor to the output file
	 * list.
	 */
	if ((enp = libld_malloc(sizeof (ent_desc))) == NULL)
		return (S_ERROR);
	(void) memcpy(enp, ent_desc, sizeof (ent_desc));
	for (idx = 0; idx < (sizeof (ent_desc) / sizeof (ent_desc[0])); idx++,
	    enp++) {

#if	defined(_ELF64)
		/* Don't use the amd64 entry conditions for non-amd64 targets */
		if ((enp->ec_attrmask & SHF_AMD64_LARGE) &&
		    (ld_targ.t_m.m_mach != EM_AMD64))
			continue;
#endif
		if (aplist_append(&ofl->ofl_ents, enp,
		    AL_CNT_OFL_ENTRANCE) == NULL)
			return (S_ERROR);

		/*
		 * The segment pointer is currently pointing at a template
		 * segment descriptor in sg_desc. Compute its array index,
		 * and then use that index to compute the address of the
		 * corresponding descriptor in the writable copy.
		 */
		enp->ec_segment =
		    &sgp[(enp->ec_segment - (Sg_desc *) &sg_desc)];
	}

	/*
	 * Add each segment descriptor to the segment descriptor list. The
	 * ones with non-NULL sg_name are also entered into the AVL tree.
	 * For each loadable segment initialize a default alignment. Note
	 * that ld(1) and ld.so.1 initialize this differently.
	 */
	for (idx = 0; idx < predef_seg_nelts; idx++, sgp++) {
		Phdr	*phdr = &(sgp->sg_phdr);

#if	defined(_ELF64)
		/* Ignore amd64 segment templates for non-amd64 targets */
		switch (sgp->sg_id) {
		case SGID_LRODATA:
		case SGID_LDATA:
			if ((ld_targ.t_m.m_mach != EM_AMD64))
				continue;
		}
#endif
		if (phdr->p_type == PT_LOAD)
			phdr->p_align = segalign;

		if ((aplist_append(&ofl->ofl_segs, sgp,
		    AL_CNT_SEGMENTS)) == NULL)
			return (S_ERROR);

#ifndef NDEBUG			/* assert() is enabled */
		/*
		 * Enforce the segment name rule: Any segment that can
		 * be referenced by an entrance descriptor must have
		 * a name. Any segment that cannot, must have a NULL
		 * name pointer.
		 */
		switch (phdr->p_type) {
		case PT_LOAD:
		case PT_NOTE:
		case PT_NULL:
			assert(sgp->sg_name != NULL);
			break;
		default:
			assert(sgp->sg_name == NULL);
			break;
		}
#endif

		/*
		 * Add named segment descriptors to the AVL tree to
		 * provide O(logN) lookups.
		 */
		if (sgp->sg_name != NULL)
			avl_add(&ofl->ofl_segs_avl, sgp);
	}

	return (1);
}
