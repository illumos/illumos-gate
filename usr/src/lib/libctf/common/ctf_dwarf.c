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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2012 Jason King.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2018 Joyent, Inc.
 */

/*
 * CTF DWARF conversion theory.
 *
 * DWARF data contains a series of compilation units. Each compilation unit
 * generally refers to an object file or what once was, in the case of linked
 * binaries and shared objects. Each compilation unit has a series of what DWARF
 * calls a DIE (Debugging Information Entry). The set of entries that we care
 * about have type information stored in a series of attributes. Each DIE also
 * has a tag that identifies the kind of attributes that it has.
 *
 * A given DIE may itself have children. For example, a DIE that represents a
 * structure has children which represent members. Whenever we encounter a DIE
 * that has children or other values or types associated with it, we recursively
 * process those children first so that way we can then refer to the generated
 * CTF type id while processing its parent. This reduces the amount of unknowns
 * and fixups that we need. It also ensures that we don't accidentally add types
 * that an overzealous compiler might add to the DWARF data but aren't used by
 * anything in the system.
 *
 * Once we do a conversion, we store a mapping in an AVL tree that goes from the
 * DWARF's die offset, which is relative to the given compilation unit), to a
 * ctf_id_t.
 *
 * Unfortunately, some compilers actually will emit duplicate entries for a
 * given type that look similar, but aren't quite. To that end, we go through
 * and do a variant on a merge once we're done processing a single compilation
 * unit which deduplicates all of the types that are in the unit.
 *
 * Finally, if we encounter an object that has multiple compilation units, then
 * we'll convert all of the compilation units separately and then do a merge, so
 * that way we can result in one single ctf_file_t that represents everything
 * for the object.
 *
 * Conversion Steps
 * ----------------
 *
 * Because a given object we've been given to convert may have multiple
 * compilation units, we break the work into two halves. The first half
 * processes each compilation unit (potentially in parallel) and then the second
 * half optionally merges all of the dies in the first half. First, we'll cover
 * what's involved in converting a single ctf_die_t's dwarf to CTF. This covers
 * the work done in ctf_dwarf_convert_one().
 *
 * An individual ctf_die_t, which represents a compilation unit, is converted to
 * CTF in a series of multiple passes.
 *
 * Pass 1: During the first pass we walk all of the dies and if we find a
 * function, variable, struct, union, enum or typedef, we recursively transform
 * all of its types. We don't recurse or process everything, because we don't
 * want to add some of the types that compilers may add which are effectively
 * unused.
 *
 * During pass 1, if we encounter any structures or unions we mark them for
 * fixing up later. This is necessary because we may not be able to determine
 * the full size of a structure at the beginning of time. This will happen if
 * the DWARF attribute DW_AT_byte_size is not present for a member. Because of
 * this possibility we defer adding members to structures or even converting
 * them during pass 1 and save that for pass 2. Adding all of the base
 * structures without any of their members helps deal with any circular
 * dependencies that we might encounter.
 *
 * Pass 2: This pass is used to do the first half of fixing up structures and
 * unions. Rather than walk the entire type space again, we actually walk the
 * list of structures and unions that we marked for later fixing up. Here, we
 * iterate over every structure and add members to the underlying ctf_file_t,
 * but not to the structs themselves. One might wonder why we don't, and the
 * main reason is that libctf requires a ctf_update() be done before adding the
 * members to structures or unions.
 *
 * Pass 3: This pass is used to do the second half of fixing up structures and
 * unions. During this part we always go through and add members to structures
 * and unions that we added to the container in the previous pass. In addition,
 * we set the structure and union's actual size, which may have additional
 * padding added by the compiler, it isn't simply the last offset. DWARF always
 * guarantees an attribute exists for this. Importantly no ctf_id_t's change
 * during pass 2.
 *
 * Pass 4: The next phase is to add CTF entries for all of the symbols and
 * variables that are present in this die. During pass 1 we added entries to a
 * map for each variable and function. During this pass, we iterate over the
 * symbol table and when we encounter a symbol that we have in our lists of
 * translated information which matches, we then add it to the ctf_file_t.
 *
 * Pass 5: Here we go and look for any weak symbols and functions and see if
 * they match anything that we recognize. If so, then we add type information
 * for them at this point based on the matching type.
 *
 * Pass 6: This pass is actually a variant on a merge. The traditional merge
 * process expects there to be no duplicate types. As such, at the end of
 * conversion, we do a dedup on all of the types in the system. The
 * deduplication process is described in lib/libctf/common/ctf_merge.c.
 *
 * Once pass 6 is done, we've finished processing the individual compilation
 * unit.
 *
 * The following steps reflect the general process of doing a conversion.
 *
 * 1) Walk the dwarf section and determine the number of compilation units
 * 2) Create a ctf_die_t for each compilation unit
 * 3) Add all ctf_die_t's to a workq
 * 4) Have the workq process each die with ctf_dwarf_convert_one. This itself
 *    is comprised of several steps, which were already enumerated.
 * 5) If we have multiple dies, we do a ctf merge of all the dies. The mechanics
 *    of the merge are discussed in lib/libctf/common/ctf_merge.c.
 * 6) Free everything up and return a ctf_file_t to the user. If we only had a
 *    single compilation unit, then we give that to the user. Otherwise, we
 *    return the merged ctf_file_t.
 *
 * Threading
 * ---------
 *
 * The process has been designed to be amenable to threading. Each compilation
 * unit has its own type stream, therefore the logical place to divide and
 * conquer is at the compilation unit. Each ctf_die_t has been built to be able
 * to be processed independently of the others. It has its own libdwarf handle,
 * as a given libdwarf handle may only be used by a single thread at a time.
 * This allows the various ctf_die_t's to be processed in parallel by different
 * threads.
 *
 * All of the ctf_die_t's are loaded into a workq which allows for a number of
 * threads to be specified and used as a thread pool to process all of the
 * queued work. We set the number of threads to use in the workq equal to the
 * number of threads that the user has specified.
 *
 * After all of the compilation units have been drained, we use the same number
 * of threads when performing a merge of multiple compilation units, if they
 * exist.
 *
 * While all of these different parts do support and allow for multiple threads,
 * it's important that when only a single thread is specified, that it be the
 * calling thread. This allows the conversion routines to be used in a context
 * that doesn't allow additional threads, such as rtld.
 *
 * Common DWARF Mechanics and Notes
 * --------------------------------
 *
 * At this time, we really only support DWARFv2, though support for DWARFv4 is
 * mostly there. There is no intent to support DWARFv3.
 *
 * Generally types for something are stored in the DW_AT_type attribute. For
 * example, a function's return type will be stored in the local DW_AT_type
 * attribute while the arguments will be in child DIEs. There are also various
 * times when we don't have any DW_AT_type. In that case, the lack of a type
 * implies, at least for C, that it's C type is void. Because DWARF doesn't emit
 * one, we have a synthetic void type that we create and manipulate instead and
 * pass it off to consumers on an as-needed basis. If nothing has a void type,
 * it will not be emitted.
 *
 * Architecture Specific Parts
 * ---------------------------
 *
 * The CTF tooling encodes various information about the various architectures
 * in the system. Importantly, the tool assumes that every architecture has a
 * data model where long and pointer are the same size. This is currently the
 * case, as the two data models illumos supports are ILP32 and LP64.
 *
 * In addition, we encode the mapping of various floating point sizes to various
 * types for each architecture. If a new architecture is being added, it should
 * be added to the list. The general design of the ctf conversion tools is to be
 * architecture independent. eg. any of the tools here should be able to convert
 * any architecture's DWARF into ctf; however, this has not been rigorously
 * tested and more importantly, the ctf routines don't currently write out the
 * data in an endian-aware form, they only use that of the currently running
 * library.
 */

#include <libctf_impl.h>
#include <sys/avl.h>
#include <sys/debug.h>
#include <gelf.h>
#include <libdwarf.h>
#include <dwarf.h>
#include <libgen.h>
#include <workq.h>
#include <errno.h>

#define	DWARF_VERSION_TWO	2
#define	DWARF_VARARGS_NAME	"..."

/*
 * Dwarf may refer recursively to other types that we've already processed. To
 * see if we've already converted them, we look them up in an AVL tree that's
 * sorted by the DWARF id.
 */
typedef struct ctf_dwmap {
	avl_node_t	cdm_avl;
	Dwarf_Off	cdm_off;
	Dwarf_Die	cdm_die;
	ctf_id_t	cdm_id;
	boolean_t	cdm_fix;
} ctf_dwmap_t;

typedef struct ctf_dwvar {
	ctf_list_t	cdv_list;
	char		*cdv_name;
	ctf_id_t	cdv_type;
	boolean_t	cdv_global;
} ctf_dwvar_t;

typedef struct ctf_dwfunc {
	ctf_list_t	cdf_list;
	char		*cdf_name;
	ctf_funcinfo_t	cdf_fip;
	ctf_id_t	*cdf_argv;
	boolean_t	cdf_global;
} ctf_dwfunc_t;

typedef struct ctf_dwbitf {
	ctf_list_t	cdb_list;
	ctf_id_t	cdb_base;
	uint_t		cdb_nbits;
	ctf_id_t	cdb_id;
} ctf_dwbitf_t;

/*
 * The ctf_die_t represents a single top-level DWARF die unit. While generally,
 * the typical object file hs only a single die, if we're asked to convert
 * something that's been linked from multiple sources, multiple dies will exist.
 */
typedef struct ctf_die {
	Elf		*cd_elf;	/* shared libelf handle */
	char		*cd_name;	/* basename of the DIE */
	ctf_merge_t	*cd_cmh;	/* merge handle */
	ctf_list_t	cd_vars;	/* List of variables */
	ctf_list_t	cd_funcs;	/* List of functions */
	ctf_list_t	cd_bitfields;	/* Bit field members */
	Dwarf_Debug	cd_dwarf;	/* shared libdwarf handle */
	Dwarf_Die	cd_cu;		/* libdwarf compilation unit */
	Dwarf_Off	cd_cuoff;	/* cu's offset */
	Dwarf_Off	cd_maxoff;	/* maximum offset */
	ctf_file_t	*cd_ctfp;	/* output CTF file */
	avl_tree_t	cd_map;		/* map die offsets to CTF types */
	char		*cd_errbuf;	/* error message buffer */
	size_t		cd_errlen;	/* error message buffer length */
	size_t		cd_ptrsz;	/* object's pointer size */
	boolean_t	cd_bigend;	/* is it big endian */
	boolean_t	cd_doweaks;	/* should we convert weak symbols? */
	uint_t		cd_mach;	/* machine type */
	ctf_id_t	cd_voidtid;	/* void pointer */
	ctf_id_t	cd_longtid;	/* id for a 'long' */
} ctf_die_t;

static int ctf_dwarf_offset(ctf_die_t *, Dwarf_Die, Dwarf_Off *);
static int ctf_dwarf_convert_die(ctf_die_t *, Dwarf_Die);
static int ctf_dwarf_convert_type(ctf_die_t *, Dwarf_Die, ctf_id_t *, int);

static int ctf_dwarf_function_count(ctf_die_t *, Dwarf_Die, ctf_funcinfo_t *,
    boolean_t);
static int ctf_dwarf_convert_fargs(ctf_die_t *, Dwarf_Die, ctf_funcinfo_t *,
    ctf_id_t *);

typedef int (ctf_dwarf_symtab_f)(ctf_die_t *, const GElf_Sym *, ulong_t,
    const char *, const char *, void *);

/*
 * This is a generic way to set a CTF Conversion backend error depending on what
 * we were doing. Unless it was one of a specific set of errors that don't
 * indicate a programming / translation bug, eg. ENOMEM, then we transform it
 * into a CTF backend error and fill in the error buffer.
 */
static int
ctf_dwarf_error(ctf_die_t *cdp, ctf_file_t *cfp, int err, const char *fmt, ...)
{
	va_list ap;
	int ret;
	size_t off = 0;
	ssize_t rem = cdp->cd_errlen;
	if (cfp != NULL)
		err = ctf_errno(cfp);

	if (err == ENOMEM)
		return (err);

	ret = snprintf(cdp->cd_errbuf, rem, "die %s: ", cdp->cd_name);
	if (ret < 0)
		goto err;
	off += ret;
	rem = MAX(rem - ret, 0);

	va_start(ap, fmt);
	ret = vsnprintf(cdp->cd_errbuf + off, rem, fmt, ap);
	va_end(ap);
	if (ret < 0)
		goto err;

	off += ret;
	rem = MAX(rem - ret, 0);
	if (fmt[strlen(fmt) - 1] != '\n') {
		(void) snprintf(cdp->cd_errbuf + off, rem,
		    ": %s\n", ctf_errmsg(err));
	}
	va_end(ap);
	return (ECTF_CONVBKERR);

err:
	cdp->cd_errbuf[0] = '\0';
	return (ECTF_CONVBKERR);
}

/*
 * DWARF often ops to put no explicit type to describe a void type. eg. if we
 * have a reference type whose DW_AT_type member doesn't exist, then we should
 * instead assume it points to void. Because this isn't represented, we
 * instead cause it to come into existence.
 */
static ctf_id_t
ctf_dwarf_void(ctf_die_t *cdp)
{
	if (cdp->cd_voidtid == CTF_ERR) {
		ctf_encoding_t enc = { CTF_INT_SIGNED, 0, 0 };
		cdp->cd_voidtid = ctf_add_integer(cdp->cd_ctfp, CTF_ADD_ROOT,
		    "void", &enc);
		if (cdp->cd_voidtid == CTF_ERR) {
			(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
			    "failed to create void type: %s\n",
			    ctf_errmsg(ctf_errno(cdp->cd_ctfp)));
		}
	}

	return (cdp->cd_voidtid);
}

/*
 * There are many different forms that an array index may take. However, we just
 * always force it to be of a type long no matter what. Therefore we use this to
 * have a single instance of long across everything.
 */
static ctf_id_t
ctf_dwarf_long(ctf_die_t *cdp)
{
	if (cdp->cd_longtid == CTF_ERR) {
		ctf_encoding_t enc;

		enc.cte_format = CTF_INT_SIGNED;
		enc.cte_offset = 0;
		/* All illumos systems are LP */
		enc.cte_bits = cdp->cd_ptrsz * 8;
		cdp->cd_longtid = ctf_add_integer(cdp->cd_ctfp, CTF_ADD_NONROOT,
		    "long", &enc);
		if (cdp->cd_longtid == CTF_ERR) {
			(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
			    "failed to create long type: %s\n",
			    ctf_errmsg(ctf_errno(cdp->cd_ctfp)));
		}

	}

	return (cdp->cd_longtid);
}

static int
ctf_dwmap_comp(const void *a, const void *b)
{
	const ctf_dwmap_t *ca = a;
	const ctf_dwmap_t *cb = b;

	if (ca->cdm_off > cb->cdm_off)
		return (1);
	if (ca->cdm_off < cb->cdm_off)
		return (-1);
	return (0);
}

static int
ctf_dwmap_add(ctf_die_t *cdp, ctf_id_t id, Dwarf_Die die, boolean_t fix)
{
	int ret;
	avl_index_t index;
	ctf_dwmap_t *dwmap;
	Dwarf_Off off;

	VERIFY(id > 0 && id < CTF_MAX_TYPE);

	if ((ret = ctf_dwarf_offset(cdp, die, &off)) != 0)
		return (ret);

	if ((dwmap = ctf_alloc(sizeof (ctf_dwmap_t))) == NULL)
		return (ENOMEM);

	dwmap->cdm_die = die;
	dwmap->cdm_off = off;
	dwmap->cdm_id = id;
	dwmap->cdm_fix = fix;

	ctf_dprintf("dwmap: %p %x->%d\n", dwmap, (uint32_t)off, id);
	VERIFY(avl_find(&cdp->cd_map, dwmap, &index) == NULL);
	avl_insert(&cdp->cd_map, dwmap, index);
	return (0);
}

static int
ctf_dwarf_attribute(ctf_die_t *cdp, Dwarf_Die die, Dwarf_Half name,
    Dwarf_Attribute *attrp)
{
	int ret;
	Dwarf_Error derr;

	if ((ret = dwarf_attr(die, name, attrp, &derr)) == DW_DLV_OK)
		return (0);
	if (ret == DW_DLV_NO_ENTRY) {
		*attrp = NULL;
		return (ENOENT);
	}
	(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
	    "failed to get attribute for type: %s\n",
	    dwarf_errmsg(derr));
	return (ECTF_CONVBKERR);
}

static int
ctf_dwarf_ref(ctf_die_t *cdp, Dwarf_Die die, Dwarf_Half name, Dwarf_Off *refp)
{
	int ret;
	Dwarf_Attribute attr;
	Dwarf_Error derr;

	if ((ret = ctf_dwarf_attribute(cdp, die, name, &attr)) != 0)
		return (ret);

	if (dwarf_formref(attr, refp, &derr) == DW_DLV_OK) {
		dwarf_dealloc(cdp->cd_dwarf, attr, DW_DLA_ATTR);
		return (0);
	}

	(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
	    "failed to get unsigned attribute for type: %s\n",
	    dwarf_errmsg(derr));
	return (ECTF_CONVBKERR);
}

static int
ctf_dwarf_refdie(ctf_die_t *cdp, Dwarf_Die die, Dwarf_Half name,
    Dwarf_Die *diep)
{
	int ret;
	Dwarf_Off off;
	Dwarf_Error derr;

	if ((ret = ctf_dwarf_ref(cdp, die, name, &off)) != 0)
		return (ret);

	off += cdp->cd_cuoff;
	if ((ret = dwarf_offdie(cdp->cd_dwarf, off, diep, &derr)) !=
	    DW_DLV_OK) {
		(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
		    "failed to get die from offset %llu: %s\n",
		    off, dwarf_errmsg(derr));
		return (ECTF_CONVBKERR);
	}

	return (0);
}

static int
ctf_dwarf_signed(ctf_die_t *cdp, Dwarf_Die die, Dwarf_Half name,
    Dwarf_Signed *valp)
{
	int ret;
	Dwarf_Attribute attr;
	Dwarf_Error derr;

	if ((ret = ctf_dwarf_attribute(cdp, die, name, &attr)) != 0)
		return (ret);

	if (dwarf_formsdata(attr, valp, &derr) == DW_DLV_OK) {
		dwarf_dealloc(cdp->cd_dwarf, attr, DW_DLA_ATTR);
		return (0);
	}

	(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
	    "failed to get unsigned attribute for type: %s\n",
	    dwarf_errmsg(derr));
	return (ECTF_CONVBKERR);
}

static int
ctf_dwarf_unsigned(ctf_die_t *cdp, Dwarf_Die die, Dwarf_Half name,
    Dwarf_Unsigned *valp)
{
	int ret;
	Dwarf_Attribute attr;
	Dwarf_Error derr;

	if ((ret = ctf_dwarf_attribute(cdp, die, name, &attr)) != 0)
		return (ret);

	if (dwarf_formudata(attr, valp, &derr) == DW_DLV_OK) {
		dwarf_dealloc(cdp->cd_dwarf, attr, DW_DLA_ATTR);
		return (0);
	}

	(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
	    "failed to get unsigned attribute for type: %s\n",
	    dwarf_errmsg(derr));
	return (ECTF_CONVBKERR);
}

static int
ctf_dwarf_boolean(ctf_die_t *cdp, Dwarf_Die die, Dwarf_Half name,
    Dwarf_Bool *val)
{
	int ret;
	Dwarf_Attribute attr;
	Dwarf_Error derr;

	if ((ret = ctf_dwarf_attribute(cdp, die, name, &attr)) != 0)
		return (ret);

	if (dwarf_formflag(attr, val, &derr) == DW_DLV_OK) {
		dwarf_dealloc(cdp->cd_dwarf, attr, DW_DLA_ATTR);
		return (0);
	}

	(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
	    "failed to get boolean attribute for type: %s\n",
	    dwarf_errmsg(derr));

	return (ECTF_CONVBKERR);
}

static int
ctf_dwarf_string(ctf_die_t *cdp, Dwarf_Die die, Dwarf_Half name, char **strp)
{
	int ret;
	char *s;
	Dwarf_Attribute attr;
	Dwarf_Error derr;

	*strp = NULL;
	if ((ret = ctf_dwarf_attribute(cdp, die, name, &attr)) != 0)
		return (ret);

	if (dwarf_formstring(attr, &s, &derr) == DW_DLV_OK) {
		if ((*strp = ctf_strdup(s)) == NULL)
			ret = ENOMEM;
		else
			ret = 0;
		dwarf_dealloc(cdp->cd_dwarf, attr, DW_DLA_ATTR);
		return (ret);
	}

	(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
	    "failed to get string attribute for type: %s\n",
	    dwarf_errmsg(derr));
	return (ECTF_CONVBKERR);
}

static int
ctf_dwarf_member_location(ctf_die_t *cdp, Dwarf_Die die, Dwarf_Unsigned *valp)
{
	int ret;
	Dwarf_Error derr;
	Dwarf_Attribute attr;
	Dwarf_Locdesc *loc;
	Dwarf_Signed locnum;

	if ((ret = ctf_dwarf_attribute(cdp, die, DW_AT_data_member_location,
	    &attr)) != 0)
		return (ret);

	if (dwarf_loclist(attr, &loc, &locnum, &derr) != DW_DLV_OK) {
		(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
		    "failed to obtain location list for member offset: %s",
		    dwarf_errmsg(derr));
		dwarf_dealloc(cdp->cd_dwarf, attr, DW_DLA_ATTR);
		return (ECTF_CONVBKERR);
	}
	dwarf_dealloc(cdp->cd_dwarf, attr, DW_DLA_ATTR);

	if (locnum != 1 || loc->ld_s->lr_atom != DW_OP_plus_uconst) {
		(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
		    "failed to parse location structure for member");
		dwarf_dealloc(cdp->cd_dwarf, loc->ld_s, DW_DLA_LOC_BLOCK);
		dwarf_dealloc(cdp->cd_dwarf, loc, DW_DLA_LOCDESC);
		return (ECTF_CONVBKERR);
	}

	*valp = loc->ld_s->lr_number;

	dwarf_dealloc(cdp->cd_dwarf, loc->ld_s, DW_DLA_LOC_BLOCK);
	dwarf_dealloc(cdp->cd_dwarf, loc, DW_DLA_LOCDESC);
	return (0);
}


static int
ctf_dwarf_offset(ctf_die_t *cdp, Dwarf_Die die, Dwarf_Off *offsetp)
{
	Dwarf_Error derr;

	if (dwarf_dieoffset(die, offsetp, &derr) == DW_DLV_OK)
		return (0);

	(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
	    "failed to get die offset: %s\n",
	    dwarf_errmsg(derr));
	return (ECTF_CONVBKERR);
}

/* simpler variant for debugging output */
static Dwarf_Off
ctf_die_offset(Dwarf_Die die)
{
	Dwarf_Off off = -1;
	Dwarf_Error derr;

	(void) dwarf_dieoffset(die, &off, &derr);
	return (off);
}

static int
ctf_dwarf_tag(ctf_die_t *cdp, Dwarf_Die die, Dwarf_Half *tagp)
{
	Dwarf_Error derr;

	if (dwarf_tag(die, tagp, &derr) == DW_DLV_OK)
		return (0);

	(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
	    "failed to get tag type: %s\n",
	    dwarf_errmsg(derr));
	return (ECTF_CONVBKERR);
}

static int
ctf_dwarf_sib(ctf_die_t *cdp, Dwarf_Die base, Dwarf_Die *sibp)
{
	Dwarf_Error derr;
	int ret;

	*sibp = NULL;
	ret = dwarf_siblingof(cdp->cd_dwarf, base, sibp, &derr);
	if (ret == DW_DLV_OK || ret == DW_DLV_NO_ENTRY)
		return (0);

	(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
	    "failed to sibling from die: %s\n",
	    dwarf_errmsg(derr));
	return (ECTF_CONVBKERR);
}

static int
ctf_dwarf_child(ctf_die_t *cdp, Dwarf_Die base, Dwarf_Die *childp)
{
	Dwarf_Error derr;
	int ret;

	*childp = NULL;
	ret = dwarf_child(base, childp, &derr);
	if (ret == DW_DLV_OK || ret == DW_DLV_NO_ENTRY)
		return (0);

	(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
	    "failed to child from die: %s\n",
	    dwarf_errmsg(derr));
	return (ECTF_CONVBKERR);
}

/*
 * Compilers disagree on what to do to determine if something has global
 * visiblity. Traditionally gcc has used DW_AT_external to indicate this while
 * Studio has used DW_AT_visibility. We check DW_AT_visibility first and then
 * fall back to DW_AT_external. Lack of DW_AT_external implies that it is not.
 */
static int
ctf_dwarf_isglobal(ctf_die_t *cdp, Dwarf_Die die, boolean_t *igp)
{
	int ret;
	Dwarf_Signed vis;
	Dwarf_Bool ext;

	if ((ret = ctf_dwarf_signed(cdp, die, DW_AT_visibility, &vis)) == 0) {
		*igp = vis == DW_VIS_exported;
		return (0);
	} else if (ret != ENOENT) {
		return (ret);
	}

	if ((ret = ctf_dwarf_boolean(cdp, die, DW_AT_external, &ext)) != 0) {
		if (ret == ENOENT) {
			*igp = B_FALSE;
			return (0);
		}
		return (ret);
	}
	*igp = ext != 0 ? B_TRUE : B_FALSE;
	return (0);
}

static int
ctf_dwarf_die_elfenc(Elf *elf, ctf_die_t *cdp, char *errbuf, size_t errlen)
{
	GElf_Ehdr ehdr;

	if (gelf_getehdr(elf, &ehdr) == NULL) {
		(void) snprintf(errbuf, errlen,
		    "failed to get ELF header: %s\n",
		    elf_errmsg(elf_errno()));
		return (ECTF_CONVBKERR);
	}

	cdp->cd_mach = ehdr.e_machine;

	if (ehdr.e_ident[EI_CLASS] == ELFCLASS32) {
		cdp->cd_ptrsz = 4;
		VERIFY(ctf_setmodel(cdp->cd_ctfp, CTF_MODEL_ILP32) == 0);
	} else if (ehdr.e_ident[EI_CLASS] == ELFCLASS64) {
		cdp->cd_ptrsz = 8;
		VERIFY(ctf_setmodel(cdp->cd_ctfp, CTF_MODEL_LP64) == 0);
	} else {
		(void) snprintf(errbuf, errlen,
		    "unknown ELF class %d", ehdr.e_ident[EI_CLASS]);
		return (ECTF_CONVBKERR);
	}

	if (ehdr.e_ident[EI_DATA] == ELFDATA2LSB) {
		cdp->cd_bigend = B_FALSE;
	} else if (ehdr.e_ident[EI_DATA] == ELFDATA2MSB) {
		cdp->cd_bigend = B_TRUE;
	} else {
		(void) snprintf(errbuf, errlen,
		    "unknown ELF data encoding: %d", ehdr.e_ident[EI_DATA]);
		return (ECTF_CONVBKERR);
	}

	return (0);
}

typedef struct ctf_dwarf_fpent {
	size_t	cdfe_size;
	uint_t	cdfe_enc[3];
} ctf_dwarf_fpent_t;

typedef struct ctf_dwarf_fpmap {
	uint_t			cdf_mach;
	ctf_dwarf_fpent_t	cdf_ents[4];
} ctf_dwarf_fpmap_t;

static const ctf_dwarf_fpmap_t ctf_dwarf_fpmaps[] = {
	{ EM_SPARC, {
		{ 4, { CTF_FP_SINGLE, CTF_FP_CPLX, CTF_FP_IMAGRY } },
		{ 8, { CTF_FP_DOUBLE, CTF_FP_DCPLX, CTF_FP_DIMAGRY } },
		{ 16, { CTF_FP_LDOUBLE, CTF_FP_LDCPLX, CTF_FP_LDIMAGRY } },
		{ 0, { 0 } }
	} },
	{ EM_SPARC32PLUS, {
		{ 4, { CTF_FP_SINGLE, CTF_FP_CPLX, CTF_FP_IMAGRY } },
		{ 8, { CTF_FP_DOUBLE, CTF_FP_DCPLX, CTF_FP_DIMAGRY } },
		{ 16, { CTF_FP_LDOUBLE, CTF_FP_LDCPLX, CTF_FP_LDIMAGRY } },
		{ 0, { 0 } }
	} },
	{ EM_SPARCV9, {
		{ 4, { CTF_FP_SINGLE, CTF_FP_CPLX, CTF_FP_IMAGRY } },
		{ 8, { CTF_FP_DOUBLE, CTF_FP_DCPLX, CTF_FP_DIMAGRY } },
		{ 16, { CTF_FP_LDOUBLE, CTF_FP_LDCPLX, CTF_FP_LDIMAGRY } },
		{ 0, { 0 } }
	} },
	{ EM_386, {
		{ 4, { CTF_FP_SINGLE, CTF_FP_CPLX, CTF_FP_IMAGRY } },
		{ 8, { CTF_FP_DOUBLE, CTF_FP_DCPLX, CTF_FP_DIMAGRY } },
		{ 12, { CTF_FP_LDOUBLE, CTF_FP_LDCPLX, CTF_FP_LDIMAGRY } },
		{ 0, { 0 } }
	} },
	{ EM_X86_64, {
		{ 4, { CTF_FP_SINGLE, CTF_FP_CPLX, CTF_FP_IMAGRY } },
		{ 8, { CTF_FP_DOUBLE, CTF_FP_DCPLX, CTF_FP_DIMAGRY } },
		{ 16, { CTF_FP_LDOUBLE, CTF_FP_LDCPLX, CTF_FP_LDIMAGRY } },
		{ 0, { 0 } }
	} },
	{ EM_NONE }
};

static int
ctf_dwarf_float_base(ctf_die_t *cdp, Dwarf_Signed type, ctf_encoding_t *enc)
{
	const ctf_dwarf_fpmap_t *map = &ctf_dwarf_fpmaps[0];
	const ctf_dwarf_fpent_t *ent;
	uint_t col = 0, mult = 1;

	for (map = &ctf_dwarf_fpmaps[0]; map->cdf_mach != EM_NONE; map++) {
		if (map->cdf_mach == cdp->cd_mach)
			break;
	}

	if (map->cdf_mach == EM_NONE) {
		(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
		    "Unsupported machine type: %d\n", cdp->cd_mach);
		return (ENOTSUP);
	}

	if (type == DW_ATE_complex_float) {
		mult = 2;
		col = 1;
	} else if (type == DW_ATE_imaginary_float ||
	    type == DW_ATE_SUN_imaginary_float) {
		col = 2;
	}

	ent = &map->cdf_ents[0];
	for (ent = &map->cdf_ents[0]; ent->cdfe_size != 0; ent++) {
		if (ent->cdfe_size * mult * 8 == enc->cte_bits) {
			enc->cte_format = ent->cdfe_enc[col];
			return (0);
		}
	}

	(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
	    "failed to find valid fp mapping for encoding %d, size %d bits\n",
	    type, enc->cte_bits);
	return (EINVAL);
}

static int
ctf_dwarf_dwarf_base(ctf_die_t *cdp, Dwarf_Die die, int *kindp,
    ctf_encoding_t *enc)
{
	int ret;
	Dwarf_Signed type;

	if ((ret = ctf_dwarf_signed(cdp, die, DW_AT_encoding, &type)) != 0)
		return (ret);

	switch (type) {
	case DW_ATE_unsigned:
	case DW_ATE_address:
		*kindp = CTF_K_INTEGER;
		enc->cte_format = 0;
		break;
	case DW_ATE_unsigned_char:
		*kindp = CTF_K_INTEGER;
		enc->cte_format = CTF_INT_CHAR;
		break;
	case DW_ATE_signed:
		*kindp = CTF_K_INTEGER;
		enc->cte_format = CTF_INT_SIGNED;
		break;
	case DW_ATE_signed_char:
		*kindp = CTF_K_INTEGER;
		enc->cte_format = CTF_INT_SIGNED | CTF_INT_CHAR;
		break;
	case DW_ATE_boolean:
		*kindp = CTF_K_INTEGER;
		enc->cte_format = CTF_INT_SIGNED | CTF_INT_BOOL;
		break;
	case DW_ATE_float:
	case DW_ATE_complex_float:
	case DW_ATE_imaginary_float:
	case DW_ATE_SUN_imaginary_float:
	case DW_ATE_SUN_interval_float:
		*kindp = CTF_K_FLOAT;
		if ((ret = ctf_dwarf_float_base(cdp, type, enc)) != 0)
			return (ret);
		break;
	default:
		(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
		    "encountered unkown DWARF encoding: %d", type);
		return (ECTF_CONVBKERR);
	}

	return (0);
}

/*
 * Different compilers (at least GCC and Studio) use different names for types.
 * This parses the types and attempts to unify them. If this fails, we just fall
 * back to using the DWARF itself.
 */
static int
ctf_dwarf_parse_base(const char *name, int *kindp, ctf_encoding_t *enc,
    char **newnamep)
{
	char buf[256];
	char *base, *c;
	int nlong = 0, nshort = 0, nchar = 0, nint = 0;
	int sign = 1;

	if (strlen(name) + 1 > sizeof (buf))
		return (EINVAL);

	(void) strlcpy(buf, name, sizeof (buf));
	for (c = strtok(buf, " "); c != NULL; c = strtok(NULL, " ")) {
		if (strcmp(c, "signed") == 0) {
			sign = 1;
		} else if (strcmp(c, "unsigned") == 0) {
			sign = 0;
		} else if (strcmp(c, "long") == 0) {
			nlong++;
		} else if (strcmp(c, "char") == 0) {
			nchar++;
		} else if (strcmp(c, "short") == 0) {
			nshort++;
		} else if (strcmp(c, "int") == 0) {
			nint++;
		} else {
			/*
			 * If we don't recognize any of the tokens, we'll tell
			 * the caller to fall back to the dwarf-provided
			 * encoding information.
			 */
			return (EINVAL);
		}
	}

	if (nchar > 1 || nshort > 1 || nint > 1 || nlong > 2)
		return (EINVAL);

	if (nchar > 0) {
		if (nlong > 0 || nshort > 0 || nint > 0)
			return (EINVAL);
		base = "char";
	} else if (nshort > 0) {
		if (nlong > 0)
			return (EINVAL);
		base = "short";
	} else if (nlong > 0) {
		base = "long";
	} else {
		base = "int";
	}

	if (nchar > 0)
		enc->cte_format = CTF_INT_CHAR;
	else
		enc->cte_format = 0;

	if (sign > 0)
		enc->cte_format |= CTF_INT_SIGNED;

	(void) snprintf(buf, sizeof (buf), "%s%s%s",
	    (sign ? "" : "unsigned "),
	    (nlong > 1 ? "long " : ""),
	    base);

	*newnamep = ctf_strdup(buf);
	if (*newnamep == NULL)
		return (ENOMEM);
	*kindp = CTF_K_INTEGER;
	return (0);
}

static int
ctf_dwarf_create_base(ctf_die_t *cdp, Dwarf_Die die, ctf_id_t *idp, int isroot,
    Dwarf_Off off)
{
	int ret;
	char *name, *nname;
	Dwarf_Unsigned sz;
	int kind;
	ctf_encoding_t enc;
	ctf_id_t id;

	if ((ret = ctf_dwarf_string(cdp, die, DW_AT_name, &name)) != 0)
		return (ret);
	if ((ret = ctf_dwarf_unsigned(cdp, die, DW_AT_byte_size, &sz)) != 0) {
		goto out;
	}
	ctf_dprintf("Creating base type %s from off %llu, size: %d\n", name,
	    off, sz);

	bzero(&enc, sizeof (ctf_encoding_t));
	enc.cte_bits = sz * 8;
	if ((ret = ctf_dwarf_parse_base(name, &kind, &enc, &nname)) == 0) {
		ctf_free(name, strlen(name) + 1);
		name = nname;
	} else {
		if (ret != EINVAL)
			return (ret);
		ctf_dprintf("falling back to dwarf for base type %s\n", name);
		if ((ret = ctf_dwarf_dwarf_base(cdp, die, &kind, &enc)) != 0)
			return (ret);
	}

	id = ctf_add_encoded(cdp->cd_ctfp, isroot, name, &enc, kind);
	if (id == CTF_ERR) {
		ret = ctf_errno(cdp->cd_ctfp);
	} else {
		*idp = id;
		ret = ctf_dwmap_add(cdp, id, die, B_FALSE);
	}
out:
	ctf_free(name, strlen(name) + 1);
	return (ret);
}

/*
 * Getting a member's offset is a surprisingly intricate dance. It works as
 * follows:
 *
 * 1) If we're in DWARFv4, then we either have a DW_AT_data_bit_offset or we
 * have a DW_AT_data_member_location. We won't have both. Thus we check first
 * for DW_AT_data_bit_offset, and if it exists, we're set.
 *
 * Next, if we have a bitfield and we don't ahve a DW_AT_data_bit_offset, then
 * we have to grab the data location and use the following dance:
 *
 * 2) Gather the set of DW_AT_byte_size, DW_AT_bit_offset, and DW_AT_bit_size.
 * Of course, the DW_AT_byte_size may be omitted, even though it isn't always.
 * When it's been omitted, we then have to say that the size is that of the
 * underlying type, which forces that to be after a ctf_update(). Here, we have
 * to do different things based on whether or not we're using big endian or
 * little endian to obtain the proper offset.
 */
static int
ctf_dwarf_member_offset(ctf_die_t *cdp, Dwarf_Die die, ctf_id_t mid,
    ulong_t *offp)
{
	int ret;
	Dwarf_Unsigned loc, bitsz, bytesz;
	Dwarf_Signed bitoff;
	size_t off, tsz;

	if ((ret = ctf_dwarf_unsigned(cdp, die, DW_AT_data_bit_offset,
	    &loc)) == 0) {
		*offp = loc;
		return (0);
	} else if (ret != ENOENT) {
		return (ret);
	}

	if ((ret = ctf_dwarf_member_location(cdp, die, &loc)) != 0)
		return (ret);
	off = loc * 8;

	if ((ret = ctf_dwarf_signed(cdp, die, DW_AT_bit_offset,
	    &bitoff)) != 0) {
		if (ret != ENOENT)
			return (ret);
		*offp = off;
		return (0);
	}

	/* At this point we have to have DW_AT_bit_size */
	if ((ret = ctf_dwarf_unsigned(cdp, die, DW_AT_bit_size, &bitsz)) != 0)
		return (ret);

	if ((ret = ctf_dwarf_unsigned(cdp, die, DW_AT_byte_size,
	    &bytesz)) != 0) {
		if (ret != ENOENT)
			return (ret);
		if ((tsz = ctf_type_size(cdp->cd_ctfp, mid)) == CTF_ERR) {
			int e = ctf_errno(cdp->cd_ctfp);
			(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
			    "failed to get type size: %s", ctf_errmsg(e));
			return (ECTF_CONVBKERR);
		}
	} else {
		tsz = bytesz;
	}
	tsz *= 8;
	if (cdp->cd_bigend == B_TRUE) {
		*offp = off + bitoff;
	} else {
		*offp = off + tsz - bitoff - bitsz;
	}

	return (0);
}

/*
 * We need to determine if the member in question is a bitfield. If it is, then
 * we need to go through and create a new type that's based on the actual base
 * type, but has a different size. We also rename the type as a result to help
 * deal with future collisions.
 *
 * Here we need to look and see if we have a DW_AT_bit_size value. If we have a
 * bit size member and it does not equal the byte size member, then we need to
 * create a bitfield type based on this.
 *
 * Note: When we support DWARFv4, there may be a chance that we ned to also
 * search for the DW_AT_byte_size if we don't have a DW_AT_bit_size member.
 */
static int
ctf_dwarf_member_bitfield(ctf_die_t *cdp, Dwarf_Die die, ctf_id_t *idp)
{
	int ret;
	Dwarf_Unsigned bitsz;
	ctf_encoding_t e;
	ctf_dwbitf_t *cdb;
	ctf_dtdef_t *dtd;
	ctf_id_t base = *idp;
	int kind;

	if ((ret = ctf_dwarf_unsigned(cdp, die, DW_AT_bit_size, &bitsz)) != 0) {
		if (ret == ENOENT)
			return (0);
		return (ret);
	}

	ctf_dprintf("Trying to deal with bitfields on %d:%d\n", base, bitsz);
	/*
	 * Given that we now have a bitsize, time to go do something about it.
	 * We're going to create a new type based on the current one, but first
	 * we need to find the base type. This means we need to traverse any
	 * typedef's, consts, and volatiles until we get to what should be
	 * something of type integer or enumeration.
	 */
	VERIFY(bitsz < UINT32_MAX);
	dtd = ctf_dtd_lookup(cdp->cd_ctfp, base);
	VERIFY(dtd != NULL);
	kind = CTF_INFO_KIND(dtd->dtd_data.ctt_info);
	while (kind == CTF_K_TYPEDEF || kind == CTF_K_CONST ||
	    kind == CTF_K_VOLATILE) {
		dtd = ctf_dtd_lookup(cdp->cd_ctfp, dtd->dtd_data.ctt_type);
		VERIFY(dtd != NULL);
		kind = CTF_INFO_KIND(dtd->dtd_data.ctt_info);
	}
	ctf_dprintf("got kind %d\n", kind);
	VERIFY(kind == CTF_K_INTEGER || kind == CTF_K_ENUM);

	/*
	 * As surprising as it may be, it is strictly possible to create a
	 * bitfield that is based on an enum. Of course, the C standard leaves
	 * enums sizing as an ABI concern more or less. To that effect, today on
	 * all illumos platforms the size of an enum is generally that of an
	 * int as our supported data models and ABIs all agree on that. So what
	 * we'll do is fake up a CTF enconding here to use. In this case, we'll
	 * treat it as an unsigned value of whatever size the underlying enum
	 * currently has (which is in the ctt_size member of its dynamic type
	 * data).
	 */
	if (kind == CTF_K_INTEGER) {
		e = dtd->dtd_u.dtu_enc;
	} else {
		bzero(&e, sizeof (ctf_encoding_t));
		e.cte_bits = dtd->dtd_data.ctt_size * NBBY;
	}

	for (cdb = ctf_list_next(&cdp->cd_bitfields); cdb != NULL;
	    cdb = ctf_list_next(cdb)) {
		if (cdb->cdb_base == base && cdb->cdb_nbits == bitsz)
			break;
	}

	/*
	 * Create a new type if none exists. We name all types in a way that is
	 * guaranteed not to conflict with the corresponding C type. We do this
	 * by using the ':' operator.
	 */
	if (cdb == NULL) {
		size_t namesz;
		char *name;

		e.cte_bits = bitsz;
		namesz = snprintf(NULL, 0, "%s:%d", dtd->dtd_name,
		    (uint32_t)bitsz);
		name = ctf_alloc(namesz + 1);
		if (name == NULL)
			return (ENOMEM);
		cdb = ctf_alloc(sizeof (ctf_dwbitf_t));
		if (cdb == NULL) {
			ctf_free(name, namesz + 1);
			return (ENOMEM);
		}
		(void) snprintf(name, namesz + 1, "%s:%d", dtd->dtd_name,
		    (uint32_t)bitsz);

		cdb->cdb_base = base;
		cdb->cdb_nbits = bitsz;
		cdb->cdb_id = ctf_add_integer(cdp->cd_ctfp, CTF_ADD_NONROOT,
		    name, &e);
		if (cdb->cdb_id == CTF_ERR) {
			(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
			    "failed to get add bitfield type %s: %s", name,
			    ctf_errmsg(ctf_errno(cdp->cd_ctfp)));
			ctf_free(name, namesz + 1);
			ctf_free(cdb, sizeof (ctf_dwbitf_t));
			return (ECTF_CONVBKERR);
		}
		ctf_free(name, namesz + 1);
		ctf_list_append(&cdp->cd_bitfields, cdb);
	}

	*idp = cdb->cdb_id;

	return (0);
}

static int
ctf_dwarf_fixup_sou(ctf_die_t *cdp, Dwarf_Die die, ctf_id_t base, boolean_t add)
{
	int ret, kind;
	Dwarf_Die child, memb;
	Dwarf_Unsigned size;
	ulong_t nsz;

	kind = ctf_type_kind(cdp->cd_ctfp, base);
	VERIFY(kind != CTF_ERR);
	VERIFY(kind == CTF_K_STRUCT || kind == CTF_K_UNION);

	/*
	 * Members are in children. However, gcc also allows empty ones.
	 */
	if ((ret = ctf_dwarf_child(cdp, die, &child)) != 0)
		return (ret);
	if (child == NULL)
		return (0);

	memb = child;
	while (memb != NULL) {
		Dwarf_Die sib, tdie;
		Dwarf_Half tag;
		ctf_id_t mid;
		char *mname;
		ulong_t memboff = 0;

		if ((ret = ctf_dwarf_tag(cdp, memb, &tag)) != 0)
			return (ret);

		if (tag != DW_TAG_member)
			continue;

		if ((ret = ctf_dwarf_refdie(cdp, memb, DW_AT_type, &tdie)) != 0)
			return (ret);

		if ((ret = ctf_dwarf_convert_type(cdp, tdie, &mid,
		    CTF_ADD_NONROOT)) != 0)
			return (ret);
		ctf_dprintf("Got back type id: %d\n", mid);

		/*
		 * If we're not adding a member, just go ahead and return.
		 */
		if (add == B_FALSE) {
			if ((ret = ctf_dwarf_member_bitfield(cdp, memb,
			    &mid)) != 0)
				return (ret);
			goto next;
		}

		if ((ret = ctf_dwarf_string(cdp, memb, DW_AT_name,
		    &mname)) != 0 && ret != ENOENT)
			return (ret);
		if (ret == ENOENT)
			mname = NULL;

		if (kind == CTF_K_UNION) {
			memboff = 0;
		} else if ((ret = ctf_dwarf_member_offset(cdp, memb, mid,
		    &memboff)) != 0) {
			if (mname != NULL)
				ctf_free(mname, strlen(mname) + 1);
			return (ret);
		}

		if ((ret = ctf_dwarf_member_bitfield(cdp, memb, &mid)) != 0)
			return (ret);

		ret = ctf_add_member(cdp->cd_ctfp, base, mname, mid, memboff);
		if (ret == CTF_ERR) {
			(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
			    "failed to add member %s: %s",
			    mname, ctf_errmsg(ctf_errno(cdp->cd_ctfp)));
			if (mname != NULL)
				ctf_free(mname, strlen(mname) + 1);
			return (ECTF_CONVBKERR);
		}

		if (mname != NULL)
			ctf_free(mname, strlen(mname) + 1);

next:
		if ((ret = ctf_dwarf_sib(cdp, memb, &sib)) != 0)
			return (ret);
		memb = sib;
	}

	/*
	 * If we're not adding members, then we don't know the final size of the
	 * structure, so end here.
	 */
	if (add == B_FALSE)
		return (0);

	/* Finally set the size of the structure to the actual byte size */
	if ((ret = ctf_dwarf_unsigned(cdp, die, DW_AT_byte_size, &size)) != 0)
		return (ret);
	nsz = size;
	if ((ctf_set_size(cdp->cd_ctfp, base, nsz)) == CTF_ERR) {
		int e = ctf_errno(cdp->cd_ctfp);
		(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
		    "failed to set type size for %d to 0x%x: %s", base,
		    (uint32_t)size, ctf_errmsg(e));
		return (ECTF_CONVBKERR);
	}

	return (0);
}

static int
ctf_dwarf_create_sou(ctf_die_t *cdp, Dwarf_Die die, ctf_id_t *idp,
    int kind, int isroot)
{
	int ret;
	char *name;
	ctf_id_t base;
	Dwarf_Die child;
	Dwarf_Bool decl;

	/*
	 * Deal with the terribly annoying case of anonymous structs and unions.
	 * If they don't have a name, set the name to the empty string.
	 */
	if ((ret = ctf_dwarf_string(cdp, die, DW_AT_name, &name)) != 0 &&
	    ret != ENOENT)
		return (ret);
	if (ret == ENOENT)
		name = NULL;

	/*
	 * We need to check if we just have a declaration here. If we do, then
	 * instead of creating an actual structure or union, we're just going to
	 * go ahead and create a forward. During a dedup or merge, the forward
	 * will be replaced with the real thing.
	 */
	if ((ret = ctf_dwarf_boolean(cdp, die, DW_AT_declaration,
	    &decl)) != 0) {
		if (ret != ENOENT)
			return (ret);
		decl = 0;
	}

	if (decl != 0) {
		base = ctf_add_forward(cdp->cd_ctfp, isroot, name, kind);
	} else if (kind == CTF_K_STRUCT) {
		base = ctf_add_struct(cdp->cd_ctfp, isroot, name);
	} else {
		base = ctf_add_union(cdp->cd_ctfp, isroot, name);
	}
	ctf_dprintf("added sou %s (%d) (%d)\n", name, kind, base);
	if (name != NULL)
		ctf_free(name, strlen(name) + 1);
	if (base == CTF_ERR)
		return (ctf_errno(cdp->cd_ctfp));
	*idp = base;

	/*
	 * If it's just a declaration, we're not going to mark it for fix up or
	 * do anything else.
	 */
	if (decl == B_TRUE)
		return (ctf_dwmap_add(cdp, base, die, B_FALSE));
	if ((ret = ctf_dwmap_add(cdp, base, die, B_TRUE)) != 0)
		return (ret);

	/*
	 * Members are in children. However, gcc also allows empty ones.
	 */
	if ((ret = ctf_dwarf_child(cdp, die, &child)) != 0)
		return (ret);
	if (child == NULL)
		return (0);

	return (0);
}

static int
ctf_dwarf_create_array_range(ctf_die_t *cdp, Dwarf_Die range, ctf_id_t *idp,
    ctf_id_t base, int isroot)
{
	int ret;
	Dwarf_Die sib;
	Dwarf_Unsigned val;
	Dwarf_Signed sval;
	ctf_arinfo_t ar;

	ctf_dprintf("creating array range\n");

	if ((ret = ctf_dwarf_sib(cdp, range, &sib)) != 0)
		return (ret);
	if (sib != NULL) {
		ctf_id_t id;
		if ((ret = ctf_dwarf_create_array_range(cdp, sib, &id,
		    base, CTF_ADD_NONROOT)) != 0)
			return (ret);
		ar.ctr_contents = id;
	} else {
		ar.ctr_contents = base;
	}

	if ((ar.ctr_index = ctf_dwarf_long(cdp)) == CTF_ERR)
		return (ctf_errno(cdp->cd_ctfp));

	/*
	 * Array bounds can be signed or unsigned, but there are several kinds
	 * of signless forms (data1, data2, etc) that take their sign from the
	 * routine that is trying to interpret them.  That is, data1 can be
	 * either signed or unsigned, depending on whether you use the signed or
	 * unsigned accessor function.  GCC will use the signless forms to store
	 * unsigned values which have their high bit set, so we need to try to
	 * read them first as unsigned to get positive values.  We could also
	 * try signed first, falling back to unsigned if we got a negative
	 * value.
	 */
	if ((ret = ctf_dwarf_unsigned(cdp, range, DW_AT_upper_bound,
	    &val)) == 0) {
		ar.ctr_nelems = val + 1;
	} else if (ret != ENOENT) {
		return (ret);
	} else if ((ret = ctf_dwarf_signed(cdp, range, DW_AT_upper_bound,
	    &sval)) == 0) {
		ar.ctr_nelems = sval + 1;
	} else if (ret != ENOENT) {
		return (ret);
	} else {
		ar.ctr_nelems = 0;
	}

	if ((*idp = ctf_add_array(cdp->cd_ctfp, isroot, &ar)) == CTF_ERR)
		return (ctf_errno(cdp->cd_ctfp));

	return (0);
}

/*
 * Try and create an array type. First, the kind of the array is specified in
 * the DW_AT_type entry. Next, the number of entries is stored in a more
 * complicated form, we should have a child that has the DW_TAG_subrange type.
 */
static int
ctf_dwarf_create_array(ctf_die_t *cdp, Dwarf_Die die, ctf_id_t *idp, int isroot)
{
	int ret;
	Dwarf_Die tdie, rdie;
	ctf_id_t tid;
	Dwarf_Half rtag;

	if ((ret = ctf_dwarf_refdie(cdp, die, DW_AT_type, &tdie)) != 0)
		return (ret);
	if ((ret = ctf_dwarf_convert_type(cdp, tdie, &tid,
	    CTF_ADD_NONROOT)) != 0)
		return (ret);

	if ((ret = ctf_dwarf_child(cdp, die, &rdie)) != 0)
		return (ret);
	if ((ret = ctf_dwarf_tag(cdp, rdie, &rtag)) != 0)
		return (ret);
	if (rtag != DW_TAG_subrange_type) {
		(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
		    "encountered array without DW_TAG_subrange_type child\n");
		return (ECTF_CONVBKERR);
	}

	/*
	 * The compiler may opt to describe a multi-dimensional array as one
	 * giant array or it may opt to instead encode it as a series of
	 * subranges. If it's the latter, then for each subrange we introduce a
	 * type. We can always use the base type.
	 */
	if ((ret = ctf_dwarf_create_array_range(cdp, rdie, idp, tid,
	    isroot)) != 0)
		return (ret);
	ctf_dprintf("Got back id %d\n", *idp);
	return (ctf_dwmap_add(cdp, *idp, die, B_FALSE));
}

static int
ctf_dwarf_create_reference(ctf_die_t *cdp, Dwarf_Die die, ctf_id_t *idp,
    int kind, int isroot)
{
	int ret;
	ctf_id_t id;
	Dwarf_Die tdie;
	char *name;
	size_t namelen;

	if ((ret = ctf_dwarf_string(cdp, die, DW_AT_name, &name)) != 0 &&
	    ret != ENOENT)
		return (ret);
	if (ret == ENOENT) {
		name = NULL;
		namelen = 0;
	} else {
		namelen = strlen(name);
	}

	ctf_dprintf("reference kind %d %s\n", kind, name != NULL ? name : "<>");

	if ((ret = ctf_dwarf_refdie(cdp, die, DW_AT_type, &tdie)) != 0) {
		if (ret != ENOENT) {
			ctf_free(name, namelen);
			return (ret);
		}
		if ((id = ctf_dwarf_void(cdp)) == CTF_ERR) {
			ctf_free(name, namelen);
			return (ctf_errno(cdp->cd_ctfp));
		}
	} else {
		if ((ret = ctf_dwarf_convert_type(cdp, tdie, &id,
		    CTF_ADD_NONROOT)) != 0) {
			ctf_free(name, namelen);
			return (ret);
		}
	}

	if ((*idp = ctf_add_reftype(cdp->cd_ctfp, isroot, name, id, kind)) ==
	    CTF_ERR) {
		ctf_free(name, namelen);
		return (ctf_errno(cdp->cd_ctfp));
	}

	ctf_free(name, namelen);
	return (ctf_dwmap_add(cdp, *idp, die, B_FALSE));
}

static int
ctf_dwarf_create_enum(ctf_die_t *cdp, Dwarf_Die die, ctf_id_t *idp, int isroot)
{
	int ret;
	ctf_id_t id;
	Dwarf_Die child;
	char *name;

	if ((ret = ctf_dwarf_string(cdp, die, DW_AT_name, &name)) != 0 &&
	    ret != ENOENT)
		return (ret);
	if (ret == ENOENT)
		name = NULL;
	id = ctf_add_enum(cdp->cd_ctfp, isroot, name);
	ctf_dprintf("added enum %s (%d)\n", name, id);
	if (name != NULL)
		ctf_free(name, strlen(name) + 1);
	if (id == CTF_ERR)
		return (ctf_errno(cdp->cd_ctfp));
	*idp = id;
	if ((ret = ctf_dwmap_add(cdp, id, die, B_FALSE)) != 0)
		return (ret);

	if ((ret = ctf_dwarf_child(cdp, die, &child)) != 0) {
		if (ret == ENOENT)
			ret = 0;
		return (ret);
	}

	while (child != NULL) {
		Dwarf_Half tag;
		Dwarf_Signed sval;
		Dwarf_Unsigned uval;
		Dwarf_Die arg = child;
		int eval;

		if ((ret = ctf_dwarf_sib(cdp, arg, &child)) != 0)
			return (ret);

		if ((ret = ctf_dwarf_tag(cdp, arg, &tag)) != 0)
			return (ret);

		if (tag != DW_TAG_enumerator) {
			if ((ret = ctf_dwarf_convert_type(cdp, arg, NULL,
			    CTF_ADD_NONROOT)) != 0)
				return (ret);
			continue;
		}

		/*
		 * DWARF v4 section 5.7 tells us we'll always have names.
		 */
		if ((ret = ctf_dwarf_string(cdp, arg, DW_AT_name, &name)) != 0)
			return (ret);

		/*
		 * We have to be careful here: newer GCCs generate DWARF where
		 * an unsigned value will happily pass ctf_dwarf_signed().
		 * Since negative values will fail ctf_dwarf_unsigned(), we try
		 * that first to make sure we get the right value.
		 */
		if ((ret = ctf_dwarf_unsigned(cdp, arg, DW_AT_const_value,
		    &uval)) == 0) {
			eval = (int)uval;
		} else if ((ret = ctf_dwarf_signed(cdp, arg, DW_AT_const_value,
		    &sval)) == 0) {
			eval = sval;
		}

		if (ret != 0) {
			if (ret != ENOENT)
				return (ret);

			(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
			    "encountered enumeration without constant value\n");
			return (ECTF_CONVBKERR);
		}

		ret = ctf_add_enumerator(cdp->cd_ctfp, id, name, eval);
		if (ret == CTF_ERR) {
			(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
			    "failed to add enumarator %s (%d) to %d\n",
			    name, eval, id);
			ctf_free(name, strlen(name) + 1);
			return (ctf_errno(cdp->cd_ctfp));
		}
		ctf_free(name, strlen(name) + 1);
	}

	return (0);
}

/*
 * For a function pointer, walk over and process all of its children, unless we
 * encounter one that's just a declaration. In which case, we error on it.
 */
static int
ctf_dwarf_create_fptr(ctf_die_t *cdp, Dwarf_Die die, ctf_id_t *idp, int isroot)
{
	int ret;
	Dwarf_Bool b;
	ctf_funcinfo_t fi;
	Dwarf_Die retdie;
	ctf_id_t *argv = NULL;

	bzero(&fi, sizeof (ctf_funcinfo_t));

	if ((ret = ctf_dwarf_boolean(cdp, die, DW_AT_declaration, &b)) != 0) {
		if (ret != ENOENT)
			return (ret);
	} else {
		if (b != 0)
			return (EPROTOTYPE);
	}

	/*
	 * Return type is in DW_AT_type, if none, it returns void.
	 */
	if ((ret = ctf_dwarf_refdie(cdp, die, DW_AT_type, &retdie)) != 0) {
		if (ret != ENOENT)
			return (ret);
		if ((fi.ctc_return = ctf_dwarf_void(cdp)) == CTF_ERR)
			return (ctf_errno(cdp->cd_ctfp));
	} else {
		if ((ret = ctf_dwarf_convert_type(cdp, retdie, &fi.ctc_return,
		    CTF_ADD_NONROOT)) != 0)
			return (ret);
	}

	if ((ret = ctf_dwarf_function_count(cdp, die, &fi, B_TRUE)) != 0) {
		return (ret);
	}

	if (fi.ctc_argc != 0) {
		argv = ctf_alloc(sizeof (ctf_id_t) * fi.ctc_argc);
		if (argv == NULL)
			return (ENOMEM);

		if ((ret = ctf_dwarf_convert_fargs(cdp, die, &fi, argv)) != 0) {
			ctf_free(argv, sizeof (ctf_id_t) * fi.ctc_argc);
			return (ret);
		}
	}

	if ((*idp = ctf_add_funcptr(cdp->cd_ctfp, isroot, &fi, argv)) ==
	    CTF_ERR) {
		ctf_free(argv, sizeof (ctf_id_t) * fi.ctc_argc);
		return (ctf_errno(cdp->cd_ctfp));
	}

	ctf_free(argv, sizeof (ctf_id_t) * fi.ctc_argc);
	return (ctf_dwmap_add(cdp, *idp, die, B_FALSE));
}

static int
ctf_dwarf_convert_type(ctf_die_t *cdp, Dwarf_Die die, ctf_id_t *idp,
    int isroot)
{
	int ret;
	Dwarf_Off offset;
	Dwarf_Half tag;
	ctf_dwmap_t lookup, *map;
	ctf_id_t id;

	if (idp == NULL)
		idp = &id;

	if ((ret = ctf_dwarf_offset(cdp, die, &offset)) != 0)
		return (ret);

	if (offset > cdp->cd_maxoff) {
		(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
		    "die offset %llu beyond maximum for header %llu\n",
		    offset, cdp->cd_maxoff);
		return (ECTF_CONVBKERR);
	}

	/*
	 * If we've already added an entry for this offset, then we're done.
	 */
	lookup.cdm_off = offset;
	if ((map = avl_find(&cdp->cd_map, &lookup, NULL)) != NULL) {
		*idp = map->cdm_id;
		return (0);
	}

	if ((ret = ctf_dwarf_tag(cdp, die, &tag)) != 0)
		return (ret);

	ret = ENOTSUP;
	switch (tag) {
	case DW_TAG_base_type:
		ctf_dprintf("base\n");
		ret = ctf_dwarf_create_base(cdp, die, idp, isroot, offset);
		break;
	case DW_TAG_array_type:
		ctf_dprintf("array\n");
		ret = ctf_dwarf_create_array(cdp, die, idp, isroot);
		break;
	case DW_TAG_enumeration_type:
		ctf_dprintf("enum\n");
		ret = ctf_dwarf_create_enum(cdp, die, idp, isroot);
		break;
	case DW_TAG_pointer_type:
		ctf_dprintf("pointer\n");
		ret = ctf_dwarf_create_reference(cdp, die, idp, CTF_K_POINTER,
		    isroot);
		break;
	case DW_TAG_structure_type:
		ctf_dprintf("struct\n");
		ret = ctf_dwarf_create_sou(cdp, die, idp, CTF_K_STRUCT,
		    isroot);
		break;
	case DW_TAG_subroutine_type:
		ctf_dprintf("fptr\n");
		ret = ctf_dwarf_create_fptr(cdp, die, idp, isroot);
		break;
	case DW_TAG_typedef:
		ctf_dprintf("typedef\n");
		ret = ctf_dwarf_create_reference(cdp, die, idp, CTF_K_TYPEDEF,
		    isroot);
		break;
	case DW_TAG_union_type:
		ctf_dprintf("union\n");
		ret = ctf_dwarf_create_sou(cdp, die, idp, CTF_K_UNION,
		    isroot);
		break;
	case DW_TAG_const_type:
		ctf_dprintf("const\n");
		ret = ctf_dwarf_create_reference(cdp, die, idp, CTF_K_CONST,
		    isroot);
		break;
	case DW_TAG_volatile_type:
		ctf_dprintf("volatile\n");
		ret = ctf_dwarf_create_reference(cdp, die, idp, CTF_K_VOLATILE,
		    isroot);
		break;
	case DW_TAG_restrict_type:
		ctf_dprintf("restrict\n");
		ret = ctf_dwarf_create_reference(cdp, die, idp, CTF_K_RESTRICT,
		    isroot);
		break;
	default:
		ctf_dprintf("ignoring tag type %x\n", tag);
		ret = 0;
		break;
	}
	ctf_dprintf("ctf_dwarf_convert_type tag specific handler returned %d\n",
	    ret);

	return (ret);
}

static int
ctf_dwarf_walk_lexical(ctf_die_t *cdp, Dwarf_Die die)
{
	int ret;
	Dwarf_Die child;

	if ((ret = ctf_dwarf_child(cdp, die, &child)) != 0)
		return (ret);

	if (child == NULL)
		return (0);

	return (ctf_dwarf_convert_die(cdp, die));
}

static int
ctf_dwarf_function_count(ctf_die_t *cdp, Dwarf_Die die, ctf_funcinfo_t *fip,
    boolean_t fptr)
{
	int ret;
	Dwarf_Die child, sib, arg;

	if ((ret = ctf_dwarf_child(cdp, die, &child)) != 0)
		return (ret);

	arg = child;
	while (arg != NULL) {
		Dwarf_Half tag;

		if ((ret = ctf_dwarf_tag(cdp, arg, &tag)) != 0)
			return (ret);

		/*
		 * We have to check for a varargs type decleration. This will
		 * happen in one of two ways. If we have a function pointer
		 * type, then it'll be done with a tag of type
		 * DW_TAG_unspecified_parameters. However, it only means we have
		 * a variable number of arguments, if we have more than one
		 * argument found so far. Otherwise, when we have a function
		 * type, it instead uses a formal parameter whose name is '...'
		 * to indicate a variable arguments member.
		 *
		 * Also, if we have a function pointer, then we have to expect
		 * that we might not get a name at all.
		 */
		if (tag == DW_TAG_formal_parameter && fptr == B_FALSE) {
			char *name;
			if ((ret = ctf_dwarf_string(cdp, die, DW_AT_name,
			    &name)) != 0)
				return (ret);
			if (strcmp(name, DWARF_VARARGS_NAME) == 0)
				fip->ctc_flags |= CTF_FUNC_VARARG;
			else
				fip->ctc_argc++;
			ctf_free(name, strlen(name) + 1);
		} else if (tag == DW_TAG_formal_parameter) {
			fip->ctc_argc++;
		} else if (tag == DW_TAG_unspecified_parameters &&
		    fip->ctc_argc > 0) {
			fip->ctc_flags |= CTF_FUNC_VARARG;
		}
		if ((ret = ctf_dwarf_sib(cdp, arg, &sib)) != 0)
			return (ret);
		arg = sib;
	}

	return (0);
}

static int
ctf_dwarf_convert_fargs(ctf_die_t *cdp, Dwarf_Die die, ctf_funcinfo_t *fip,
    ctf_id_t *argv)
{
	int ret;
	int i = 0;
	Dwarf_Die child, sib, arg;

	if ((ret = ctf_dwarf_child(cdp, die, &child)) != 0)
		return (ret);

	arg = child;
	while (arg != NULL) {
		Dwarf_Half tag;

		if ((ret = ctf_dwarf_tag(cdp, arg, &tag)) != 0)
			return (ret);
		if (tag == DW_TAG_formal_parameter) {
			Dwarf_Die tdie;

			if ((ret = ctf_dwarf_refdie(cdp, arg, DW_AT_type,
			    &tdie)) != 0)
				return (ret);

			if ((ret = ctf_dwarf_convert_type(cdp, tdie, &argv[i],
			    CTF_ADD_ROOT)) != 0)
				return (ret);
			i++;

			/*
			 * Once we hit argc entries, we're done. This ensures we
			 * don't accidentally hit a varargs which should be the
			 * least entry.
			 */
			if (i == fip->ctc_argc)
				break;
		}

		if ((ret = ctf_dwarf_sib(cdp, arg, &sib)) != 0)
			return (ret);
		arg = sib;
	}

	return (0);
}

static int
ctf_dwarf_convert_function(ctf_die_t *cdp, Dwarf_Die die)
{
	int ret;
	char *name;
	ctf_dwfunc_t *cdf;
	Dwarf_Die tdie;

	/*
	 * Functions that don't have a name are generally functions that have
	 * been inlined and thus most information about them has been lost. If
	 * we can't get a name, then instead of returning ENOENT, we silently
	 * swallow the error.
	 */
	if ((ret = ctf_dwarf_string(cdp, die, DW_AT_name, &name)) != 0) {
		if (ret == ENOENT)
			return (0);
		return (ret);
	}

	ctf_dprintf("beginning work on function %s\n", name);
	if ((cdf = ctf_alloc(sizeof (ctf_dwfunc_t))) == NULL) {
		ctf_free(name, strlen(name) + 1);
		return (ENOMEM);
	}
	bzero(cdf, sizeof (ctf_dwfunc_t));
	cdf->cdf_name = name;

	if ((ret = ctf_dwarf_refdie(cdp, die, DW_AT_type, &tdie)) == 0) {
		if ((ret = ctf_dwarf_convert_type(cdp, tdie,
		    &(cdf->cdf_fip.ctc_return), CTF_ADD_ROOT)) != 0) {
			ctf_free(name, strlen(name) + 1);
			ctf_free(cdf, sizeof (ctf_dwfunc_t));
			return (ret);
		}
	} else if (ret != ENOENT) {
		ctf_free(name, strlen(name) + 1);
		ctf_free(cdf, sizeof (ctf_dwfunc_t));
		return (ret);
	} else {
		if ((cdf->cdf_fip.ctc_return = ctf_dwarf_void(cdp)) ==
		    CTF_ERR) {
			ctf_free(name, strlen(name) + 1);
			ctf_free(cdf, sizeof (ctf_dwfunc_t));
			return (ctf_errno(cdp->cd_ctfp));
		}
	}

	/*
	 * A function has a number of children, some of which may not be ones we
	 * care about. Children that we care about have a type of
	 * DW_TAG_formal_parameter. We're going to do two passes, the first to
	 * count the arguments, the second to process them. Afterwards, we
	 * should be good to go ahead and add this function.
	 *
	 * Note, we already got the return type by going in and grabbing it out
	 * of the DW_AT_type.
	 */
	if ((ret = ctf_dwarf_function_count(cdp, die, &cdf->cdf_fip,
	    B_FALSE)) != 0) {
		ctf_free(name, strlen(name) + 1);
		ctf_free(cdf, sizeof (ctf_dwfunc_t));
		return (ret);
	}

	ctf_dprintf("beginning to convert function arguments %s\n", name);
	if (cdf->cdf_fip.ctc_argc != 0) {
		uint_t argc = cdf->cdf_fip.ctc_argc;
		cdf->cdf_argv = ctf_alloc(sizeof (ctf_id_t) * argc);
		if (cdf->cdf_argv == NULL) {
			ctf_free(name, strlen(name) + 1);
			ctf_free(cdf, sizeof (ctf_dwfunc_t));
			return (ENOMEM);
		}
		if ((ret = ctf_dwarf_convert_fargs(cdp, die,
		    &cdf->cdf_fip, cdf->cdf_argv)) != 0) {
			ctf_free(cdf->cdf_argv, sizeof (ctf_id_t) * argc);
			ctf_free(name, strlen(name) + 1);
			ctf_free(cdf, sizeof (ctf_dwfunc_t));
			return (ret);
		}
	} else {
		cdf->cdf_argv = NULL;
	}

	if ((ret = ctf_dwarf_isglobal(cdp, die, &cdf->cdf_global)) != 0) {
		ctf_free(cdf->cdf_argv, sizeof (ctf_id_t) *
		    cdf->cdf_fip.ctc_argc);
		ctf_free(name, strlen(name) + 1);
		ctf_free(cdf, sizeof (ctf_dwfunc_t));
		return (ret);
	}

	ctf_list_append(&cdp->cd_funcs, cdf);
	return (ret);
}

/*
 * Convert variables, but only if they're not prototypes and have names.
 */
static int
ctf_dwarf_convert_variable(ctf_die_t *cdp, Dwarf_Die die)
{
	int ret;
	char *name;
	Dwarf_Bool b;
	Dwarf_Die tdie;
	ctf_id_t id;
	ctf_dwvar_t *cdv;

	/* Skip "Non-Defining Declarations" */
	if ((ret = ctf_dwarf_boolean(cdp, die, DW_AT_declaration, &b)) == 0) {
		if (b != 0)
			return (0);
	} else if (ret != ENOENT) {
		return (ret);
	}

	/*
	 * If we find a DIE of "Declarations Completing Non-Defining
	 * Declarations", we will use the referenced type's DIE.  This isn't
	 * quite correct, e.g. DW_AT_decl_line will be the forward declaration
	 * not this site.  It's sufficient for what we need, however: in
	 * particular, we should find DW_AT_external as needed there.
	 */
	if ((ret = ctf_dwarf_refdie(cdp, die, DW_AT_specification,
	    &tdie)) == 0) {
		Dwarf_Off offset;
		if ((ret = ctf_dwarf_offset(cdp, tdie, &offset)) != 0)
			return (ret);
		ctf_dprintf("die 0x%llx DW_AT_specification -> die 0x%llx\n",
		    ctf_die_offset(die), ctf_die_offset(tdie));
		die = tdie;
	} else if (ret != ENOENT) {
		return (ret);
	}

	if ((ret = ctf_dwarf_string(cdp, die, DW_AT_name, &name)) != 0 &&
	    ret != ENOENT)
		return (ret);
	if (ret == ENOENT)
		return (0);

	if ((ret = ctf_dwarf_refdie(cdp, die, DW_AT_type, &tdie)) != 0) {
		ctf_free(name, strlen(name) + 1);
		return (ret);
	}

	if ((ret = ctf_dwarf_convert_type(cdp, tdie, &id,
	    CTF_ADD_ROOT)) != 0)
		return (ret);

	if ((cdv = ctf_alloc(sizeof (ctf_dwvar_t))) == NULL) {
		ctf_free(name, strlen(name) + 1);
		return (ENOMEM);
	}

	cdv->cdv_name = name;
	cdv->cdv_type = id;

	if ((ret = ctf_dwarf_isglobal(cdp, die, &cdv->cdv_global)) != 0) {
		ctf_free(cdv, sizeof (ctf_dwvar_t));
		ctf_free(name, strlen(name) + 1);
		return (ret);
	}

	ctf_list_append(&cdp->cd_vars, cdv);
	return (0);
}

/*
 * Walk through our set of top-level types and process them.
 */
static int
ctf_dwarf_walk_toplevel(ctf_die_t *cdp, Dwarf_Die die)
{
	int ret;
	Dwarf_Off offset;
	Dwarf_Half tag;

	if ((ret = ctf_dwarf_offset(cdp, die, &offset)) != 0)
		return (ret);

	if (offset > cdp->cd_maxoff) {
		(void) snprintf(cdp->cd_errbuf, cdp->cd_errlen,
		    "die offset %llu beyond maximum for header %llu\n",
		    offset, cdp->cd_maxoff);
		return (ECTF_CONVBKERR);
	}

	if ((ret = ctf_dwarf_tag(cdp, die, &tag)) != 0)
		return (ret);

	ret = 0;
	switch (tag) {
	case DW_TAG_subprogram:
		ctf_dprintf("top level func\n");
		ret = ctf_dwarf_convert_function(cdp, die);
		break;
	case DW_TAG_variable:
		ctf_dprintf("top level var\n");
		ret = ctf_dwarf_convert_variable(cdp, die);
		break;
	case DW_TAG_lexical_block:
		ctf_dprintf("top level block\n");
		ret = ctf_dwarf_walk_lexical(cdp, die);
		break;
	case DW_TAG_enumeration_type:
	case DW_TAG_structure_type:
	case DW_TAG_typedef:
	case DW_TAG_union_type:
		ctf_dprintf("top level type\n");
		ret = ctf_dwarf_convert_type(cdp, die, NULL, B_TRUE);
		break;
	default:
		break;
	}

	return (ret);
}


/*
 * We're given a node. At this node we need to convert it and then proceed to
 * convert any siblings that are associaed with this die.
 */
static int
ctf_dwarf_convert_die(ctf_die_t *cdp, Dwarf_Die die)
{
	while (die != NULL) {
		int ret;
		Dwarf_Die sib;

		if ((ret = ctf_dwarf_walk_toplevel(cdp, die)) != 0)
			return (ret);

		if ((ret = ctf_dwarf_sib(cdp, die, &sib)) != 0)
			return (ret);
		die = sib;
	}
	return (0);
}

static int
ctf_dwarf_fixup_die(ctf_die_t *cdp, boolean_t addpass)
{
	ctf_dwmap_t *map;

	for (map = avl_first(&cdp->cd_map); map != NULL;
	    map = AVL_NEXT(&cdp->cd_map, map)) {
		int ret;
		if (map->cdm_fix == B_FALSE)
			continue;
		if ((ret = ctf_dwarf_fixup_sou(cdp, map->cdm_die, map->cdm_id,
		    addpass)) != 0)
			return (ret);
	}

	return (0);
}

static ctf_dwfunc_t *
ctf_dwarf_match_func(ctf_die_t *cdp, const char *file, const char *name,
    int bind)
{
	ctf_dwfunc_t *cdf;

	if (bind == STB_WEAK)
		return (NULL);

	/* Nothing we can do if we can't find a name to compare it to. */
	if (bind == STB_LOCAL && (file == NULL || cdp->cd_name == NULL))
		return (NULL);

	for (cdf = ctf_list_next(&cdp->cd_funcs); cdf != NULL;
	    cdf = ctf_list_next(cdf)) {
		if (bind == STB_GLOBAL && cdf->cdf_global == B_FALSE)
			continue;
		if (bind == STB_LOCAL && cdf->cdf_global == B_TRUE)
			continue;
		if (strcmp(name, cdf->cdf_name) != 0)
			continue;
		if (bind == STB_LOCAL && strcmp(file, cdp->cd_name) != 0)
			continue;
		return (cdf);
	}

	return (NULL);
}
static ctf_dwvar_t *
ctf_dwarf_match_var(ctf_die_t *cdp, const char *file, const char *name,
    int bind)
{
	ctf_dwvar_t *cdv;

	/* Nothing we can do if we can't find a name to compare it to. */
	if (bind == STB_LOCAL && (file == NULL || cdp->cd_name == NULL))
		return (NULL);
	ctf_dprintf("Still considering %s\n", name);

	for (cdv = ctf_list_next(&cdp->cd_vars); cdv != NULL;
	    cdv = ctf_list_next(cdv)) {
		if (bind == STB_GLOBAL && cdv->cdv_global == B_FALSE)
			continue;
		if (bind == STB_LOCAL && cdv->cdv_global == B_TRUE)
			continue;
		if (strcmp(name, cdv->cdv_name) != 0)
			continue;
		if (bind == STB_LOCAL && strcmp(file, cdp->cd_name) != 0)
			continue;
		return (cdv);
	}

	return (NULL);
}

static int
ctf_dwarf_symtab_iter(ctf_die_t *cdp, ctf_dwarf_symtab_f *func, void *arg)
{
	int ret;
	ulong_t i;
	ctf_file_t *fp = cdp->cd_ctfp;
	const char *file = NULL;
	uintptr_t symbase = (uintptr_t)fp->ctf_symtab.cts_data;
	uintptr_t strbase = (uintptr_t)fp->ctf_strtab.cts_data;

	for (i = 0; i < fp->ctf_nsyms; i++) {
		const char *name;
		int type;
		GElf_Sym gsym;
		const GElf_Sym *gsymp;

		if (fp->ctf_symtab.cts_entsize == sizeof (Elf32_Sym)) {
			const Elf32_Sym *symp = (Elf32_Sym *)symbase + i;
			type = ELF32_ST_TYPE(symp->st_info);
			if (type == STT_FILE) {
				file = (char *)(strbase + symp->st_name);
				continue;
			}
			if (type != STT_OBJECT && type != STT_FUNC)
				continue;
			if (ctf_sym_valid(strbase, type, symp->st_shndx,
			    symp->st_value, symp->st_name) == B_FALSE)
				continue;
			name = (char *)(strbase + symp->st_name);
			gsym.st_name = symp->st_name;
			gsym.st_value = symp->st_value;
			gsym.st_size = symp->st_size;
			gsym.st_info = symp->st_info;
			gsym.st_other = symp->st_other;
			gsym.st_shndx = symp->st_shndx;
			gsymp = &gsym;
		} else {
			const Elf64_Sym *symp = (Elf64_Sym *)symbase + i;
			type = ELF64_ST_TYPE(symp->st_info);
			if (type == STT_FILE) {
				file = (char *)(strbase + symp->st_name);
				continue;
			}
			if (type != STT_OBJECT && type != STT_FUNC)
				continue;
			if (ctf_sym_valid(strbase, type, symp->st_shndx,
			    symp->st_value, symp->st_name) == B_FALSE)
				continue;
			name = (char *)(strbase + symp->st_name);
			gsymp = symp;
		}

		ret = func(cdp, gsymp, i, file, name, arg);
		if (ret != 0)
			return (ret);
	}

	return (0);
}

static int
ctf_dwarf_conv_funcvars_cb(ctf_die_t *cdp, const GElf_Sym *symp, ulong_t idx,
    const char *file, const char *name, void *arg)
{
	int ret, bind, type;

	bind = GELF_ST_BIND(symp->st_info);
	type = GELF_ST_TYPE(symp->st_info);

	/*
	 * Come back to weak symbols in another pass
	 */
	if (bind == STB_WEAK)
		return (0);

	if (type == STT_OBJECT) {
		ctf_dwvar_t *cdv = ctf_dwarf_match_var(cdp, file, name,
		    bind);
		ctf_dprintf("match for %s (%d): %p\n", name, idx, cdv);
		if (cdv == NULL)
			return (0);
		ret = ctf_add_object(cdp->cd_ctfp, idx, cdv->cdv_type);
		ctf_dprintf("added object %s\n", name);
	} else {
		ctf_dwfunc_t *cdf = ctf_dwarf_match_func(cdp, file, name,
		    bind);
		if (cdf == NULL)
			return (0);
		ret = ctf_add_function(cdp->cd_ctfp, idx, &cdf->cdf_fip,
		    cdf->cdf_argv);
	}

	if (ret == CTF_ERR) {
		return (ctf_errno(cdp->cd_ctfp));
	}

	return (0);
}

static int
ctf_dwarf_conv_funcvars(ctf_die_t *cdp)
{
	return (ctf_dwarf_symtab_iter(cdp, ctf_dwarf_conv_funcvars_cb, NULL));
}

/*
 * Note, this comment comes from the original version of the CTF tools.
 *
 * If we have a weak symbol, attempt to find the strong symbol it will
 * resolve to.  Note: the code where this actually happens is in
 * sym_process() in cmd/sgs/libld/common/syms.c
 *
 * Finding the matching symbol is unfortunately not trivial.  For a
 * symbol to be a candidate, it must:
 *
 * - have the same type (function, object)
 * - have the same value (address)
 * - have the same size
 * - not be another weak symbol
 * - belong to the same section (checked via section index)
 *
 * If such a candidate is global, then we assume we've found it.  The
 * linker generates the symbol table such that the curfile might be
 * incorrect; this is OK for global symbols, since find_iidesc() doesn't
 * need to check for the source file for the symbol.
 *
 * We might have found a strong local symbol, where the curfile is
 * accurate and matches that of the weak symbol.  We assume this is a
 * reasonable match.
 *
 * If we've got a local symbol with a non-matching curfile, there are
 * two possibilities.  Either this is a completely different symbol, or
 * it's a once-global symbol that was scoped to local via a mapfile.  In
 * the latter case, curfile is likely inaccurate since the linker does
 * not preserve the needed curfile in the order of the symbol table (see
 * the comments about locally scoped symbols in libld's update_osym()).
 * As we can't tell this case from the former one, we use this symbol
 * iff no other matching symbol is found.
 *
 * What we really need here is a SUNW section containing weak<->strong
 * mappings that we can consume.
 */
typedef struct ctf_dwarf_weak_arg {
	const GElf_Sym *cweak_symp;
	const char *cweak_file;
	boolean_t cweak_candidate;
	ulong_t cweak_idx;
} ctf_dwarf_weak_arg_t;

static int
ctf_dwarf_conv_check_weak(ctf_die_t *cdp, const GElf_Sym *symp,
    ulong_t idx, const char *file, const char *name, void *arg)
{
	ctf_dwarf_weak_arg_t *cweak = arg;
	const GElf_Sym *wsymp = cweak->cweak_symp;

	ctf_dprintf("comparing weak to %s\n", name);

	if (GELF_ST_BIND(symp->st_info) == STB_WEAK) {
		return (0);
	}

	if (GELF_ST_TYPE(wsymp->st_info) != GELF_ST_TYPE(symp->st_info)) {
		return (0);
	}

	if (wsymp->st_value != symp->st_value) {
		return (0);
	}

	if (wsymp->st_size != symp->st_size) {
		return (0);
	}

	if (wsymp->st_shndx != symp->st_shndx) {
		return (0);
	}

	/*
	 * Check if it's a weak candidate.
	 */
	if (GELF_ST_BIND(symp->st_info) == STB_LOCAL &&
	    (file == NULL || cweak->cweak_file == NULL ||
	    strcmp(file, cweak->cweak_file) != 0)) {
		cweak->cweak_candidate = B_TRUE;
		cweak->cweak_idx = idx;
		return (0);
	}

	/*
	 * Found a match, break.
	 */
	cweak->cweak_idx = idx;
	return (1);
}

static int
ctf_dwarf_duplicate_sym(ctf_die_t *cdp, ulong_t idx, ulong_t matchidx)
{
	ctf_id_t id = ctf_lookup_by_symbol(cdp->cd_ctfp, matchidx);

	/*
	 * If we matched something that for some reason didn't have type data,
	 * we don't consider that a fatal error and silently swallow it.
	 */
	if (id == CTF_ERR) {
		if (ctf_errno(cdp->cd_ctfp) == ECTF_NOTYPEDAT)
			return (0);
		else
			return (ctf_errno(cdp->cd_ctfp));
	}

	if (ctf_add_object(cdp->cd_ctfp, idx, id) == CTF_ERR)
		return (ctf_errno(cdp->cd_ctfp));

	return (0);
}

static int
ctf_dwarf_duplicate_func(ctf_die_t *cdp, ulong_t idx, ulong_t matchidx)
{
	int ret;
	ctf_funcinfo_t fip;
	ctf_id_t *args = NULL;

	if (ctf_func_info(cdp->cd_ctfp, matchidx, &fip) == CTF_ERR) {
		if (ctf_errno(cdp->cd_ctfp) == ECTF_NOFUNCDAT)
			return (0);
		else
			return (ctf_errno(cdp->cd_ctfp));
	}

	if (fip.ctc_argc != 0) {
		args = ctf_alloc(sizeof (ctf_id_t) * fip.ctc_argc);
		if (args == NULL)
			return (ENOMEM);

		if (ctf_func_args(cdp->cd_ctfp, matchidx, fip.ctc_argc, args) ==
		    CTF_ERR) {
			ctf_free(args, sizeof (ctf_id_t) * fip.ctc_argc);
			return (ctf_errno(cdp->cd_ctfp));
		}
	}

	ret = ctf_add_function(cdp->cd_ctfp, idx, &fip, args);
	if (args != NULL)
		ctf_free(args, sizeof (ctf_id_t) * fip.ctc_argc);
	if (ret == CTF_ERR)
		return (ctf_errno(cdp->cd_ctfp));

	return (0);
}

static int
ctf_dwarf_conv_weaks_cb(ctf_die_t *cdp, const GElf_Sym *symp,
    ulong_t idx, const char *file, const char *name, void *arg)
{
	int ret, type;
	ctf_dwarf_weak_arg_t cweak;

	/*
	 * We only care about weak symbols.
	 */
	if (GELF_ST_BIND(symp->st_info) != STB_WEAK)
		return (0);

	type = GELF_ST_TYPE(symp->st_info);
	ASSERT(type == STT_OBJECT || type == STT_FUNC);

	/*
	 * For each weak symbol we encounter, we need to do a second iteration
	 * to try and find a match. We should probably think about other
	 * techniques to try and save us time in the future.
	 */
	cweak.cweak_symp = symp;
	cweak.cweak_file = file;
	cweak.cweak_candidate = B_FALSE;
	cweak.cweak_idx = 0;

	ctf_dprintf("Trying to find weak equiv for %s\n", name);

	ret = ctf_dwarf_symtab_iter(cdp, ctf_dwarf_conv_check_weak, &cweak);
	VERIFY(ret == 0 || ret == 1);

	/*
	 * Nothing was ever found, we're not going to add anything for this
	 * entry.
	 */
	if (ret == 0 && cweak.cweak_candidate == B_FALSE) {
		ctf_dprintf("found no weak match for %s\n", name);
		return (0);
	}

	/*
	 * Now, finally go and add the type based on the match.
	 */
	if (type == STT_OBJECT) {
		ret = ctf_dwarf_duplicate_sym(cdp, idx, cweak.cweak_idx);
	} else {
		ret = ctf_dwarf_duplicate_func(cdp, idx, cweak.cweak_idx);
	}

	return (ret);
}

static int
ctf_dwarf_conv_weaks(ctf_die_t *cdp)
{
	return (ctf_dwarf_symtab_iter(cdp, ctf_dwarf_conv_weaks_cb, NULL));
}

/* ARGSUSED */
static int
ctf_dwarf_convert_one(void *arg, void *unused)
{
	int ret;
	ctf_file_t *dedup;
	ctf_die_t *cdp = arg;

	ctf_dprintf("converting die: %s\n", cdp->cd_name);
	ctf_dprintf("max offset: %x\n", cdp->cd_maxoff);
	VERIFY(cdp != NULL);

	ret = ctf_dwarf_convert_die(cdp, cdp->cd_cu);
	ctf_dprintf("ctf_dwarf_convert_die (%s) returned %d\n", cdp->cd_name,
	    ret);
	if (ret != 0) {
		return (ret);
	}
	if (ctf_update(cdp->cd_ctfp) != 0) {
		return (ctf_dwarf_error(cdp, cdp->cd_ctfp, 0,
		    "failed to update output ctf container"));
	}

	ret = ctf_dwarf_fixup_die(cdp, B_FALSE);
	ctf_dprintf("ctf_dwarf_fixup_die (%s) returned %d\n", cdp->cd_name,
	    ret);
	if (ret != 0) {
		return (ret);
	}
	if (ctf_update(cdp->cd_ctfp) != 0) {
		return (ctf_dwarf_error(cdp, cdp->cd_ctfp, 0,
		    "failed to update output ctf container"));
	}

	ret = ctf_dwarf_fixup_die(cdp, B_TRUE);
	ctf_dprintf("ctf_dwarf_fixup_die (%s) returned %d\n", cdp->cd_name,
	    ret);
	if (ret != 0) {
		return (ret);
	}
	if (ctf_update(cdp->cd_ctfp) != 0) {
		return (ctf_dwarf_error(cdp, cdp->cd_ctfp, 0,
		    "failed to update output ctf container"));
	}


	if ((ret = ctf_dwarf_conv_funcvars(cdp)) != 0) {
		return (ctf_dwarf_error(cdp, NULL, ret,
		    "failed to convert strong functions and variables"));
	}

	if (ctf_update(cdp->cd_ctfp) != 0) {
		return (ctf_dwarf_error(cdp, cdp->cd_ctfp, 0,
		    "failed to update output ctf container"));
	}

	if (cdp->cd_doweaks == B_TRUE) {
		if ((ret = ctf_dwarf_conv_weaks(cdp)) != 0) {
			return (ctf_dwarf_error(cdp, NULL, ret,
			    "failed to convert weak functions and variables"));
		}

		if (ctf_update(cdp->cd_ctfp) != 0) {
			return (ctf_dwarf_error(cdp, cdp->cd_ctfp, 0,
			    "failed to update output ctf container"));
		}
	}

	ctf_phase_dump(cdp->cd_ctfp, "pre-dedup");
	ctf_dprintf("adding inputs for dedup\n");
	if ((ret = ctf_merge_add(cdp->cd_cmh, cdp->cd_ctfp)) != 0) {
		return (ctf_dwarf_error(cdp, NULL, ret,
		    "failed to add inputs for merge"));
	}

	ctf_dprintf("starting merge\n");
	if ((ret = ctf_merge_dedup(cdp->cd_cmh, &dedup)) != 0) {
		return (ctf_dwarf_error(cdp, NULL, ret,
		    "failed to deduplicate die"));
	}
	ctf_close(cdp->cd_ctfp);
	cdp->cd_ctfp = dedup;

	return (0);
}

/*
 * Note, we expect that if we're returning a ctf_file_t from one of the dies,
 * say in the single node case, it's been saved and the entry here has been set
 * to NULL, which ctf_close happily ignores.
 */
static void
ctf_dwarf_free_die(ctf_die_t *cdp)
{
	ctf_dwfunc_t *cdf, *ndf;
	ctf_dwvar_t *cdv, *ndv;
	ctf_dwbitf_t *cdb, *ndb;
	ctf_dwmap_t *map;
	void *cookie;
	Dwarf_Error derr;

	ctf_dprintf("Beginning to free die: %p\n", cdp);
	cdp->cd_elf = NULL;
	ctf_dprintf("Trying to free name: %p\n", cdp->cd_name);
	if (cdp->cd_name != NULL)
		ctf_free(cdp->cd_name, strlen(cdp->cd_name) + 1);
	ctf_dprintf("Trying to free merge handle: %p\n", cdp->cd_cmh);
	if (cdp->cd_cmh != NULL) {
		ctf_merge_fini(cdp->cd_cmh);
		cdp->cd_cmh = NULL;
	}

	ctf_dprintf("Trying to free functions\n");
	for (cdf = ctf_list_next(&cdp->cd_funcs); cdf != NULL; cdf = ndf) {
		ndf = ctf_list_next(cdf);
		ctf_free(cdf->cdf_name, strlen(cdf->cdf_name) + 1);
		if (cdf->cdf_fip.ctc_argc != 0) {
			ctf_free(cdf->cdf_argv,
			    sizeof (ctf_id_t) * cdf->cdf_fip.ctc_argc);
		}
		ctf_free(cdf, sizeof (ctf_dwfunc_t));
	}

	ctf_dprintf("Trying to free variables\n");
	for (cdv = ctf_list_next(&cdp->cd_vars); cdv != NULL; cdv = ndv) {
		ndv = ctf_list_next(cdv);
		ctf_free(cdv->cdv_name, strlen(cdv->cdv_name) + 1);
		ctf_free(cdv, sizeof (ctf_dwvar_t));
	}

	ctf_dprintf("Trying to free bitfields\n");
	for (cdb = ctf_list_next(&cdp->cd_bitfields); cdb != NULL; cdb = ndb) {
		ndb = ctf_list_next(cdb);
		ctf_free(cdb, sizeof (ctf_dwbitf_t));
	}

	/* How do we clean up die usage? */
	ctf_dprintf("Trying to clean up dwarf_t: %p\n", cdp->cd_dwarf);
	(void) dwarf_finish(cdp->cd_dwarf, &derr);
	cdp->cd_dwarf = NULL;
	ctf_close(cdp->cd_ctfp);

	cookie = NULL;
	while ((map = avl_destroy_nodes(&cdp->cd_map, &cookie)) != NULL) {
		ctf_free(map, sizeof (ctf_dwmap_t));
	}
	avl_destroy(&cdp->cd_map);
	cdp->cd_errbuf = NULL;
}

static void
ctf_dwarf_free_dies(ctf_die_t *cdies, int ndies)
{
	int i;

	ctf_dprintf("Beginning to free dies\n");
	for (i = 0; i < ndies; i++) {
		ctf_dwarf_free_die(&cdies[i]);
	}

	ctf_free(cdies, sizeof (ctf_die_t) * ndies);
}

static int
ctf_dwarf_count_dies(Dwarf_Debug dw, Dwarf_Error *derr, int *ndies,
    char *errbuf, size_t errlen)
{
	int ret;
	Dwarf_Half vers;
	Dwarf_Unsigned nexthdr;

	while ((ret = dwarf_next_cu_header(dw, NULL, &vers, NULL, NULL,
	    &nexthdr, derr)) != DW_DLV_NO_ENTRY) {
		if (ret != DW_DLV_OK) {
			(void) snprintf(errbuf, errlen,
			    "file does not contain valid DWARF data: %s\n",
			    dwarf_errmsg(*derr));
			return (ECTF_CONVBKERR);
		}

		if (vers != DWARF_VERSION_TWO) {
			(void) snprintf(errbuf, errlen,
			    "unsupported DWARF version: %d\n", vers);
			return (ECTF_CONVBKERR);
		}
		*ndies = *ndies + 1;
	}

	if (*ndies == 0) {
		(void) snprintf(errbuf, errlen,
		    "file does not contain valid DWARF data: %s\n",
		    dwarf_errmsg(*derr));
		return (ECTF_CONVBKERR);
	}

	return (0);
}

/*
 * Iterate over all of the dies and create a ctf_die_t for each of them. This is
 * used to determine if we have zero, one, or multiple dies to convert. If we
 * have zero, that's an error. If there's only one die, that's the simple case.
 * No merge needed and only a single Dwarf_Debug as well.
 */
static int
ctf_dwarf_init_die(int fd, Elf *elf, ctf_die_t *cdp, int ndie, char *errbuf,
    size_t errlen)
{
	int ret;
	Dwarf_Unsigned hdrlen, abboff, nexthdr;
	Dwarf_Half addrsz;
	Dwarf_Unsigned offset = 0;
	Dwarf_Error derr;

	while ((ret = dwarf_next_cu_header(cdp->cd_dwarf, &hdrlen, NULL,
	    &abboff, &addrsz, &nexthdr, &derr)) != DW_DLV_NO_ENTRY) {
		char *name;
		Dwarf_Die cu, child;

		/* Based on the counting above, we should be good to go */
		VERIFY(ret == DW_DLV_OK);
		if (ndie > 0) {
			ndie--;
			offset = nexthdr;
			continue;
		}

		/*
		 * Compilers are apparently inconsistent. Some emit no DWARF for
		 * empty files and others emit empty compilation unit.
		 */
		cdp->cd_voidtid = CTF_ERR;
		cdp->cd_longtid = CTF_ERR;
		cdp->cd_elf = elf;
		cdp->cd_maxoff = nexthdr - 1;
		cdp->cd_ctfp = ctf_fdcreate(fd, &ret);
		if (cdp->cd_ctfp == NULL) {
			ctf_free(cdp, sizeof (ctf_die_t));
			return (ret);
		}
		avl_create(&cdp->cd_map, ctf_dwmap_comp, sizeof (ctf_dwmap_t),
		    offsetof(ctf_dwmap_t, cdm_avl));
		cdp->cd_errbuf = errbuf;
		cdp->cd_errlen = errlen;
		bzero(&cdp->cd_vars, sizeof (ctf_list_t));
		bzero(&cdp->cd_funcs, sizeof (ctf_list_t));
		bzero(&cdp->cd_bitfields, sizeof (ctf_list_t));

		if ((ret = ctf_dwarf_die_elfenc(elf, cdp, errbuf,
		    errlen)) != 0) {
			avl_destroy(&cdp->cd_map);
			ctf_free(cdp, sizeof (ctf_die_t));
			return (ret);
		}

		if ((ret = ctf_dwarf_sib(cdp, NULL, &cu)) != 0) {
			avl_destroy(&cdp->cd_map);
			ctf_free(cdp, sizeof (ctf_die_t));
			return (ret);
		}
		if (cu == NULL) {
			(void) snprintf(errbuf, errlen,
			    "file does not contain DWARF data\n");
			avl_destroy(&cdp->cd_map);
			ctf_free(cdp, sizeof (ctf_die_t));
			return (ECTF_CONVBKERR);
		}

		if ((ret = ctf_dwarf_child(cdp, cu, &child)) != 0) {
			avl_destroy(&cdp->cd_map);
			ctf_free(cdp, sizeof (ctf_die_t));
			return (ret);
		}
		if (child == NULL) {
			(void) snprintf(errbuf, errlen,
			    "file does not contain DWARF data\n");
			avl_destroy(&cdp->cd_map);
			ctf_free(cdp, sizeof (ctf_die_t));
			return (ECTF_CONVBKERR);
		}

		cdp->cd_cuoff = offset;
		cdp->cd_cu = child;

		if ((cdp->cd_cmh = ctf_merge_init(fd, &ret)) == NULL) {
			avl_destroy(&cdp->cd_map);
			ctf_free(cdp, sizeof (ctf_die_t));
			return (ret);
		}

		if (ctf_dwarf_string(cdp, cu, DW_AT_name, &name) == 0) {
			size_t len = strlen(name) + 1;
			char *b = basename(name);
			cdp->cd_name = strdup(b);
			ctf_free(name, len);
		}
		break;
	}

	return (0);
}


ctf_conv_status_t
ctf_dwarf_convert(int fd, Elf *elf, uint_t nthrs, int *errp, ctf_file_t **fpp,
    char *errmsg, size_t errlen)
{
	int err, ret, ndies, i;
	Dwarf_Debug dw;
	Dwarf_Error derr;
	ctf_die_t *cdies = NULL, *cdp;
	workq_t *wqp = NULL;

	if (errp == NULL)
		errp = &err;
	*errp = 0;
	*fpp = NULL;

	ret = dwarf_elf_init(elf, DW_DLC_READ, NULL, NULL, &dw, &derr);
	if (ret != DW_DLV_OK) {
		/*
		 * The old CTF tools used to check if we expected DWARF data
		 * here. In this case, if we actually have some amount of DWARF,
		 * but no section, for now, just go ahead and create an empty
		 * CTF file.
		 */
		if (ret == DW_DLV_NO_ENTRY ||
		    dwarf_errno(derr) == DW_DLE_DEBUG_INFO_NULL) {
			*fpp = ctf_create(errp);
			return (*fpp != NULL ? CTF_CONV_SUCCESS :
			    CTF_CONV_ERROR);
		}
		(void) snprintf(errmsg, errlen,
		    "failed to initialize DWARF: %s\n",
		    dwarf_errmsg(derr));
		*errp = ECTF_CONVBKERR;
		return (CTF_CONV_ERROR);
	}

	ndies = 0;
	ret = ctf_dwarf_count_dies(dw, &derr, &ndies, errmsg, errlen);
	if (ret != 0) {
		*errp = ret;
		goto out;
	}

	(void) dwarf_finish(dw, &derr);
	cdies = ctf_alloc(sizeof (ctf_die_t) * ndies);
	if (cdies == NULL) {
		*errp = ENOMEM;
		return (CTF_CONV_ERROR);
	}

	for (i = 0; i < ndies; i++) {
		cdp = &cdies[i];
		ret = dwarf_elf_init(elf, DW_DLC_READ, NULL, NULL,
		    &cdp->cd_dwarf, &derr);
		if (ret != 0) {
			ctf_free(cdies, sizeof (ctf_die_t) * ndies);
			(void) snprintf(errmsg, errlen,
			    "failed to initialize DWARF: %s\n",
			    dwarf_errmsg(derr));
			*errp = ECTF_CONVBKERR;
			return (CTF_CONV_ERROR);
		}

		ret = ctf_dwarf_init_die(fd, elf, &cdies[i], i, errmsg, errlen);
		if (ret != 0) {
			*errp = ret;
			goto out;
		}
		cdp->cd_doweaks = ndies > 1 ? B_FALSE : B_TRUE;
	}

	ctf_dprintf("found %d DWARF die(s)\n", ndies);

	/*
	 * If we only have one die, there's no reason to use multiple threads,
	 * even if the user requested them. After all, they just gave us an
	 * upper bound.
	 */
	if (ndies == 1)
		nthrs = 1;

	if (workq_init(&wqp, nthrs) == -1) {
		*errp = errno;
		goto out;
	}

	for (i = 0; i < ndies; i++) {
		cdp = &cdies[i];
		ctf_dprintf("adding die %s: %p, %x %x\n", cdp->cd_name,
		    cdp->cd_cu, cdp->cd_cuoff, cdp->cd_maxoff);
		if (workq_add(wqp, cdp) == -1) {
			*errp = errno;
			goto out;
		}
	}

	ret = workq_work(wqp, ctf_dwarf_convert_one, NULL, errp);
	if (ret == WORKQ_ERROR) {
		*errp = errno;
		goto out;
	} else if (ret == WORKQ_UERROR) {
		ctf_dprintf("internal convert failed: %s\n",
		    ctf_errmsg(*errp));
		goto out;
	}

	ctf_dprintf("Determining next phase: have %d dies\n", ndies);
	if (ndies != 1) {
		ctf_merge_t *cmp;

		cmp = ctf_merge_init(fd, &ret);
		if (cmp == NULL) {
			*errp = ret;
			goto out;
		}

		ctf_dprintf("setting threads\n");
		if ((ret = ctf_merge_set_nthreads(cmp, nthrs)) != 0) {
			ctf_merge_fini(cmp);
			*errp = ret;
			goto out;
		}

		ctf_dprintf("adding dies\n");
		for (i = 0; i < ndies; i++) {
			cdp = &cdies[i];
			if ((ret = ctf_merge_add(cmp, cdp->cd_ctfp)) != 0) {
				ctf_merge_fini(cmp);
				*errp = ret;
				goto out;
			}
		}

		ctf_dprintf("performing merge\n");
		ret = ctf_merge_merge(cmp, fpp);
		if (ret != 0) {
			ctf_dprintf("failed merge!\n");
			*fpp = NULL;
			ctf_merge_fini(cmp);
			*errp = ret;
			goto out;
		}
		ctf_merge_fini(cmp);
		*errp = 0;
		ctf_dprintf("successfully converted!\n");
	} else {
		*errp = 0;
		*fpp = cdies->cd_ctfp;
		cdies->cd_ctfp = NULL;
		ctf_dprintf("successfully converted!\n");
	}

out:
	workq_fini(wqp);
	ctf_dwarf_free_dies(cdies, ndies);
	return (*fpp != NULL ? CTF_CONV_SUCCESS : CTF_CONV_ERROR);
}
