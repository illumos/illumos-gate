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
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

/*
 * mdb(1M) module for debugging the V8 JavaScript engine.  This implementation
 * makes heavy use of metadata defined in the V8 binary for inspecting in-memory
 * structures.  Canned configurations can be manually loaded for V8 binaries
 * that predate this metadata.  See mdb_v8_cfg.c for details.
 */

#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <sys/mdb_modapi.h>

#include "v8dbg.h"
#include "v8cfg.h"

/*
 * The "v8_class" and "v8_field" structures describe the C++ classes used to
 * represent V8 heap objects.
 */
typedef struct v8_class {
	struct v8_class *v8c_next;	/* list linkage */
	struct v8_class *v8c_parent;	/* parent class (inheritance) */
	struct v8_field *v8c_fields;	/* array of class fields */
	size_t		v8c_start;	/* offset of first class field */
	size_t		v8c_end;	/* offset of first subclass field */
	char		v8c_name[64];	/* heap object class name */
} v8_class_t;

typedef struct v8_field {
	struct v8_field	*v8f_next;	/* list linkage */
	ssize_t		v8f_offset;	/* field offset */
	char 		v8f_name[64];	/* field name */
	boolean_t	v8f_isbyte;	/* 1-byte int field */
} v8_field_t;

/*
 * Similarly, the "v8_enum" structure describes an enum from V8.
 */
typedef struct {
	char 	v8e_name[64];
	uint_t	v8e_value;
} v8_enum_t;

/*
 * During configuration, the dmod updates these globals with the actual set of
 * classes, types, and frame types based on the debug metadata.
 */
static v8_class_t	*v8_classes;

static v8_enum_t	v8_types[128];
static int 		v8_next_type;

static v8_enum_t 	v8_frametypes[16];
static int 		v8_next_frametype;

/*
 * The following constants describe offsets from the frame pointer that are used
 * to inspect each stack frame.  They're initialized from the debug metadata.
 */
static ssize_t	V8_OFF_FP_CONTEXT;
static ssize_t	V8_OFF_FP_MARKER;
static ssize_t	V8_OFF_FP_FUNCTION;
static ssize_t	V8_OFF_FP_ARGS;

/*
 * The following constants are used by macros defined in heap-dbg-common.h to
 * examine the types of various V8 heap objects.  In general, the macros should
 * be preferred to using the constants directly.  The values of these constants
 * are initialized from the debug metadata.
 */
static intptr_t	V8_FirstNonstringType;
static intptr_t	V8_IsNotStringMask;
static intptr_t	V8_StringTag;
static intptr_t	V8_NotStringTag;
static intptr_t	V8_StringEncodingMask;
static intptr_t	V8_TwoByteStringTag;
static intptr_t	V8_AsciiStringTag;
static intptr_t	V8_StringRepresentationMask;
static intptr_t	V8_SeqStringTag;
static intptr_t	V8_ConsStringTag;
static intptr_t	V8_ExternalStringTag;
static intptr_t	V8_FailureTag;
static intptr_t	V8_FailureTagMask;
static intptr_t	V8_HeapObjectTag;
static intptr_t	V8_HeapObjectTagMask;
static intptr_t	V8_SmiTag;
static intptr_t	V8_SmiTagMask;
static intptr_t	V8_SmiValueShift;
static intptr_t	V8_PointerSizeLog2;

static intptr_t	V8_PROP_IDX_CONTENT;
static intptr_t	V8_PROP_IDX_FIRST;
static intptr_t	V8_PROP_TYPE_FIELD;
static intptr_t	V8_PROP_FIRST_PHANTOM;
static intptr_t	V8_PROP_TYPE_MASK;

/*
 * Although we have this information in v8_classes, the following offsets are
 * defined explicitly because they're used directly in code below.
 */
static ssize_t	V8_OFF_FIXEDARRAY_DATA;
static ssize_t	V8_OFF_SEQASCIISTR_CHARS;

static const char *V8_FIXEDARRAY_BASE;

#define	NODE_OFF_EXTSTR_DATA		0x4	/* see node_string.h */

/*
 * Table of constants used directly by this file.
 */
typedef struct v8_constant {
	intptr_t	*v8c_valp;
	const char	*v8c_symbol;
} v8_constant_t;

static v8_constant_t v8_constants[] = {
	{ &V8_OFF_FP_CONTEXT,		"v8dbg_off_fp_context"		},
	{ &V8_OFF_FP_FUNCTION,		"v8dbg_off_fp_function"		},
	{ &V8_OFF_FP_MARKER,		"v8dbg_off_fp_marker"		},
	{ &V8_OFF_FP_ARGS,		"v8dbg_off_fp_args"		},

	{ &V8_FirstNonstringType,	"v8dbg_FirstNonstringType"	},
	{ &V8_IsNotStringMask,		"v8dbg_IsNotStringMask"		},
	{ &V8_StringTag,		"v8dbg_StringTag"		},
	{ &V8_NotStringTag,		"v8dbg_NotStringTag"		},
	{ &V8_StringEncodingMask,	"v8dbg_StringEncodingMask"	},
	{ &V8_TwoByteStringTag,		"v8dbg_TwoByteStringTag"	},
	{ &V8_AsciiStringTag,		"v8dbg_AsciiStringTag"		},
	{ &V8_StringRepresentationMask,	"v8dbg_StringRepresentationMask" },
	{ &V8_SeqStringTag,		"v8dbg_SeqStringTag"		},
	{ &V8_ConsStringTag,		"v8dbg_ConsStringTag"		},
	{ &V8_ExternalStringTag,	"v8dbg_ExternalStringTag"	},
	{ &V8_FailureTag,		"v8dbg_FailureTag"		},
	{ &V8_FailureTagMask,		"v8dbg_FailureTagMask"		},
	{ &V8_HeapObjectTag,		"v8dbg_HeapObjectTag"		},
	{ &V8_HeapObjectTagMask,	"v8dbg_HeapObjectTagMask"	},
	{ &V8_SmiTag,			"v8dbg_SmiTag"			},
	{ &V8_SmiTagMask,		"v8dbg_SmiTagMask"		},
	{ &V8_SmiValueShift,		"v8dbg_SmiValueShift"		},
	{ &V8_PointerSizeLog2,		"v8dbg_PointerSizeLog2"		},

	{ &V8_PROP_IDX_CONTENT,		"v8dbg_prop_idx_content"	},
	{ &V8_PROP_IDX_FIRST,		"v8dbg_prop_idx_first"		},
	{ &V8_PROP_TYPE_FIELD,		"v8dbg_prop_type_field"		},
	{ &V8_PROP_FIRST_PHANTOM,	"v8dbg_prop_type_first_phantom"	},
	{ &V8_PROP_TYPE_MASK,		"v8dbg_prop_type_mask"		},
};

static int v8_nconstants = sizeof (v8_constants) / sizeof (v8_constants[0]);

static int autoconf_iter_symbol(mdb_symbol_t *, void *);
static v8_class_t *conf_class_findcreate(const char *);
static v8_field_t *conf_field_create(v8_class_t *, const char *, size_t);
static char *conf_next_part(char *, char *);
static int conf_update_parent(const char *);
static int conf_update_field(v8_cfg_t *, const char *);
static int conf_update_enum(v8_cfg_t *, const char *, const char *,
    v8_enum_t *);
static int conf_update_type(v8_cfg_t *, const char *);
static int conf_update_frametype(v8_cfg_t *, const char *);
static void conf_class_compute_offsets(v8_class_t *);

static int heap_offset(const char *, const char *, ssize_t *, boolean_t);

/*
 * Invoked when this dmod is initially loaded to load the set of classes, enums,
 * and other constants from the metadata in the target binary.
 */
static int
autoconfigure(v8_cfg_t *cfgp)
{
	v8_class_t *clp;
	struct v8_constant *cnp;
	ssize_t unused;
	int ii;

	assert(v8_classes == NULL);

	/*
	 * Iterate all global symbols looking for metadata.
	 */
	if (cfgp->v8cfg_iter(cfgp, autoconf_iter_symbol, cfgp) != 0) {
		mdb_warn("failed to autoconfigure V8 support\n");
		return (-1);
	}

	/*
	 * By now we've configured all of the classes so we can update the
	 * "start" and "end" fields in each class with information from its
	 * parent class.
	 */
	for (clp = v8_classes; clp != NULL; clp = clp->v8c_next) {
		if (clp->v8c_end != (size_t)-1)
			continue;

		conf_class_compute_offsets(clp);
	};

	/*
	 * Finally, load various constants used directly in the module.
	 */
	for (ii = 0; ii < v8_nconstants; ii++) {
		cnp = &v8_constants[ii];

		if (cfgp->v8cfg_readsym(cfgp, cnp->v8c_symbol,
		    cnp->v8c_valp) == -1) {
			mdb_warn("failed to read \"%s\"", cnp->v8c_symbol);
			return (-1);
		}
	}

	if (heap_offset("SeqAsciiString", "chars", &V8_OFF_SEQASCIISTR_CHARS,
	    B_FALSE) != 0 || heap_offset("FixedArray", "data",
	    &V8_OFF_FIXEDARRAY_DATA, B_FALSE) != 0)
		return (-1);

	/*
	 * The V8 included in node v0.6 uses a FixedArrayBase class to contain
	 * the "length" field, while the one in v0.4 has no such base class and
	 * stores the field directly in FixedArray.  We handle both cases here.
	 */
	V8_FIXEDARRAY_BASE = heap_offset("FixedArray", "length", &unused,
	    B_TRUE) == 0 ?  "FixedArray" : "FixedArrayBase";

	return (0);
}

/* ARGSUSED */
static int
autoconf_iter_symbol(mdb_symbol_t *symp, void *arg)
{
	v8_cfg_t *cfgp = arg;

	if (strncmp(symp->sym_name, "v8dbg_parent_",
	    sizeof ("v8dbg_parent_") - 1) == 0)
		return (conf_update_parent(symp->sym_name));

	if (strncmp(symp->sym_name, "v8dbg_class_",
	    sizeof ("v8dbg_class_") - 1) == 0)
		return (conf_update_field(cfgp, symp->sym_name));

	if (strncmp(symp->sym_name, "v8dbg_type_",
	    sizeof ("v8dbg_type_") - 1) == 0)
		return (conf_update_type(cfgp, symp->sym_name));

	if (strncmp(symp->sym_name, "v8dbg_frametype_",
	    sizeof ("v8dbg_frametype_") - 1) == 0)
		return (conf_update_frametype(cfgp, symp->sym_name));

	return (0);
}

/*
 * Extracts the next field of a string whose fields are separated by "__" (as
 * the V8 metadata symbols are).
 */
static char *
conf_next_part(char *buf, char *start)
{
	char *pp;

	if ((pp = strstr(start, "__")) == NULL) {
		mdb_warn("malformed symbol name: %s\n", buf);
		return (NULL);
	}

	*pp = '\0';
	return (pp + sizeof ("__") - 1);
}

static v8_class_t *
conf_class_findcreate(const char *name)
{
	v8_class_t *clp, *iclp, **ptr;
	int cmp;

	if (v8_classes == NULL || strcmp(v8_classes->v8c_name, name) > 0) {
		ptr = &v8_classes;
	} else {
		for (iclp = v8_classes; iclp->v8c_next != NULL;
		    iclp = iclp->v8c_next) {
			cmp = strcmp(iclp->v8c_next->v8c_name, name);

			if (cmp == 0)
				return (iclp->v8c_next);

			if (cmp > 0)
				break;
		}

		ptr = &iclp->v8c_next;
	}

	if ((clp = mdb_zalloc(sizeof (*clp), UM_NOSLEEP)) == NULL)
		return (NULL);

	(void) strlcpy(clp->v8c_name, name, sizeof (clp->v8c_name));
	clp->v8c_end = (size_t)-1;

	clp->v8c_next = *ptr;
	*ptr = clp;
	return (clp);
}

static v8_field_t *
conf_field_create(v8_class_t *clp, const char *name, size_t offset)
{
	v8_field_t *flp, *iflp;

	if ((flp = mdb_zalloc(sizeof (*flp), UM_NOSLEEP)) == NULL)
		return (NULL);

	(void) strlcpy(flp->v8f_name, name, sizeof (flp->v8f_name));
	flp->v8f_offset = offset;

	if (clp->v8c_fields == NULL || clp->v8c_fields->v8f_offset > offset) {
		flp->v8f_next = clp->v8c_fields;
		clp->v8c_fields = flp;
		return (flp);
	}

	for (iflp = clp->v8c_fields; iflp->v8f_next != NULL;
	    iflp = iflp->v8f_next) {
		if (iflp->v8f_next->v8f_offset > offset)
			break;
	}

	flp->v8f_next = iflp->v8f_next;
	iflp->v8f_next = flp;
	return (flp);
}

/*
 * Given a "v8dbg_parent_X__Y", symbol, update the parent of class X to class Y.
 * Note that neither class necessarily exists already.
 */
static int
conf_update_parent(const char *symbol)
{
	char *pp, *qq;
	char buf[128];
	v8_class_t *clp, *pclp;

	(void) strlcpy(buf, symbol, sizeof (buf));
	pp = buf + sizeof ("v8dbg_parent_") - 1;
	qq = conf_next_part(buf, pp);

	if (qq == NULL)
		return (-1);

	clp = conf_class_findcreate(pp);
	pclp = conf_class_findcreate(qq);

	if (clp == NULL || pclp == NULL) {
		mdb_warn("mdb_v8: out of memory\n");
		return (-1);
	}

	clp->v8c_parent = pclp;
	return (0);
}

/*
 * Given a "v8dbg_class_CLASS__FIELD__TYPE", symbol, save field "FIELD" into
 * class CLASS with the offset described by the symbol.  Note that CLASS does
 * not necessarily exist already.
 */
static int
conf_update_field(v8_cfg_t *cfgp, const char *symbol)
{
	v8_class_t *clp;
	v8_field_t *flp;
	intptr_t offset;
	char *pp, *qq, *tt;
	char buf[128];

	(void) strlcpy(buf, symbol, sizeof (buf));

	pp = buf + sizeof ("v8dbg_class_") - 1;
	qq = conf_next_part(buf, pp);

	if (qq == NULL || (tt = conf_next_part(buf, qq)) == NULL)
		return (-1);

	if (cfgp->v8cfg_readsym(cfgp, symbol, &offset) == -1) {
		mdb_warn("failed to read symbol \"%s\"", symbol);
		return (-1);
	}

	if ((clp = conf_class_findcreate(pp)) == NULL ||
	    (flp = conf_field_create(clp, qq, (size_t)offset)) == NULL)
		return (-1);

	if (strcmp(tt, "int") == 0)
		flp->v8f_isbyte = B_TRUE;

	return (0);
}

static int
conf_update_enum(v8_cfg_t *cfgp, const char *symbol, const char *name,
    v8_enum_t *enp)
{
	intptr_t value;

	if (cfgp->v8cfg_readsym(cfgp, symbol, &value) == -1) {
		mdb_warn("failed to read symbol \"%s\"", symbol);
		return (-1);
	}

	enp->v8e_value = (int)value;
	(void) strlcpy(enp->v8e_name, name, sizeof (enp->v8e_name));
	return (0);
}

/*
 * Given a "v8dbg_type_TYPENAME" constant, save the type name in v8_types.  Note
 * that this enum has multiple integer values with the same string label.
 */
static int
conf_update_type(v8_cfg_t *cfgp, const char *symbol)
{
	char *klass;
	v8_enum_t *enp;
	char buf[128];

	if (v8_next_type > sizeof (v8_types) / sizeof (v8_types[0])) {
		mdb_warn("too many V8 types\n");
		return (-1);
	}

	(void) strlcpy(buf, symbol, sizeof (buf));

	klass = buf + sizeof ("v8dbg_type_") - 1;
	if (conf_next_part(buf, klass) == NULL)
		return (-1);

	enp = &v8_types[v8_next_type++];
	return (conf_update_enum(cfgp, symbol, klass, enp));
}

/*
 * Given a "v8dbg_frametype_TYPENAME" constant, save the frame type in
 * v8_frametypes.
 */
static int
conf_update_frametype(v8_cfg_t *cfgp, const char *symbol)
{
	const char *frametype;
	v8_enum_t *enp;

	if (v8_next_frametype >
	    sizeof (v8_frametypes) / sizeof (v8_frametypes[0])) {
		mdb_warn("too many V8 frame types\n");
		return (-1);
	}

	enp = &v8_frametypes[v8_next_frametype++];
	frametype = symbol + sizeof ("v8dbg_frametype_") - 1;
	return (conf_update_enum(cfgp, symbol, frametype, enp));
}

/*
 * Now that all classes have been loaded, update the "start" and "end" fields of
 * each class based on the values of its parent class.
 */
static void
conf_class_compute_offsets(v8_class_t *clp)
{
	v8_field_t *flp;

	assert(clp->v8c_start == 0);
	assert(clp->v8c_end == (size_t)-1);

	if (clp->v8c_parent != NULL) {
		if (clp->v8c_parent->v8c_end == (size_t)-1)
			conf_class_compute_offsets(clp->v8c_parent);

		clp->v8c_start = clp->v8c_parent->v8c_end;
	}

	if (clp->v8c_fields == NULL) {
		clp->v8c_end = clp->v8c_start;
		return;
	}

	for (flp = clp->v8c_fields; flp->v8f_next != NULL; flp = flp->v8f_next)
		;

	if (flp == NULL)
		clp->v8c_end = clp->v8c_start;
	else
		clp->v8c_end = flp->v8f_offset + sizeof (uintptr_t);
}

/*
 * Utility functions
 */
static int jsstr_print(uintptr_t, boolean_t, char **, size_t *);

static const char *
enum_lookup_str(v8_enum_t *enums, int val, const char *dflt)
{
	v8_enum_t *ep;

	for (ep = enums; ep->v8e_name[0] != '\0'; ep++) {
		if (ep->v8e_value == val)
			return (ep->v8e_name);
	}

	return (dflt);
}

static void
enum_print(v8_enum_t *enums)
{
	v8_enum_t *itp;

	for (itp = enums; itp->v8e_name[0] != '\0'; itp++)
		mdb_printf("%-30s = 0x%02x\n", itp->v8e_name, itp->v8e_value);
}

/*
 * b[v]snprintf behave like [v]snprintf(3c), except that they update the buffer
 * and length arguments based on how much buffer space is used by the operation.
 * This makes it much easier to combine multiple calls in sequence without
 * worrying about buffer overflow.
 */
static size_t
bvsnprintf(char **bufp, size_t *buflenp, const char *format, va_list alist)
{
	size_t rv, len;

	if (*buflenp == 0)
		return (vsnprintf(NULL, 0, format, alist));

	rv = vsnprintf(*bufp, *buflenp, format, alist);

	len = MIN(rv, *buflenp);
	*buflenp -= len;
	*bufp += len;

	return (len);
}

static size_t
bsnprintf(char **bufp, size_t *buflenp, const char *format, ...)
{
	va_list alist;
	size_t rv;

	va_start(alist, format);
	rv = bvsnprintf(bufp, buflenp, format, alist);
	va_end(alist);

	return (rv);
}

/*
 * Returns in "offp" the offset of field "field" in C++ class "klass".
 */
static int
heap_offset(const char *klass, const char *field, ssize_t *offp,
    boolean_t silent)
{
	v8_class_t *clp;
	v8_field_t *flp;

	for (clp = v8_classes; clp != NULL; clp = clp->v8c_next) {
		if (strcmp(klass, clp->v8c_name) == 0)
			break;
	}

	if (clp == NULL) {
		if (!silent)
			mdb_warn("couldn't find class \"%s\"\n", klass);
		return (-1);
	}

	for (flp = clp->v8c_fields; flp != NULL; flp = flp->v8f_next) {
		if (strcmp(field, flp->v8f_name) == 0)
			break;
	}

	if (flp == NULL) {
		if (!silent)
			mdb_warn("couldn't find class \"%s\" field \"%s\"\n",
			    klass, field);
		return (-1);
	}

	*offp = V8_OFF_HEAP(flp->v8f_offset);
	return (0);
}

/*
 * Assuming "addr" is an instance of the C++ heap class "klass", read into *valp
 * the pointer-sized value of field "field".
 */
static int
read_heap_ptr(uintptr_t *valp, uintptr_t addr, const char *klass,
    const char *field)
{
	ssize_t off;

	if (heap_offset(klass, field, &off, B_FALSE) != 0)
		return (-1);

	if (mdb_vread(valp, sizeof (*valp), addr + off) == -1) {
		mdb_warn("failed to read %s::%s from %p", klass, field,
		    addr + off);
		return (-1);
	}

	return (0);
}

/*
 * Like read_heap_ptr, but assume the field is an SMI and store the actual value
 * into *valp rather than the encoded representation.
 */
static int
read_heap_smi(uintptr_t *valp, uintptr_t addr, const char *klass,
    const char *field)
{
	if (read_heap_ptr(valp, addr, klass, field) != 0)
		return (-1);

	if (!V8_IS_SMI(*valp)) {
		mdb_warn("expected SMI, got %p\n", *valp);
		return (-1);
	}

	*valp = V8_SMI_VALUE(*valp);

	return (0);
}

static int
read_heap_double(double *valp, uintptr_t addr, const char *klass,
    const char *field)
{
	ssize_t off;

	if (heap_offset(klass, field, &off, B_FALSE) != 0)
		return (-1);

	if (mdb_vread(valp, sizeof (*valp), addr + off) == -1) {
		mdb_warn("failed to read heap value at %p", addr + off);
		return (-1);
	}

	return (0);
}

/*
 * Assuming "addr" refers to a FixedArray, return a newly-allocated array
 * representing its contents.
 */
static int
read_heap_array(uintptr_t addr, uintptr_t **retp, size_t *lenp)
{
	uintptr_t len;

	if (read_heap_smi(&len, addr, V8_FIXEDARRAY_BASE, "length") != 0)
		return (-1);

	*lenp = len;

	if (len == 0) {
		*retp = NULL;
		return (0);
	}

	if ((*retp = mdb_zalloc(len * sizeof (uintptr_t), UM_GC)) == NULL)
		return (-1);

	if (mdb_vread(*retp, len * sizeof (uintptr_t),
	    addr + V8_OFF_FIXEDARRAY_DATA) == -1)
		return (-1);

	return (0);
}

static int
read_heap_byte(uint8_t *valp, uintptr_t addr, const char *klass,
    const char *field)
{
	ssize_t off;

	if (heap_offset(klass, field, &off, B_FALSE) != 0)
		return (-1);

	if (mdb_vread(valp, sizeof (*valp), addr + off) == -1) {
		mdb_warn("failed to read heap value at %p", addr + off);
		return (-1);
	}

	return (0);
}

/*
 * Given a heap object, returns in *valp the byte describing the type of the
 * object.  This is shorthand for first retrieving the Map at the start of the
 * heap object and then retrieving the type byte from the Map object.
 */
static int
read_typebyte(uint8_t *valp, uintptr_t addr, boolean_t silent)
{
	uintptr_t mapaddr;
	ssize_t off;

	if (heap_offset("HeapObject", "map", &off, silent) != 0)
		return (-1);

	if (mdb_vread(&mapaddr, sizeof (mapaddr), addr + off) == -1) {
		if (!silent)
			mdb_warn("failed to read type of %p", addr);
		return (-1);
	}

	if (!V8_IS_HEAPOBJECT(mapaddr)) {
		if (!silent)
			mdb_warn("object map is not a heap object\n");
		return (-1);
	}

	if (read_heap_byte(valp, mapaddr, "Map", "instance_attributes") == -1)
		return (-1);

	return (0);
}

/*
 * Given a heap object, returns in *valp the size of the object.  For
 * variable-size objects, returns an undefined value.
 */
static int
read_size(size_t *valp, uintptr_t addr)
{
	uintptr_t mapaddr;
	uint8_t size;

	if (read_heap_ptr(&mapaddr, addr, "HeapObject", "map") != 0)
		return (-1);

	if (!V8_IS_HEAPOBJECT(mapaddr)) {
		mdb_warn("heap object map is not itself a heap object\n");
		return (-1);
	}

	if (read_heap_byte(&size, mapaddr, "Map", "instance_size") != 0)
		return (-1);

	*valp = size << V8_PointerSizeLog2;
	return (0);
}

/*
 * Returns in "buf" a description of the type of "addr" suitable for printing.
 */
static int
obj_jstype(uintptr_t addr, char **bufp, size_t *lenp, uint8_t *typep)
{
	uint8_t typebyte;
	uintptr_t strptr;
	const char *typename;

	if (V8_IS_FAILURE(addr)) {
		if (typep)
			*typep = 0;
		(void) bsnprintf(bufp, lenp, "'Failure' object");
		return (0);
	}

	if (V8_IS_SMI(addr)) {
		if (typep)
			*typep = 0;
		(void) bsnprintf(bufp, lenp, "SMI: value = %d",
		    V8_SMI_VALUE(addr));
		return (0);
	}

	if (read_typebyte(&typebyte, addr, B_FALSE) != 0)
		return (-1);

	if (typep)
		*typep = typebyte;

	typename = enum_lookup_str(v8_types, typebyte, "<unknown>");
	(void) bsnprintf(bufp, lenp, typename);

	if (strcmp(typename, "Oddball") == 0) {
		if (read_heap_ptr(&strptr, addr, "Oddball",
		    "to_string") != -1) {
			(void) bsnprintf(bufp, lenp, ": \"");
			(void) jsstr_print(strptr, B_FALSE, bufp, lenp);
			(void) bsnprintf(bufp, lenp, "\"");
		}
	}

	return (0);
}

/*
 * Print out the fields of the given object that come from the given class.
 */
static int
obj_print_fields(uintptr_t baddr, v8_class_t *clp)
{
	v8_field_t *flp;
	uintptr_t addr, value;
	int rv;
	char *bufp;
	size_t len;
	uint8_t type;
	char buf[256];

	for (flp = clp->v8c_fields; flp != NULL; flp = flp->v8f_next) {
		bufp = buf;
		len = sizeof (buf);

		addr = baddr + V8_OFF_HEAP(flp->v8f_offset);

		if (flp->v8f_isbyte) {
			uint8_t sv;
			if (mdb_vread(&sv, sizeof (sv), addr) == -1) {
				mdb_printf("%p %s (unreadable)\n",
				    addr, flp->v8f_name);
				continue;
			}

			mdb_printf("%p %s = 0x%x\n", addr, flp->v8f_name, sv);
			continue;
		}

		rv = mdb_vread((void *)&value, sizeof (value), addr);

		if (rv != sizeof (value) ||
		    obj_jstype(value, &bufp, &len, &type) != 0) {
			mdb_printf("%p %s (unreadable)\n", addr, flp->v8f_name);
			continue;
		}

		if (type != 0 && V8_TYPE_STRING(type)) {
			(void) bsnprintf(&bufp, &len, ": \"");
			(void) jsstr_print(value, B_FALSE, &bufp, &len);
			(void) bsnprintf(&bufp, &len, "\"");
		}

		mdb_printf("%p %s = %p (%s)\n", addr, flp->v8f_name, value,
		    buf);
	}

	return (DCMD_OK);
}

/*
 * Print out all fields of the given object, starting with the root of the class
 * hierarchy and working down the most specific type.
 */
static int
obj_print_class(uintptr_t addr, v8_class_t *clp)
{
	int rv = 0;

	/*
	 * If we have no fields, we just print a simple inheritance hierarchy.
	 * If we have fields but our parent doesn't, our header includes the
	 * inheritance hierarchy.
	 */
	if (clp->v8c_end == 0) {
		mdb_printf("%s ", clp->v8c_name);

		if (clp->v8c_parent != NULL) {
			mdb_printf("< ");
			(void) obj_print_class(addr, clp->v8c_parent);
		}

		return (0);
	}

	mdb_printf("%p %s", addr, clp->v8c_name);

	if (clp->v8c_start == 0 && clp->v8c_parent != NULL) {
		mdb_printf(" < ");
		(void) obj_print_class(addr, clp->v8c_parent);
	}

	mdb_printf(" {\n");
	(void) mdb_inc_indent(4);

	if (clp->v8c_start > 0 && clp->v8c_parent != NULL)
		rv = obj_print_class(addr, clp->v8c_parent);

	rv |= obj_print_fields(addr, clp);
	(void) mdb_dec_indent(4);
	mdb_printf("}\n");

	return (rv);
}

/*
 * Print the ASCII string for the given ASCII JS string, expanding ConsStrings
 * and ExternalStrings as needed.
 */
static int jsstr_print_seq(uintptr_t, boolean_t, char **, size_t *);
static int jsstr_print_cons(uintptr_t, boolean_t, char **, size_t *);
static int jsstr_print_external(uintptr_t, boolean_t, char **, size_t *);

static int
jsstr_print(uintptr_t addr, boolean_t verbose, char **bufp, size_t *lenp)
{
	uint8_t typebyte;
	int err = 0;
	char *lbufp;
	size_t llen;
	char buf[64];

	if (read_typebyte(&typebyte, addr, B_FALSE) != 0)
		return (0);

	if (!V8_TYPE_STRING(typebyte)) {
		(void) bsnprintf(bufp, lenp, "<not a string>");
		return (0);
	}

	if (!V8_STRENC_ASCII(typebyte)) {
		(void) bsnprintf(bufp, lenp, "<two-byte string>");
		return (0);
	}

	if (verbose) {
		lbufp = buf;
		llen = sizeof (buf);
		(void) obj_jstype(addr, &lbufp, &llen, NULL);
		mdb_printf("%s\n", buf);
		(void) mdb_inc_indent(4);
	}

	if (V8_STRREP_SEQ(typebyte))
		err = jsstr_print_seq(addr, verbose, bufp, lenp);
	else if (V8_STRREP_CONS(typebyte))
		err = jsstr_print_cons(addr, verbose, bufp, lenp);
	else if (V8_STRREP_EXT(typebyte))
		err = jsstr_print_external(addr, verbose, bufp, lenp);
	else {
		(void) bsnprintf(bufp, lenp, "<unknown string type>");
		err = -1;
	}

	if (verbose)
		(void) mdb_dec_indent(4);

	return (err);
}

static int
jsstr_print_seq(uintptr_t addr, boolean_t verbose, char **bufp, size_t *lenp)
{
	uintptr_t len, rlen;
	char buf[256];

	if (read_heap_smi(&len, addr, "String", "length") != 0)
		return (-1);

	rlen = len <= sizeof (buf) - 1 ? len : sizeof (buf) - sizeof ("[...]");

	if (verbose)
		mdb_printf("length: %d, will read: %d\n", len, rlen);

	buf[0] = '\0';

	if (rlen > 0 && mdb_readstr(buf, rlen + 1,
	    addr + V8_OFF_SEQASCIISTR_CHARS) == -1) {
		mdb_warn("failed to read SeqString data");
		return (-1);
	}

	if (rlen != len)
		(void) strlcat(buf, "[...]", sizeof (buf));

	if (verbose)
		mdb_printf("value: \"%s\"\n", buf);

	(void) bsnprintf(bufp, lenp, "%s", buf);
	return (0);
}

static int
jsstr_print_cons(uintptr_t addr, boolean_t verbose, char **bufp, size_t *lenp)
{
	uintptr_t ptr1, ptr2;

	if (read_heap_ptr(&ptr1, addr, "ConsString", "first") != 0 ||
	    read_heap_ptr(&ptr2, addr, "ConsString", "second") != 0)
		return (-1);

	if (verbose) {
		mdb_printf("ptr1: %p\n", ptr1);
		mdb_printf("ptr2: %p\n", ptr2);
	}

	if (jsstr_print(ptr1, verbose, bufp, lenp) != 0)
		return (-1);

	return (jsstr_print(ptr2, verbose, bufp, lenp));
}

static int
jsstr_print_external(uintptr_t addr, boolean_t verbose, char **bufp,
    size_t *lenp)
{
	uintptr_t ptr1, ptr2;
	char buf[256];

	if (verbose)
		mdb_printf("assuming Node.js string\n");

	if (read_heap_ptr(&ptr1, addr, "ExternalString", "resource") != 0)
		return (-1);

	if (mdb_vread(&ptr2, sizeof (ptr2),
	    ptr1 + NODE_OFF_EXTSTR_DATA) == -1) {
		mdb_warn("failed to read node external pointer: %p",
		    ptr1 + NODE_OFF_EXTSTR_DATA);
		return (-1);
	}

	if (mdb_readstr(buf, sizeof (buf), ptr2) == -1) {
		mdb_warn("failed to read ExternalString data");
		return (-1);
	}

	if (buf[0] != '\0' && !isascii(buf[0])) {
		mdb_warn("failed to read ExternalString ascii data\n");
		return (-1);
	}

	(void) bsnprintf(bufp, lenp, "%s", buf);
	return (0);
}

/*
 * Returns true if the given address refers to the "undefined" object.  Returns
 * false on failure (since we shouldn't fail on the actual "undefined" value).
 */
static boolean_t
jsobj_is_undefined(uintptr_t addr)
{
	uint8_t type;
	uintptr_t strptr;
	const char *typename;
	char buf[16];
	char *bufp = buf;
	size_t len = sizeof (buf);

	if (read_typebyte(&type, addr, B_TRUE) != 0)
		return (B_FALSE);

	typename = enum_lookup_str(v8_types, type, "<unknown>");
	if (strcmp(typename, "Oddball") != 0)
		return (B_FALSE);

	if (read_heap_ptr(&strptr, addr, "Oddball", "to_string") == -1)
		return (B_FALSE);

	if (jsstr_print(strptr, B_FALSE, &bufp, &len) != 0)
		return (B_FALSE);

	return (strcmp(buf, "undefined") == 0);
}

/*
 * Given the line endings table in "lendsp", computes the line number for the
 * given token position and print the result into "buf".  If "lendsp" is
 * undefined, prints the token position instead.
 */
static int
jsfunc_lineno(uintptr_t lendsp, uintptr_t tokpos, char *buf, size_t buflen)
{
	uintptr_t size, bufsz, lower, upper, ii;
	uintptr_t *data;

	if (jsobj_is_undefined(lendsp)) {
		mdb_snprintf(buf, buflen, "position %d", tokpos);
		return (0);
	}

	if (read_heap_smi(&size, lendsp, V8_FIXEDARRAY_BASE, "length") != 0)
		return (-1);

	bufsz = size * sizeof (data[0]);

	if ((data = mdb_alloc(bufsz, UM_NOSLEEP)) == NULL) {
		mdb_warn("failed to alloc %d bytes for FixedArray data", bufsz);
		return (-1);
	}

	if (mdb_vread(data, bufsz, lendsp + V8_OFF_FIXEDARRAY_DATA) != bufsz) {
		mdb_warn("failed to read FixedArray data");
		mdb_free(data, bufsz);
		return (-1);
	}

	lower = 0;
	upper = size - 1;

	if (tokpos > data[upper]) {
		(void) strlcpy(buf, "position out of range", buflen);
		mdb_free(data, bufsz);
		return (0);
	}

	if (tokpos <= data[0]) {
		(void) strlcpy(buf, "line 1", buflen);
		mdb_free(data, bufsz);
		return (0);
	}

	while (upper >= 1) {
		ii = (lower + upper) >> 1;
		if (tokpos > data[ii])
			lower = ii + 1;
		else if (tokpos <= data[ii - 1])
			upper = ii - 1;
		else
			break;
	}

	(void) mdb_snprintf(buf, buflen, "line %d", ii + 1);
	mdb_free(data, bufsz);
	return (0);
}

/*
 * Given a SharedFunctionInfo object, prints into bufp a name of the function
 * suitable for printing.  This function attempts to infer a name for anonymous
 * functions.
 */
static int
jsfunc_name(uintptr_t funcinfop, char **bufp, size_t *lenp)
{
	uintptr_t ptrp;
	char *bufs = *bufp;

	if (read_heap_ptr(&ptrp, funcinfop, "SharedFunctionInfo",
	    "name") != 0 || jsstr_print(ptrp, B_FALSE, bufp, lenp) != 0)
		return (-1);

	if (*bufp != bufs)
		return (0);

	if (read_heap_ptr(&ptrp, funcinfop, "SharedFunctionInfo",
	    "inferred_name") != 0) {
		(void) bsnprintf(bufp, lenp, "<anonymous>");
		return (0);
	}

	(void) bsnprintf(bufp, lenp, "<anonymous> (as ");
	bufs = *bufp;

	if (jsstr_print(ptrp, B_FALSE, bufp, lenp) != 0)
		return (-1);

	if (*bufp == bufs)
		(void) bsnprintf(bufp, lenp, "<anon>");

	(void) bsnprintf(bufp, lenp, ")");

	return (0);
}

/*
 * JavaScript-level object printing
 */
static int jsobj_print_number(uintptr_t, char **, size_t *);
static int jsobj_print_oddball(uintptr_t, char **, size_t *);
static int jsobj_print_jsobject(uintptr_t, boolean_t, int, int, char **,
    size_t *);
static int jsobj_print_jsarray(uintptr_t, boolean_t, int, int, char **,
    size_t *);
static int jsobj_print_jsfunction(uintptr_t, char **, size_t *);

static int
jsobj_print(uintptr_t addr, boolean_t printaddr, int indent, int depth,
    char **bufp, size_t *lenp)
{
	uint8_t type;
	const char *klass;

	if (printaddr)
		(void) bsnprintf(bufp, lenp, "%p: ", addr);

	if (V8_IS_SMI(addr)) {
		(void) bsnprintf(bufp, lenp, "%d", V8_SMI_VALUE(addr));
		return (0);
	}

	if (!V8_IS_HEAPOBJECT(addr)) {
		mdb_warn("not a heap object: %p\n", addr);
		return (-1);
	}

	if (read_typebyte(&type, addr, B_FALSE) != 0)
		return (-1);

	if (V8_TYPE_STRING(type))
		return (jsstr_print(addr, B_FALSE, bufp, lenp));

	klass = enum_lookup_str(v8_types, type, "<unknown>");
	if (strcmp(klass, "HeapNumber") == 0)
		return (jsobj_print_number(addr, bufp, lenp));
	if (strcmp(klass, "Oddball") == 0)
		return (jsobj_print_oddball(addr, bufp, lenp));
	if (strcmp(klass, "JSObject") == 0)
		return (jsobj_print_jsobject(addr, printaddr, indent, depth,
		    bufp, lenp));
	if (strcmp(klass, "JSArray") == 0)
		return (jsobj_print_jsarray(addr, printaddr, indent, depth,
		    bufp, lenp));
	if (strcmp(klass, "JSFunction") == 0)
		return (jsobj_print_jsfunction(addr, bufp, lenp));

	mdb_warn("unknown JavaScript object type \"%s\"\n", klass);
	return (-1);
}

static int
jsobj_print_number(uintptr_t addr, char **bufp, size_t *lenp)
{
	double numval;

	if (read_heap_double(&numval, addr, "HeapNumber", "value") == -1)
		return (-1);

	if (numval == (long long)numval)
		(void) bsnprintf(bufp, lenp, "%lld", (long long)numval);
	else
		(void) bsnprintf(bufp, lenp, "%e", numval);

	return (0);
}

static int
jsobj_print_oddball(uintptr_t addr, char **bufp, size_t *lenp)
{
	uintptr_t strptr;

	if (read_heap_ptr(&strptr, addr, "Oddball", "to_string") != 0)
		return (-1);

	return (jsstr_print(strptr, B_FALSE, bufp, lenp));
}

static int
jsobj_print_jsobject(uintptr_t addr, boolean_t printaddr, int indent,
    int depth, char **bufp, size_t *lenp)
{
	uintptr_t ptr, map;
	uintptr_t *props, *descs, *content;
	size_t ii, size, nprops, rndescs, ndescs, ncontent;
	uint8_t type, ninprops;

	if (depth == 0) {
		(void) bsnprintf(bufp, lenp, "[...]");
		return (0);
	}

	/*
	 * Objects have either "fast" properties represented with a FixedArray
	 * or slow properties represented with a Dictionary.  We only support
	 * the former, so we check that up front.
	 */
	if (read_heap_ptr(&ptr, addr, "JSObject", "properties") != 0)
		return (-1);

	if (read_typebyte(&type, ptr, B_FALSE) != 0)
		return (-1);

	if (strcmp(enum_lookup_str(v8_types, type, ""), "FixedArray") != 0) {
		(void) bsnprintf(bufp, lenp, "{ /* unknown property */ }");
		return (0);
	}

	if (read_heap_array(ptr, &props, &nprops) != 0)
		return (-1);

	/*
	 * To iterate the properties, we need to examine the instance
	 * descriptors of the associated Map object.  Some properties may be
	 * stored inside the object itself, in which case we need to know how
	 * big the object is and how many such properties there are.
	 */
	if (read_heap_ptr(&map, addr, "HeapObject", "map") != 0 ||
	    read_heap_ptr(&ptr, map, "Map", "instance_descriptors") != 0 ||
	    read_heap_array(ptr, &descs, &ndescs) != 0)
		return (-1);

	if (read_size(&size, addr) != 0)
		size = 0;

	if (read_heap_byte(&ninprops, map, "Map", "inobject_properties") != 0)
		return (-1);

	if (V8_PROP_IDX_CONTENT < ndescs &&
	    read_heap_array(descs[V8_PROP_IDX_CONTENT], &content,
	    &ncontent) != 0)
		return (-1);

	(void) bsnprintf(bufp, lenp, "{");

	/*
	 * The first FIRST (2) entries in the descriptors array are special.
	 */
	rndescs = ndescs <= V8_PROP_IDX_FIRST ? 0 : ndescs - V8_PROP_IDX_FIRST;

	for (ii = 0; ii < rndescs; ii++) {
		uintptr_t keyidx, validx, detidx;
		intptr_t val;

		keyidx = V8_DESC_KEYIDX(ii);
		validx = V8_DESC_VALIDX(ii);
		detidx = V8_DESC_DETIDX(ii);

		if (detidx >= ncontent) {
			mdb_warn("property descriptor %d: detidx (%d) "
			    "out of bounds for content array (length %d)\n",
			    ii, detidx, ncontent);
			continue;
		}

		if (!V8_DESC_ISFIELD(content[detidx]))
			continue;

		if (keyidx >= ndescs) {
			mdb_warn("property descriptor %d: keyidx (%d) "
			    "out of bounds for descriptor array (length %d)\n",
			    ii, keyidx, ndescs);
			continue;
		}

		(void) bsnprintf(bufp, lenp, "\n%*s", indent + 4, "");
		if (jsstr_print(descs[keyidx], B_FALSE, bufp, lenp) != 0)
			continue;

		(void) bsnprintf(bufp, lenp, ": ");

		val = (intptr_t)content[validx];

		if (!V8_IS_SMI(val)) {
			mdb_warn("property descriptor %d: value index value "
			    "is not an SMI: %p\n", ii, val);
			continue;
		}

		val = V8_SMI_VALUE(val) - ninprops;

		if (val < 0) {
			/* property is stored directly in the object */
			if (mdb_vread(&ptr, sizeof (ptr), addr + V8_OFF_HEAP(
			    size + val * sizeof (uintptr_t))) == -1) {
				mdb_warn("failed to read in-object "
				    "property at %p\n", addr + V8_OFF_HEAP(
				    size + val * sizeof (uintptr_t)));
				continue;
			}
		} else {
			/* property should be in "props" array */
			if (val >= nprops) {
				mdb_warn("property descriptor %d: value index "
				    "value (%d) out of bounds (%d)\n", ii, val,
				    nprops);
				continue;
			}

			ptr = props[val];
		}


		(void) jsobj_print(ptr, printaddr, indent + 4,
		    depth - 1, bufp, lenp);

		(void) bsnprintf(bufp, lenp, ",");
	}

	if (ii > 0)
		(void) bsnprintf(bufp, lenp, "\n%*s", indent, "");

	(void) bsnprintf(bufp, lenp, "}");

	return (DCMD_OK);
}

static int
jsobj_print_jsarray(uintptr_t addr, boolean_t printaddr, int indent,
    int depth, char **bufp, size_t *lenp)
{
	uintptr_t ptr;
	uintptr_t *elts;
	size_t ii, len;

	if (depth == 0) {
		(void) bsnprintf(bufp, lenp, "[...]");
		return (0);
	}

	if (read_heap_ptr(&ptr, addr, "JSObject", "elements") != 0 ||
	    read_heap_array(ptr, &elts, &len) != 0)
		return (-1);

	if (len == 0) {
		(void) bsnprintf(bufp, lenp, "[]");
		return (0);
	}

	if (len == 1) {
		(void) bsnprintf(bufp, lenp, "[ ");
		(void) jsobj_print(elts[0], printaddr, indent + 4,
		    depth - 1, bufp, lenp);
		(void) bsnprintf(bufp, lenp, " ]");
		return (0);
	}

	(void) bsnprintf(bufp, lenp, "[\n");
	for (ii = 0; ii < len; ii++) {
		(void) bsnprintf(bufp, lenp, "%*s", indent + 4, "");
		(void) jsobj_print(elts[ii], printaddr, indent + 4,
		    depth - 1, bufp, lenp);
		(void) bsnprintf(bufp, lenp, ",\n");
	}

	(void) bsnprintf(bufp, lenp, "%*s", indent, "");
	(void) bsnprintf(bufp, lenp, "]");

	return (0);
}

static int
jsobj_print_jsfunction(uintptr_t addr, char **bufp, size_t *lenp)
{
	uintptr_t shared;

	if (read_heap_ptr(&shared, addr, "JSFunction", "shared") != 0)
		return (-1);

	(void) bsnprintf(bufp, lenp, "function ");
	return (jsfunc_name(shared, bufp, lenp) != 0);
}

/*
 * dcmd implementations
 */

/* ARGSUSED */
static int
dcmd_v8classes(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	v8_class_t *clp;

	for (clp = v8_classes; clp != NULL; clp = clp->v8c_next)
		mdb_printf("%s\n", clp->v8c_name);

	return (DCMD_OK);
}

static int
do_v8code(uintptr_t addr, boolean_t opt_d)
{
	uintptr_t instrlen;
	ssize_t instroff;

	if (read_heap_ptr(&instrlen, addr, "Code", "instruction_size") != 0 ||
	    heap_offset("Code", "instruction_start", &instroff, B_FALSE) != 0)
		return (DCMD_ERR);

	mdb_printf("code: %p\n", addr);
	mdb_printf("instructions: [%p, %p)\n", addr + instroff,
	    addr + instroff + instrlen);

	if (!opt_d)
		return (DCMD_OK);

	mdb_set_dot(addr + instroff);

	do {
		(void) mdb_inc_indent(8); /* gets reset by mdb_eval() */

		/*
		 * This is absolutely awful. We want to disassemble the above
		 * range of instructions.  Because we don't know how many there
		 * are, we can't use "::dis".  We resort to evaluating "./i",
		 * but then we need to advance "." by the size of the
		 * instruction just printed.  The only way to do that is by
		 * printing out "+", but we don't want that to show up, so we
		 * redirect it to /dev/null.
		 */
		if (mdb_eval("/i") != 0 ||
		    mdb_eval("+=p ! cat > /dev/null") != 0) {
			(void) mdb_dec_indent(8);
			mdb_warn("failed to disassemble at %p", mdb_get_dot());
			return (DCMD_ERR);
		}
	} while (mdb_get_dot() < addr + instroff + instrlen);

	(void) mdb_dec_indent(8);
	return (DCMD_OK);
}

/* ARGSUSED */
static int
dcmd_v8code(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	boolean_t opt_d = B_FALSE;

	if (mdb_getopts(argc, argv, 'd', MDB_OPT_SETBITS, B_TRUE, &opt_d,
	    NULL) != argc)
		return (DCMD_USAGE);

	return (do_v8code(addr, opt_d));
}

/* ARGSUSED */
static int
dcmd_v8function(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint8_t type;
	uintptr_t funcinfop, scriptp, lendsp, tokpos, namep, codep;
	char *bufp;
	uint_t len;
	boolean_t opt_d = B_FALSE;
	char buf[512];

	if (mdb_getopts(argc, argv, 'd', MDB_OPT_SETBITS, B_TRUE, &opt_d,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (read_typebyte(&type, addr, B_FALSE) != 0)
		return (DCMD_ERR);

	if (strcmp(enum_lookup_str(v8_types, type, ""), "JSFunction") != 0) {
		mdb_warn("%p is not an instance of JSFunction\n", addr);
		return (DCMD_ERR);
	}

	if (read_heap_ptr(&funcinfop, addr, "JSFunction", "shared") != 0 ||
	    read_heap_ptr(&tokpos, funcinfop,
	    "SharedFunctionInfo", "function_token_position") != 0 ||
	    read_heap_ptr(&scriptp, funcinfop,
	    "SharedFunctionInfo", "script") != 0 ||
	    read_heap_ptr(&namep, scriptp, "Script", "name") != 0 ||
	    read_heap_ptr(&lendsp, scriptp, "Script", "line_ends") != 0)
		return (DCMD_ERR);

	bufp = buf;
	len = sizeof (buf);
	if (jsfunc_name(funcinfop, &bufp, &len) != 0)
		return (DCMD_ERR);

	mdb_printf("%p: JSFunction: %s\n", addr, buf);

	bufp = buf;
	len = sizeof (buf);
	mdb_printf("defined at ");

	if (jsstr_print(namep, B_FALSE, &bufp, &len) == 0)
		mdb_printf("%s ", buf);

	if (jsfunc_lineno(lendsp, tokpos, buf, sizeof (buf)) == 0)
		mdb_printf("%s", buf);

	mdb_printf("\n");

	if (read_heap_ptr(&codep, funcinfop, "SharedFunctionInfo", "code") != 0)
		return (DCMD_ERR);

	return (do_v8code(codep, opt_d));
}

/* ARGSUSED */
static int
dcmd_v8frametypes(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	enum_print(v8_frametypes);
	return (DCMD_OK);
}

static void
dcmd_v8print_help(void)
{
	mdb_printf(
	    "Prints out \".\" (a V8 heap object) as an instance of its C++\n"
	    "class.  With no arguments, the appropriate class is detected\n"
	    "automatically.  The 'class' argument overrides this to print an\n"
	    "object as an instance of the given class.  The list of known\n"
	    "classes can be viewed with ::jsclasses.");
}

/* ARGSUSED */
static int
dcmd_v8print(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const char *rqclass;
	v8_class_t *clp;
	char *bufp;
	size_t len;
	uint8_t type;
	char buf[256];

	if (argc < 1) {
		/*
		 * If no type was specified, determine it automatically.
		 */
		bufp = buf;
		len = sizeof (buf);
		if (obj_jstype(addr, &bufp, &len, &type) != 0)
			return (DCMD_ERR);

		if (type == 0) {
			/* For SMI or Failure, just print out the type. */
			mdb_printf("%s\n", buf);
			return (DCMD_OK);
		}

		if ((rqclass = enum_lookup_str(v8_types, type, NULL)) == NULL) {
			mdb_warn("object has unknown type\n");
			return (DCMD_ERR);
		}
	} else {
		if (argv[0].a_type != MDB_TYPE_STRING)
			return (DCMD_USAGE);

		rqclass = argv[0].a_un.a_str;
	}

	for (clp = v8_classes; clp != NULL; clp = clp->v8c_next) {
		if (strcmp(rqclass, clp->v8c_name) == 0)
			break;
	}

	if (clp == NULL) {
		mdb_warn("unknown class '%s'\n", rqclass);
		return (DCMD_USAGE);
	}

	return (obj_print_class(addr, clp));
}

/* ARGSUSED */
static int
dcmd_v8type(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char buf[64];
	char *bufp = buf;
	size_t len = sizeof (buf);

	if (obj_jstype(addr, &bufp, &len, NULL) != 0)
		return (DCMD_ERR);

	mdb_printf("0x%p: %s\n", addr, buf);
	return (DCMD_OK);
}

/* ARGSUSED */
static int
dcmd_v8types(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	enum_print(v8_types);
	return (DCMD_OK);
}

static int
load_current_context(uintptr_t *fpp, uintptr_t *raddrp)
{
	mdb_reg_t regfp, regip;

	if (mdb_getareg(1, "ebp", &regfp) != 0 ||
	    mdb_getareg(1, "eip", &regip) != 0) {
		mdb_warn("failed to load current context");
		return (-1);
	}

	if (fpp != NULL)
		*fpp = (uintptr_t)regfp;

	if (raddrp != NULL)
		*raddrp = (uintptr_t)regip;

	return (0);
}

static int
do_jsframe_special(uintptr_t fptr, uintptr_t raddr)
{
	uintptr_t ftype;
	const char *ftypename;

	/*
	 * Figure out what kind of frame this is using the same algorithm as
	 * V8's ComputeType function.  First, look for an ArgumentsAdaptorFrame.
	 */
	if (mdb_vread(&ftype, sizeof (ftype), fptr + V8_OFF_FP_CONTEXT) != -1 &&
	    V8_IS_SMI(ftype) &&
	    (ftypename = enum_lookup_str(v8_frametypes, V8_SMI_VALUE(ftype),
	    NULL)) != NULL && strstr(ftypename, "ArgumentsAdaptor") != NULL) {
		mdb_printf("%p %a <%s>\n", fptr, raddr, ftypename);
		return (0);
	}

	/*
	 * Other special frame types are indicated by a marker.
	 */
	if (mdb_vread(&ftype, sizeof (ftype), fptr + V8_OFF_FP_MARKER) != -1 &&
	    V8_IS_SMI(ftype)) {
		ftypename = enum_lookup_str(v8_frametypes, V8_SMI_VALUE(ftype),
		    NULL);

		if (ftypename != NULL)
			mdb_printf("%p %a <%s>\n", fptr, raddr, ftypename);
		else
			mdb_printf("%p %a\n", fptr, raddr);

		return (0);
	}

	return (-1);
}

static int
do_jsframe(uintptr_t fptr, uintptr_t raddr, boolean_t verbose)
{
	uintptr_t funcp, funcinfop, tokpos, scriptp, lendsp, ptrp;
	uintptr_t ii, nargs;
	const char *typename;
	char *bufp;
	size_t len;
	uint8_t type;
	char buf[256];

	/*
	 * Check for non-JavaScript frames first.
	 */
	if (do_jsframe_special(fptr, raddr) == 0)
		return (DCMD_OK);

	/*
	 * At this point we assume we're looking at a JavaScript frame.  As with
	 * native frames, fish the address out of the parent frame.
	 */
	if (mdb_vread(&funcp, sizeof (funcp),
	    fptr + V8_OFF_FP_FUNCTION) == -1) {
		mdb_warn("failed to read stack at %p",
		    fptr + V8_OFF_FP_FUNCTION);
		return (DCMD_ERR);
	}

	/*
	 * Check if this thing is really a JSFunction at all. For some frames,
	 * it's a Code object, presumably indicating some internal frame.
	 */
	if (read_typebyte(&type, funcp, B_TRUE) != 0 ||
	    (typename = enum_lookup_str(v8_types, type, NULL)) == NULL) {
		mdb_printf("%p %a\n", fptr, raddr);
		return (DCMD_OK);
	}

	if (strcmp("Code", typename) == 0) {
		mdb_printf("%p %a internal (Code: %p)\n", fptr, raddr, funcp);
		return (DCMD_OK);
	}

	if (strcmp("JSFunction", typename) != 0) {
		mdb_printf("%p %a unknown (%s: %p)", fptr, raddr, typename,
		    funcp);
		return (DCMD_OK);
	}

	if (read_heap_ptr(&funcinfop, funcp, "JSFunction", "shared") != 0)
		return (DCMD_ERR);

	bufp = buf;
	len = sizeof (buf);
	if (jsfunc_name(funcinfop, &bufp, &len) != 0)
		return (DCMD_ERR);

	mdb_printf("%p %a %s (%p)\n", fptr, raddr, buf, funcp);

	if (!verbose)
		return (DCMD_OK);

	/*
	 * Although the token position is technically an SMI, we're going to
	 * byte-compare it to other SMI values so we don't want decode it here.
	 */
	if (read_heap_ptr(&tokpos, funcinfop,
	    "SharedFunctionInfo", "function_token_position") != 0)
		return (DCMD_ERR);

	if (read_heap_ptr(&scriptp, funcinfop,
	    "SharedFunctionInfo", "script") != 0)
		return (DCMD_ERR);

	if (read_heap_ptr(&ptrp, scriptp, "Script", "name") != 0)
		return (DCMD_ERR);

	bufp = buf;
	len = sizeof (buf);
	(void) jsstr_print(ptrp, B_FALSE, &bufp, &len);

	(void) mdb_inc_indent(4);
	mdb_printf("file: %s\n", buf);

	if (read_heap_ptr(&lendsp, scriptp, "Script", "line_ends") != 0)
		return (DCMD_ERR);

	(void) jsfunc_lineno(lendsp, tokpos, buf, sizeof (buf));

	mdb_printf("posn: %s\n", buf);

	if (read_heap_smi(&nargs, funcinfop, "SharedFunctionInfo",
	    "length") == 0) {
		for (ii = 0; ii < nargs; ii++) {
			uintptr_t argptr;

			if (mdb_vread(&argptr, sizeof (argptr),
			    fptr + V8_OFF_FP_ARGS + (nargs - ii - 1) *
			    sizeof (uintptr_t)) == -1)
				continue;

			bufp = buf;
			len = sizeof (buf);
			(void) obj_jstype(argptr, &bufp, &len, NULL);

			mdb_printf("arg%d: %p (%s)\n", (ii + 1), argptr, buf);
		}
	}

	(void) mdb_dec_indent(4);

	return (DCMD_OK);
}

/* ARGSUSED */
static int
dcmd_jsframe(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t fptr, raddr;
	boolean_t opt_v = B_FALSE, opt_i = B_FALSE;

	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, B_TRUE, &opt_v,
	    'i', MDB_OPT_SETBITS, B_TRUE, &opt_i, NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * As with $C, we assume we are given a *pointer* to the frame pointer
	 * for a frame, rather than the actual frame pointer for the frame of
	 * interest. This is needed to show the instruction pointer, which is
	 * actually stored with the next frame.  For debugging, this can be
	 * overridden with the "-i" option (for "immediate").
	 */
	if (opt_i)
		return (do_jsframe(addr, 0, opt_v));

	if (mdb_vread(&raddr, sizeof (raddr),
	    addr + sizeof (uintptr_t)) == -1) {
		mdb_warn("failed to read return address from %p",
		    addr + sizeof (uintptr_t));
		return (DCMD_ERR);
	}

	if (mdb_vread(&fptr, sizeof (fptr), addr) == -1) {
		mdb_warn("failed to read frame pointer from %p", addr);
		return (DCMD_ERR);
	}

	if (fptr == NULL)
		return (DCMD_OK);

	return (do_jsframe(fptr, raddr, opt_v));
}

/* ARGSUSED */
static int
dcmd_jsprint(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	char *buf;
	char *bufp;
	size_t len, bufsz = 262144;
	boolean_t verbose;
	uint64_t depth;
	int rv;

	verbose = B_FALSE;
	depth = 2;

	if (mdb_getopts(argc, argv,
	    'a', MDB_OPT_SETBITS, B_TRUE, &verbose,
	    'd', MDB_OPT_UINT64, &depth, NULL) != argc)
		return (DCMD_USAGE);

	if ((buf = mdb_zalloc(bufsz, UM_NOSLEEP)) == NULL)
		return (DCMD_ERR);

	bufp = buf;
	len = bufsz;
	rv = jsobj_print(addr, verbose, 0, (int)depth, &bufp, &len);
	(void) mdb_printf("%s\n", buf);
	mdb_free(buf, bufsz);
	return (rv == 0 ? DCMD_OK : DCMD_ERR);
}

/* ARGSUSED */
static int
dcmd_v8field(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	v8_class_t *clp;
	v8_field_t *flp;
	const char *klass, *field;
	uintptr_t offset;

	/*
	 * We may be invoked with either two arguments (class and field name) or
	 * three (an offset to save).
	 */
	if (argc != 2 && argc != 3)
		return (DCMD_USAGE);

	if (argv[0].a_type != MDB_TYPE_STRING ||
	    argv[1].a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	klass = argv[0].a_un.a_str;
	field = argv[1].a_un.a_str;

	if (argc == 3) {
		if (argv[2].a_type != MDB_TYPE_STRING)
			return (DCMD_USAGE);

		offset = mdb_strtoull(argv[2].a_un.a_str);
	}

	for (clp = v8_classes; clp != NULL; clp = clp->v8c_next)
		if (strcmp(clp->v8c_name, klass) == 0)
			break;

	if (clp == NULL) {
		(void) mdb_printf("error: no such class: \"%s\"", klass);
		return (DCMD_ERR);
	}

	for (flp = clp->v8c_fields; flp != NULL; flp = flp->v8f_next)
		if (strcmp(field, flp->v8f_name) == 0)
			break;

	if (flp == NULL) {
		if (argc == 2) {
			mdb_printf("error: no such field in class \"%s\": "
			    "\"%s\"", klass, field);
			return (DCMD_ERR);
		}

		flp = conf_field_create(clp, field, offset);
		if (flp == NULL) {
			mdb_warn("failed to create field");
			return (DCMD_ERR);
		}
	} else if (argc == 3) {
		flp->v8f_offset = offset;
	}

	mdb_printf("%s::%s at offset 0x%x\n", klass, field, flp->v8f_offset);
	return (DCMD_OK);
}

/* ARGSUSED */
static int
dcmd_v8array(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint8_t type;
	uintptr_t *array;
	size_t ii, len;

	if (read_typebyte(&type, addr, B_FALSE) != 0)
		return (DCMD_ERR);

	if (strcmp(enum_lookup_str(v8_types, type, ""), "FixedArray") != 0) {
		mdb_warn("%p is not an instance of FixedArray\n", addr);
		return (DCMD_ERR);
	}

	if (read_heap_array(addr, &array, &len) != 0)
		return (DCMD_ERR);

	for (ii = 0; ii < len; ii++)
		mdb_printf("%p\n", array[ii]);

	return (DCMD_OK);
}

/* ARGSUSED */
static int
dcmd_jsstack(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uintptr_t raddr;
	boolean_t opt_v;

	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, B_TRUE, &opt_v,
	    NULL) != argc)
		return (DCMD_USAGE);

	/*
	 * The "::jsframe" walker iterates the valid frame pointers, but the
	 * "::jsframe" dcmd looks at the frame after the one it was given, so we
	 * have to explicitly examine the top frame here.
	 */
	if (!(flags & DCMD_ADDRSPEC)) {
		if (load_current_context(&addr, &raddr) != 0 ||
		    do_jsframe(addr, raddr, opt_v) != 0)
			return (DCMD_ERR);
	}

	if (mdb_pwalk_dcmd("jsframe", "jsframe", argc, argv, addr) == -1)
		return (DCMD_ERR);

	return (DCMD_OK);
}

/* ARGSUSED */
static int
dcmd_v8str(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	boolean_t opt_v = B_FALSE;
	char buf[256];
	char *bufp;
	size_t len;

	if (mdb_getopts(argc, argv, 'v', MDB_OPT_SETBITS, B_TRUE, &opt_v,
	    NULL) != argc)
		return (DCMD_USAGE);

	bufp = buf;
	len = sizeof (buf);
	if (jsstr_print(addr, opt_v, &bufp, &len) != 0)
		return (DCMD_ERR);

	mdb_printf("%s\n", buf);
	return (DCMD_OK);
}

static void
dcmd_v8load_help(void)
{
	v8_cfg_t *cfp, **cfgpp;

	mdb_printf(
	    "To traverse in-memory V8 structures, the V8 dmod requires\n"
	    "configuration that describes the layout of various V8 structures\n"
	    "in memory.  Normally, this information is pulled from metadata\n"
	    "in the target binary.  However, it's possible to use the module\n"
	    "with a binary not built with metadata by loading one of the\n"
	    "canned configurations.\n\n");

	mdb_printf("Available configurations:\n");

	(void) mdb_inc_indent(4);

	for (cfgpp = v8_cfgs; *cfgpp != NULL; cfgpp++) {
		cfp = *cfgpp;
		mdb_printf("%-10s    %s\n", cfp->v8cfg_name, cfp->v8cfg_label);
	}

	(void) mdb_dec_indent(4);
}

/* ARGSUSED */
static int
dcmd_v8load(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	v8_cfg_t *cfgp, **cfgpp;

	if (v8_classes != NULL) {
		mdb_warn("v8 module already configured\n");
		return (DCMD_ERR);
	}

	if (argc < 1 || argv->a_type != MDB_TYPE_STRING)
		return (DCMD_USAGE);

	for (cfgpp = v8_cfgs; *cfgpp != NULL; cfgpp++) {
		cfgp = *cfgpp;
		if (strcmp(argv->a_un.a_str, cfgp->v8cfg_name) == 0)
			break;
	}

	if (cfgp->v8cfg_name == NULL) {
		mdb_warn("unknown configuration: \"%s\"\n", argv->a_un.a_str);
		return (DCMD_ERR);
	}

	if (autoconfigure(cfgp) == -1) {
		mdb_warn("autoconfigure failed\n");
		return (DCMD_ERR);
	}

	mdb_printf("V8 dmod configured based on %s\n", cfgp->v8cfg_name);
	return (DCMD_OK);
}

static int
walk_jsframes_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr != NULL)
		return (WALK_NEXT);

	if (load_current_context(&wsp->walk_addr, NULL) != 0)
		return (WALK_ERR);

	return (WALK_NEXT);
}

static int
walk_jsframes_step(mdb_walk_state_t *wsp)
{
	uintptr_t ftype, addr, next;
	int rv;

	addr = wsp->walk_addr;
	rv = wsp->walk_callback(wsp->walk_addr, NULL, wsp->walk_cbdata);

	if (rv != WALK_NEXT)
		return (rv);

	/*
	 * Figure out the type of this frame.
	 */
	if (mdb_vread(&ftype, sizeof (ftype), addr + V8_OFF_FP_MARKER) == -1)
		return (WALK_ERR);

	if (V8_IS_SMI(ftype) && V8_SMI_VALUE(ftype) == 0)
		return (WALK_DONE);

	if (mdb_vread(&next, sizeof (next), addr) == -1)
		return (WALK_ERR);

	if (next == NULL)
		return (WALK_DONE);

	wsp->walk_addr = next;
	return (WALK_NEXT);
}

/*
 * MDB linkage
 */

static const mdb_dcmd_t v8_mdb_dcmds[] = {
	/*
	 * Commands to inspect JavaScript-level state
	 */
	{ "jsframe", ":[-v]", "summarize a JavaScript stack frame",
		dcmd_jsframe },
	{ "jsprint", ":[-a] [-d depth]", "print a JavaScript object",
		dcmd_jsprint },
	{ "jsstack", "[-v]", "print a JavaScript stacktrace",
		dcmd_jsstack },

	/*
	 * Commands to inspect V8-level state
	 */
	{ "v8array", ":", "print elements of a V8 FixedArray",
		dcmd_v8array },
	{ "v8classes", NULL, "list known V8 heap object C++ classes",
		dcmd_v8classes },
	{ "v8code", ":[-d]", "print information about a V8 Code object",
		dcmd_v8code },
	{ "v8field", "classname fieldname offset",
		"manually add a field to a given class", dcmd_v8field },
	{ "v8function", ":[-d]", "print JSFunction object details",
		dcmd_v8function },
	{ "v8load", "version", "load canned config for a specific V8 version",
		dcmd_v8load, dcmd_v8load_help },
	{ "v8frametypes", NULL, "list known V8 frame types",
		dcmd_v8frametypes },
	{ "v8print", ":[class]", "print a V8 heap object",
		dcmd_v8print, dcmd_v8print_help },
	{ "v8str", ":[-v]", "print the contents of a V8 string",
		dcmd_v8str },
	{ "v8type", ":", "print the type of a V8 heap object",
		dcmd_v8type },
	{ "v8types", NULL, "list known V8 heap object types",
		dcmd_v8types },

	{ NULL }
};

static const mdb_walker_t v8_mdb_walkers[] = {
	{ "jsframe", "walk V8 JavaScript stack frames",
		walk_jsframes_init, walk_jsframes_step },
	{ NULL }
};

static mdb_modinfo_t v8_mdb = { MDB_API_VERSION, v8_mdb_dcmds, v8_mdb_walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	uintptr_t v8major, v8minor, v8build, v8patch;
	GElf_Sym sym;

	if (mdb_readsym(&v8major, sizeof (v8major),
	    "_ZN2v88internal7Version6major_E") == -1 ||
	    mdb_readsym(&v8minor, sizeof (v8minor),
	    "_ZN2v88internal7Version6minor_E") == -1 ||
	    mdb_readsym(&v8build, sizeof (v8build),
	    "_ZN2v88internal7Version6build_E") == -1 ||
	    mdb_readsym(&v8patch, sizeof (v8patch),
	    "_ZN2v88internal7Version6patch_E") == -1) {
		mdb_warn("failed to determine V8 version");
		return (&v8_mdb);
	}

	mdb_printf("V8 version: %d.%d.%d.%d\n", v8major, v8minor, v8build,
	    v8patch);

	/*
	 * First look for debug metadata embedded within the binary, which may
	 * be present in recent V8 versions built with postmortem metadata.
	 */
	if (mdb_lookup_by_name("v8dbg_SmiTag", &sym) == 0) {
		if (autoconfigure(&v8_cfg_target) != 0)
			mdb_warn("failed to autoconfigure from target\n");

		else
			mdb_printf("Autoconfigured V8 support from target.\n");

		return (&v8_mdb);
	}

	if (v8major == 3 && v8minor == 1 && v8build == 8 &&
	    autoconfigure(&v8_cfg_04) == 0) {
		mdb_printf("Configured V8 support based on node v0.4");
		return (&v8_mdb);
	}

	if (v8major == 3 && v8minor == 6 && v8build == 6 &&
	    autoconfigure(&v8_cfg_06) == 0) {
		mdb_printf("Configured V8 support based on node v0.6");
		return (&v8_mdb);
	}

	mdb_printf("mdb_v8: target has no debug metadata and no existing "
	    "config found");
	return (&v8_mdb);
}
