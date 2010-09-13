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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Used to dump structures and unions in forth mode.
 *
 * structures and unions are a bit more complicated than enums.  To make things
 * just that much more interesting, we have to dump the members in reverse
 * order, which is nice.  But wait!  It gets better!  For compatibility reasons,
 * we need to dump the members in reverse-offset order, even if member-specific
 * mode was used to request the members in something other than that order.
 *
 * The header op prints the macro header and saves the type being printed.
 *
 * In member-specific mode, the member op will be invoked for each structure
 * or union member.  The member op adds the member name, format, type ID,
 * and offset to a list, sorted in reverse order by offset.
 *
 * The trailer op is called when the structure or enum is complete.  If no
 * members were specifically requested, then the trailer iterates through all
 * of the members of the structure, pretending they were.  Each member is thus
 * added, in reverse-offset order, to the list used in specific-member mode.
 * Either way, we then proceed through the list, dumping each member out with
 * fth_print_member.  Structure and union members are printed out differently,
 * depending on member type, as follows:
 *
 *  Integer:
 *	Normal integers: ' <format> <offset> <type>-field <name>
 *	  <format> defaults to ".d" for enums, ".x" for others
 *	  <offset> is the member offset, in bytes.
 *	  <type> is "byte", "short", "long", or "ext" for 8-, 16-, 32-, and
 *	    64-bit integers, respectively.
 *	  <name> is the name of the member being printed
 *
 *	Bitfields:	 ' <format> <shift> <mask> <offset> bits-field <name>
 *	  <format> defaults to ".x"
 *	  <shift> is the number of times to right-shift the masked value
 *	  <mask> use to extract the bit-field value from the read value
 *	  <offset> is the member offset, in bytes
 *	  <name> is the name of the member being printed
 *
 *  Float:		Ignored
 *
 *  Pointer:		 ' <format> <offset> ptr-field <name>
 *	  <format> defaults to .x
 *	  <offset> is in bytes
 *	  <name> is the name of the member being printed
 *
 *  Array:
 *	Arrays have a content-type-specific prefix, followed by an array
 *	suffix.  The resulting line looks like this if the array contents
 *	type is an integer, a pointer, or an enum:
 *
 *			 ' <fldc> ' <fmt> <sz> <elsz> <off> array-field <name>
 *
 *	The following is printed for array contents that are arrays:
 *
 *			 ' noop ' .x <sz> <elsz> <off> array-field <name>
 *
 *	The following is printed for array contents that are structs:
 *
 *			 ' noop ' <fmt> <sz> <elsz> <off> array-field <name>
 *
 *	  <fldc> is "c@", "w@", "l@", or "x@", depending on whether array
 *	    elements are 8, 16, 32 or 64 bits wide.
 *	  <fmt> defaults to ".x"
 *	  <sz> is the size of the array, in bytes
 *	  <elsz> is the size of the array elements
 *	  <off> is the member offset, in bytes
 *	  <name> is the nam eof the member being printed
 *
 *  Struct/Union:	 ' <format> <offset> struct-field <name>
 *	  <format> defaults to ".x"
 *	  <offset> is the member offset, in bytes
 *	  <name> is the name of the member being printed
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ctf_headers.h"
#include "forth.h"
#include "list.h"
#include "memory.h"

static ctf_id_t	fth_str_curtid;
static list_t	*fth_str_curmems;

/*
 * Node type for the member-storage list (fth_str_curmems) built by
 * fth_struct_members()
 */
typedef struct fth_str_mem {
	char		*fsm_memname;
	char		*fsm_format;
	ctf_id_t	fsm_tid;
	ulong_t		fsm_off;
} fth_str_mem_t;

typedef struct fth_struct_members_data {
	char		*fsmd_strname;
	char		*fsmd_memfilter;
	char		*fsmd_format;
	int		fsmd_matched;
} fth_struct_members_data_t;

static int fth_print_member(fth_str_mem_t *, int);

/* Comparison routined used to insert members into the fth_str_curmems list */
static int
fth_struct_memcmp(void *m1, void *m2)
{
	fth_str_mem_t *mem1 = m1, *mem2 = m2;

	if (mem1->fsm_off < mem2->fsm_off)
		return (1);
	else if (mem1->fsm_off > mem2->fsm_off)
		return (-1);
	else
		return (0);
}

static void
fth_free_str_mem(fth_str_mem_t *mem)
{
	free(mem->fsm_memname);
	if (mem->fsm_format)
		free(mem->fsm_format);
	free(mem);
}

static int
fth_struct_header(ctf_id_t tid)
{
	ssize_t sz;

	fth_str_curtid = tid;
	fth_str_curmems = NULL;

	if ((sz = ctf_type_size(ctf, fth_str_curtid)) == CTF_ERR)
		return (parse_warn("Can't get size for %s", fth_curtype));

	(void) fprintf(out, "\n");
	(void) fprintf(out, "vocabulary %s-words\n", fth_curtype);
	(void) fprintf(out, "h# %x constant %s-sz\n", sz, fth_curtype);
	(void) fprintf(out, "%x ' %s-words c-struct .%s\n", sz, fth_curtype,
	    fth_curtype);
	(void) fprintf(out, "also %s-words definitions\n\n", fth_curtype);

	return (0);
}

/* Print the array prefix for integer and pointer members */
static int
fth_print_level(uint_t bits, char *format)
{
	if ((bits & (bits - 1)) != 0 ||(bits % 8) != 0 || bits > 64) {
		return (parse_warn("Unexpected bit size %d in %s",
		    bits, fth_curtype));
	}

	(void) fprintf(out, "' %c@ ' %s", " cw l   x"[bits / 8], format);

	return (0);
}

/*
 * Return the format to be used to print the member.  If one of the builtin
 * formats "d" or "x" were specified, return ".d" or ".x", respectively.
 * Otherwise, use the user-provided format as is, or use the default if none
 * was provided.
 */
static char *
fth_convert_format(char *format, char *def)
{
	static char dot[3] = ".";

	if (format == NULL)
		return (def);
	else if (strlen(format) == 1) {
		dot[1] = *format;
		return (dot);
	} else
		return (format);
}

static int
fth_print_integer(const char *memname, ulong_t off, uint_t bits, char *format,
    int level)
{
	format = fth_convert_format(format, ".x");

	if (bits > 64) {
		return (parse_warn("%s.%s is too large (>8 bytes)",
		    fth_curtype, memname));
	}

	if (level != 0)
		return (fth_print_level(bits, format));

	if ((bits % NBBY) != 0 || (bits & (bits - 1)) != 0) {
		/* bit field */
		uint_t offset, shift, mask;

		offset = (off / 32) * 4;
		shift = 32 - ((off % 32) + bits);
		mask = ((1 << bits) - 1) << shift;

		(void) fprintf(out, "' %s %x %x %x bits-field %s\n",
		    format, shift, mask, offset, memname);

	} else {
		char *type[] = {
			NULL, "byte", "short", NULL, "long",
			NULL, NULL, NULL, "ext"
		};

		(void) fprintf(out, "' %s %lx %s-field %s\n", format, off / 8,
		    type[bits / 8], memname);
	}

	return (0);
}

static int
fth_print_pointer(const char *memname, ulong_t off, uint_t bits, char *format,
    int level)
{
	format = fth_convert_format(format, ".x");

	if (level != 0)
		return (fth_print_level(bits, format));

	(void) fprintf(out, "' %s %lx ptr-field %s\n", format, off / 8,
	    memname);

	return (0);
}

static int
fth_print_struct(char *memname, ulong_t off, char *format,
    int level)
{
	format = fth_convert_format(format, ".x");

	if (level != 0)
		(void) fprintf(out, "' noop ' %s", format);
	else {
		(void) fprintf(out, "' %s %lx struct-field %s\n", format,
		    off / 8, memname);
	}

	return (0);
}

static int
fth_print_enum(char *memname, ulong_t off, char *format,
    int level)
{
	format = fth_convert_format(format, ".d");

	if (level != 0)
		(void) fprintf(out, "' l@ ' %s", format);
	else {
		(void) fprintf(out, "' %s %lx long-field %s\n", format, off / 8,
		    memname);
	}

	return (0);
}

static int
fth_print_array(char *memname, ctf_id_t tid, ulong_t off, ssize_t sz,
    char *format, int level)
{
	if (level != 0)
		(void) fprintf(out, "' noop ' .x");
	else {
		fth_str_mem_t mem;
		ctf_arinfo_t ar;

		/*
		 * print the prefix for the array contents type, then print
		 * the array macro
		 */

		if (ctf_array_info(ctf, tid, &ar) == CTF_ERR) {
			return (parse_warn("Can't read array in %s.%s",
			    fth_curtype, memname));
		}

		mem.fsm_memname = memname;
		mem.fsm_format = format;
		mem.fsm_tid = ar.ctr_contents;
		mem.fsm_off = off;

		if (fth_print_member(&mem, level + 1) < 0)
			return (-1);

		(void) fprintf(out, " %x %x %lx array-field %s\n", sz,
		    (sz / ar.ctr_nelems), off / 8, memname);
	}

	return (0);
}

/* dump a structure or union member */
static int
fth_print_member(fth_str_mem_t *mem, int level)
{
	ctf_encoding_t e;
	ctf_id_t tid;
	int kind;
	ssize_t sz;

	if ((tid = ctf_type_resolve(ctf, mem->fsm_tid)) == CTF_ERR) {
		return (parse_warn("Can't resolve %s.%s", fth_curtype,
		    mem->fsm_memname));
	}

	if ((kind = ctf_type_kind(ctf, tid)) == CTF_ERR) {
		return (parse_warn("Can't get kind for %s.%s",
		    fth_curtype, mem->fsm_memname));
	}

	if ((sz = ctf_type_size(ctf, tid)) == CTF_ERR) {
		return (parse_warn("Can't get size for %s.%s",
		    fth_curtype, mem->fsm_memname));
	}

	switch (kind) {
	case CTF_K_INTEGER:
		if (ctf_type_encoding(ctf, tid, &e) == CTF_ERR)
			return (parse_warn("Can't get encoding for %ld", tid));

		return (fth_print_integer(mem->fsm_memname, mem->fsm_off,
		    e.cte_bits, mem->fsm_format, level));

	case CTF_K_FLOAT:
		(void) parse_warn("Ignoring floating point member %s.%s",
		    fth_curtype, mem->fsm_memname);
		return (0);

	case CTF_K_POINTER:
		return (fth_print_pointer(mem->fsm_memname, mem->fsm_off,
		    sz * 8, mem->fsm_format, level));

	case CTF_K_ARRAY:
		return (fth_print_array(mem->fsm_memname, tid, mem->fsm_off, sz,
		    mem->fsm_format, level));

	case CTF_K_STRUCT:
	case CTF_K_UNION:
		return (fth_print_struct(mem->fsm_memname, mem->fsm_off,
		    mem->fsm_format, level));

	case CTF_K_ENUM:
		return (fth_print_enum(mem->fsm_memname, mem->fsm_off,
		    mem->fsm_format, level));

	case CTF_K_FORWARD:
		return (parse_warn("Type %ld in %s.%s is undefined", tid,
		    fth_curtype, mem->fsm_memname));

	default:
		return (parse_warn("Unexpected kind %d for %s.%s", kind,
		    fth_curtype, mem->fsm_memname));
	}
}

/*
 * Add a member to list of members to be printed (fth_str_curmems).  If
 * fsmd_memfilter is non-null, only add this member if its name matches that
 * in the filter.
 */
static int
fth_struct_members_cb(const char *memname, ctf_id_t tid, ulong_t off, void *arg)
{
	fth_struct_members_data_t *fsmd = arg;
	fth_str_mem_t *mem;

	if (fsmd->fsmd_memfilter != NULL && strcmp(fsmd->fsmd_memfilter,
	    memname) != 0)
		return (0);

	fsmd->fsmd_matched = 1;

	mem = xcalloc(sizeof (fth_str_mem_t));
	mem->fsm_memname = xstrdup(memname);
	if (fsmd->fsmd_format)
		mem->fsm_format = xstrdup(fsmd->fsmd_format);
	mem->fsm_tid = tid;
	mem->fsm_off = off;

	slist_add(&fth_str_curmems, mem, fth_struct_memcmp);

	return (0);
}

/*
 * If memfilter is non-null, iterate through the members of this type, causing
 * every member to be added to the list.  Otherwise, use the iterator and
 * the callback to add only the specified member.
 */
static int
fth_struct_members(char *memfilter, char *format)
{
	fth_struct_members_data_t fsmd;

	fsmd.fsmd_strname = fth_curtype;
	fsmd.fsmd_memfilter = memfilter;
	fsmd.fsmd_format = format;
	fsmd.fsmd_matched = 0;

	if (ctf_member_iter(ctf, fth_str_curtid, fth_struct_members_cb,
	    &fsmd) != 0)
		return (-1);

	if (memfilter != NULL && fsmd.fsmd_matched == 0) {
		return (parse_warn("Invalid member %s.%s", fth_curtype,
		    memfilter));
	}

	return (0);
}

static int
fth_struct_trailer(void)
{
	if (list_count(fth_str_curmems) == 0) {
		if (fth_struct_members(NULL, NULL) < 0)
			return (-1);
	}

	while (!list_empty(fth_str_curmems)) {
		fth_str_mem_t *mem = list_remove(&fth_str_curmems,
		    list_first(fth_str_curmems), NULL, NULL);

		if (fth_print_member(mem, 0) < 0)
			return (-1);

		fth_free_str_mem(mem);
	}

	(void) fprintf(out, "\n");
	(void) fprintf(out, "kdbg-words definitions\n");
	(void) fprintf(out, "previous\n");
	(void) fprintf(out, "\n");
	(void) fprintf(out, "\\ end %s section\n", fth_curtype);
	(void) fprintf(out, "\n");

	return (0);
}

fth_type_ops_t fth_struct_ops = {
	fth_struct_header,
	fth_struct_members,
	fth_struct_trailer
};
