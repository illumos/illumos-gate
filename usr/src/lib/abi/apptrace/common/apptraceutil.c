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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <floatingpoint.h>
#include <libctf.h>
#include <apptrace.h>

typedef struct printarg {
	ulong_t		pa_addr;
	ctf_file_t	*pa_ctfp;
	int		pa_depth;
	int		pa_nest;
} printarg_t;

typedef void printarg_f(ctf_id_t, ulong_t, printarg_t *);

static int elt_print(const char *, ctf_id_t, ulong_t, int, void *);

const char *
type_name(ctf_file_t *ctfp, ctf_id_t type, char *buf, size_t len)
{
	if (ctf_type_name(ctfp, type, buf, len) == NULL)
		(void) snprintf(buf, len, "<%ld>", type);

	return (buf);
}

void
print_value(ctf_file_t *ctfp, ctf_id_t type, ulong_t value)
{
	ctf_id_t	rtype = ctf_type_resolve(ctfp, type);
	ctf_encoding_t	e;

	(void) fprintf(ABISTREAM, "0x%p", (void *)value);

	if (ctf_type_kind(ctfp, rtype) == CTF_K_POINTER) {
		type = ctf_type_reference(ctfp, rtype);
		rtype = ctf_type_resolve(ctfp, type);

		if (ctf_type_encoding(ctfp, rtype, &e) == 0 &&
		    (e.cte_format & (CTF_INT_CHAR | CTF_INT_SIGNED)) ==
		    (CTF_INT_CHAR | CTF_INT_SIGNED) && e.cte_bits == NBBY) {
			if ((char *)value != NULL)
				(void) fprintf(ABISTREAM,
				    " \"%s\"", (char *)value);
			else
				(void) fprintf(ABISTREAM, " <NULL>");
			(void) fflush(ABISTREAM);
			return;
		}

		if (ctf_type_kind(ctfp, rtype) == CTF_K_STRUCT) {
			printarg_t pa;

			(void) fprintf(ABISTREAM, " ");

			pa.pa_addr = value;
			pa.pa_ctfp = ctfp;
			pa.pa_nest = 0;
			pa.pa_depth = 0;

			(void) ctf_type_visit(ctfp, rtype, elt_print, &pa);
			(void) fprintf(ABISTREAM, "\t}");
			(void) fflush(ABISTREAM);
			return;
		}
	}
	(void) fflush(ABISTREAM);
}

static void
print_bitfield(ulong_t off, ctf_encoding_t *ep)
{
	uint64_t mask = (1ULL << ep->cte_bits) - 1;
	uint64_t value = 0;
#ifdef _BIG_ENDIAN
	size_t size = (ep->cte_bits + (NBBY - 1)) / NBBY;
	uint8_t *buf = (uint8_t *)&value;
#endif
	uint8_t shift;

	/*
	 * On big-endian machines, we need to adjust the buf pointer to refer
	 * to the lowest 'size' bytes in 'value', and we need shift based on
	 * the offset from the end of the data, not the offset of the start.
	 */
#ifdef _BIG_ENDIAN
	buf += sizeof (value) - size;
	off += ep->cte_bits;
#endif
	shift = off % NBBY;

	/*
	 * Offsets are counted from opposite ends on little- and
	 * big-endian machines.
	 */
#ifdef _BIG_ENDIAN
	shift = NBBY - shift;
#endif

	/*
	 * If the bits we want do not begin on a byte boundary, shift the data
	 * right so that the value is in the lowest 'cte_bits' of 'value'.
	 */
	if (off % NBBY != 0)
		value >>= shift;

	(void) fprintf(ABISTREAM, "%llu", (unsigned long long)(value & mask));
	(void) fflush(ABISTREAM);
}

/* ARGSUSED */
static void
print_int(ctf_id_t base, ulong_t off, printarg_t *pap)
{
	ctf_file_t *ctfp = pap->pa_ctfp;
	ctf_encoding_t e;
	size_t size;
	ulong_t addr = pap->pa_addr + off / NBBY;

	if (ctf_type_encoding(ctfp, base, &e) == CTF_ERR) {
		(void) fprintf(ABISTREAM, "???");
		(void) fflush(ABISTREAM);
		return;
	}

	if (e.cte_format & CTF_INT_VARARGS) {
		(void) fprintf(ABISTREAM, "...\n");
		(void) fflush(ABISTREAM);
		return;
	}

	size = e.cte_bits / NBBY;
	if (size > 8 || (e.cte_bits % NBBY) != 0 || (size & (size - 1)) != 0) {
		print_bitfield(off, &e);
		return;
	}

	if (((e).cte_format & (CTF_INT_CHAR | CTF_INT_SIGNED)) ==
	    (CTF_INT_CHAR | CTF_INT_SIGNED) && (e).cte_bits == NBBY) {
		(void) fprintf(ABISTREAM, "'%c'", *(char *)addr);
		(void) fflush(ABISTREAM);
		return;
	}

	switch (size) {
	case sizeof (uint8_t):
		(void) fprintf(ABISTREAM, "%#x", *(uint8_t *)addr);
		break;
	case sizeof (uint16_t):
		(void) fprintf(ABISTREAM, "%#x", *(uint16_t *)addr);
		break;
	case sizeof (uint32_t):
		(void) fprintf(ABISTREAM, "%#x", *(uint32_t *)addr);
		break;
	case sizeof (uint64_t):
		(void) fprintf(ABISTREAM, "%#llx",
		    (unsigned long long)*(uint64_t *)addr);
		break;
	}
	(void) fflush(ABISTREAM);
}

/* ARGSUSED */
static void
print_float(ctf_id_t base, ulong_t off, printarg_t *pap)
{
	ctf_file_t *ctfp = pap->pa_ctfp;
	ctf_encoding_t e;

	union {
		float f;
		double d;
		long double ld;
	} u;

	u.f = 0;
	if (ctf_type_encoding(ctfp, base, &e) == 0) {
		if (e.cte_format == CTF_FP_SINGLE &&
		    e.cte_bits == sizeof (float) * NBBY) {
			(void) fprintf(ABISTREAM, "%+.7e", u.f);
		} else if (e.cte_format == CTF_FP_DOUBLE &&
		    e.cte_bits == sizeof (double) * NBBY) {
			(void) fprintf(ABISTREAM, "%+.7e", u.d);
		} else if (e.cte_format == CTF_FP_LDOUBLE &&
		    e.cte_bits == sizeof (long double) * NBBY) {
			(void) fprintf(ABISTREAM,
			    "%+.16LE", u.ld);
		}
	}
	(void) fflush(ABISTREAM);
}

/* ARGSUSED */
static void
print_ptr(ctf_id_t base, ulong_t off, printarg_t *pap)
{
	ctf_file_t *ctfp = pap->pa_ctfp;
	ulong_t addr = pap->pa_addr + off / NBBY;
	ctf_encoding_t e;

	if (ctf_type_kind(ctfp, base) != CTF_K_POINTER)
		return;

	if ((base = ctf_type_reference(ctfp, base)) == CTF_ERR)
		return;

	if ((base = ctf_type_resolve(ctfp, base)) == CTF_ERR)
		return;

	if (ctf_type_encoding(ctfp, base, &e) != 0)
		return;

	if (((e).cte_format & (CTF_INT_CHAR | CTF_INT_SIGNED)) ==
	    (CTF_INT_CHAR | CTF_INT_SIGNED) && (e).cte_bits == NBBY)
		(void) fprintf(ABISTREAM, "'%c'", *(char *)addr);
	(void) fflush(ABISTREAM);
}

/* ARGSUSED */
static void
print_array(ctf_id_t base, ulong_t off, printarg_t *pap)
{
	ulong_t addr = pap->pa_addr + off / NBBY;

	(void) fprintf(ABISTREAM, "0x%p", (void *)addr);
	(void) fflush(ABISTREAM);
}

/* ARGSUSED */
static void
print_sou(ctf_id_t base, ulong_t off, printarg_t *pap)
{
	(void) fprintf(ABISTREAM, "{");
}

/* ARGSUSED */
static void
print_enum(ctf_id_t base, ulong_t off, printarg_t *pap)
{
	ctf_file_t *ctfp = pap->pa_ctfp;
	const char *ename;
	int value = 0;

	if ((ename = ctf_enum_name(ctfp, base, value)) != NULL)
		(void) fprintf(ABISTREAM, "%s", ename);
	else
		(void) fprintf(ABISTREAM, "%d", value);
	(void) fflush(ABISTREAM);
}

/* ARGSUSED */
static void
print_tag(ctf_id_t base, ulong_t off, printarg_t *pap)
{
	(void) fprintf(ABISTREAM, "; ");
}

static printarg_f *const printfuncs[] = {
	print_int,	/* CTF_K_INTEGER */
	print_float,	/* CTF_K_FLOAT */
	print_ptr,	/* CTF_K_POINTER */
	print_array,	/* CTF_K_ARRAY */
	print_ptr,	/* CTF_K_FUNCTION */
	print_sou,	/* CTF_K_STRUCT */
	print_sou,	/* CTF_K_UNION */
	print_enum,	/* CTF_K_ENUM */
	print_tag	/* CTF_K_FORWARD */
};

static int
elt_print(const char *name, ctf_id_t id, ulong_t off, int depth, void *data)
{
	char type[256];
	int kind, d;
	ctf_id_t base;
	printarg_t *pap = data;
	ctf_file_t *ctfp = pap->pa_ctfp;

	for (d = pap->pa_depth - 1; d >= depth; d--) {
		(void) fprintf(ABISTREAM, "%*s}\n",
		    (depth + pap->pa_nest) * 4, "");
	}

	if ((base = ctf_type_resolve(ctfp, id)) == CTF_ERR ||
	    (kind = ctf_type_kind(ctfp, base)) == CTF_ERR)
		return (-1);

	if (ctf_type_name(ctfp, id, type, sizeof (type)) == NULL)
		(void) snprintf(type, sizeof (type), "<%ld>", id);

	(void) fprintf(ABISTREAM, "%*s", (depth + pap->pa_nest) * 4, "");
	if (name[0] != '\0')
		(void) fprintf(ABISTREAM, "\t%s: ", name);
	(void) fprintf(ABISTREAM, "(%s) ", type);

	printfuncs[kind - 1](base, off, pap);
	(void) fprintf(ABISTREAM, "\n");

	(void) fflush(ABISTREAM);
	return (0);
}
