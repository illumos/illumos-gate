/*
 * Copyright (C) 2015 Rasmus Villemoes.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see http://www.gnu.org/copyleft/gpl.txt
 */

#include <assert.h>
#include <ctype.h>
#include <string.h>
#include "smatch.h"
#include "smatch_slist.h"

#define spam(args...) do {			\
	if (option_spammy)			\
		sm_msg(args);			\
	} while (0)

static int my_id;

/*
 * Much of this is taken directly from the kernel (mostly vsprintf.c),
 * with a few modifications here and there.
 */

#define KERN_SOH_ASCII  '\001'

typedef unsigned char u8;
typedef signed short s16;

#define SIGN	1		/* unsigned/signed, must be 1 */
#define LEFT	2		/* left justified */
#define PLUS	4		/* show plus */
#define SPACE	8		/* space if plus */
#define ZEROPAD	16		/* pad with zero, must be 16 == '0' - ' ' */
#define SMALL	32		/* use lowercase in hex (must be 32 == 0x20) */
#define SPECIAL	64		/* prefix hex with "0x", octal with "0" */

enum format_type {
	FORMAT_TYPE_NONE, /* Just a string part */
	FORMAT_TYPE_WIDTH,
	FORMAT_TYPE_PRECISION,
	FORMAT_TYPE_CHAR,
	FORMAT_TYPE_STR,
	FORMAT_TYPE_PTR,
	FORMAT_TYPE_PERCENT_CHAR,
	FORMAT_TYPE_INVALID,
	FORMAT_TYPE_LONG_LONG,
	FORMAT_TYPE_ULONG,
	FORMAT_TYPE_LONG,
	FORMAT_TYPE_UBYTE,
	FORMAT_TYPE_BYTE,
	FORMAT_TYPE_USHORT,
	FORMAT_TYPE_SHORT,
	FORMAT_TYPE_UINT,
	FORMAT_TYPE_INT,
	FORMAT_TYPE_SIZE_T,
	FORMAT_TYPE_PTRDIFF,
	FORMAT_TYPE_NRCHARS, /* Reintroduced for this checker */
	FORMAT_TYPE_FLOAT, /* for various floating point formatters */
};

struct printf_spec {
	unsigned int	type:8;		/* format_type enum */
	signed int	field_width:24;	/* width of output field */
	unsigned int	flags:8;	/* flags to number() */
	unsigned int	base:8;		/* number base, 8, 10 or 16 only */
	signed int	precision:16;	/* # of digits/chars */
} __packed;
#define FIELD_WIDTH_MAX ((1 << 23) - 1)
#define PRECISION_MAX ((1 << 15) - 1)
extern char __check_printf_spec[1-2*(sizeof(struct printf_spec) != 8)];

static int
skip_atoi(const char **s)
{
	int i = 0;

	while (isdigit(**s))
		i = i*10 + *((*s)++) - '0';

	return i;
}

static int
format_decode(const char *fmt, struct printf_spec *spec)
{
	const char *start = fmt;
	char qualifier;

	/* we finished early by reading the field width */
	if (spec->type == FORMAT_TYPE_WIDTH) {
		if (spec->field_width < 0) {
			spec->field_width = -spec->field_width;
			spec->flags |= LEFT;
		}
		spec->type = FORMAT_TYPE_NONE;
		goto precision;
	}

	/* we finished early by reading the precision */
	if (spec->type == FORMAT_TYPE_PRECISION) {
		if (spec->precision < 0)
			spec->precision = 0;

		spec->type = FORMAT_TYPE_NONE;
		goto qualifier;
	}

	/* By default */
	spec->type = FORMAT_TYPE_NONE;

	for (; *fmt ; ++fmt) {
		if (*fmt == '%')
			break;
	}

	/* Return the current non-format string */
	if (fmt != start || !*fmt)
		return fmt - start;

	/* Process flags */
	spec->flags = 0;

	while (1) { /* this also skips first '%' */
		bool found = true;

		++fmt;

		switch (*fmt) {
		case '-': spec->flags |= LEFT;    break;
		case '+': spec->flags |= PLUS;    break;
		case ' ': spec->flags |= SPACE;   break;
		case '#': spec->flags |= SPECIAL; break;
		case '0': spec->flags |= ZEROPAD; break;
		default:  found = false;
		}

		if (!found)
			break;
	}

	/* get field width */
	spec->field_width = -1;

	if (isdigit(*fmt))
		spec->field_width = skip_atoi(&fmt);
	else if (*fmt == '*') {
		/* it's the next argument */
		spec->type = FORMAT_TYPE_WIDTH;
		return ++fmt - start;
	}

precision:
	/* get the precision */
	spec->precision = -1;
	if (*fmt == '.') {
		++fmt;
		if (isdigit(*fmt)) {
			spec->precision = skip_atoi(&fmt);
			if (spec->precision < 0)
				spec->precision = 0;
		} else if (*fmt == '*') {
			/* it's the next argument */
			spec->type = FORMAT_TYPE_PRECISION;
			return ++fmt - start;
		}
	}

qualifier:
	/* get the conversion qualifier */
	qualifier = 0;
	if (*fmt == 'h' || _tolower(*fmt) == 'l' ||
	    _tolower(*fmt) == 'z' || *fmt == 't') {
		qualifier = *fmt++;
		if (qualifier == *fmt) {
			if (qualifier == 'l') {
				qualifier = 'L';
				++fmt;
			} else if (qualifier == 'h') {
				qualifier = 'H';
				++fmt;
			} else {
				sm_warning("invalid repeated qualifier '%c'", *fmt);
			}
		}
	}

	/* default base */
	spec->base = 10;
	switch (*fmt) {
	case 'c':
		if (qualifier)
			sm_warning("qualifier '%c' ignored for %%c specifier", qualifier);

		spec->type = FORMAT_TYPE_CHAR;
		return ++fmt - start;

	case 's':
		if (qualifier)
			sm_warning("qualifier '%c' ignored for %%s specifier", qualifier);

		spec->type = FORMAT_TYPE_STR;
		return ++fmt - start;

	case 'p':
		spec->type = FORMAT_TYPE_PTR;
		return ++fmt - start;

	case '%':
		spec->type = FORMAT_TYPE_PERCENT_CHAR;
		return ++fmt - start;

	/* integer number formats - set up the flags and "break" */
	case 'o':
		spec->base = 8;
		break;

	case 'x':
		spec->flags |= SMALL;

	case 'X':
		spec->base = 16;
		break;

	case 'd':
	case 'i':
		spec->flags |= SIGN;
	case 'u':
		break;

	case 'n':
		spec->type = FORMAT_TYPE_NRCHARS;
		return ++fmt - start;

	case 'a': case 'A':
	case 'e': case 'E':
	case 'f': case 'F':
	case 'g': case 'G':
		spec->type = FORMAT_TYPE_FLOAT;
		return ++fmt - start;

	default:
		spec->type = FORMAT_TYPE_INVALID;
		/* Unlike the kernel code, we 'consume' the invalid
		 * character so that it can get included in the
		 * report. After that, we bail out. */
		return ++fmt - start;
	}

	if (qualifier == 'L')
		spec->type = FORMAT_TYPE_LONG_LONG;
	else if (qualifier == 'l') {
		if (spec->flags & SIGN)
			spec->type = FORMAT_TYPE_LONG;
		else
			spec->type = FORMAT_TYPE_ULONG;
	} else if (_tolower(qualifier) == 'z') {
		spec->type = FORMAT_TYPE_SIZE_T;
	} else if (qualifier == 't') {
		spec->type = FORMAT_TYPE_PTRDIFF;
	} else if (qualifier == 'H') {
		if (spec->flags & SIGN)
			spec->type = FORMAT_TYPE_BYTE;
		else
			spec->type = FORMAT_TYPE_UBYTE;
	} else if (qualifier == 'h') {
		if (spec->flags & SIGN)
			spec->type = FORMAT_TYPE_SHORT;
		else
			spec->type = FORMAT_TYPE_USHORT;
	} else {
		if (spec->flags & SIGN)
			spec->type = FORMAT_TYPE_INT;
		else
			spec->type = FORMAT_TYPE_UINT;
	}

	return ++fmt - start;
}

static int is_struct_tag(struct symbol *type, const char *tag)
{
	return type->type == SYM_STRUCT && type->ident && !strcmp(type->ident->name, tag);
}

static int has_struct_tag(struct symbol *type, const char *tag)
{
	struct symbol *tmp;

	if (type->type == SYM_STRUCT)
		return is_struct_tag(type, tag);
	if (type->type == SYM_UNION) {
		FOR_EACH_PTR(type->symbol_list, tmp) {
			tmp = get_real_base_type(tmp);
			if (tmp && is_struct_tag(tmp, tag))
				return 1;
		} END_FOR_EACH_PTR(tmp);
	}
	return 0;
}

static int is_char_type(struct symbol *type)
{
	return type == &uchar_ctype || type == &char_ctype || type == &schar_ctype;
}

/*
 * I have absolutely no idea if this is how one is supposed to get the
 * symbol representing a typedef, but it seems to work.
 */
struct typedef_lookup {
	const char *name;
	struct symbol *sym;
	int failed;
};

static struct symbol *_typedef_lookup(const char *name)
{
	struct ident *id;
	struct symbol *node;

	id = built_in_ident(name);
	if (!id)
		return NULL;
	node = lookup_symbol(id, NS_TYPEDEF);
	if (!node || node->type != SYM_NODE)
		return NULL;
	return get_real_base_type(node);
}

static void typedef_lookup(struct typedef_lookup *tl)
{
	if (tl->sym || tl->failed)
		return;
	tl->sym = _typedef_lookup(tl->name);
	if (!tl->sym) {
		sm_perror(" could not find typedef '%s'", tl->name);
		tl->failed = 1;
	}
}


static void ip4(const char *fmt, struct symbol *type, struct symbol *basetype, int vaidx)
{
	enum { ENDIAN_BIG, ENDIAN_LITTLE, ENDIAN_HOST } endian = ENDIAN_BIG;

	assert(fmt[0] == 'i' || fmt[0] == 'I');
	assert(fmt[1] == '4');

	if (isalnum(fmt[2])) {
		switch (fmt[2]) {
		case 'h':
			endian = ENDIAN_HOST;
			break;
		case 'l':
			endian = ENDIAN_LITTLE;
			break;
		case 'n':
		case 'b':
			endian = ENDIAN_BIG;
			break;
		default:
			sm_warning("'%%p%c4' can only be followed by one of [hnbl], not '%c'", fmt[0], fmt[2]);
		}
		if (isalnum(fmt[3]))
			sm_warning("'%%p%c4' can only be followed by precisely one of [hnbl]", fmt[0]);
	}


	if (type->ctype.modifiers & MOD_NODEREF)
		sm_error("passing __user pointer to '%%p%c4'", fmt[0]);

	/*
	 * If we have a pointer to char/u8/s8, we expect the caller to
	 * handle endianness; I don't think there's anything we can
	 * do. I'd like to check that if we're passed a pointer to a
	 * __bitwise u32 (most likely a __be32), we should have endian
	 * == ENDIAN_BIG. But I can't figure out how to get that
	 * information (it also seems to require ensuring certain
	 * macros are defined). But struct in_addr certainly consists
	 * of only a single __be32, so in that case we can do a check.
	 */
	if (is_char_type(basetype))
		return;

	if (is_struct_tag(basetype, "in_addr") && endian != ENDIAN_BIG)
		sm_warning("passing struct in_addr* to '%%p%c4%c', is the endianness ok?", fmt[0], fmt[2]);

	/* ... */
}

static void ip6(const char *fmt, struct symbol *type, struct symbol *basetype, int vaidx)
{
	assert(fmt[0] == 'i' || fmt[0] == 'I');
	assert(fmt[1] == '6');

	if (isalnum(fmt[2])) {
		if (fmt[2] != 'c')
			sm_warning("'%%p%c6' can only be followed by c", fmt[0]);
		else if (fmt[0] == 'i')
			sm_warning("'%%pi6' does not allow flag c");
		if (isalnum(fmt[3]))
			sm_warning("'%%p%c6%c' cannot be followed by other alphanumerics", fmt[0], fmt[2]);
	}

	if (type->ctype.modifiers & MOD_NODEREF)
		sm_error("passing __user pointer to '%%p%c6'", fmt[0]);
}

static void ipS(const char *fmt, struct symbol *type, struct symbol *basetype, int vaidx)
{
	const char *f;

	assert(tolower(fmt[0]) == 'i');
	assert(fmt[1] == 'S');

	for (f = fmt+2; isalnum(*f); ++f) {
		/* It's probably too anal checking for duplicate flags. */
		if (!strchr("pfschnbl", *f))
			sm_warning("'%%p%cS' cannot be followed by '%c'", fmt[0], *f);
	}

	/*
	 * XXX: Should we also allow passing a pointer to a union, one
	 * member of which is a struct sockaddr? It may be slightly
	 * cleaner actually passing &u.raw instead of just &u, though
	 * the generated code is of course exactly the same. For now,
	 * we do accept struct sockaddr_in and struct sockaddr_in6,
	 * since those are easy to handle and rather harmless.
	 */
	if (!has_struct_tag(basetype, "sockaddr") &&
	    !has_struct_tag(basetype, "sockaddr_in") &&
	    !has_struct_tag(basetype, "sockaddr_in6") &&
	    !has_struct_tag(basetype, "__kernel_sockaddr_storage"))
		sm_error("'%%p%cS' expects argument of type struct sockaddr *, "
			"argument %d has type '%s'", fmt[0], vaidx, type_to_str(type));
}

static void hex_string(const char *fmt, struct symbol *type, struct symbol *basetype, int vaidx)
{
	assert(fmt[0] == 'h');
	if (isalnum(fmt[1])) {
		if (!strchr("CDN", fmt[1]))
			sm_warning("'%%ph' cannot be followed by '%c'", fmt[1]);
		if (isalnum(fmt[2]))
			sm_warning("'%%ph' can be followed by at most one of [CDN], and no other alphanumerics");
	}
	if (type->ctype.modifiers & MOD_NODEREF)
		sm_error("passing __user pointer to %%ph");
}

static void escaped_string(const char *fmt, struct symbol *type, struct symbol *basetype, int vaidx)
{
	assert(fmt[0] == 'E');
	while (isalnum(*++fmt)) {
		if (!strchr("achnops", *fmt))
			sm_warning("%%pE can only be followed by a combination of [achnops]");
	}
	if (type->ctype.modifiers & MOD_NODEREF)
		sm_error("passing __user pointer to %%pE");
}

static void resource_string(const char *fmt, struct symbol *type, struct symbol *basetype, int vaidx)
{
	assert(tolower(fmt[0]) == 'r');
	if (!is_struct_tag(basetype, "resource")) {
		sm_error("'%%p%c' expects argument of type struct resource *, "
			"but argument %d has type '%s'", fmt[0], vaidx, type_to_str(type));
	}
	if (isalnum(fmt[1]))
		sm_warning("'%%p%c' cannot be followed by '%c'", fmt[0], fmt[1]);
}

static void mac_address_string(const char *fmt, struct symbol *type, struct symbol *basetype, int vaidx)
{
	assert(tolower(fmt[0]) == 'm');
	if (isalnum(fmt[1])) {
		if (!(fmt[1] == 'F' || fmt[1] == 'R'))
			sm_warning("'%%p%c' cannot be followed by '%c'", fmt[0], fmt[1]);
		if (fmt[0] == 'm' && fmt[1] == 'F')
			sm_warning("it is pointless to pass flag F to %%pm");
		if (isalnum(fmt[2]))
			sm_warning("'%%p%c%c' cannot be followed by other alphanumeric", fmt[0], fmt[1]);
	}
	/* Technically, bdaddr_t is a typedef for an anonymous struct, but this still seems to work. */
	if (!is_char_type(basetype) && !is_struct_tag(basetype, "bdaddr_t") && basetype != &void_ctype) {
		sm_warning("'%%p%c' expects argument of type u8 * or bdaddr_t *, argument %d has type '%s'",
			fmt[0], vaidx, type_to_str(type));
	}
	if (type->ctype.modifiers & MOD_NODEREF)
		sm_error("passing __user pointer to '%%p%c'", fmt[0]);
}

static void dentry_file(const char *fmt, struct symbol *type, struct symbol *basetype, int vaidx)
{
	const char *tag;

	assert(tolower(fmt[0]) == 'd');
	tag = fmt[0] == 'd' ? "dentry" : "file";

	if (isalnum(fmt[1])) {
		if (!strchr("234", fmt[1]))
			sm_warning("'%%p%c' can only be followed by one of [234]", fmt[0]);
		if (isalnum(fmt[2]))
			sm_warning("'%%p%c%c' cannot be followed by '%c'", fmt[0], fmt[1], fmt[2]);
	}

	if (!is_struct_tag(basetype, tag))
		sm_error("'%%p%c' expects argument of type struct '%s*', argument %d has type '%s'",
			fmt[0], tag, vaidx, type_to_str(type));
}

static void check_clock(const char *fmt, struct symbol *type, struct symbol *basetype, int vaidx)
{
	assert(fmt[0] == 'C');
	if (isalnum(fmt[1])) {
		if (!strchr("nr", fmt[1]))
			sm_warning("'%%pC' can only be followed by one of [nr]");
		if (isalnum(fmt[2]))
			sm_warning("'%%pC%c' cannot be followed by '%c'", fmt[1], fmt[2]);
	}
	if (!is_struct_tag(basetype, "clk"))
		sm_error("'%%pC' expects argument of type 'struct clk*', argument %d has type '%s'",
		       vaidx, type_to_str(type));
}

static void va_format(const char *fmt, struct symbol *type, struct symbol *basetype, int vaidx)
{
	assert(fmt[0] == 'V');
	if (isalnum(fmt[1]))
		sm_warning("%%pV cannot be followed by any alphanumerics");
	if (!is_struct_tag(basetype, "va_format"))
		sm_error("%%pV expects argument of type struct va_format*, argument %d has type '%s'", vaidx, type_to_str(type));
}

static void netdev_feature(const char *fmt, struct symbol *type, struct symbol *basetype, int vaidx)
{
	static struct typedef_lookup netdev = { .name = "netdev_features_t" };

	assert(fmt[0] == 'N');
	if (fmt[1] != 'F') {
		sm_error("%%pN must be followed by 'F'");
		return;
	}
	if (isalnum(fmt[2]))
		sm_warning("%%pNF cannot be followed by '%c'", fmt[2]);

	typedef_lookup(&netdev);
	if (!netdev.sym)
		return;
	if (basetype != netdev.sym)
		sm_error("%%pNF expects argument of type netdev_features_t*, argument %d has type '%s'",
			vaidx, type_to_str(type));

}
static void address_val(const char *fmt, struct symbol *type, struct symbol *basetype, int vaidx)
{
	static struct typedef_lookup dma = { .name = "dma_addr_t" };
	static struct typedef_lookup phys = { .name = "phys_addr_t" };
	struct typedef_lookup *which = &phys;
	const char *suf = "";
	assert(fmt[0] == 'a');

	if (isalnum(fmt[1])) {
		switch (fmt[1]) {
		case 'd':
			which = &dma;
			suf = "d";
			break;
		case 'p':
			suf = "p";
			break;
		default:
			sm_error("'%%pa' can only be followed by one of [dp]");
		}
		if (isalnum(fmt[2]))
			sm_error("'%%pa%c' cannot be followed by '%c'", fmt[1], fmt[2]);
	}

	typedef_lookup(which);
	if (!which->sym)
		return;
	if (basetype != which->sym) {
		sm_error("'%%pa%s' expects argument of type '%s*', argument %d has type '%s'",
			suf, which->name, vaidx, type_to_str(type));
	}
}

static void block_device(const char *fmt, struct symbol *type, struct symbol *basetype, int vaidx)
{
	const char *tag = "block_device";

	assert(fmt[0] == 'g');
	if (isalnum(fmt[1])) {
		sm_warning("%%pg cannot be followed by '%c'", fmt[1]);
	}
	if (!is_struct_tag(basetype, tag))
		sm_error("'%%p%c' expects argument of type struct '%s*', argument %d has type '%s'",
			fmt[0], tag, vaidx, type_to_str(type));
}

static void flag_string(const char *fmt, struct symbol *type, struct symbol *basetype, int vaidx)
{
	static struct typedef_lookup gfp = { .name = "gfp_t" };

	assert(fmt[0] == 'G');
	if (!isalnum(fmt[1])) {
		sm_error("%%pG must be followed by one of [gpv]");
		return;
	}
	switch (fmt[1]) {
	case 'p':
	case 'v':
		if (basetype != &ulong_ctype)
			sm_error("'%%pG%c' expects argument of type 'unsigned long *', argument %d has type '%s'",
				fmt[1], vaidx, type_to_str(type));
		break;
	case 'g':
		typedef_lookup(&gfp);
		if (basetype != gfp.sym)
			sm_error("'%%pGg' expects argument of type 'gfp_t *', argument %d has type '%s'",
				vaidx, type_to_str(type));
		break;
	default:
		sm_error("'%%pG' must be followed by one of [gpv]");
	}
}

static void device_node_string(const char *fmt, struct symbol *type, struct symbol *basetype, int vaidx)
{
	if (fmt[1] != 'F') {
		sm_error("%%pO can only be followed by 'F'");
		return;
	}
	if (!is_struct_tag(basetype, "device_node"))
		sm_error("'%%pOF' expects argument of type 'struct device_node*', argument %d has type '%s'",
		       vaidx, type_to_str(type));
}

static void
pointer(const char *fmt, struct expression *arg, int vaidx)
{
	struct symbol *type, *basetype;

	type = get_type(arg);
	if (!type) {
		sm_warning("could not determine type of argument %d", vaidx);
		return;
	}
	if (!is_ptr_type(type)) {
		sm_error("%%p expects pointer argument, but argument %d has type '%s'",
			vaidx, type_to_str(type));
		return;
	}
	/* Just plain %p, nothing to check. */
	if (!isalnum(*fmt))
		return;

	basetype = get_real_base_type(type);
	if (is_void_type(basetype))
		return;
	/*
	 * Passing a pointer-to-array is harmless, but most likely one
	 * meant to pass pointer-to-first-element. If basetype is
	 * array type, we issue a notice and "dereference" the types
	 * once more.
	 */
	if (basetype->type == SYM_ARRAY) {
		spam("note: passing pointer-to-array; is the address-of redundant?");
		type = basetype;
		basetype = get_real_base_type(type);
	}

	/*
	 * We pass both the type and the basetype to the helpers. If,
	 * for example, the pointer is really a decayed array which is
	 * passed to %pI4, we might want to check that it is in fact
	 * an array of four bytes. But most are probably only
	 * interested in whether the basetype makes sense. Also, the
	 * pointer may carry some annotation such as __user which
	 * might be worth checking in the handlers which actually
	 * dereference the pointer.
	 */

	switch (*fmt) {
	case 'b':
	case 'F':
	case 'f':
	case 'S':
	case 's':
	case 'B':
		/* Can we do anything sensible? Check that the arg is a function pointer, for example? */
		break;

	case 'R':
	case 'r':
		resource_string(fmt, type, basetype, vaidx);
		break;
	case 'M':
	case 'm':
		mac_address_string(fmt, type, basetype, vaidx);
		break;
	case 'I':
	case 'i':
		switch (fmt[1]) {
		case '4':
			ip4(fmt, type, basetype, vaidx);
			break;
		case '6':
			ip6(fmt, type, basetype, vaidx);
			break;
		case 'S':
			ipS(fmt, type, basetype, vaidx);
			break;
		default:
			sm_warning("'%%p%c' must be followed by one of [46S]", fmt[0]);
			break;
		}
		break;
       /*
	* %pE and %ph can handle any valid pointer. We still check
	* whether all the subsequent alphanumerics are valid for the
	* particular %pX conversion.
	*/
	case 'E':
		escaped_string(fmt, type, basetype, vaidx);
		break;
	case 'h':
		hex_string(fmt, type, basetype, vaidx);
		break;
	case 'U': /* TODO */
		break;
	case 'V':
		va_format(fmt, type, basetype, vaidx);
		break;
	case 'K': /* TODO */
		break;
	case 'N':
		netdev_feature(fmt, type, basetype, vaidx);
		break;
	case 'a':
		address_val(fmt, type, basetype, vaidx);
		break;
	case 'D':
	case 'd':
		dentry_file(fmt, type, basetype, vaidx);
		break;
	case 'C':
		check_clock(fmt, type, basetype, vaidx);
		break;
	case 'g':
		block_device(fmt, type, basetype, vaidx);
		break;
	case 'G':
		flag_string(fmt, type, basetype, vaidx);
		break;
	case 'O':
		device_node_string(fmt, type, basetype, vaidx);
		break;
	case 'x':
		/* 'x' is for an unhashed pointer */
		break;
	default:
		sm_error("unrecognized %%p extension '%c', treated as normal %%p", *fmt);
	}
}

/*
 * A common error is to pass a "char" or "signed char" to %02x (or
 * %.2X or some other variant). This can actually be a security
 * problem, because a lot of code expects this to produce exactly two
 * characters of output. Unfortunately this also produces false
 * positives, since we're sometimes in arch-specific code on an arch
 * where char is always unsigned.
 */
static void
hexbyte(const char *fmt, int fmt_len, struct expression *arg, int vaidx, struct printf_spec spec)
{
	struct symbol *type;

	/*
	 * For now, just check the most common and obvious, which is
	 * roughly %[.0]2[xX].
	 */
	if (spec.field_width != 2 && spec.precision != 2)
		return;
	if (spec.base != 16)
		return;

	type = get_type(arg);
	if (!type) {
		sm_warning("could not determine type of argument %d", vaidx);
		return;
	}
	if (type == &char_ctype || type == &schar_ctype)
		sm_warning("argument %d to %.*s specifier has type '%s'",
		       vaidx, fmt_len, fmt, type_to_str(type));
}

static int
check_format_string(const char *fmt, const char *caller)
{
	const char *f;

	for (f = fmt; *f; ++f) {
		unsigned char c = *f;
		switch (c) {
		case KERN_SOH_ASCII:
			/*
			 * This typically arises from bad conversion
			 * to pr_*, e.g. pr_warn(KERN_WARNING "something").
			 */
			if (f != fmt)
				sm_warning("KERN_* level not at start of string");
			/*
			 * In a very few cases, the level is actually
			 * computed and passed via %c, as in KERN_SOH
			 * "%c...". printk explicitly supports
			 * this.
			 */
			if (!(('0' <= f[1] && f[1] <= '7') ||
			      f[1] == 'd' || /* KERN_DEFAULT */
			      f[1] == 'c' || /* KERN_CONT */
			      (f[1] == '%' && f[2] == 'c')))
				sm_warning("invalid KERN_* level: KERN_SOH_ASCII followed by '\\x%02x'", (unsigned char)f[1]);
			break;
		case '\t':
		case '\n':
		case '\r':
		case 0x20 ... 0x7e:
			break;
		case 0x80 ... 0xff:
			sm_warning("format string contains non-ascii character '\\x%02x'", c);
			break;
		case 0x08:
			if (f == fmt)
				break;
			/* fall through */
		default:
			sm_warning("format string contains unusual character '\\x%02x'", c);
			break;
		}
	}

	f = strstr(fmt, caller);
	if (f && strstr(f+1, caller))
		sm_warning("format string contains name of enclosing function '%s' twice", caller);

	return f != NULL;
}

static int arg_is___func__(struct expression *arg)
{
	if (arg->type != EXPR_SYMBOL)
		return 0;
	return !strcmp(arg->symbol_name->name, "__func__") ||
	       !strcmp(arg->symbol_name->name, "__FUNCTION__") ||
	       !strcmp(arg->symbol_name->name, "__PRETTY_FUNCTION__");
}
static int arg_contains_caller(struct expression *arg, const char *caller)
{
	if (arg->type != EXPR_STRING)
		return 0;
	return strstr(arg->string->data, caller) != NULL;
}

static int is_array_of_const_char(struct symbol *sym)
{
	struct symbol *base = sym->ctype.base_type;
	if (base->type != SYM_ARRAY)
		return 0;
	if (!(base->ctype.modifiers & MOD_CONST))
		return 0;
	if (!is_char_type(base->ctype.base_type)) {
		spam("weird: format argument is array of const '%s'", type_to_str(base->ctype.base_type));
		return 0;
	}
	return 1;
}

static int is_const_pointer_to_const_char(struct symbol *sym)
{
	struct symbol *base = sym->ctype.base_type;
	if (!(sym->ctype.modifiers & MOD_CONST))
		return 0;
	if (base->type != SYM_PTR)
		return 0;
	if (!(base->ctype.modifiers & MOD_CONST))
		return 0;
	if (!is_char_type(base->ctype.base_type)) {
		spam("weird: format argument is pointer to const '%s'", type_to_str(base->ctype.base_type));
		return 0;
	}
	return 1;
}

static int unknown_format(struct expression *expr)
{
	struct state_list *slist;

	slist = get_strings(expr);
	if (!slist)
		return 1;
	if (slist_has_state(slist, &undefined))
		return 1;
	free_slist(&slist);
	return 0;
}

static bool has_hex_prefix(const char *orig_fmt, const char *old_fmt)
{
	return old_fmt >= orig_fmt + 2 &&
		old_fmt[-2] == '0' && _tolower(old_fmt[-1]) == 'x';
}

static bool is_integer_specifier(int type)
{
	switch (type) {
	case FORMAT_TYPE_LONG_LONG:
	case FORMAT_TYPE_ULONG:
	case FORMAT_TYPE_LONG:
	case FORMAT_TYPE_UBYTE:
	case FORMAT_TYPE_BYTE:
	case FORMAT_TYPE_USHORT:
	case FORMAT_TYPE_SHORT:
	case FORMAT_TYPE_UINT:
	case FORMAT_TYPE_INT:
	case FORMAT_TYPE_SIZE_T:
	case FORMAT_TYPE_PTRDIFF:
		return true;
	default:
		return false;
	}
}

static int
is_cast_expr(struct expression *expr)
{
	if (!expr)
		return 0;

	switch (expr->type) {
	case EXPR_CAST:
	case EXPR_FORCE_CAST:
		/* not EXPR_IMPLIED_CAST for our purposes */
		return 1;
	default:
		return 0;
	}
}

static void
check_cast_from_pointer(const char *fmt, int len, struct expression *arg, int va_idx)
{
	/*
	 * This can easily be fooled by passing 0+(long)ptr or doing
	 * "long local_var = (long)ptr" and passing local_var to
	 * %lx. Tough.
	 */
	if (!is_cast_expr(arg))
		return;
	while (is_cast_expr(arg))
		arg = arg->cast_expression;
	if (is_ptr_type(get_final_type(arg)))
		sm_warning("argument %d to %.*s specifier is cast from pointer",
			va_idx, len, fmt);
}

static void
do_check_printf_call(const char *caller, const char *name, struct expression *callexpr, struct expression *fmtexpr, int vaidx)
{
	struct printf_spec spec = {0};
	const char *fmt, *orig_fmt;
	int caller_in_fmt;

	fmtexpr = strip_parens(fmtexpr);
	if (fmtexpr->type == EXPR_CONDITIONAL) {
		do_check_printf_call(caller, name, callexpr, fmtexpr->cond_true ? : fmtexpr->conditional, vaidx);
		do_check_printf_call(caller, name, callexpr, fmtexpr->cond_false, vaidx);
		return;
	}
	if (fmtexpr->type == EXPR_SYMBOL) {
		/*
		 * If the symbol has an initializer, we can handle
		 *
		 *   const char foo[] = "abc";         and
		 *   const char * const foo = "abc";
		 *
		 * We simply replace fmtexpr with the initializer
		 * expression. If foo is not one of the above, or if
		 * the initializer expression is somehow not a string
		 * literal, fmtexpr->type != EXPR_STRING will trigger
		 * below and we'll spam+return.
		 */
		struct symbol *sym = fmtexpr->symbol;
		if (sym && sym->initializer &&
		    (is_array_of_const_char(sym) ||
		     is_const_pointer_to_const_char(sym))) {
			fmtexpr = strip_parens(sym->initializer);
		}
	}

	if (fmtexpr->type != EXPR_STRING) {
		if (!unknown_format(fmtexpr))
			return;
		/*
		 * Since we're now handling both ?: and static const
		 * char[] arguments, we don't get as much noise. It's
		 * still spammy, though.
		 */
		spam("warn: call of '%s' with non-constant format argument", name);
		return;
	}

	orig_fmt = fmt = fmtexpr->string->data;
	caller_in_fmt = check_format_string(fmt, caller);

	while (*fmt) {
		const char *old_fmt = fmt;
		int read = format_decode(fmt, &spec);
		struct expression *arg;

		fmt += read;
		if (spec.type == FORMAT_TYPE_NONE ||
		    spec.type == FORMAT_TYPE_PERCENT_CHAR)
			continue;

		/*
		 * vaidx is currently the correct 0-based index for
		 * get_argument_from_call_expr. We post-increment it
		 * here so that it is the correct 1-based index for
		 * all the handlers below. This of course requires
		 * that we handle all FORMAT_TYPE_* things not taking
		 * an argument above.
		 */
		arg = get_argument_from_call_expr(callexpr->args, vaidx++);

		if (spec.flags & SPECIAL && has_hex_prefix(orig_fmt, old_fmt))
			sm_warning("'%.2s' prefix is redundant when # flag is used", old_fmt-2);
		if (is_integer_specifier(spec.type)) {
			if (spec.base != 16 && has_hex_prefix(orig_fmt, old_fmt))
				sm_warning("'%.2s' prefix is confusing together with '%.*s' specifier",
				       old_fmt-2, (int)(fmt-old_fmt), old_fmt);

			check_cast_from_pointer(old_fmt, read, arg, vaidx);
		}

		switch (spec.type) {
		/* case FORMAT_TYPE_NONE: */
		/* case FORMAT_TYPE_PERCENT_CHAR: */
		/* 	break; */

		case FORMAT_TYPE_INVALID:
			sm_error("format specifier '%.*s' invalid", read, old_fmt);
			return;

		case FORMAT_TYPE_FLOAT:
			sm_error("no floats in the kernel; invalid format specifier '%.*s'", read, old_fmt);
			return;

		case FORMAT_TYPE_NRCHARS:
			sm_error("%%n not supported in kernel");
			return;

		case FORMAT_TYPE_WIDTH:
		case FORMAT_TYPE_PRECISION:
			/* check int argument */
			break;

		case FORMAT_TYPE_STR:
			/*
			 * If the format string already contains the
			 * function name, it probably doesn't make
			 * sense to pass __func__ as well (or rather
			 * vice versa: If pr_fmt(fmt) has been defined
			 * to '"%s: " fmt, __func__', it doesn't make
			 * sense to use a format string containing the
			 * function name).
			 *
			 * This produces a lot of hits. They are not
			 * false positives, but it is easier to handle
			 * the things which don't occur that often
			 * first, so we use spam().
			 */
			if (caller_in_fmt) {
				if (arg_is___func__(arg))
					spam("warn: passing __func__ while the format string already contains the name of the function '%s'",
					     caller);
				else if (arg_contains_caller(arg, caller))
					sm_warning("passing string constant '%s' containing '%s' which is already part of the format string",
					       arg->string->data, caller);
			}
			break;

		case FORMAT_TYPE_PTR:
			/* This is the most important part: Checking %p extensions. */
			pointer(fmt, arg, vaidx);
			while (isalnum(*fmt))
				fmt++;
			break;

		case FORMAT_TYPE_CHAR:

		case FORMAT_TYPE_UBYTE:
		case FORMAT_TYPE_BYTE:
		case FORMAT_TYPE_USHORT:
		case FORMAT_TYPE_SHORT:
		case FORMAT_TYPE_INT:
			/* argument should have integer type of width <= sizeof(int) */
			break;

		case FORMAT_TYPE_UINT:
			hexbyte(old_fmt, fmt-old_fmt, arg, vaidx, spec);
		case FORMAT_TYPE_LONG:
		case FORMAT_TYPE_ULONG:
		case FORMAT_TYPE_LONG_LONG:
		case FORMAT_TYPE_PTRDIFF:
		case FORMAT_TYPE_SIZE_T:
			break;
		}


	}

	if (get_argument_from_call_expr(callexpr->args, vaidx))
		sm_warning("excess argument passed to '%s'", name);


}

static void
check_printf_call(const char *name, struct expression *callexpr, void *_info)
{
	/*
	 * Note: attribute(printf) uses 1-based indexing, but
	 * get_argument_from_call_expr() uses 0-based indexing.
	 */
	int info = PTR_INT(_info);
	int fmtidx = (info & 0xff) - 1;
	int vaidx = ((info >> 8) & 0xff) - 1;
	struct expression *fmtexpr;
	const char *caller = get_function();

	if (!caller)
		return;

	/*
	 * Calling a v*printf function with a literal format arg is
	 * extremely rare, so we don't bother doing the only checking
	 * we could do, namely checking that the format string is
	 * valid.
	 */
	if (vaidx < 0)
		return;

	/*
	 * For the things we use the name of the calling function for,
	 * it is more appropriate to skip a potential SyS_ prefix; the
	 * same goes for leading underscores.
	 */
	if (!strncmp(caller, "SyS_", 4))
		caller += 4;
	while (*caller == '_')
		++caller;

	/* Lack of format argument is a bug. */
	fmtexpr = get_argument_from_call_expr(callexpr->args, fmtidx);
	if (!fmtexpr) {
		sm_error("call of '%s' with no format argument", name);
		return;
	}

	do_check_printf_call(caller, name, callexpr, fmtexpr, vaidx);
}


void check_kernel_printf(int id)
{
	if (option_project != PROJ_KERNEL)
		return;

	my_id = id;

#define printf_hook(func, fmt, first_to_check)	\
	add_function_hook(#func, check_printf_call, INT_PTR(fmt + (first_to_check << 8)))

	/* Extracted using stupid perl script. */

#if 0
	printf_hook(srm_printk, 1, 2);                    /* arch/alpha/include/asm/console.h */
	printf_hook(die_if_kernel, 1, 2);                 /* arch/frv/include/asm/bug.h */
	printf_hook(ia64_mca_printk, 1, 2);               /* arch/ia64/include/asm/mca.h */
	printf_hook(nfprint, 1, 2);                       /* arch/m68k/include/asm/natfeat.h */
	printf_hook(gdbstub_printk, 1, 2);                /* arch/mn10300/include/asm/gdb-stub.h */
	printf_hook(DBG, 1, 2);                           /* arch/powerpc/boot/ps3.c */
	printf_hook(printf, 1, 2);                        /* arch/powerpc/boot/stdio.h */
	printf_hook(udbg_printf, 1, 2);                   /* arch/powerpc/include/asm/udbg.h */
	printf_hook(__debug_sprintf_event, 3, 4);         /* arch/s390/include/asm/debug.h */
	printf_hook(__debug_sprintf_exception, 3, 4);     /* arch/s390/include/asm/debug.h */
	printf_hook(prom_printf, 1, 2);                   /* arch/sparc/include/asm/oplib_32.h */

	printf_hook(fail, 1, 2);                          /* arch/x86/vdso/vdso2c.c */
#endif

	printf_hook(_ldm_printk, 3, 4);                   /* block/partitions/ldm.c */
	printf_hook(rbd_warn, 2, 3);                      /* drivers/block/rbd.c */
	printf_hook(fw_err, 2, 3);                        /* drivers/firewire/core.h */
	printf_hook(fw_notice, 2, 3);                     /* drivers/firewire/core.h */
	printf_hook(i915_error_printf, 2, 3);             /* drivers/gpu/drm/i915/i915_drv.h */
	printf_hook(i915_handle_error, 3, 4);             /* drivers/gpu/drm/i915/i915_drv.h */
	printf_hook(nv_printk_, 3, 4);                    /* drivers/gpu/drm/nouveau/core/include/core/printk.h */
	printf_hook(host1x_debug_output, 2, 3);           /* drivers/gpu/host1x/debug.h */
	printf_hook(callc_debug, 2, 3);                   /* drivers/isdn/hisax/callc.c */
	printf_hook(link_debug, 3, 4);                    /* drivers/isdn/hisax/callc.c */
	printf_hook(HiSax_putstatus, 3, 4);               /* drivers/isdn/hisax/hisax.h */
	printf_hook(VHiSax_putstatus, 3, 0);              /* drivers/isdn/hisax/hisax.h */
	printf_hook(debugl1, 2, 3);                       /* drivers/isdn/hisax/isdnl1.h */
	printf_hook(l3m_debug, 2, 3);                     /* drivers/isdn/hisax/isdnl3.c */
	printf_hook(dout_debug, 2, 3);                    /* drivers/isdn/hisax/st5481_d.c */
	printf_hook(l1m_debug, 2, 3);                     /* drivers/isdn/hisax/st5481_d.c */
	printf_hook(bch_cache_set_error, 2, 3);           /* drivers/md/bcache/bcache.h */
	printf_hook(_tda_printk, 4, 5);                   /* drivers/media/tuners/tda18271-priv.h */
	printf_hook(i40evf_debug_d, 3, 4);                /* drivers/net/ethernet/intel/i40evf/i40e_osdep.h */
	printf_hook(en_print, 3, 4);                      /* drivers/net/ethernet/mellanox/mlx4/mlx4_en.h */
	printf_hook(_ath_dbg, 3, 4);                      /* drivers/net/wireless/ath/ath.h */
	printf_hook(ath_printk, 3, 4);                    /* drivers/net/wireless/ath/ath.h */
	printf_hook(ath10k_dbg, 3, 4);                    /* drivers/net/wireless/ath/ath10k/debug.h */
	printf_hook(ath10k_err, 2, 3);                    /* drivers/net/wireless/ath/ath10k/debug.h */
	printf_hook(ath10k_info, 2, 3);                   /* drivers/net/wireless/ath/ath10k/debug.h */
	printf_hook(ath10k_warn, 2, 3);                   /* drivers/net/wireless/ath/ath10k/debug.h */
	printf_hook(_ath5k_printk, 3, 4);                 /* drivers/net/wireless/ath/ath5k/ath5k.h */
	printf_hook(ATH5K_DBG, 3, 4);                     /* drivers/net/wireless/ath/ath5k/debug.h */
	printf_hook(ATH5K_DBG_UNLIMIT, 3, 4);             /* drivers/net/wireless/ath/ath5k/debug.h */
	printf_hook(ath6kl_printk, 2, 3);                 /* drivers/net/wireless/ath/ath6kl/common.h */
	printf_hook(ath6kl_err, 1, 2);                    /* drivers/net/wireless/ath/ath6kl/debug.h */
	printf_hook(ath6kl_info, 1, 2);                   /* drivers/net/wireless/ath/ath6kl/debug.h */
	printf_hook(ath6kl_warn, 1, 2);                   /* drivers/net/wireless/ath/ath6kl/debug.h */
	printf_hook(wil_dbg_trace, 2, 3);                 /* drivers/net/wireless/ath/wil6210/wil6210.h */
	printf_hook(wil_err, 2, 3);                       /* drivers/net/wireless/ath/wil6210/wil6210.h */
	printf_hook(wil_err_ratelimited, 2, 3);           /* drivers/net/wireless/ath/wil6210/wil6210.h */
	printf_hook(wil_info, 2, 3);                      /* drivers/net/wireless/ath/wil6210/wil6210.h */
	printf_hook(b43dbg, 2, 3);                        /* drivers/net/wireless/b43/b43.h */
	printf_hook(b43err, 2, 3);                        /* drivers/net/wireless/b43/b43.h */
	printf_hook(b43info, 2, 3);                       /* drivers/net/wireless/b43/b43.h */
	printf_hook(b43warn, 2, 3);                       /* drivers/net/wireless/b43/b43.h */
	printf_hook(b43legacydbg, 2, 3);                  /* drivers/net/wireless/b43legacy/b43legacy.h */
	printf_hook(b43legacyerr, 2, 3);                  /* drivers/net/wireless/b43legacy/b43legacy.h */
	printf_hook(b43legacyinfo, 2, 3);                 /* drivers/net/wireless/b43legacy/b43legacy.h */
	printf_hook(b43legacywarn, 2, 3);                 /* drivers/net/wireless/b43legacy/b43legacy.h */
	printf_hook(__brcmf_dbg, 3, 4);                   /* drivers/net/wireless/brcm80211/brcmfmac/debug.h */
	printf_hook(__brcmf_err, 2, 3);                   /* drivers/net/wireless/brcm80211/brcmfmac/debug.h */
	printf_hook(__brcms_crit, 2, 3);                  /* drivers/net/wireless/brcm80211/brcmsmac/debug.h */
	printf_hook(__brcms_dbg, 4, 5);                   /* drivers/net/wireless/brcm80211/brcmsmac/debug.h */
	printf_hook(__brcms_err, 2, 3);                   /* drivers/net/wireless/brcm80211/brcmsmac/debug.h */
	printf_hook(__brcms_info, 2, 3);                  /* drivers/net/wireless/brcm80211/brcmsmac/debug.h */
	printf_hook(__brcms_warn, 2, 3);                  /* drivers/net/wireless/brcm80211/brcmsmac/debug.h */
	printf_hook(brcmu_dbg_hex_dump, 3, 4);            /* drivers/net/wireless/brcm80211/include/brcmu_utils.h */
	printf_hook(__iwl_crit, 2, 3);                    /* drivers/net/wireless/iwlwifi/iwl-debug.h */
	printf_hook(__iwl_dbg, 5, 6);                     /* drivers/net/wireless/iwlwifi/iwl-debug.h */
	printf_hook(__iwl_err, 4, 5);                     /* drivers/net/wireless/iwlwifi/iwl-debug.h */
	printf_hook(__iwl_info, 2, 3);                    /* drivers/net/wireless/iwlwifi/iwl-debug.h */
	printf_hook(__iwl_warn, 2, 3);                    /* drivers/net/wireless/iwlwifi/iwl-debug.h */
	printf_hook(rsi_dbg, 2, 3);                       /* drivers/net/wireless/rsi/rsi_main.h */
	printf_hook(RTPRINT, 4, 5);                       /* drivers/net/wireless/rtlwifi/debug.h */
	printf_hook(RT_ASSERT, 2, 3);                     /* drivers/net/wireless/rtlwifi/debug.h */
	printf_hook(RT_TRACE, 4, 5);                      /* drivers/net/wireless/rtlwifi/debug.h */
	printf_hook(__of_node_dup, 2, 3);                 /* drivers/of/of_private.h */
	printf_hook(BNX2FC_HBA_DBG, 2, 3);                /* drivers/scsi/bnx2fc/bnx2fc_debug.h */
	printf_hook(BNX2FC_IO_DBG, 2, 3);                 /* drivers/scsi/bnx2fc/bnx2fc_debug.h */
	printf_hook(BNX2FC_TGT_DBG, 2, 3);                /* drivers/scsi/bnx2fc/bnx2fc_debug.h */
	printf_hook(ql_dbg, 4, 5);                        /* drivers/scsi/qla2xxx/qla_dbg.h */
	printf_hook(ql_dbg_pci, 4, 5);                    /* drivers/scsi/qla2xxx/qla_dbg.h */
	printf_hook(ql_log, 4, 5);                        /* drivers/scsi/qla2xxx/qla_dbg.h */
	printf_hook(ql_log_pci, 4, 5);                    /* drivers/scsi/qla2xxx/qla_dbg.h */
	printf_hook(libcfs_debug_msg, 2, 3);              /* drivers/staging/lustre/include/linux/libcfs/libcfs_debug.h */
	printf_hook(libcfs_debug_vmsg2, 4, 5);            /* drivers/staging/lustre/include/linux/libcfs/libcfs_debug.h */
	printf_hook(_ldlm_lock_debug, 3, 4);              /* drivers/staging/lustre/lustre/include/lustre_dlm.h */
	printf_hook(_debug_req, 3, 4);                    /* drivers/staging/lustre/lustre/include/lustre_net.h */
	printf_hook(iscsi_change_param_sprintf, 2, 3);    /* drivers/target/iscsi/iscsi_target_login.c */
	printf_hook(dbg, 1, 2);                           /* drivers/tty/serial/samsung.c */
	printf_hook(_usb_stor_dbg, 2, 3);                 /* drivers/usb/storage/debug.h */
	printf_hook(usb_stor_dbg, 2, 3);                  /* drivers/usb/storage/debug.h */
	printf_hook(vringh_bad, 1, 2);                    /* drivers/vhost/vringh.c */
	printf_hook(__adfs_error, 3, 4);                  /* fs/adfs/adfs.h */
	printf_hook(affs_error, 3, 4);                    /* fs/affs/affs.h */
	printf_hook(affs_warning, 3, 4);                  /* fs/affs/affs.h */
	printf_hook(befs_debug, 2, 3);                    /* fs/befs/befs.h */
	printf_hook(befs_error, 2, 3);                    /* fs/befs/befs.h */
	printf_hook(befs_warning, 2, 3);                  /* fs/befs/befs.h */
	printf_hook(__btrfs_panic, 5, 6);                 /* fs/btrfs/ctree.h */
	printf_hook(__btrfs_std_error, 5, 6);             /* fs/btrfs/ctree.h */
	printf_hook(btrfs_printk, 2, 3);                  /* fs/btrfs/ctree.h */
	printf_hook(cifs_vfs_err, 1, 2);                  /* fs/cifs/cifs_debug.h */
	printf_hook(__ecryptfs_printk, 1, 2);             /* fs/ecryptfs/ecryptfs_kernel.h */
	printf_hook(ext2_error, 3, 4);                    /* fs/ext2/ext2.h */
	printf_hook(ext2_msg, 3, 4);                      /* fs/ext2/ext2.h */
	printf_hook(ext3_abort, 3, 4);                    /* fs/ext3/ext3.h */
	printf_hook(ext3_error, 3, 4);                    /* fs/ext3/ext3.h */
	printf_hook(ext3_msg, 3, 4);                      /* fs/ext3/ext3.h */
	printf_hook(ext3_warning, 3, 4);                  /* fs/ext3/ext3.h */
	printf_hook(__ext4_abort, 4, 5);                  /* fs/ext4/ext4.h */
	printf_hook(__ext4_error, 4, 5);                  /* fs/ext4/ext4.h */
	printf_hook(__ext4_error_file, 5, 6);             /* fs/ext4/ext4.h */
	printf_hook(__ext4_error_inode, 5, 6);            /* fs/ext4/ext4.h */
	printf_hook(__ext4_grp_locked_error, 7, 8);       /* fs/ext4/ext4.h */
	printf_hook(__ext4_msg, 3, 4);                    /* fs/ext4/ext4.h */
	printf_hook(__ext4_warning, 4, 5);                /* fs/ext4/ext4.h */
	printf_hook(f2fs_msg, 3, 4);                      /* fs/f2fs/f2fs.h */
	printf_hook(__fat_fs_error, 3, 4);                /* fs/fat/fat.h */
	printf_hook(fat_msg, 3, 4);                       /* fs/fat/fat.h */
	printf_hook(gfs2_print_dbg, 2, 3);                /* fs/gfs2/glock.h */
	printf_hook(gfs2_lm_withdraw, 2, 3);              /* fs/gfs2/util.h */
	printf_hook(hpfs_error, 2, 3);                    /* fs/hpfs/hpfs_fn.h */
	printf_hook(jfs_error, 2, 3);                     /* fs/jfs/jfs_superblock.h */
	printf_hook(nilfs_error, 3, 4);                   /* fs/nilfs2/nilfs.h */
	printf_hook(nilfs_warning, 3, 4);                 /* fs/nilfs2/nilfs.h */
	printf_hook(__ntfs_debug, 4, 5);                  /* fs/ntfs/debug.h */
	printf_hook(__ntfs_error, 3, 4);                  /* fs/ntfs/debug.h */
	printf_hook(__ntfs_warning, 3, 4);                /* fs/ntfs/debug.h */
	printf_hook(__ocfs2_abort, 3, 4);                 /* fs/ocfs2/super.h */
	printf_hook(__ocfs2_error, 3, 4);                 /* fs/ocfs2/super.h */
	printf_hook(_udf_err, 3, 4);                      /* fs/udf/udfdecl.h */
	printf_hook(_udf_warn, 3, 4);                     /* fs/udf/udfdecl.h */
	printf_hook(ufs_error, 3, 4);                     /* fs/ufs/ufs.h */
	printf_hook(ufs_panic, 3, 4);                     /* fs/ufs/ufs.h */
	printf_hook(ufs_warning, 3, 4);                   /* fs/ufs/ufs.h */
	printf_hook(xfs_alert, 2, 3);                     /* fs/xfs/xfs_message.h */
	printf_hook(xfs_alert_tag, 3, 4);                 /* fs/xfs/xfs_message.h */
	printf_hook(xfs_crit, 2, 3);                      /* fs/xfs/xfs_message.h */
	printf_hook(xfs_debug, 2, 3);                     /* fs/xfs/xfs_message.h */
	printf_hook(xfs_emerg, 2, 3);                     /* fs/xfs/xfs_message.h */
	printf_hook(xfs_err, 2, 3);                       /* fs/xfs/xfs_message.h */
	printf_hook(xfs_info, 2, 3);                      /* fs/xfs/xfs_message.h */
	printf_hook(xfs_notice, 2, 3);                    /* fs/xfs/xfs_message.h */
	printf_hook(xfs_warn, 2, 3);                      /* fs/xfs/xfs_message.h */
	printf_hook(warn_slowpath_fmt, 3, 4);             /* include/asm-generic/bug.h */
	printf_hook(warn_slowpath_fmt_taint, 4, 5);       /* include/asm-generic/bug.h */
	printf_hook(drm_err, 1, 2);                       /* include/drm/drmP.h */
	printf_hook(drm_ut_debug_printk, 2, 3);           /* include/drm/drmP.h */
	printf_hook(__acpi_handle_debug, 3, 4);           /* include/linux/acpi.h */
	printf_hook(acpi_handle_printk, 3, 4);            /* include/linux/acpi.h */
	printf_hook(audit_log, 4, 5);                     /* include/linux/audit.h */
	printf_hook(audit_log_format, 2, 3);              /* include/linux/audit.h */
	printf_hook(bdi_register, 3, 4);                  /* include/linux/backing-dev.h */
	printf_hook(__trace_note_message, 2, 3);          /* include/linux/blktrace_api.h */
	printf_hook(_dev_info, 2, 3);                     /* include/linux/device.h */
	printf_hook(dev_alert, 2, 3);                     /* include/linux/device.h */
	printf_hook(dev_crit, 2, 3);                      /* include/linux/device.h */
	printf_hook(dev_emerg, 2, 3);                     /* include/linux/device.h */
	printf_hook(dev_err, 2, 3);                       /* include/linux/device.h */
	printf_hook(dev_notice, 2, 3);                    /* include/linux/device.h */
	printf_hook(dev_printk, 3, 4);                    /* include/linux/device.h */
	printf_hook(dev_printk_emit, 3, 4);               /* include/linux/device.h */
	printf_hook(dev_set_name, 2, 3);                  /* include/linux/device.h */
	printf_hook(dev_vprintk_emit, 3, 0);              /* include/linux/device.h */
	printf_hook(dev_warn, 2, 3);                      /* include/linux/device.h */
	printf_hook(device_create, 5, 6);                 /* include/linux/device.h */
	printf_hook(device_create_with_groups, 6, 7);     /* include/linux/device.h */
	printf_hook(devm_kasprintf, 3, 4);                /* include/linux/device.h */
	printf_hook(__dynamic_dev_dbg, 3, 4);             /* include/linux/dynamic_debug.h */
	printf_hook(__dynamic_netdev_dbg, 3, 4);          /* include/linux/dynamic_debug.h */
	printf_hook(__dynamic_pr_debug, 2, 3);            /* include/linux/dynamic_debug.h */
	printf_hook(__simple_attr_check_format, 1, 2);    /* include/linux/fs.h */
	printf_hook(fscache_init_cache, 3, 4);            /* include/linux/fscache-cache.h */
	printf_hook(gameport_set_phys, 2, 3);             /* include/linux/gameport.h */
	printf_hook(iio_trigger_alloc, 1, 2);             /* include/linux/iio/trigger.h */
	printf_hook(__check_printsym_format, 1, 2);       /* include/linux/kallsyms.h */
	printf_hook(kdb_printf, 1, 2);                    /* include/linux/kdb.h */
	printf_hook(vkdb_printf, 1, 0);                   /* include/linux/kdb.h */
	printf_hook(____trace_printk_check_format, 1, 2);  /* include/linux/kernel.h */
	printf_hook(__trace_bprintk, 2, 3);               /* include/linux/kernel.h */
	printf_hook(__trace_printk, 2, 3);                /* include/linux/kernel.h */
	printf_hook(kasprintf, 2, 3);                     /* include/linux/kernel.h */
	printf_hook(panic, 1, 2);                         /* include/linux/kernel.h */
	printf_hook(scnprintf, 3, 4);                     /* include/linux/kernel.h */
	printf_hook(snprintf, 3, 4);                      /* include/linux/kernel.h */
	printf_hook(sprintf, 2, 3);                       /* include/linux/kernel.h */
	printf_hook(trace_printk, 1, 2);                  /* include/linux/kernel.h */
	printf_hook(vscnprintf, 3, 0);                    /* include/linux/kernel.h */
	printf_hook(vsnprintf, 3, 0);                     /* include/linux/kernel.h */
	printf_hook(vsprintf, 2, 0);                      /* include/linux/kernel.h */
	printf_hook(vmcoreinfo_append_str, 1, 2);         /* include/linux/kexec.h */
	printf_hook(__request_module, 2, 3);              /* include/linux/kmod.h */
	printf_hook(add_uevent_var, 2, 3);                /* include/linux/kobject.h */
	printf_hook(kobject_add, 3, 4);                   /* include/linux/kobject.h */
	printf_hook(kobject_init_and_add, 4, 5);          /* include/linux/kobject.h */
	printf_hook(kobject_set_name, 2, 3);              /* include/linux/kobject.h */
	printf_hook(kthread_create_on_node, 4, 5);        /* include/linux/kthread.h */
	printf_hook(__ata_ehi_push_desc, 2, 3);           /* include/linux/libata.h */
	printf_hook(ata_dev_printk, 3, 4);                /* include/linux/libata.h */
	printf_hook(ata_ehi_push_desc, 2, 3);             /* include/linux/libata.h */
	printf_hook(ata_link_printk, 3, 4);               /* include/linux/libata.h */
	printf_hook(ata_port_desc, 2, 3);                 /* include/linux/libata.h */
	printf_hook(ata_port_printk, 3, 4);               /* include/linux/libata.h */
	printf_hook(warn_alloc_failed, 3, 4);             /* include/linux/mm.h */
	printf_hook(mmiotrace_printk, 1, 2);              /* include/linux/mmiotrace.h */
	printf_hook(netdev_alert, 2, 3);                  /* include/linux/netdevice.h */
	printf_hook(netdev_crit, 2, 3);                   /* include/linux/netdevice.h */
	printf_hook(netdev_emerg, 2, 3);                  /* include/linux/netdevice.h */
	printf_hook(netdev_err, 2, 3);                    /* include/linux/netdevice.h */
	printf_hook(netdev_info, 2, 3);                   /* include/linux/netdevice.h */
	printf_hook(netdev_notice, 2, 3);                 /* include/linux/netdevice.h */
	printf_hook(netdev_printk, 3, 4);                 /* include/linux/netdevice.h */
	printf_hook(netdev_warn, 2, 3);                   /* include/linux/netdevice.h */
	printf_hook(early_printk, 1, 2);                  /* include/linux/printk.h */
	printf_hook(no_printk, 1, 2);                     /* include/linux/printk.h */
	printf_hook(printk, 1, 2);                        /* include/linux/printk.h */
	printf_hook(printk_deferred, 1, 2);               /* include/linux/printk.h */
	printf_hook(printk_emit, 5, 6);                   /* include/linux/printk.h */
	printf_hook(vprintk, 1, 0);                       /* include/linux/printk.h */
	printf_hook(vprintk_emit, 5, 0);                  /* include/linux/printk.h */
	printf_hook(__quota_error, 3, 4);                 /* include/linux/quotaops.h */
	printf_hook(seq_buf_printf, 2, 3);                /* include/linux/seq_buf.h */
	printf_hook(seq_buf_vprintf, 2, 0);               /* include/linux/seq_buf.h */
	printf_hook(seq_printf, 2, 3);                    /* include/linux/seq_file.h */
	printf_hook(seq_vprintf, 2, 0);                   /* include/linux/seq_file.h */
	printf_hook(bprintf, 3, 4);                       /* include/linux/string.h */
	printf_hook(trace_seq_printf, 2, 3);              /* include/linux/trace_seq.h */
	printf_hook(trace_seq_vprintf, 2, 0);             /* include/linux/trace_seq.h */
	printf_hook(__alloc_workqueue_key, 1, 6);         /* include/linux/workqueue.h */
	printf_hook(set_worker_desc, 1, 2);               /* include/linux/workqueue.h */
	printf_hook(_p9_debug, 3, 4);                     /* include/net/9p/9p.h */
	printf_hook(bt_err, 1, 2);                        /* include/net/bluetooth/bluetooth.h */
	printf_hook(bt_info, 1, 2);                       /* include/net/bluetooth/bluetooth.h */
	printf_hook(nf_ct_helper_log, 3, 4);              /* include/net/netfilter/nf_conntrack_helper.h */
	printf_hook(nf_log_buf_add, 2, 3);                /* include/net/netfilter/nf_log.h */
	printf_hook(nf_log_packet, 8, 9);                 /* include/net/netfilter/nf_log.h */
	printf_hook(SOCK_DEBUG, 2, 3);                    /* include/net/sock.h */
	printf_hook(__snd_printk, 4, 5);                  /* include/sound/core.h */
	printf_hook(_snd_printd, 2, 3);                   /* include/sound/core.h */
	printf_hook(snd_printd, 1, 2);                    /* include/sound/core.h */
	printf_hook(snd_printdd, 1, 2);                   /* include/sound/core.h */
	printf_hook(snd_iprintf, 2, 3);                   /* include/sound/info.h */
	printf_hook(snd_seq_create_kernel_client, 3, 4);  /* include/sound/seq_kernel.h */
	printf_hook(xen_raw_printk, 1, 2);                /* include/xen/hvc-console.h */
	printf_hook(xenbus_dev_error, 3, 4);              /* include/xen/xenbus.h */
	printf_hook(xenbus_dev_fatal, 3, 4);              /* include/xen/xenbus.h */
	printf_hook(xenbus_printf, 4, 5);                 /* include/xen/xenbus.h */
	printf_hook(xenbus_watch_pathfmt, 4, 5);          /* include/xen/xenbus.h */
	printf_hook(batadv_fdebug_log, 2, 3);             /* net/batman-adv/debugfs.c */
	printf_hook(_batadv_dbg, 4, 5);                   /* net/batman-adv/main.h */
	printf_hook(batadv_debug_log, 2, 3);              /* net/batman-adv/main.h */
	printf_hook(__sdata_dbg, 2, 3);                   /* net/mac80211/debug.h */
	printf_hook(__sdata_err, 1, 2);                   /* net/mac80211/debug.h */
	printf_hook(__sdata_info, 1, 2);                  /* net/mac80211/debug.h */
	printf_hook(__wiphy_dbg, 3, 4);                   /* net/mac80211/debug.h */
	printf_hook(mac80211_format_buffer, 4, 5);        /* net/mac80211/debugfs.h */
	printf_hook(__rds_conn_error, 2, 3);              /* net/rds/rds.h */
	printf_hook(rdsdebug, 1, 2);                      /* net/rds/rds.h */
	printf_hook(printl, 1, 2);                        /* net/sctp/probe.c */
	printf_hook(svc_printk, 2, 3);                    /* net/sunrpc/svc.c */
	printf_hook(tomoyo_io_printf, 2, 3);              /* security/tomoyo/common.c */
	printf_hook(tomoyo_supervisor, 2, 3);             /* security/tomoyo/common.h */
	printf_hook(tomoyo_write_log, 2, 3);              /* security/tomoyo/common.h */
	printf_hook(cmp_error, 2, 3);                     /* sound/firewire/cmp.c */
}
