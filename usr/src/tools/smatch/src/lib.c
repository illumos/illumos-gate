/*
 * 'sparse' library helper routines.
 *
 * Copyright (C) 2003 Transmeta Corp.
 *               2003-2004 Linus Torvalds
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <sys/types.h>

#include "lib.h"
#include "allocate.h"
#include "token.h"
#include "parse.h"
#include "symbol.h"
#include "expression.h"
#include "scope.h"
#include "linearize.h"
#include "target.h"
#include "version.h"

static const char *progname;

int sparse_errors = 0;
int sparse_warnings = 0;

int verbose, optimize, optimize_size, preprocessing;
int die_if_error = 0;
int parse_error;
int has_error = 0;

#ifndef __GNUC__
# define __GNUC__ 2
# define __GNUC_MINOR__ 95
# define __GNUC_PATCHLEVEL__ 0
#endif

int gcc_major = __GNUC__;
int gcc_minor = __GNUC_MINOR__;
int gcc_patchlevel = __GNUC_PATCHLEVEL__;

static const char *gcc_base_dir = GCC_BASE;
static const char *multiarch_dir = MULTIARCH_TRIPLET;

struct token *skip_to(struct token *token, int op)
{
	while (!match_op(token, op) && !eof_token(token))
		token = token->next;
	return token;
}

struct token *expect(struct token *token, int op, const char *where)
{
	if (!match_op(token, op)) {
		static struct token bad_token;
		if (token != &bad_token) {
			bad_token.next = token;
			sparse_error(token->pos, "Expected %s %s", show_special(op), where);
			sparse_error(token->pos, "got %s", show_token(token));
		}
		if (op == ';')
			return skip_to(token, op);
		return &bad_token;
	}
	return token->next;
}

unsigned int hexval(unsigned int c)
{
	int retval = 256;
	switch (c) {
	case '0'...'9':
		retval = c - '0';
		break;
	case 'a'...'f':
		retval = c - 'a' + 10;
		break;
	case 'A'...'F':
		retval = c - 'A' + 10;
		break;
	}
	return retval;
}

static void do_warn(const char *type, struct position pos, const char * fmt, va_list args)
{
	static char buffer[512];
	const char *name;

	vsprintf(buffer, fmt, args);	
	name = stream_name(pos.stream);
		
	fprintf(stderr, "%s: %s:%d:%d: %s%s\n",
		progname, name, pos.line, pos.pos, type, buffer);
}

static int max_warnings = 100;
static int show_info = 1;

void info(struct position pos, const char * fmt, ...)
{
	va_list args;

	if (!show_info)
		return;
	va_start(args, fmt);
	do_warn("", pos, fmt, args);
	va_end(args);
}

static void do_error(struct position pos, const char * fmt, va_list args)
{
	static int errors = 0;

	parse_error = 1;
        die_if_error = 1;
	show_info = 1;
	/* Shut up warnings after an error */
	has_error |= ERROR_CURR_PHASE;
	if (errors > 100) {
		static int once = 0;
		show_info = 0;
		if (once)
			return;
		fmt = "too many errors";
		once = 1;
	}

	do_warn("error: ", pos, fmt, args);
	errors++;
}	

void warning(struct position pos, const char * fmt, ...)
{
	va_list args;

	if (Wsparse_error) {
		va_start(args, fmt);
		do_error(pos, fmt, args);
		va_end(args);
		return;
	}

	if (!max_warnings || has_error) {
		show_info = 0;
		return;
	}

	if (!--max_warnings) {
		show_info = 0;
		fmt = "too many warnings";
	}

	va_start(args, fmt);
	do_warn("warning: ", pos, fmt, args);
	va_end(args);
}

void sparse_error(struct position pos, const char * fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	do_error(pos, fmt, args);
	va_end(args);
}

void expression_error(struct expression *expr, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	do_error(expr->pos, fmt, args);
	va_end(args);
	expr->ctype = &bad_ctype;
}

NORETURN_ATTR
void error_die(struct position pos, const char * fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	do_warn("error: ", pos, fmt, args);
	va_end(args);
	exit(1);
}

NORETURN_ATTR
void die(const char *fmt, ...)
{
	va_list args;
	static char buffer[512];

	va_start(args, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, args);
	va_end(args);

	fprintf(stderr, "%s: %s\n", progname, buffer);
	exit(1);
}

static struct token *pre_buffer_begin = NULL;
static struct token *pre_buffer_end = NULL;

int Waddress = 0;
int Waddress_space = 1;
int Wbitwise = 1;
int Wcast_to_as = 0;
int Wcast_truncate = 1;
int Wconstant_suffix = 0;
int Wconstexpr_not_const = 0;
int Wcontext = 1;
int Wdecl = 1;
int Wdeclarationafterstatement = -1;
int Wdefault_bitfield_sign = 0;
int Wdesignated_init = 1;
int Wdo_while = 0;
int Wimplicit_int = 1;
int Winit_cstring = 0;
int Wenum_mismatch = 1;
int Wexternal_function_has_definition = 1;
int Wsparse_error = 0;
int Wmemcpy_max_count = 1;
int Wnon_pointer_null = 1;
int Wold_initializer = 1;
int Wold_style_definition = 1;
int Wone_bit_signed_bitfield = 1;
int Woverride_init = 1;
int Woverride_init_all = 0;
int Woverride_init_whole_range = 0;
int Wparen_string = 0;
int Wpointer_arith = 0;
int Wptr_subtraction_blows = 0;
int Wreturn_void = 0;
int Wshadow = 0;
int Wsizeof_bool = 0;
int Wstrict_prototypes = 1;
int Wtautological_compare = 0;
int Wtransparent_union = 0;
int Wtypesign = 0;
int Wundef = 0;
int Wuninitialized = 1;
int Wunknown_attribute = 0;
int Wvla = 1;

int dump_macro_defs = 0;

int dbg_entry = 0;
int dbg_dead = 0;

int fmem_report = 0;
int fdump_linearize;
unsigned long long fmemcpy_max_count = 100000;

int preprocess_only;

static enum { STANDARD_C89,
              STANDARD_C94,
              STANDARD_C99,
              STANDARD_C11,
              STANDARD_GNU11,
              STANDARD_GNU89,
              STANDARD_GNU99, } standard = STANDARD_GNU89;

#define ARCH_LP32  0
#define ARCH_LP64  1
#define ARCH_LLP64 2

#ifdef __x86_64__
#define ARCH_M64_DEFAULT ARCH_LP64
#else
#define ARCH_M64_DEFAULT ARCH_LP32
#endif

int arch_m64 = ARCH_M64_DEFAULT;
int arch_msize_long = 0;

#ifdef __BIG_ENDIAN__
#define ARCH_BIG_ENDIAN 1
#else
#define ARCH_BIG_ENDIAN 0
#endif
int arch_big_endian = ARCH_BIG_ENDIAN;


#define CMDLINE_INCLUDE 20
static int cmdline_include_nr = 0;
static char *cmdline_include[CMDLINE_INCLUDE];


void add_pre_buffer(const char *fmt, ...)
{
	va_list args;
	unsigned int size;
	struct token *begin, *end;
	char buffer[4096];

	va_start(args, fmt);
	size = vsnprintf(buffer, sizeof(buffer), fmt, args);
	va_end(args);
	begin = tokenize_buffer(buffer, size, &end);
	if (!pre_buffer_begin)
		pre_buffer_begin = begin;
	if (pre_buffer_end)
		pre_buffer_end->next = begin;
	pre_buffer_end = end;
}

static char **handle_switch_D(char *arg, char **next)
{
	const char *name = arg + 1;
	const char *value = "1";

	if (!*name) {
		arg = *++next;
		if (!arg)
			die("argument to `-D' is missing");
		name = arg;
	}

	for (;;arg++) {
		char c;
		c = *arg;
		if (!c)
			break;
		if (c == '=') {
			*arg = '\0';
			value = arg + 1;
			break;
		}
	}
	add_pre_buffer("#define %s %s\n", name, value);
	return next;
}

static char **handle_switch_E(char *arg, char **next)
{
	if (arg[1] == '\0')
		preprocess_only = 1;
	return next;
}

static char **handle_switch_I(char *arg, char **next)
{
	char *path = arg+1;

	switch (arg[1]) {
	case '-':
		add_pre_buffer("#split_include\n");
		break;

	case '\0':	/* Plain "-I" */
		path = *++next;
		if (!path)
			die("missing argument for -I option");
		/* Fall through */
	default:
		add_pre_buffer("#add_include \"%s/\"\n", path);
	}
	return next;
}

static void add_cmdline_include(char *filename)
{
	if (cmdline_include_nr >= CMDLINE_INCLUDE)
		die("too many include files for %s\n", filename);
	cmdline_include[cmdline_include_nr++] = filename;
}

static char **handle_switch_i(char *arg, char **next)
{
	if (*next && !strcmp(arg, "include"))
		add_cmdline_include(*++next);
	else if (*next && !strcmp(arg, "imacros"))
		add_cmdline_include(*++next);
	else if (*next && !strcmp(arg, "isystem")) {
		char *path = *++next;
		if (!path)
			die("missing argument for -isystem option");
		add_pre_buffer("#add_isystem \"%s/\"\n", path);
	} else if (*next && !strcmp(arg, "idirafter")) {
		char *path = *++next;
		if (!path)
			die("missing argument for -idirafter option");
		add_pre_buffer("#add_dirafter \"%s/\"\n", path);
	}
	return next;
}

static char **handle_switch_M(char *arg, char **next)
{
	if (!strcmp(arg, "MF") || !strcmp(arg,"MQ") || !strcmp(arg,"MT")) {
		if (!*next)
			die("missing argument for -%s option", arg);
		return next + 1;
	}
	return next;
}

static char **handle_multiarch_dir(char *arg, char **next)
{
	multiarch_dir = *++next;
	if (!multiarch_dir)
		die("missing argument for -multiarch-dir option");
	return next;
}

static char **handle_switch_m(char *arg, char **next)
{
	if (!strcmp(arg, "m64")) {
		arch_m64 = ARCH_LP64;
	} else if (!strcmp(arg, "m32")) {
		arch_m64 = ARCH_LP32;
	} else if (!strcmp(arg, "msize-llp64")) {
		arch_m64 = ARCH_LLP64;
	} else if (!strcmp(arg, "msize-long")) {
		arch_msize_long = 1;
	} else if (!strcmp(arg, "multiarch-dir")) {
		return handle_multiarch_dir(arg, next);
	} else if (!strcmp(arg, "mbig-endian")) {
		arch_big_endian = 1;
	} else if (!strcmp(arg, "mlittle-endian")) {
		arch_big_endian = 0;
	}
	return next;
}

static void handle_arch_m64_finalize(void)
{
	switch (arch_m64) {
	case ARCH_LP32:
		/* default values */
#if defined(__x86_64__) || defined (__i386)
 		add_pre_buffer("#weak_define __i386__ 1\n");
 		add_pre_buffer("#weak_define __i386 1\n");
 		add_pre_buffer("#weak_define i386 1\n");
#endif
		return;
	case ARCH_LP64:
		bits_in_long = 64;
		max_int_alignment = 8;
		size_t_ctype = &ulong_ctype;
		ssize_t_ctype = &long_ctype;
		add_pre_buffer("#weak_define __LP64__ 1\n");
		add_pre_buffer("#weak_define __LP64 1\n");
		add_pre_buffer("#weak_define _LP64 1\n");
		goto case_64bit_common;
	case ARCH_LLP64:
		bits_in_long = 32;
		max_int_alignment = 4;
		size_t_ctype = &ullong_ctype;
		ssize_t_ctype = &llong_ctype;
		add_pre_buffer("#weak_define __LLP64__ 1\n");
		goto case_64bit_common;
	case_64bit_common:
		bits_in_pointer = 64;
		pointer_alignment = 8;
#if defined(__x86_64__) || defined (__i386)
		add_pre_buffer("#weak_define __x86_64__ 1\n");
		add_pre_buffer("#weak_define __x86_64 1\n");
#endif
		break;
	}
}

static void handle_arch_msize_long_finalize(void)
{
	if (arch_msize_long) {
		size_t_ctype = &ulong_ctype;
		ssize_t_ctype = &long_ctype;
	}
}

static void handle_arch_finalize(void)
{
	handle_arch_m64_finalize();
	handle_arch_msize_long_finalize();
}


static int handle_simple_switch(const char *arg, const char *name, int *flag)
{
	int val = 1;

	// Prefixe "no-" mean to turn flag off.
	if (strncmp(arg, "no-", 3) == 0) {
		arg += 3;
		val = 0;
	}

	if (strcmp(arg, name) == 0) {
		*flag = val;
		return 1;
	}

	// not handled
	return 0;
}

static char **handle_switch_o(char *arg, char **next)
{
	if (!strcmp (arg, "o")) {       // "-o foo"
		if (!*++next)
			die("argument to '-o' is missing");
	}
	// else "-ofoo"

	return next;
}

static const struct warning {
	const char *name;
	int *flag;
} warnings[] = {
	{ "address", &Waddress },
	{ "address-space", &Waddress_space },
	{ "bitwise", &Wbitwise },
	{ "cast-to-as", &Wcast_to_as },
	{ "cast-truncate", &Wcast_truncate },
	{ "constant-suffix", &Wconstant_suffix },
	{ "constexpr-not-const", &Wconstexpr_not_const},
	{ "context", &Wcontext },
	{ "decl", &Wdecl },
	{ "declaration-after-statement", &Wdeclarationafterstatement },
	{ "default-bitfield-sign", &Wdefault_bitfield_sign },
	{ "designated-init", &Wdesignated_init },
	{ "do-while", &Wdo_while },
	{ "enum-mismatch", &Wenum_mismatch },
	{ "external-function-has-definition", &Wexternal_function_has_definition },
	{ "implicit-int", &Wimplicit_int },
	{ "init-cstring", &Winit_cstring },
	{ "memcpy-max-count", &Wmemcpy_max_count },
	{ "non-pointer-null", &Wnon_pointer_null },
	{ "old-initializer", &Wold_initializer },
	{ "old-style-definition", &Wold_style_definition },
	{ "one-bit-signed-bitfield", &Wone_bit_signed_bitfield },
	{ "override-init", &Woverride_init },
	{ "override-init-all", &Woverride_init_all },
	{ "paren-string", &Wparen_string },
	{ "ptr-subtraction-blows", &Wptr_subtraction_blows },
	{ "return-void", &Wreturn_void },
	{ "shadow", &Wshadow },
	{ "sizeof-bool", &Wsizeof_bool },
	{ "strict-prototypes", &Wstrict_prototypes },
	{ "pointer-arith", &Wpointer_arith },
	{ "sparse-error", &Wsparse_error },
	{ "tautological-compare", &Wtautological_compare },
	{ "transparent-union", &Wtransparent_union },
	{ "typesign", &Wtypesign },
	{ "undef", &Wundef },
	{ "uninitialized", &Wuninitialized },
	{ "unknown-attribute", &Wunknown_attribute },
	{ "vla", &Wvla },
};

enum {
	WARNING_OFF,
	WARNING_ON,
	WARNING_FORCE_OFF
};


static char **handle_onoff_switch(char *arg, char **next, const struct warning warnings[], int n)
{
	int flag = WARNING_ON;
	char *p = arg + 1;
	unsigned i;

	if (!strcmp(p, "sparse-all")) {
		for (i = 0; i < n; i++) {
			if (*warnings[i].flag != WARNING_FORCE_OFF && warnings[i].flag != &Wsparse_error)
				*warnings[i].flag = WARNING_ON;
		}
	}

	// Prefixes "no" and "no-" mean to turn warning off.
	if (p[0] == 'n' && p[1] == 'o') {
		p += 2;
		if (p[0] == '-')
			p++;
		flag = WARNING_FORCE_OFF;
	}

	for (i = 0; i < n; i++) {
		if (!strcmp(p,warnings[i].name)) {
			*warnings[i].flag = flag;
			return next;
		}
	}

	// Unknown.
	return NULL;
}

static char **handle_switch_W(char *arg, char **next)
{
	char ** ret = handle_onoff_switch(arg, next, warnings, ARRAY_SIZE(warnings));
	if (ret)
		return ret;

	// Unknown.
	return next;
}

static struct warning debugs[] = {
	{ "entry", &dbg_entry},
	{ "dead", &dbg_dead},
};


static char **handle_switch_v(char *arg, char **next)
{
	char ** ret = handle_onoff_switch(arg, next, debugs, ARRAY_SIZE(debugs));
	if (ret)
		return ret;

	// Unknown.
	do {
		verbose++;
	} while (*++arg == 'v');
	return next;
}

static struct warning dumps[] = {
	{ "D", &dump_macro_defs},
};

static char **handle_switch_d(char *arg, char **next)
{
	char ** ret = handle_onoff_switch(arg, next, dumps, ARRAY_SIZE(dumps));
	if (ret)
		return ret;

	return next;
}


static void handle_onoff_switch_finalize(const struct warning warnings[], int n)
{
	unsigned i;

	for (i = 0; i < n; i++) {
		if (*warnings[i].flag == WARNING_FORCE_OFF)
			*warnings[i].flag = WARNING_OFF;
	}
}

static void handle_switch_W_finalize(void)
{
	handle_onoff_switch_finalize(warnings, ARRAY_SIZE(warnings));

	/* default Wdeclarationafterstatement based on the C dialect */
	if (-1 == Wdeclarationafterstatement)
	{
		switch (standard)
		{
			case STANDARD_C89:
			case STANDARD_C94:
				Wdeclarationafterstatement = 1;
				break;

			case STANDARD_C99:
			case STANDARD_GNU89:
			case STANDARD_GNU99:
			case STANDARD_C11:
			case STANDARD_GNU11:
				Wdeclarationafterstatement = 0;
				break;

			default:
				assert (0);
		}

	}
}

static void handle_switch_v_finalize(void)
{
	handle_onoff_switch_finalize(debugs, ARRAY_SIZE(debugs));
}

static char **handle_switch_U(char *arg, char **next)
{
	const char *name = arg + 1;
	if (*name == '\0')
		name = *++next;
	add_pre_buffer ("#undef %s\n", name);
	return next;
}

static char **handle_switch_O(char *arg, char **next)
{
	int level = 1;
	if (arg[1] >= '0' && arg[1] <= '9')
		level = arg[1] - '0';
	optimize = level;
	optimize_size = arg[1] == 's';
	return next;
}

static char **handle_switch_fmemcpy_max_count(char *arg, char **next)
{
	unsigned long long val;
	char *end;

	val = strtoull(arg, &end, 0);
	if (*end != '\0' || end == arg)
		die("error: missing argument to \"-fmemcpy-max-count=\"");

	if (val == 0)
		val = ~0ULL;
	fmemcpy_max_count = val;
	return next;
}

static char **handle_switch_ftabstop(char *arg, char **next)
{
	char *end;
	unsigned long val;

	if (*arg == '\0')
		die("error: missing argument to \"-ftabstop=\"");

	/* we silently ignore silly values */
	val = strtoul(arg, &end, 10);
	if (*end == '\0' && 1 <= val && val <= 100)
		tabstop = val;

	return next;
}

static int funsigned_char;
static void handle_funsigned_char(void)
{
	if (funsigned_char) {
		char_ctype.ctype.modifiers &= ~MOD_SIGNED;
		char_ctype.ctype.modifiers |= MOD_UNSIGNED;
	}
}

	static char **handle_switch_fdump(char *arg, char **next)
{
	if (!strncmp(arg, "linearize", 9)) {
		arg += 9;
		if (*arg == '\0')
			fdump_linearize = 1;
		else if (!strcmp(arg, "=only"))
			fdump_linearize = 2;
		else
			goto err;
	}

	/* ignore others flags */
	return next;

err:
	die("error: unknown flag \"-fdump-%s\"", arg);
}

static char **handle_switch_f(char *arg, char **next)
{
	arg++;

	if (!strncmp(arg, "tabstop=", 8))
		return handle_switch_ftabstop(arg+8, next);
	if (!strncmp(arg, "dump-", 5))
		return handle_switch_fdump(arg+5, next);
	if (!strncmp(arg, "memcpy-max-count=", 17))
		return handle_switch_fmemcpy_max_count(arg+17, next);

	if (!strcmp(arg, "unsigned-char")) {
		funsigned_char = 1;
		return next;
	}

	/* handle switches w/ arguments above, boolean and only boolean below */
	if (handle_simple_switch(arg, "mem-report", &fmem_report))
		return next;

	return next;
}

static char **handle_switch_G(char *arg, char **next)
{
	if (!strcmp (arg, "G") && *next)
		return next + 1; // "-G 0"
	else
		return next;     // "-G0" or (bogus) terminal "-G"
}

static char **handle_switch_a(char *arg, char **next)
{
	if (!strcmp (arg, "ansi"))
		standard = STANDARD_C89;

	return next;
}

static char **handle_switch_s(char *arg, char **next)
{
	if (!strncmp (arg, "std=", 4))
	{
		arg += 4;

		if (!strcmp (arg, "c89") ||
		    !strcmp (arg, "iso9899:1990"))
			standard = STANDARD_C89;

		else if (!strcmp (arg, "iso9899:199409"))
			standard = STANDARD_C94;

		else if (!strcmp (arg, "c99") ||
			 !strcmp (arg, "c9x") ||
			 !strcmp (arg, "iso9899:1999") ||
			 !strcmp (arg, "iso9899:199x"))
			standard = STANDARD_C99;

		else if (!strcmp (arg, "gnu89"))
			standard = STANDARD_GNU89;

		else if (!strcmp (arg, "gnu99") || !strcmp (arg, "gnu9x"))
			standard = STANDARD_GNU99;

		else if (!strcmp(arg, "c11") ||
			 !strcmp(arg, "c1x") ||
			 !strcmp(arg, "iso9899:2011"))
			standard = STANDARD_C11;

		else if (!strcmp(arg, "gnu11"))
			standard = STANDARD_GNU11;

		else
			die ("Unsupported C dialect");
	}

	return next;
}

static char **handle_nostdinc(char *arg, char **next)
{
	add_pre_buffer("#nostdinc\n");
	return next;
}

static char **handle_switch_n(char *arg, char **next)
{
	if (!strcmp (arg, "nostdinc"))
		return handle_nostdinc(arg, next);

	return next;
}

static char **handle_base_dir(char *arg, char **next)
{
	gcc_base_dir = *++next;
	if (!gcc_base_dir)
		die("missing argument for -gcc-base-dir option");
	return next;
}

static char **handle_no_lineno(char *arg, char **next)
{
	no_lineno = 1;
	return next;
}

static char **handle_switch_g(char *arg, char **next)
{
	if (!strcmp (arg, "gcc-base-dir"))
		return handle_base_dir(arg, next);

	return next;
}

static char **handle_version(char *arg, char **next)
{
	printf("%s\n", SPARSE_VERSION);
	exit(0);
}

static char **handle_param(char *arg, char **next)
{
	char *value = NULL;

	/* Ignore smatch's --param-mapper */
	if (strcmp(arg, "-mapper") == 0)
		return next;


	/* For now just skip any '--param=*' or '--param *' */
	if (*arg == '\0') {
		value = *++next;
	} else if (isspace((unsigned char)*arg) || *arg == '=') {
		value = ++arg;
	}

	if (!value)
		die("missing argument for --param option");

	return next;
}

struct switches {
	const char *name;
	char **(*fn)(char *, char **);
	unsigned int prefix:1;
};

static char **handle_long_options(char *arg, char **next)
{
	static struct switches cmd[] = {
		{ "param", handle_param, 1 },
		{ "version", handle_version },
		{ "nostdinc", handle_nostdinc },
		{ "gcc-base-dir", handle_base_dir},
		{ "no-lineno", handle_no_lineno},
		{ NULL, NULL }
	};
	struct switches *s = cmd;

	while (s->name) {
		int optlen = strlen(s->name);
		if (!strncmp(s->name, arg, optlen + !s->prefix))
			return s->fn(arg + optlen, next);
		s++;
	}
	return next;
}

static char **handle_switch(char *arg, char **next)
{
	switch (*arg) {
	case 'a': return handle_switch_a(arg, next);
	case 'D': return handle_switch_D(arg, next);
	case 'd': return handle_switch_d(arg, next);
	case 'E': return handle_switch_E(arg, next);
	case 'f': return handle_switch_f(arg, next);
	case 'g': return handle_switch_g(arg, next);
	case 'G': return handle_switch_G(arg, next);
	case 'I': return handle_switch_I(arg, next);
	case 'i': return handle_switch_i(arg, next);
	case 'M': return handle_switch_M(arg, next);
	case 'm': return handle_switch_m(arg, next);
	case 'n': return handle_switch_n(arg, next);
	case 'o': return handle_switch_o(arg, next);
	case 'O': return handle_switch_O(arg, next);
	case 's': return handle_switch_s(arg, next);
	case 'U': return handle_switch_U(arg, next);
	case 'v': return handle_switch_v(arg, next);
	case 'W': return handle_switch_W(arg, next);
	case '-': return handle_long_options(arg + 1, next);
	default:
		break;
	}

	/*
	 * Ignore unknown command line options:
	 * they're probably gcc switches
	 */
	return next;
}

static void predefined_sizeof(const char *name, unsigned bits)
{
	add_pre_buffer("#weak_define __SIZEOF_%s__ %d\n", name, bits/8);
}

static void predefined_max(const char *name, const char *suffix, unsigned bits)
{
	unsigned long long max = (1ULL << (bits - 1 )) - 1;

	add_pre_buffer("#weak_define __%s_MAX__ %#llx%s\n", name, max, suffix);
}

static void predefined_type_size(const char *name, const char *suffix, unsigned bits)
{
	predefined_max(name, suffix, bits);
	predefined_sizeof(name, bits);
}

static void predefined_macros(void)
{
	add_pre_buffer("#define __CHECKER__ 1\n");

	predefined_sizeof("SHORT", bits_in_short);
	predefined_max("SHRT", "", bits_in_short);
	predefined_max("SCHAR", "", bits_in_char);
	predefined_max("WCHAR", "", bits_in_wchar);
	add_pre_buffer("#weak_define __CHAR_BIT__ %d\n", bits_in_char);

	predefined_type_size("INT", "", bits_in_int);
	predefined_type_size("LONG", "L", bits_in_long);
	predefined_type_size("LONG_LONG", "LL", bits_in_longlong);

	predefined_sizeof("INT128", 128);

	predefined_sizeof("SIZE_T", bits_in_pointer);
	predefined_sizeof("PTRDIFF_T", bits_in_pointer);
	predefined_sizeof("POINTER", bits_in_pointer);

	predefined_sizeof("FLOAT", bits_in_float);
	predefined_sizeof("DOUBLE", bits_in_double);
	predefined_sizeof("LONG_DOUBLE", bits_in_longdouble);

	add_pre_buffer("#weak_define __%s_ENDIAN__ 1\n",
		arch_big_endian ? "BIG" : "LITTLE");

	add_pre_buffer("#weak_define __ORDER_LITTLE_ENDIAN__ 1234\n");
	add_pre_buffer("#weak_define __ORDER_BIG_ENDIAN__ 4321\n");
	add_pre_buffer("#weak_define __ORDER_PDP_ENDIAN__ 3412\n");
	add_pre_buffer("#weak_define __BYTE_ORDER__ __ORDER_%s_ENDIAN__\n",
		arch_big_endian ? "BIG" : "LITTLE");

	add_pre_buffer("#weak_define __PRAGMA_REDEFINE_EXTNAME 1\n");

	/*
	 * This is far from perfect...
	 */
#ifdef	__sun
	add_pre_buffer("#weak_define __unix__ 1\n");
	add_pre_buffer("#weak_define __unix 1\n");
	add_pre_buffer("#weak_define unix 1\n");
	add_pre_buffer("#weak_define __sun__ 1\n");
	add_pre_buffer("#weak_define __sun 1\n");
	add_pre_buffer("#weak_define sun 1\n");
	add_pre_buffer("#weak_define __svr4__ 1\n");
#endif
}

void declare_builtin_functions(void)
{
	/* Gaah. gcc knows tons of builtin <string.h> functions */
	add_pre_buffer("extern void *__builtin_memchr(const void *, int, __SIZE_TYPE__);\n");
	add_pre_buffer("extern void *__builtin_memcpy(void *, const void *, __SIZE_TYPE__);\n");
	add_pre_buffer("extern void *__builtin_mempcpy(void *, const void *, __SIZE_TYPE__);\n");
	add_pre_buffer("extern void *__builtin_memmove(void *, const void *, __SIZE_TYPE__);\n");
	add_pre_buffer("extern void *__builtin_memset(void *, int, __SIZE_TYPE__);\n");
	add_pre_buffer("extern int __builtin_memcmp(const void *, const void *, __SIZE_TYPE__);\n");
	add_pre_buffer("extern char *__builtin_strcat(char *, const char *);\n");
	add_pre_buffer("extern char *__builtin_strncat(char *, const char *, __SIZE_TYPE__);\n");
	add_pre_buffer("extern int __builtin_strcmp(const char *, const char *);\n");
	add_pre_buffer("extern int __builtin_strncmp(const char *, const char *, __SIZE_TYPE__);\n");
	add_pre_buffer("extern int __builtin_strcasecmp(const char *, const char *);\n");
	add_pre_buffer("extern int __builtin_strncasecmp(const char *, const char *, __SIZE_TYPE__);\n");
	add_pre_buffer("extern char *__builtin_strchr(const char *, int);\n");
	add_pre_buffer("extern char *__builtin_strrchr(const char *, int);\n");
	add_pre_buffer("extern char *__builtin_strcpy(char *, const char *);\n");
	add_pre_buffer("extern char *__builtin_strncpy(char *, const char *, __SIZE_TYPE__);\n");
	add_pre_buffer("extern char *__builtin_strdup(const char *);\n");
	add_pre_buffer("extern char *__builtin_strndup(const char *, __SIZE_TYPE__);\n");
	add_pre_buffer("extern __SIZE_TYPE__ __builtin_strspn(const char *, const char *);\n");
	add_pre_buffer("extern __SIZE_TYPE__ __builtin_strcspn(const char *, const char *);\n");
	add_pre_buffer("extern char * __builtin_strpbrk(const char *, const char *);\n");
	add_pre_buffer("extern char* __builtin_stpcpy(const char *, const char*);\n");
	add_pre_buffer("extern char* __builtin_stpncpy(const char *, const char*, __SIZE_TYPE__);\n");
	add_pre_buffer("extern __SIZE_TYPE__ __builtin_strlen(const char *);\n");
	add_pre_buffer("extern char *__builtin_strstr(const char *, const char *);\n");
	add_pre_buffer("extern char *__builtin_strcasestr(const char *, const char *);\n");
	add_pre_buffer("extern char *__builtin_strnstr(const char *, const char *, __SIZE_TYPE__);\n");

	/* And even some from <strings.h> */
	add_pre_buffer("extern int  __builtin_bcmp(const void *, const void *, __SIZE_TYPE__);\n");
	add_pre_buffer("extern void __builtin_bcopy(const void *, void *, __SIZE_TYPE__);\n");
	add_pre_buffer("extern void __builtin_bzero(void *, __SIZE_TYPE__);\n");
	add_pre_buffer("extern char*__builtin_index(const char *, int);\n");
	add_pre_buffer("extern char*__builtin_rindex(const char *, int);\n");

	/* And bitwise operations.. */
	add_pre_buffer("extern int __builtin_clrsb(int);\n");
	add_pre_buffer("extern int __builtin_clrsbl(long);\n");
	add_pre_buffer("extern int __builtin_clrsbll(long long);\n");
	add_pre_buffer("extern int __builtin_clz(int);\n");
	add_pre_buffer("extern int __builtin_clzl(long);\n");
	add_pre_buffer("extern int __builtin_clzll(long long);\n");
	add_pre_buffer("extern int __builtin_ctz(int);\n");
	add_pre_buffer("extern int __builtin_ctzl(long);\n");
	add_pre_buffer("extern int __builtin_ctzll(long long);\n");
	add_pre_buffer("extern int __builtin_ffs(int);\n");
	add_pre_buffer("extern int __builtin_ffsl(long);\n");
	add_pre_buffer("extern int __builtin_ffsll(long long);\n");
	add_pre_buffer("extern int __builtin_parity(unsigned int);\n");
	add_pre_buffer("extern int __builtin_parityl(unsigned long);\n");
	add_pre_buffer("extern int __builtin_parityll(unsigned long long);\n");
	add_pre_buffer("extern int __builtin_popcount(unsigned int);\n");
	add_pre_buffer("extern int __builtin_popcountl(unsigned long);\n");
	add_pre_buffer("extern int __builtin_popcountll(unsigned long long);\n");

	/* And byte swaps.. */
	add_pre_buffer("extern unsigned short __builtin_bswap16(unsigned short);\n");
	add_pre_buffer("extern unsigned int __builtin_bswap32(unsigned int);\n");
	add_pre_buffer("extern unsigned long long __builtin_bswap64(unsigned long long);\n");

	/* And atomic memory access functions.. */
	add_pre_buffer("extern int __sync_fetch_and_add(void *, ...);\n");
	add_pre_buffer("extern int __sync_fetch_and_sub(void *, ...);\n");
	add_pre_buffer("extern int __sync_fetch_and_or(void *, ...);\n");
	add_pre_buffer("extern int __sync_fetch_and_and(void *, ...);\n");
	add_pre_buffer("extern int __sync_fetch_and_xor(void *, ...);\n");
	add_pre_buffer("extern int __sync_fetch_and_nand(void *, ...);\n");
	add_pre_buffer("extern int __sync_add_and_fetch(void *, ...);\n");
	add_pre_buffer("extern int __sync_sub_and_fetch(void *, ...);\n");
	add_pre_buffer("extern int __sync_or_and_fetch(void *, ...);\n");
	add_pre_buffer("extern int __sync_and_and_fetch(void *, ...);\n");
	add_pre_buffer("extern int __sync_xor_and_fetch(void *, ...);\n");
	add_pre_buffer("extern int __sync_nand_and_fetch(void *, ...);\n");
	add_pre_buffer("extern int __sync_bool_compare_and_swap(void *, ...);\n");
	add_pre_buffer("extern int __sync_val_compare_and_swap(void *, ...);\n");
	add_pre_buffer("extern void __sync_synchronize();\n");
	add_pre_buffer("extern int __sync_lock_test_and_set(void *, ...);\n");
	add_pre_buffer("extern void __sync_lock_release(void *, ...);\n");

	/* And some random ones.. */
	add_pre_buffer("extern void *__builtin_return_address(unsigned int);\n");
	add_pre_buffer("extern void *__builtin_extract_return_addr(void *);\n");
	add_pre_buffer("extern void *__builtin_frame_address(unsigned int);\n");
	add_pre_buffer("extern void __builtin_trap(void);\n");
	add_pre_buffer("extern void *__builtin_alloca(__SIZE_TYPE__);\n");
	add_pre_buffer("extern void __builtin_prefetch (const void *, ...);\n");
	add_pre_buffer("extern long __builtin_alpha_extbl(long, long);\n");
	add_pre_buffer("extern long __builtin_alpha_extwl(long, long);\n");
	add_pre_buffer("extern long __builtin_alpha_insbl(long, long);\n");
	add_pre_buffer("extern long __builtin_alpha_inswl(long, long);\n");
	add_pre_buffer("extern long __builtin_alpha_insql(long, long);\n");
	add_pre_buffer("extern long __builtin_alpha_inslh(long, long);\n");
	add_pre_buffer("extern long __builtin_alpha_cmpbge(long, long);\n");
	add_pre_buffer("extern int  __builtin_abs(int);\n");
	add_pre_buffer("extern long __builtin_labs(long);\n");
	add_pre_buffer("extern long long __builtin_llabs(long long);\n");
	add_pre_buffer("extern double __builtin_fabs(double);\n");
	add_pre_buffer("extern __SIZE_TYPE__ __builtin_va_arg_pack_len(void);\n");

	/* Add Blackfin-specific stuff */
	add_pre_buffer(
		"#ifdef __bfin__\n"
		"extern void __builtin_bfin_csync(void);\n"
		"extern void __builtin_bfin_ssync(void);\n"
		"extern int __builtin_bfin_norm_fr1x32(int);\n"
		"#endif\n"
	);

	/* And some floating point stuff.. */
	add_pre_buffer("extern int __builtin_isgreater(float, float);\n");
	add_pre_buffer("extern int __builtin_isgreaterequal(float, float);\n");
	add_pre_buffer("extern int __builtin_isless(float, float);\n");
	add_pre_buffer("extern int __builtin_islessequal(float, float);\n");
	add_pre_buffer("extern int __builtin_islessgreater(float, float);\n");
	add_pre_buffer("extern int __builtin_isunordered(float, float);\n");

	/* And some INFINITY / NAN stuff.. */
	add_pre_buffer("extern double __builtin_huge_val(void);\n");
	add_pre_buffer("extern float __builtin_huge_valf(void);\n");
	add_pre_buffer("extern long double __builtin_huge_vall(void);\n");
	add_pre_buffer("extern double __builtin_inf(void);\n");
	add_pre_buffer("extern float __builtin_inff(void);\n");
	add_pre_buffer("extern long double __builtin_infl(void);\n");
	add_pre_buffer("extern double __builtin_nan(const char *);\n");
	add_pre_buffer("extern float __builtin_nanf(const char *);\n");
	add_pre_buffer("extern long double __builtin_nanl(const char *);\n");
	add_pre_buffer("extern int __builtin_isinf_sign(float);\n");
	add_pre_buffer("extern int __builtin_isfinite(float);\n");
	add_pre_buffer("extern int __builtin_isnan(float);\n");

	/* And some __FORTIFY_SOURCE ones.. */
	add_pre_buffer ("extern __SIZE_TYPE__ __builtin_object_size(const void *, int);\n");
	add_pre_buffer ("extern void * __builtin___memcpy_chk(void *, const void *, __SIZE_TYPE__, __SIZE_TYPE__);\n");
	add_pre_buffer ("extern void * __builtin___memmove_chk(void *, const void *, __SIZE_TYPE__, __SIZE_TYPE__);\n");
	add_pre_buffer ("extern void * __builtin___mempcpy_chk(void *, const void *, __SIZE_TYPE__, __SIZE_TYPE__);\n");
	add_pre_buffer ("extern void * __builtin___memset_chk(void *, int, __SIZE_TYPE__, __SIZE_TYPE__);\n");
	add_pre_buffer ("extern int __builtin___sprintf_chk(char *, int, __SIZE_TYPE__, const char *, ...);\n");
	add_pre_buffer ("extern int __builtin___snprintf_chk(char *, __SIZE_TYPE__, int , __SIZE_TYPE__, const char *, ...);\n");
	add_pre_buffer ("extern char * __builtin___stpcpy_chk(char *, const char *, __SIZE_TYPE__);\n");
	add_pre_buffer ("extern char * __builtin___strcat_chk(char *, const char *, __SIZE_TYPE__);\n");
	add_pre_buffer ("extern char * __builtin___strcpy_chk(char *, const char *, __SIZE_TYPE__);\n");
	add_pre_buffer ("extern char * __builtin___strncat_chk(char *, const char *, __SIZE_TYPE__, __SIZE_TYPE__);\n");
	add_pre_buffer ("extern char * __builtin___strncpy_chk(char *, const char *, __SIZE_TYPE__, __SIZE_TYPE__);\n");
	add_pre_buffer ("extern int __builtin___vsprintf_chk(char *, int, __SIZE_TYPE__, const char *, __builtin_va_list);\n");
	add_pre_buffer ("extern int __builtin___vsnprintf_chk(char *, __SIZE_TYPE__, int, __SIZE_TYPE__, const char *, __builtin_va_list ap);\n");
	add_pre_buffer ("extern void __builtin_unreachable(void);\n");

	/* And some from <stdlib.h> */
	add_pre_buffer("extern void __builtin_abort(void);\n");
	add_pre_buffer("extern void *__builtin_calloc(__SIZE_TYPE__, __SIZE_TYPE__);\n");
	add_pre_buffer("extern void __builtin_exit(int);\n");
	add_pre_buffer("extern void *__builtin_malloc(__SIZE_TYPE__);\n");
	add_pre_buffer("extern void *__builtin_realloc(void *, __SIZE_TYPE__);\n");
	add_pre_buffer("extern void __builtin_free(void *);\n");

	/* And some from <stdio.h> */
	add_pre_buffer("extern int __builtin_printf(const char *, ...);\n");
	add_pre_buffer("extern int __builtin_sprintf(char *, const char *, ...);\n");
	add_pre_buffer("extern int __builtin_snprintf(char *, __SIZE_TYPE__, const char *, ...);\n");
	add_pre_buffer("extern int __builtin_puts(const char *);\n");
	add_pre_buffer("extern int __builtin_vprintf(const char *, __builtin_va_list);\n");
	add_pre_buffer("extern int __builtin_vsprintf(char *, const char *, __builtin_va_list);\n");
	add_pre_buffer("extern int __builtin_vsnprintf(char *, __SIZE_TYPE__, const char *, __builtin_va_list ap);\n");
}

void create_builtin_stream(void)
{
	add_pre_buffer("#weak_define __GNUC__ %d\n", gcc_major);
	add_pre_buffer("#weak_define __GNUC_MINOR__ %d\n", gcc_minor);
	add_pre_buffer("#weak_define __GNUC_PATCHLEVEL__ %d\n", gcc_patchlevel);

	/* add the multiarch include directories, if any */
	if (multiarch_dir && *multiarch_dir) {
		add_pre_buffer("#add_system \"/usr/include/%s\"\n", multiarch_dir);
		add_pre_buffer("#add_system \"/usr/local/include/%s\"\n", multiarch_dir);
	}

	/* We add compiler headers path here because we have to parse
	 * the arguments to get it, falling back to default. */
	add_pre_buffer("#add_system \"%s/include\"\n", gcc_base_dir);
	add_pre_buffer("#add_system \"%s/include-fixed\"\n", gcc_base_dir);

	add_pre_buffer("#define __extension__\n");
	add_pre_buffer("#define __pragma__\n");
	add_pre_buffer("#define _Pragma(x)\n");

	// gcc defines __SIZE_TYPE__ to be size_t.  For linux/i86 and
	// solaris/sparc that is really "unsigned int" and for linux/x86_64
	// it is "long unsigned int".  In either case we can probably
	// get away with this.  We need the #weak_define as cgcc will define
	// the right __SIZE_TYPE__.
	if (size_t_ctype == &ulong_ctype)
		add_pre_buffer("#weak_define __SIZE_TYPE__ long unsigned int\n");
	else
		add_pre_buffer("#weak_define __SIZE_TYPE__ unsigned int\n");
	add_pre_buffer("#weak_define __STDC__ 1\n");

	switch (standard)
	{
		case STANDARD_C89:
			add_pre_buffer("#weak_define __STRICT_ANSI__\n");
			break;

		case STANDARD_C94:
			add_pre_buffer("#weak_define __STDC_VERSION__ 199409L\n");
			add_pre_buffer("#weak_define __STRICT_ANSI__\n");
			break;

		case STANDARD_C99:
			add_pre_buffer("#weak_define __STDC_VERSION__ 199901L\n");
			add_pre_buffer("#weak_define __STRICT_ANSI__\n");
			break;

		case STANDARD_GNU89:
			break;

		case STANDARD_GNU99:
			add_pre_buffer("#weak_define __STDC_VERSION__ 199901L\n");
			break;

		case STANDARD_C11:
			add_pre_buffer("#weak_define __STRICT_ANSI__ 1\n");
		case STANDARD_GNU11:
			add_pre_buffer("#weak_define __STDC_NO_ATOMICS__ 1\n");
			add_pre_buffer("#weak_define __STDC_NO_COMPLEX__ 1\n");
			add_pre_buffer("#weak_define __STDC_NO_THREADS__ 1\n");
			add_pre_buffer("#weak_define __STDC_VERSION__ 201112L\n");
			break;

		default:
			assert (0);
	}

	add_pre_buffer("#define __builtin_stdarg_start(a,b) ((a) = (__builtin_va_list)(&(b)))\n");
	add_pre_buffer("#define __builtin_va_start(a,b) ((a) = (__builtin_va_list)(&(b)))\n");
	add_pre_buffer("#define __builtin_ms_va_start(a,b) ((a) = (__builtin_ms_va_list)(&(b)))\n");
	add_pre_buffer("#define __builtin_va_arg(arg,type)  ({ type __va_arg_ret = *(type *)(arg); arg += sizeof(type); __va_arg_ret; })\n");
	add_pre_buffer("#define __builtin_va_alist (*(void *)0)\n");
	add_pre_buffer("#define __builtin_va_arg_incr(x) ((x) + 1)\n");
	add_pre_buffer("#define __builtin_va_copy(dest, src) ({ dest = src; (void)0; })\n");
	add_pre_buffer("#define __builtin_ms_va_copy(dest, src) ({ dest = src; (void)0; })\n");
	add_pre_buffer("#define __builtin_va_end(arg)\n");
	add_pre_buffer("#define __builtin_ms_va_end(arg)\n");
	add_pre_buffer("#define __builtin_va_arg_pack()\n");

	/* FIXME! We need to do these as special magic macros at expansion time! */
	add_pre_buffer("#define __BASE_FILE__ \"base_file.c\"\n");

	if (optimize)
		add_pre_buffer("#define __OPTIMIZE__ 1\n");
	if (optimize_size)
		add_pre_buffer("#define __OPTIMIZE_SIZE__ 1\n");
}

static struct symbol_list *sparse_tokenstream(struct token *token)
{
	int builtin = token && !token->pos.stream;

	// Preprocess the stream
	token = preprocess(token);

	if (dump_macro_defs && !builtin)
		dump_macro_definitions();

	if (preprocess_only) {
		while (!eof_token(token)) {
			int prec = 1;
			struct token *next = token->next;
			const char *separator = "";
			if (next->pos.whitespace)
				separator = " ";
			if (next->pos.newline) {
				separator = "\n\t\t\t\t\t";
				prec = next->pos.pos;
				if (prec > 4)
					prec = 4;
			}
			printf("%s%.*s", show_token(token), prec, separator);
			token = next;
		}
		putchar('\n');

		return NULL;
	}

	// Parse the resulting C code
	while (!eof_token(token))
		token = external_declaration(token, &translation_unit_used_list, NULL);
	return translation_unit_used_list;
}

static struct symbol_list *sparse_file(const char *filename)
{
	int fd;
	struct token *token;

	if (strcmp (filename, "-") == 0) {
		fd = 0;
	} else {
		fd = open(filename, O_RDONLY);
		if (fd < 0)
			die("No such file: %s", filename);
	}

	// Tokenize the input stream
	token = tokenize(filename, fd, NULL, includepath);
	store_all_tokens(token);
	close(fd);

	return sparse_tokenstream(token);
}

static int endswith(const char *str, const char *suffix)
{
	const char *found = strstr(str, suffix);
	return (found && strcmp(found, suffix) == 0);
}

/*
 * This handles the "-include" directive etc: we're in global
 * scope, and all types/macros etc will affect all the following
 * files.
 *
 * NOTE NOTE NOTE! "#undef" of anything in this stage will
 * affect all subsequent files too, i.e. we can have non-local
 * behaviour between files!
 */
static struct symbol_list *sparse_initial(void)
{
	int i;

	// Prepend any "include" file to the stream.
	// We're in global scope, it will affect all files!
	for (i = 0; i < cmdline_include_nr; i++)
		add_pre_buffer("#argv_include \"%s\"\n", cmdline_include[i]);

	return sparse_tokenstream(pre_buffer_begin);
}

struct symbol_list *sparse_initialize(int argc, char **argv, struct string_list **filelist)
{
	char **args;
	struct symbol_list *list;

	// Initialize symbol stream first, so that we can add defines etc
	init_symbols();
	init_include_path();

	progname = argv[0];

	args = argv;
	for (;;) {
		char *arg = *++args;
		if (!arg)
			break;

		if (arg[0] == '-' && arg[1]) {
			args = handle_switch(arg+1, args);
			continue;
		}

		if (endswith(arg, ".a") || endswith(arg, ".so") ||
		    endswith(arg, ".so.1") || endswith(arg, ".o"))
			continue;

		add_ptr_list_notag(filelist, arg);
	}
	handle_switch_W_finalize();
	handle_switch_v_finalize();

	handle_arch_finalize();

	list = NULL;
	if (!ptr_list_empty(filelist)) {
		// Initialize type system
		init_ctype();
		handle_funsigned_char();

		create_builtin_stream();
		predefined_macros();
		if (!preprocess_only)
			declare_builtin_functions();

		list = sparse_initial();

		/*
		 * Protect the initial token allocations, since
		 * they need to survive all the others
		 */
		protect_token_alloc();
	}
	/*
	 * Evaluate the complete symbol list
	 * Note: This is not needed for normal cases.
	 *	 These symbols should only be predefined defines and
	 *	 declaratons which will be evaluated later, when needed.
	 *	 This is also the case when a file is directly included via
	 *	 '-include <file>' on the command line *AND* the file only
	 *	 contains defines, declarations and inline definitions.
	 *	 However, in the rare cases where the given file should
	 *	 contain some definitions, these will never be evaluated
	 *	 and thus won't be able to be linearized correctly.
	 *	 Hence the evaluate_symbol_list() here under.
	 */
	evaluate_symbol_list(list);
	return list;
}

struct symbol_list * sparse_keep_tokens(char *filename)
{
	struct symbol_list *res;

	/* Clear previous symbol list */
	translation_unit_used_list = NULL;

	new_file_scope();
	res = sparse_file(filename);

	/* And return it */
	return res;
}


struct symbol_list * __sparse(char *filename)
{
	struct symbol_list *res;

	res = sparse_keep_tokens(filename);

	/* Drop the tokens for this file after parsing */
	clear_token_alloc();

	/* And return it */
	return res;
}

struct symbol_list * sparse(char *filename)
{
	struct symbol_list *res = __sparse(filename);

	if (has_error & ERROR_CURR_PHASE)
		has_error = ERROR_PREV_PHASE;
	/* Evaluate the complete symbol list */
	evaluate_symbol_list(res);

	return res;
}
