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
#include <errno.h>
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
#include "evaluate.h"
#include "scope.h"
#include "linearize.h"
#include "target.h"
#include "machine.h"
#include "version.h"
#include "bits.h"

int verbose, optimize_level, optimize_size, preprocessing;
int die_if_error = 0;
int parse_error;
int has_error = 0;
int do_output = 0;

#ifndef __GNUC__
# define __GNUC__ 2
# define __GNUC_MINOR__ 95
# define __GNUC_PATCHLEVEL__ 0
#endif

int gcc_major = __GNUC__;
int gcc_minor = __GNUC_MINOR__;
int gcc_patchlevel = __GNUC_PATCHLEVEL__;

const char *base_filename;

static const char *diag_prefix = "";
static const char *gcc_base_dir = GCC_BASE;
static const char *multiarch_dir = MULTIARCH_TRIPLET;
static const char *outfile = NULL;

struct token *skip_to(struct token *token, int op)
{
	while (!match_op(token, op) && !eof_token(token))
		token = token->next;
	return token;
}

static struct token bad_token = { .pos.type = TOKEN_BAD };
struct token *expect(struct token *token, int op, const char *where)
{
	if (!match_op(token, op)) {
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

///
// issue an error message on new parsing errors
// @token: the current token
// @errmsg: the error message
// If the current token is from a previous error, an error message
// has already been issued, so nothing more is done.
// Otherwise, @errmsg is displayed followed by the current token.
void unexpected(struct token *token, const char *errmsg)
{
	if (token == &bad_token)
		return;
	sparse_error(token->pos, "%s", errmsg);
	sparse_error(token->pos, "got %s", show_token(token));
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

	/* Shut up warnings if position is bad_token.pos */
	if (pos.type == TOKEN_BAD)
		return;

	vsprintf(buffer, fmt, args);	
	name = stream_name(pos.stream);
		
	fflush(stdout);
	fprintf(stderr, "%s: %s:%d:%d: %s%s\n",
		diag_prefix, name, pos.line, pos.pos, type, buffer);
}

unsigned int fmax_warnings = 100;
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
	/* Shut up warnings if position is bad_token.pos */
	if (pos.type == TOKEN_BAD)
		return;
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

	if (!fmax_warnings || has_error) {
		show_info = 0;
		return;
	}

	if (!--fmax_warnings) {
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

	fprintf(stderr, "%s: %s\n", diag_prefix, buffer);
	exit(1);
}

static struct token *pre_buffer_begin = NULL;
static struct token *pre_buffer_end = NULL;

int Waddress = 0;
int Waddress_space = 1;
int Wbitwise = 1;
int Wbitwise_pointer = 0;
int Wcast_from_as = 0;
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
int Wint_to_pointer_cast = 1;
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
int Wpointer_to_int_cast = 1;
int Wptr_subtraction_blows = 0;
int Wreturn_void = 0;
int Wshadow = 0;
int Wshift_count_negative = 1;
int Wshift_count_overflow = 1;
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
int dump_macros_only = 0;

int dbg_compound = 0;
int dbg_dead = 0;
int dbg_domtree = 0;
int dbg_entry = 0;
int dbg_ir = 0;
int dbg_postorder = 0;

unsigned long fdump_ir;
int fmem_report = 0;
unsigned long long fmemcpy_max_count = 100000;
unsigned long fpasses = ~0UL;
int funsigned_char = UNSIGNED_CHAR;

int preprocess_only;

enum standard standard = STANDARD_GNU89;

int arch_m64 = ARCH_M64_DEFAULT;
int arch_msize_long = 0;
int arch_big_endian = ARCH_BIG_ENDIAN;
int arch_mach = MACH_NATIVE;


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
	} else if (!strcmp(arg, "m32") || !strcmp(arg, "m16")) {
		arch_m64 = ARCH_LP32;
	} else if (!strcmp(arg, "mx32")) {
		arch_m64 = ARCH_X32;
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

static void handle_arch_msize_long_finalize(void)
{
	if (arch_msize_long) {
		size_t_ctype = &ulong_ctype;
		ssize_t_ctype = &long_ctype;
	}
}

static void handle_arch_finalize(void)
{
	handle_arch_msize_long_finalize();
}

static const char *match_option(const char *arg, const char *prefix)
{
	unsigned int n = strlen(prefix);
	if (strncmp(arg, prefix, n) == 0)
		return arg + n;
	return NULL;
}


struct mask_map {
	const char *name;
	unsigned long mask;
};

static int apply_mask(unsigned long *val, const char *str, unsigned len, const struct mask_map *map, int neg)
{
	const char *name;

	for (;(name = map->name); map++) {
		if (!strncmp(name, str, len) && !name[len]) {
			if (neg == 0)
				*val |= map->mask;
			else
				*val &= ~map->mask;
			return 0;
		}
	}
	return 1;
}

static int handle_suboption_mask(const char *arg, const char *opt, const struct mask_map *map, unsigned long *flag)
{
	if (*opt == '\0') {
		apply_mask(flag, "", 0, map, 0);
		return 1;
	}
	if (*opt++ != '=')
		return 0;
	while (1) {
		unsigned int len = strcspn(opt, ",+");
		int neg = 0;
		if (len == 0)
			goto end;
		if (!strncmp(opt, "no-", 3)) {
			opt += 3;
			len -= 3;
			neg = 1;
		}
		if (apply_mask(flag, opt, len, map, neg))
			die("error: wrong option '%.*s' for \'%s\'", len, opt, arg);

end:
		opt += len;
		if (*opt++ == '\0')
			break;
	}
	return 1;
}


#define OPT_INVERSE	1
struct flag {
	const char *name;
	int *flag;
	int (*fun)(const char *arg, const char *opt, const struct flag *, int options);
	unsigned long mask;
};

static int handle_switches(const char *ori, const char *opt, const struct flag *flags)
{
	const char *arg = opt;
	int val = 1;

	// Prefixe "no-" mean to turn flag off.
	if (strncmp(arg, "no-", 3) == 0) {
		arg += 3;
		val = 0;
	}

	for (; flags->name; flags++) {
		const char *opt = match_option(arg, flags->name);
		int rc;

		if (!opt)
			continue;

		if (flags->fun) {
			int options = 0;
			if (!val)
				options |= OPT_INVERSE;
			if ((rc = flags->fun(ori, opt, flags, options)))
				return rc;
		}

		// boolean flag
		if (opt[0] == '\0' && flags->flag) {
			if (flags->mask & OPT_INVERSE)
				val = !val;
			*flags->flag = val;
			return 1;
		}
	}

	// not handled
	return 0;
}


#define	OPTNUM_ZERO_IS_INF		1
#define	OPTNUM_UNLIMITED		2

#define OPT_NUMERIC(NAME, TYPE, FUNCTION)	\
static int opt_##NAME(const char *arg, const char *opt, TYPE *ptr, int flag)	\
{									\
	char *end;							\
	TYPE val;							\
									\
	val = FUNCTION(opt, &end, 0);					\
	if (*end != '\0' || end == opt) {				\
		if ((flag & OPTNUM_UNLIMITED) && !strcmp(opt, "unlimited"))	\
			val = ~val;					\
		else							\
			die("error: wrong argument to \'%s\'", arg);	\
	}								\
	if ((flag & OPTNUM_ZERO_IS_INF) && val == 0)			\
		val = ~val;						\
	*ptr = val;							\
	return 1;							\
}

OPT_NUMERIC(ullong, unsigned long long, strtoull)
OPT_NUMERIC(uint, unsigned int, strtoul)


static char **handle_switch_o(char *arg, char **next)
{
	if (!strcmp (arg, "o")) {       // "-o foo"
		if (!*++next)
			die("argument to '-o' is missing");
		outfile = *next;
	}
	// else "-ofoo"

	return next;
}

static const struct flag warnings[] = {
	{ "address", &Waddress },
	{ "address-space", &Waddress_space },
	{ "bitwise", &Wbitwise },
	{ "bitwise-pointer", &Wbitwise_pointer},
	{ "cast-from-as", &Wcast_from_as },
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
	{ "int-to-pointer-cast", &Wint_to_pointer_cast },
	{ "memcpy-max-count", &Wmemcpy_max_count },
	{ "non-pointer-null", &Wnon_pointer_null },
	{ "old-initializer", &Wold_initializer },
	{ "old-style-definition", &Wold_style_definition },
	{ "one-bit-signed-bitfield", &Wone_bit_signed_bitfield },
	{ "override-init", &Woverride_init },
	{ "override-init-all", &Woverride_init_all },
	{ "paren-string", &Wparen_string },
	{ "pointer-to-int-cast", &Wpointer_to_int_cast },
	{ "ptr-subtraction-blows", &Wptr_subtraction_blows },
	{ "return-void", &Wreturn_void },
	{ "shadow", &Wshadow },
	{ "shift-count-negative", &Wshift_count_negative },
	{ "shift-count-overflow", &Wshift_count_overflow },
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


static char **handle_onoff_switch(char *arg, char **next, const struct flag warnings[], int n)
{
	int flag = WARNING_ON;
	char *p = arg + 1;
	unsigned i;

	if (!strcmp(p, "sparse-all")) {
		for (i = 0; i < n; i++) {
			if (*warnings[i].flag != WARNING_FORCE_OFF && warnings[i].flag != &Wsparse_error)
				*warnings[i].flag = WARNING_ON;
		}
		return NULL;
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

static struct flag debugs[] = {
	{ "compound", &dbg_compound},
	{ "dead", &dbg_dead},
	{ "domtree", &dbg_domtree},
	{ "entry", &dbg_entry},
	{ "ir", &dbg_ir},
	{ "postorder", &dbg_postorder},
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

static char **handle_switch_d(char *arg, char **next)
{
	char *arg_char = arg + 1;

	/*
	 * -d<CHARS>, where <CHARS> is a sequence of characters, not preceded
	 * by a space. If you specify characters whose behaviour conflicts,
	 * the result is undefined.
	 */
	while (*arg_char) {
		switch (*arg_char) {
		case 'M': /* dump just the macro definitions */
			dump_macros_only = 1;
			dump_macro_defs = 0;
			break;
		case 'D': /* like 'M', but also output pre-processed text */
			dump_macro_defs = 1;
			dump_macros_only = 0;
			break;
		case 'N': /* like 'D', but only output macro names not bodies */
			break;
		case 'I': /* like 'D', but also output #include directives */
			break;
		case 'U': /* like 'D', but only output expanded macros */
			break;
		}
		arg_char++;
	}
	return next;
}


static void handle_onoff_switch_finalize(const struct flag warnings[], int n)
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
	optimize_level = level;
	optimize_size = arg[1] == 's';
	return next;
}

static int handle_ftabstop(const char *arg, const char *opt, const struct flag *flag, int options)
{
	unsigned long val;
	char *end;

	if (*opt == '\0')
		die("error: missing argument to \"%s\"", arg);

	/* we silently ignore silly values */
	val = strtoul(opt, &end, 10);
	if (*end == '\0' && 1 <= val && val <= 100)
		tabstop = val;

	return 1;
}

static int handle_fpasses(const char *arg, const char *opt, const struct flag *flag, int options)
{
	unsigned long mask;

	mask = flag->mask;
	if (*opt == '\0') {
		if (options & OPT_INVERSE)
			fpasses &= ~mask;
		else
			fpasses |=  mask;
		return 1;
	}
	if (options & OPT_INVERSE)
		return 0;
	if (!strcmp(opt, "-enable")) {
		fpasses |= mask;
		return 1;
	}
	if (!strcmp(opt, "-disable")) {
		fpasses &= ~mask;
		return 1;
	}
	if (!strcmp(opt, "=last")) {
		// clear everything above
		mask |= mask - 1;
		fpasses &= mask;
		return 1;
	}
	return 0;
}

static int handle_fdiagnostic_prefix(const char *arg, const char *opt, const struct flag *flag, int options)
{
	switch (*opt) {
	case '\0':
		diag_prefix = "sparse";
		return 1;
	case '=':
		diag_prefix = xasprintf("%s", opt+1);
		return 1;
	default:
		return 0;
	}
}

static int handle_fdump_ir(const char *arg, const char *opt, const struct flag *flag, int options)
{
	static const struct mask_map dump_ir_options[] = {
		{ "",			PASS_LINEARIZE },
		{ "linearize",		PASS_LINEARIZE },
		{ "mem2reg",		PASS_MEM2REG },
		{ "final",		PASS_FINAL },
		{ },
	};

	return handle_suboption_mask(arg, opt, dump_ir_options, &fdump_ir);
}

static int handle_fmemcpy_max_count(const char *arg, const char *opt, const struct flag *flag, int options)
{
	opt_ullong(arg, opt, &fmemcpy_max_count, OPTNUM_ZERO_IS_INF|OPTNUM_UNLIMITED);
	return 1;
}

static int handle_fmax_warnings(const char *arg, const char *opt, const struct flag *flag, int options)
{
	opt_uint(arg, opt, &fmax_warnings, OPTNUM_UNLIMITED);
	return 1;
}

static struct flag fflags[] = {
	{ "diagnostic-prefix",	NULL,	handle_fdiagnostic_prefix },
	{ "dump-ir",		NULL,	handle_fdump_ir },
	{ "linearize",		NULL,	handle_fpasses,	PASS_LINEARIZE },
	{ "max-warnings=",	NULL,	handle_fmax_warnings },
	{ "mem-report",		&fmem_report },
	{ "memcpy-max-count=",	NULL,	handle_fmemcpy_max_count },
	{ "tabstop=",		NULL,	handle_ftabstop },
	{ "mem2reg",		NULL,	handle_fpasses,	PASS_MEM2REG },
	{ "optim",		NULL,	handle_fpasses,	PASS_OPTIM },
	{ "signed-char",	&funsigned_char, NULL,	OPT_INVERSE },
	{ "unsigned-char",	&funsigned_char, NULL, },
	{ },
};

static char **handle_switch_f(char *arg, char **next)
{
	if (handle_switches(arg-1, arg+1, fflags))
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

static char **handle_switch_s(const char *arg, char **next)
{
	if ((arg = match_option(arg, "std="))) {
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

		/*
		 * For the interim, allow GNU17 to be treated as GNU11 as C17 is
		 * mostly just a clean up of C11 and is not supposed to add any
		 * new features.
		 */
		else if (!strcmp(arg, "gnu11") ||
		         !strcmp(arg, "gnu17"))
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

static char **handle_switch_x(char *arg, char **next)
{
	if (!*++next)
		die("missing argument for -x option");
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
	case 'x': return handle_switch_x(arg, next);
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

#define	PTYPE_SIZEOF	(1U << 0)
#define	PTYPE_T		(1U << 1)
#define	PTYPE_MAX	(1U << 2)
#define	PTYPE_MIN	(1U << 3)
#define	PTYPE_WIDTH	(1U << 4)
#define	PTYPE_TYPE	(1U << 5)
#define	PTYPE_ALL	(PTYPE_MAX|PTYPE_SIZEOF|PTYPE_WIDTH)
#define	PTYPE_ALL_T	(PTYPE_MAX|PTYPE_SIZEOF|PTYPE_WIDTH|PTYPE_T)

static void predefined_sizeof(const char *name, const char *suffix, unsigned bits)
{
	char buf[32];

	snprintf(buf, sizeof(buf), "__SIZEOF_%s%s__", name, suffix);
	predefine(buf, 1, "%d", bits/8);
}

static void predefined_width(const char *name, unsigned bits)
{
	char buf[32];

	snprintf(buf, sizeof(buf), "__%s_WIDTH__", name);
	predefine(buf, 1, "%d", bits);
}

static void predefined_max(const char *name, struct symbol *type)
{
	const char *suffix = builtin_type_suffix(type);
	unsigned bits = type->bit_size - is_signed_type(type);
	unsigned long long max = bits_mask(bits);
	char buf[32];

	snprintf(buf, sizeof(buf), "__%s_MAX__", name);
	predefine(buf, 1, "%#llx%s", max, suffix);
}

static void predefined_min(const char *name, struct symbol *type)
{
	const char *suffix = builtin_type_suffix(type);
	char buf[32];

	snprintf(buf, sizeof(buf), "__%s_MIN__", name);

	if (is_signed_type(type))
		predefine(buf, 1, "(-__%s_MAX__ - 1)", name);
	else
		predefine(buf, 1, "0%s", suffix);
}

static void predefined_type(const char *name, struct symbol *type)
{
	const char *typename = builtin_typename(type);
	add_pre_buffer("#weak_define __%s_TYPE__ %s\n", name, typename);
}

static void predefined_ctype(const char *name, struct symbol *type, int flags)
{
	unsigned bits = type->bit_size;

	if (flags & PTYPE_SIZEOF) {
		const char *suffix = (flags & PTYPE_T) ? "_T" : "";
		predefined_sizeof(name, suffix, bits);
	}
	if (flags & PTYPE_MAX)
		predefined_max(name, type);
	if (flags & PTYPE_MIN)
		predefined_min(name, type);
	if (flags & PTYPE_TYPE)
		predefined_type(name, type);
	if (flags & PTYPE_WIDTH)
		predefined_width(name, bits);
}

static void predefined_macros(void)
{
	predefine("__CHECKER__", 0, "1");
	predefine("__GNUC__", 1, "%d", gcc_major);
	predefine("__GNUC_MINOR__", 1, "%d", gcc_minor);
	predefine("__GNUC_PATCHLEVEL__", 1, "%d", gcc_patchlevel);

	predefine("__STDC__", 1, "1");
	switch (standard) {
	case STANDARD_C89:
		predefine("__STRICT_ANSI__", 1, "1");
		break;

	case STANDARD_C94:
		predefine("__STDC_VERSION__", 1, "199409L");
		predefine("__STRICT_ANSI__", 1, "1");
		break;

	case STANDARD_C99:
		predefine("__STDC_VERSION__", 1, "199901L");
		predefine("__STRICT_ANSI__", 1, "1");
		break;

	case STANDARD_GNU89:
	default:
		break;

	case STANDARD_GNU99:
		predefine("__STDC_VERSION__", 1, "199901L");
		break;

	case STANDARD_C11:
		predefine("__STRICT_ANSI__", 1, "1");
	case STANDARD_GNU11:
		predefine("__STDC_NO_ATOMICS__", 1, "1");
		predefine("__STDC_NO_COMPLEX__", 1, "1");
		predefine("__STDC_NO_THREADS__", 1, "1");
		predefine("__STDC_VERSION__", 1, "201112L");
		break;
	}

	predefine("__CHAR_BIT__", 1, "%d", bits_in_char);
	if (funsigned_char)
		predefine("__CHAR_UNSIGNED__", 1, "1");

	predefined_ctype("SHORT",     &short_ctype, PTYPE_SIZEOF);
	predefined_ctype("SHRT",      &short_ctype, PTYPE_MAX|PTYPE_WIDTH);
	predefined_ctype("SCHAR",     &schar_ctype, PTYPE_MAX|PTYPE_WIDTH);
	predefined_ctype("WCHAR",      wchar_ctype, PTYPE_ALL_T|PTYPE_MIN|PTYPE_TYPE);
	predefined_ctype("WINT",        wint_ctype, PTYPE_ALL_T|PTYPE_MIN|PTYPE_TYPE);
	predefined_ctype("CHAR16",   &ushort_ctype, PTYPE_TYPE);
	predefined_ctype("CHAR32",     &uint_ctype, PTYPE_TYPE);

	predefined_ctype("INT",         &int_ctype, PTYPE_ALL);
	predefined_ctype("LONG",       &long_ctype, PTYPE_ALL);
	predefined_ctype("LONG_LONG", &llong_ctype, PTYPE_ALL);

	predefined_ctype("INT8",      &schar_ctype, PTYPE_MAX|PTYPE_TYPE);
	predefined_ctype("UINT8",     &uchar_ctype, PTYPE_MAX|PTYPE_TYPE);
	predefined_ctype("INT16",     &short_ctype, PTYPE_MAX|PTYPE_TYPE);
	predefined_ctype("UINT16",   &ushort_ctype, PTYPE_MAX|PTYPE_TYPE);
	predefined_ctype("INT32",      int32_ctype, PTYPE_MAX|PTYPE_TYPE);
	predefined_ctype("UINT32",    uint32_ctype, PTYPE_MAX|PTYPE_TYPE);
	predefined_ctype("INT64",      int64_ctype, PTYPE_MAX|PTYPE_TYPE);
	predefined_ctype("UINT64",    uint64_ctype, PTYPE_MAX|PTYPE_TYPE);

	predefined_sizeof("INT128", "", 128);

	predefined_ctype("INTMAX",    intmax_ctype, PTYPE_MAX|PTYPE_TYPE|PTYPE_WIDTH);
	predefined_ctype("UINTMAX",  uintmax_ctype, PTYPE_MAX|PTYPE_TYPE);
	predefined_ctype("INTPTR",   ssize_t_ctype, PTYPE_MAX|PTYPE_TYPE|PTYPE_WIDTH);
	predefined_ctype("UINTPTR",   size_t_ctype, PTYPE_MAX|PTYPE_TYPE);
	predefined_ctype("PTRDIFF",  ssize_t_ctype, PTYPE_ALL_T|PTYPE_TYPE);
	predefined_ctype("SIZE",      size_t_ctype, PTYPE_ALL_T|PTYPE_TYPE);
	predefined_ctype("POINTER",     &ptr_ctype, PTYPE_SIZEOF);

	predefined_sizeof("FLOAT", "", bits_in_float);
	predefined_sizeof("DOUBLE", "", bits_in_double);
	predefined_sizeof("LONG_DOUBLE", "", bits_in_longdouble);

	predefine("__ORDER_LITTLE_ENDIAN__", 1, "1234");
	predefine("__ORDER_BIG_ENDIAN__", 1, "4321");
	predefine("__ORDER_PDP_ENDIAN__", 1, "3412");
	if (arch_big_endian) {
		predefine("__BIG_ENDIAN__", 1, "1");
		predefine("__BYTE_ORDER__", 1, "__ORDER_BIG_ENDIAN__");
	} else {
		predefine("__LITTLE_ENDIAN__", 1, "1");
		predefine("__BYTE_ORDER__", 1, "__ORDER_LITTLE_ENDIAN__");
	}

	if (optimize_level)
		predefine("__OPTIMIZE__", 0, "1");
	if (optimize_size)
		predefine("__OPTIMIZE_SIZE__", 0, "1");

	predefine("__PRAGMA_REDEFINE_EXTNAME", 1, "1");

	// Temporary hacks
	predefine("__extension__", 0, NULL);
	predefine("__pragma__", 0, NULL);

	switch (arch_m64) {
	case ARCH_LP32:
		break;
	case ARCH_X32:
		predefine("__ILP32__", 1, "1");
		predefine("_ILP32", 1, "1");
		break;
	case ARCH_LP64:
		predefine("__LP64__", 1, "1");
		predefine("_LP64", 1, "1");
		break;
	case ARCH_LLP64:
		predefine("__LLP64__", 1, "1");
		break;
	}

	switch (arch_mach) {
	case MACH_ARM64:
		predefine("__aarch64__", 1, "1");
		break;
	case MACH_ARM:
		predefine("__arm__", 1, "1");
		break;
	case MACH_M68K:
		predefine("__m68k__", 1, "1");
		break;
	case MACH_MIPS64:
		if (arch_m64 == ARCH_LP64)
			predefine("__mips64", 1, "64");
		/* fall-through */
	case MACH_MIPS32:
		predefine("__mips", 1, "%d", ptr_ctype.bit_size);
		predefine("_MIPS_SZINT", 1, "%d", int_ctype.bit_size);
		predefine("_MIPS_SZLONG", 1, "%d", long_ctype.bit_size);
		predefine("_MIPS_SZPTR", 1, "%d", ptr_ctype.bit_size);
		break;
	case MACH_PPC64:
		if (arch_m64 == ARCH_LP64) {
			predefine("__powerpc64__", 1, "1");
			predefine("__ppc64__", 1, "1");
			predefine("__PPC64__", 1, "1");
		}
		/* fall-through */
	case MACH_PPC32:
		predefine("__powerpc__", 1, "1");
		predefine("__powerpc", 1, "1");
		predefine("__ppc__", 1, "1");
		predefine("__PPC__", 1, "1");
		break;
	case MACH_RISCV64:
	case MACH_RISCV32:
		predefine("__riscv", 1, "1");
		predefine("__riscv_xlen", 1, "%d", ptr_ctype.bit_size);
		break;
	case MACH_S390X:
		predefine("__zarch__", 1, "1");
		predefine("__s390x__", 1, "1");
		predefine("__s390__", 1, "1");
		break;
	case MACH_SPARC64:
		if (arch_m64 == ARCH_LP64) {
			predefine("__sparc_v9__", 1, "1");
			predefine("__sparcv9__", 1, "1");
			predefine("__sparcv9", 1, "1");
			predefine("__sparc64__", 1, "1");
			predefine("__arch64__", 1, "1");
		}
		/* fall-through */
	case MACH_SPARC32:
		predefine("__sparc__", 1, "1");
		predefine("__sparc", 1, "1");
		predefine_nostd("sparc");
		break;
	case MACH_X86_64:
		if (arch_m64 != ARCH_LP32) {
			predefine("__x86_64__", 1, "1");
			predefine("__x86_64", 1, "1");
			predefine("__amd64__", 1, "1");
			predefine("__amd64", 1, "1");
			break;
		}
		/* fall-through */
	case MACH_I386:
		predefine("__i386__", 1, "1");
		predefine("__i386", 1, "1");
		predefine_nostd("i386");
		break;
	}

#if defined(__unix__)
	predefine("__unix__", 1, "1");
	predefine("__unix", 1, "1");
	predefine_nostd("unix");
#endif


#if defined(__sun__) || defined(__sun)
	predefine("__sun__", 1, "1");
	predefine("__sun", 1, "1");
	predefine_nostd("sun");
	predefine("__svr4__", 1, "1");
#endif

}

static void create_builtin_stream(void)
{
	// Temporary hack
	add_pre_buffer("#define _Pragma(x)\n");

	/* add the multiarch include directories, if any */
	if (multiarch_dir && *multiarch_dir) {
		add_pre_buffer("#add_system \"/usr/include/%s\"\n", multiarch_dir);
		add_pre_buffer("#add_system \"/usr/local/include/%s\"\n", multiarch_dir);
	}

	/* We add compiler headers path here because we have to parse
	 * the arguments to get it, falling back to default. */
	add_pre_buffer("#add_system \"%s/include\"\n", gcc_base_dir);
	add_pre_buffer("#add_system \"%s/include-fixed\"\n", gcc_base_dir);

	add_pre_buffer("#define __has_builtin(x) 0\n");
	add_pre_buffer("#define __has_attribute(x) 0\n");
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
}

static struct symbol_list *sparse_tokenstream(struct token *token)
{
	int builtin = token && !token->pos.stream;

	// Preprocess the stream
	token = preprocess(token);

	if (dump_macro_defs || dump_macros_only) {
		if (!builtin)
			dump_macro_definitions();
		if (dump_macros_only)
			return NULL;
	}

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
	base_filename = filename;

	// Tokenize the input stream
	token = tokenize(filename, fd, NULL, includepath);
	store_all_tokens(token);
	close(fd);

	return sparse_tokenstream(token);
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

static int endswith(const char *str, const char *suffix)
{
	const char *found = strstr(str, suffix);
	return (found && strcmp(found, suffix) == 0);
}

struct symbol_list *sparse_initialize(int argc, char **argv, struct string_list **filelist)
{
	char **args;
	struct symbol_list *list;

	// Initialize symbol stream first, so that we can add defines etc
	init_symbols();
	init_include_path();

	diag_prefix = argv[0];

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

		add_ptr_list(filelist, arg);
	}
	handle_switch_W_finalize();
	handle_switch_v_finalize();

	// Redirect stdout if needed
	if (dump_macro_defs || preprocess_only)
		do_output = 1;
	if (do_output && outfile && strcmp(outfile, "-")) {
		if (!freopen(outfile, "w", stdout))
			die("error: cannot open %s: %s", outfile, strerror(errno));
	}

	if (fdump_ir == 0)
		fdump_ir = PASS_FINAL;

	list = NULL;
	if (filelist) {
		// Initialize type system
		init_target();
		handle_arch_finalize();
		init_ctype();

		predefined_macros();
		create_builtin_stream();
		declare_builtins();

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
