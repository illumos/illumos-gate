#include "dissect.h"

static unsigned dotc_stream;

static inline char storage(struct symbol *sym)
{
	int t = sym->type;
	unsigned m = sym->ctype.modifiers;

	if (m & MOD_INLINE || t == SYM_STRUCT || t == SYM_UNION /*|| t == SYM_ENUM*/)
		return sym->pos.stream == dotc_stream ? 's' : 'g';

	return (m & MOD_STATIC) ? 's' : (m & MOD_NONLOCAL) ? 'g' : 'l';
}

static inline const char *show_mode(unsigned mode)
{
	static char str[3];

	if (mode == -1)
		return "def";

#define	U(u_r)	"-rwm"[(mode / u_r) & 3]
	str[0] = U(U_R_AOF);
	str[1] = U(U_R_VAL);
	str[2] = U(U_R_PTR);
#undef	U

	return str;
}

static void print_usage(struct position *pos, struct symbol *sym, unsigned mode)
{
	static unsigned curr_stream = -1;

	if (curr_stream != pos->stream) {
		curr_stream = pos->stream;
		printf("\nFILE: %s\n\n", stream_name(curr_stream));
	}

	printf("%4d:%-3d %c %-5.3s",
		pos->line, pos->pos, storage(sym), show_mode(mode));
}

static void r_symbol(unsigned mode, struct position *pos, struct symbol *sym)
{
	print_usage(pos, sym, mode);

	if (!sym->ident)
		sym->ident = built_in_ident("__asm__");

	printf("%-32.*s %s\n",
		sym->ident->len, sym->ident->name,
		show_typename(sym->ctype.base_type));
}

static void r_member(unsigned mode, struct position *pos, struct symbol *sym, struct symbol *mem)
{
	struct ident *ni, *si, *mi;

	print_usage(pos, sym, mode);

	ni = built_in_ident("?");
	si = sym->ident ?: ni;
	/* mem == NULL means entire struct accessed */
	mi = mem ? (mem->ident ?: ni) : built_in_ident("*");

	printf("%.*s.%-*.*s %s\n",
		si->len, si->name,
		32-1 - si->len, mi->len, mi->name,
		show_typename(mem ? mem->ctype.base_type : sym));
}

static void r_symdef(struct symbol *sym)
{
	r_symbol(-1, &sym->pos, sym);
}

int main(int argc, char **argv)
{
	static struct reporter reporter = {
		.r_symdef = r_symdef,
		.r_symbol = r_symbol,
		.r_member = r_member,
	};
	struct string_list *filelist = NULL;
	char *file;

	sparse_initialize(argc, argv, &filelist);

	FOR_EACH_PTR(filelist, file) {
		dotc_stream = input_stream_nr;
		dissect(__sparse(file), &reporter);
	} END_FOR_EACH_PTR(file);

	return 0;
}
