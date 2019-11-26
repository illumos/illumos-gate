
#define IDENT(n) __IDENT(n## _ident, #n, 0)
#define IDENT_RESERVED(n) __IDENT(n## _ident, #n, 1)

/* Basic C reserved words.. */
IDENT_RESERVED(sizeof);
IDENT_RESERVED(if);
IDENT_RESERVED(else);
IDENT_RESERVED(return);
IDENT_RESERVED(switch);
IDENT_RESERVED(case);
IDENT_RESERVED(default);
IDENT_RESERVED(break);
IDENT_RESERVED(continue);
IDENT_RESERVED(for);
IDENT_RESERVED(while);
IDENT_RESERVED(do);
IDENT_RESERVED(goto);

/* C typenames. They get marked as reserved when initialized */
IDENT(struct);
IDENT(union);
IDENT(enum);
IDENT(__attribute); IDENT(__attribute__);
IDENT(volatile); IDENT(__volatile); IDENT(__volatile__);
IDENT(double);

/* C storage classes. They get marked as reserved when initialized */
IDENT(static);

/* C99 keywords */
IDENT(restrict); IDENT(__restrict); IDENT(__restrict__);
IDENT(_Bool);
IDENT_RESERVED(_Complex);
IDENT_RESERVED(_Imaginary);

/* C11 keywords */
IDENT(_Alignas);
IDENT_RESERVED(_Alignof);
IDENT(_Atomic);
IDENT_RESERVED(_Generic);
IDENT(_Noreturn);
IDENT_RESERVED(_Static_assert);
IDENT(_Thread_local);

/* Special case for L'\t' */
IDENT(L);

/* Extended gcc identifiers */
IDENT(asm); IDENT_RESERVED(__asm); IDENT_RESERVED(__asm__);
IDENT(alignof); IDENT_RESERVED(__alignof); IDENT_RESERVED(__alignof__); 
IDENT_RESERVED(__sizeof_ptr__);
IDENT_RESERVED(__builtin_types_compatible_p);
IDENT_RESERVED(__builtin_offsetof);
IDENT_RESERVED(__label__);

/* Preprocessor idents.  Direct use of __IDENT avoids mentioning the keyword
 * itself by name, preventing these tokens from expanding when compiling
 * sparse. */
IDENT(defined);
IDENT(once);
IDENT(__has_attribute);
IDENT(__has_builtin);
__IDENT(pragma_ident, "__pragma__", 0);
__IDENT(_Pragma_ident, "_Pragma", 0);
__IDENT(__VA_ARGS___ident, "__VA_ARGS__", 0);
__IDENT(__func___ident, "__func__", 0);
__IDENT(__FUNCTION___ident, "__FUNCTION__", 0);
__IDENT(__PRETTY_FUNCTION___ident, "__PRETTY_FUNCTION__", 0);

/* Sparse commands */
IDENT_RESERVED(__context__);
IDENT_RESERVED(__range__);

/* Magic function names we recognize */
IDENT(memset); IDENT(memcpy);
IDENT(copy_to_user); IDENT(copy_from_user);
IDENT(main);

#undef __IDENT
#undef IDENT
#undef IDENT_RESERVED
