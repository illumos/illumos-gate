static int (auto);
static int (break);
static int (case);
static int (char);
static int (const);
static int (__const);
static int (__const__);
static int (continue);
static int (default);
static int (do);
static int (double);
static int (else);
static int (enum);
static int (extern);
static int (float);
static int (for);
static int (goto);
static int (if);
static int (inline);
static int (__inline);
static int (__inline__);
static int (int);
static int (long);
static int (register);
static int (restrict);
static int (__restrict);
static int (__restrict__);
static int (return);
static int (short);
static int (signed);
static int (sizeof);
static int (static);
static int (struct);
static int (switch);
static int (typedef);
static int (union);
static int (unsigned);
static int (void);
static int (volatile);
static int (volatile);
static int (__volatile);
static int (__volatile__);
static int (while);

static int (_Alignas);
static int (_Alignof);
static int (_Atomic);
static int (_Bool);
static int (_Complex);
static int (_Generic);
static int (_Imaginary);
static int (_Noreturn);
static int (_Static_assert);
static int (_Thread_local);

// Sparse extensions
static int (__context__);
static int (__range__);
static int (__sizeof_ptr__);

// GCC extensions
static int (__alignof);
static int (__alignof__);
static int (asm);			// not reserved!
static int (__asm);
static int (__asm__);
static int (__label__);
static int (__thread);
static int (typeof);
static int (__typeof);
static int (__typeof__);

static int (__int128);
static int (__int128_t);
static int (__uint128_t);

static int (__builtin_ms_va_list);
static int (__builtin_offsetof);
static int (__builtin_types_compatible_p);
static int (__builtin_va_list);

/*
 * check-name: const et.al. are reserved identifiers
 * check-error-start
reserved.c:1:12: error: Trying to use reserved word 'auto' as identifier
reserved.c:2:12: error: Trying to use reserved word 'break' as identifier
reserved.c:3:12: error: Trying to use reserved word 'case' as identifier
reserved.c:4:12: error: Trying to use reserved word 'char' as identifier
reserved.c:5:12: error: Trying to use reserved word 'const' as identifier
reserved.c:6:12: error: Trying to use reserved word '__const' as identifier
reserved.c:7:12: error: Trying to use reserved word '__const__' as identifier
reserved.c:8:12: error: Trying to use reserved word 'continue' as identifier
reserved.c:9:12: error: Trying to use reserved word 'default' as identifier
reserved.c:10:12: error: Trying to use reserved word 'do' as identifier
reserved.c:11:12: error: Trying to use reserved word 'double' as identifier
reserved.c:12:12: error: Trying to use reserved word 'else' as identifier
reserved.c:13:12: error: Trying to use reserved word 'enum' as identifier
reserved.c:14:12: error: Trying to use reserved word 'extern' as identifier
reserved.c:15:12: error: Trying to use reserved word 'float' as identifier
reserved.c:16:12: error: Trying to use reserved word 'for' as identifier
reserved.c:17:12: error: Trying to use reserved word 'goto' as identifier
reserved.c:18:12: error: Trying to use reserved word 'if' as identifier
reserved.c:19:12: error: Trying to use reserved word 'inline' as identifier
reserved.c:20:12: error: Trying to use reserved word '__inline' as identifier
reserved.c:21:12: error: Trying to use reserved word '__inline__' as identifier
reserved.c:22:12: error: Trying to use reserved word 'int' as identifier
reserved.c:23:12: error: Trying to use reserved word 'long' as identifier
reserved.c:24:12: error: Trying to use reserved word 'register' as identifier
reserved.c:25:12: error: Trying to use reserved word 'restrict' as identifier
reserved.c:26:12: error: Trying to use reserved word '__restrict' as identifier
reserved.c:27:12: error: Trying to use reserved word '__restrict__' as identifier
reserved.c:28:12: error: Trying to use reserved word 'return' as identifier
reserved.c:29:12: error: Trying to use reserved word 'short' as identifier
reserved.c:30:12: error: Trying to use reserved word 'signed' as identifier
reserved.c:31:12: error: Trying to use reserved word 'sizeof' as identifier
reserved.c:32:12: error: Trying to use reserved word 'static' as identifier
reserved.c:33:12: error: Trying to use reserved word 'struct' as identifier
reserved.c:34:12: error: Trying to use reserved word 'switch' as identifier
reserved.c:35:12: error: Trying to use reserved word 'typedef' as identifier
reserved.c:36:12: error: Trying to use reserved word 'union' as identifier
reserved.c:37:12: error: Trying to use reserved word 'unsigned' as identifier
reserved.c:38:12: error: Trying to use reserved word 'void' as identifier
reserved.c:39:12: error: Trying to use reserved word 'volatile' as identifier
reserved.c:40:12: error: Trying to use reserved word 'volatile' as identifier
reserved.c:41:12: error: Trying to use reserved word '__volatile' as identifier
reserved.c:42:12: error: Trying to use reserved word '__volatile__' as identifier
reserved.c:43:12: error: Trying to use reserved word 'while' as identifier
reserved.c:45:12: error: Trying to use reserved word '_Alignas' as identifier
reserved.c:46:12: error: Trying to use reserved word '_Alignof' as identifier
reserved.c:47:12: error: Trying to use reserved word '_Atomic' as identifier
reserved.c:48:12: error: Trying to use reserved word '_Bool' as identifier
reserved.c:49:12: error: Trying to use reserved word '_Complex' as identifier
reserved.c:50:12: error: Trying to use reserved word '_Generic' as identifier
reserved.c:51:12: error: Trying to use reserved word '_Imaginary' as identifier
reserved.c:52:12: error: Trying to use reserved word '_Noreturn' as identifier
reserved.c:53:12: error: Trying to use reserved word '_Static_assert' as identifier
reserved.c:54:12: error: Trying to use reserved word '_Thread_local' as identifier
reserved.c:57:12: error: Trying to use reserved word '__context__' as identifier
reserved.c:58:12: error: Trying to use reserved word '__range__' as identifier
reserved.c:59:12: error: Trying to use reserved word '__sizeof_ptr__' as identifier
reserved.c:62:12: error: Trying to use reserved word '__alignof' as identifier
reserved.c:63:12: error: Trying to use reserved word '__alignof__' as identifier
reserved.c:65:12: error: Trying to use reserved word '__asm' as identifier
reserved.c:66:12: error: Trying to use reserved word '__asm__' as identifier
reserved.c:67:12: error: Trying to use reserved word '__label__' as identifier
reserved.c:68:12: error: Trying to use reserved word '__thread' as identifier
reserved.c:69:12: error: Trying to use reserved word 'typeof' as identifier
reserved.c:70:12: error: Trying to use reserved word '__typeof' as identifier
reserved.c:71:12: error: Trying to use reserved word '__typeof__' as identifier
reserved.c:73:12: error: Trying to use reserved word '__int128' as identifier
reserved.c:74:12: error: Trying to use reserved word '__int128_t' as identifier
reserved.c:75:12: error: Trying to use reserved word '__uint128_t' as identifier
reserved.c:77:12: error: Trying to use reserved word '__builtin_ms_va_list' as identifier
reserved.c:78:12: error: Trying to use reserved word '__builtin_offsetof' as identifier
reserved.c:79:12: error: Trying to use reserved word '__builtin_types_compatible_p' as identifier
reserved.c:80:12: error: Trying to use reserved word '__builtin_va_list' as identifier
 * check-error-end
 */
