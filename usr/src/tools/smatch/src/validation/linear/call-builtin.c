typedef unsigned int u32;

u32 ff(u32 a) { return __builtin_popcount(a); }

u32 f0(u32 a) { return (__builtin_popcount)(a); }
u32 f1(u32 a) { return (*__builtin_popcount)(a); }	// C99,C11 6.5.3.2p4
u32 f2(u32 a) { return (**__builtin_popcount)(a); }	// C99,C11 6.5.3.2p4
u32 f3(u32 a) { return (***__builtin_popcount)(a); }	// C99,C11 6.5.3.2p4

/*
 * check-name: builtin calls
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-ignore
 * check-output-excludes: load
 * check-output-pattern(5): call\\..*__builtin_.*, %arg1
 */
