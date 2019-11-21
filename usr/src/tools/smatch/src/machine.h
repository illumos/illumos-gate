#ifndef MACHINE_H
#define MACHINE_H

#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define ARCH_BIG_ENDIAN 1
#else
#define ARCH_BIG_ENDIAN 0
#endif


enum {
	ARCH_LP32,
	ARCH_X32,
	ARCH_LP64,
	ARCH_LLP64,
};

#ifdef __LP64__
#define ARCH_M64_DEFAULT ARCH_LP64
#elif defined(__x86_64__) || defined(__x86_64)
#define ARCH_M64_DEFAULT ARCH_X32
#else
#define ARCH_M64_DEFAULT ARCH_LP32
#endif


enum machine {
	MACH_ARM,
	MACH_ARM64,
	MACH_I386,
	MACH_X86_64,
	MACH_MIPS32,
	MACH_MIPS64,
	MACH_PPC32,
	MACH_PPC64,
	MACH_RISCV32,
	MACH_RISCV64,
	MACH_SPARC32,
	MACH_SPARC64,
	MACH_M68K,
	MACH_S390X,
	MACH_UNKNOWN
};

#if defined(__aarch64__)
#define MACH_NATIVE	MACH_ARM64
#elif defined(__arm__)
#define	MACH_NATIVE	MACH_ARM
#elif defined(__x86_64__) || defined(__x86_64)
#define	MACH_NATIVE	MACH_X86_64
#elif defined(__i386__) || defined(__i386)
#define	MACH_NATIVE	MACH_I386
#elif defined(__mips64__) || (defined(__mips) && __mips == 64)
#define	MACH_NATIVE	MACH_MIPS64
#elif defined(__mips__) || defined(__mips)
#define	MACH_NATIVE	MACH_MIPS32
#elif defined(__powerpc64__) || defined(__ppc64__)
#define	MACH_NATIVE	MACH_PPC64
#elif defined(__powerpc__) || defined(__powerpc) || defined(__ppc__)
#define	MACH_NATIVE	MACH_PPC32
#elif defined(__riscv) && (__riscv_xlen == 64)
#define	MACH_NATIVE	MACH_RISCV64
#elif defined(__riscv) && (__riscv_xlen == 32)
#define	MACH_NATIVE	MACH_RISCV32
#elif defined(__sparc_v9__)
#define	MACH_NATIVE	MACH_SPARC64
#elif defined(__sparc__) || defined(__sparc)
#define	MACH_NATIVE	MACH_SPARC32
#elif defined(__m68k__)
#define MACH_NATIVE	MACH_M68K
#elif defined(__s390x__) || defined(__zarch__)
#define MACH_NATIVE	MACH_S390X
#else
#define MACH_NATIVE	MACH_UNKNOWN
#endif

#if defined(__CHAR_UNSIGNED__)
#define	UNSIGNED_CHAR	1
#else
#define UNSIGNED_CHAR	0
#endif

#endif
