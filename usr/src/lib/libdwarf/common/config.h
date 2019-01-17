/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.in by autoheader.  */

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* Define to 1 if you have the <alloca.h> header file. */
#define HAVE_ALLOCA_H 1

/* Define 1 if want to allow producer to build with 32/64bit section offsets
   per dwarf3 */
#define HAVE_DWARF2_99_EXTENSION 1

/* Define to 1 if the elf64_getehdr function is in libelf.a. */
#define HAVE_ELF64_GETEHDR 1

/* Define to 1 if the elf64_getshdr function is in libelf.a. */
#define HAVE_ELF64_GETSHDR 1

/* Define 1 if Elf64_Rela defined. */
#define HAVE_ELF64_RELA 1

/* Define 1 if Elf64_Sym defined. */
#define HAVE_ELF64_SYM 1

/* Define to 1 if you have the <elfaccess.h> header file. */
/* #undef HAVE_ELFACCESS_H */

/* Define to 1 if you have the <elf.h> header file. */
#define HAVE_ELF_H 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <libelf.h> header file. */
#define HAVE_LIBELF_H 1

/* Define to 1 if you have the <libelf/libelf.h> header file. */
/* #undef HAVE_LIBELF_LIBELF_H */

/* Define 1 if off64 is defined via libelf with GNU_SOURCE. */
#define HAVE_LIBELF_OFF64_OK 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define 1 if need nonstandard printf format for 64bit */
/* #undef HAVE_NONSTANDARD_PRINTF_64_FORMAT */

/* Define 1 to default to old DW_FRAME_CFA_COL */
/* #undef HAVE_OLD_FRAME_CFA_COL */

/* Define 1 if plain libelf builds. */
#define HAVE_RAW_LIBELF_OK 1

/* Define 1 if R_IA_64_DIR32LSB is defined (might be enum value). */
/* #undef HAVE_R_IA_64_DIR32LSB */

/* Define 1 if want producer to build with IRIX offset sizes */
/* #undef HAVE_SGI_IRIX_OFFSETS */

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define 1 if want producer to build with only 32bit section offsets */
/* #undef HAVE_STRICT_DWARF2_32BIT_OFFSET */

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/ia64/elf.h> header file. */
/* #undef HAVE_SYS_IA64_ELF_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define 1 if want to allow Windows full path detection */
/* #undef HAVE_WINDOWS_PATH */

/* See if __uint32_t is predefined in the compiler. */
/* #undef HAVE___UINT32_T */

/* Define 1 if __uint32_t is in sgidefs.h. */
/* #undef HAVE___UINT32_T_IN_SGIDEFS_H */

/* Define 1 if sys/types.h defines __uint32_t. */
/* #undef HAVE___UINT32_T_IN_SYS_TYPES_H */

/* See if __uint64_t is predefined in the compiler. */
/* #undef HAVE___UINT64_T */

/* Define 1 if is in sgidefs.h. */
/* #undef HAVE___UINT64_T_IN_SGIDEFS_H */

/* Define 1 if sys/types.h defines __uint64_t. */
/* #undef HAVE___UINT64_T_IN_SYS_TYPES_H */

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME ""

/* Define to the full name and version of this package. */
#define PACKAGE_STRING ""

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME ""

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION ""

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
   significant byte first (like Motorola and SPARC, unlike Intel). */
#if defined AC_APPLE_UNIVERSAL_BUILD
# if defined __BIG_ENDIAN__
#  define WORDS_BIGENDIAN 1
# endif
#else
# if defined(__sparc)
#  define WORDS_BIGENDIAN 1
# else
#  undef WORDS_BIGENDIAN
# endif         
#endif
