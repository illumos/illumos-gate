/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define if building universal (internal helper macro) */
/* #undef AC_APPLE_UNIVERSAL_BUILD */

/* Define to one of `_getb67', `GETB67', `getb67' for Cray-2 and Cray-YMP
   systems. This function is required for `alloca.c' support on those systems.
   */
/* #undef CRAY_STACKSEG_END */

/* Define to 1 if using `alloca.c'. */
/* #undef C_ALLOCA */

/* Set to 1 as we are building with libelf */
#define DWARF_WITH_LIBELF 1

/* Define to 1 if you have `alloca', as a function or macro. */
#define HAVE_ALLOCA 1

/* Define to 1 if you have <alloca.h> and it should be used (not on Ultrix).
   */
#define HAVE_ALLOCA_H 1

/* Define 1 if including a custom libelf library */
/* #undef HAVE_CUSTOM_LIBELF */

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Set to 1 if the elf64_getehdr function is in libelf. */
#define HAVE_ELF64_GETEHDR 1

/* Set to 1 if the elf64_getshdr function is in libelf. */
#define HAVE_ELF64_GETSHDR 1

/* Set to 1 if Elf64_Rela defined in elf.h. */
#define HAVE_ELF64_RELA 1

/* Set to 1 if Elf64_Rel structure as r_info field. */
#define HAVE_ELF64_R_INFO 1

/* Set to 1 if Elf64_Sym defined in elf.h. */
#define HAVE_ELF64_SYM 1

/* Define to 1 if you have the <elfaccess.h> header file. */
/* #undef HAVE_ELFACCESS_H */

/* Define to 1 if you have the <elf.h> header file. */
#define HAVE_ELF_H 1

/* Define 1 if want some specialized allocation counting */
/* #undef HAVE_GLOBAL_ALLOC_SUMS */

/* Define to 1 if the system has the type `intptr_t'. */
#define HAVE_INTPTR_T 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the <libelf.h> header file. */
#define HAVE_LIBELF_H 1

/* Define to 1 if you have the <libelf/libelf.h> header file. */
/* #undef HAVE_LIBELF_LIBELF_H */

/* Define to 1 if you have the <malloc.h> header file. */
#define HAVE_MALLOC_H 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define 1 if need nonstandard printf format for 64bit */
/* #undef HAVE_NONSTANDARD_PRINTF_64_FORMAT */

/* Set to 1 if old frame columns are enabled. */
/* #undef HAVE_OLD_FRAME_CFA_COL */

/* Set to 1 if regex is usable. */
#define HAVE_REGEX 1

/* Define to 1 if you have the <regex.h> header file. */
#define HAVE_REGEX_H 1

/* Define to 1 if you have the <sgidefs.h> header file. */
/* #undef HAVE_SGIDEFS_H */

/* Define to 1 if you have the <stddef.h> header file. */
#define HAVE_STDDEF_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/elf_386.h> header file. */
#define HAVE_SYS_ELF_386_H 1

/* Define to 1 if you have the <sys/elf_amd64.h> header file. */
#define HAVE_SYS_ELF_AMD64_H 1

/* Define to 1 if you have the <sys/elf_SPARC.h> header file. */
#define HAVE_SYS_ELF_SPARC_H 1

/* Define to 1 if you have the <sys/ia64/elf.h> header file. */
/* #undef HAVE_SYS_IA64_ELF_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if the system has the type `uintptr_t'. */
#define HAVE_UINTPTR_T 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Set to 1 if __attribute__ ((unused)) is available. */
#define HAVE_UNUSED_ATTRIBUTE 1

/* Define to 1 if you have the <windows.h> header file. */
/* #undef HAVE_WINDOWS_H */

/* Define 1 if want to allow Windows full path detection */
/* #undef HAVE_WINDOWS_PATH */

/* Set to 1 if zlib decompression is available. */
#define HAVE_ZLIB 1

/* Define to 1 if you have the <zlib.h> header file. */
#define HAVE_ZLIB_H 1

/* Define to the sub-directory where libtool stores uninstalled libraries. */
#define LT_OBJDIR ".libs/"

/* Define to 1 if your C compiler doesn't accept -c and -o together. */
/* #undef NO_MINUS_C_MINUS_O */

/* Name of package */
#define PACKAGE "libdwarf"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT "libdwarf-list -at- linuxmail -dot- org"

/* Define to the full name of this package. */
#define PACKAGE_NAME "libdwarf"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "libdwarf 20200612"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "libdwarf"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "20200612"

/* If using the C implementation of alloca, define if you know the
   direction of stack growth for your system; otherwise it will be
   automatically deduced at runtime.
	STACK_DIRECTION > 0 => grows toward higher addresses
	STACK_DIRECTION < 0 => grows toward lower addresses
	STACK_DIRECTION = 0 => direction of growth unknown */
/* #undef STACK_DIRECTION */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Version number of package */
#define VERSION "20200612"

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

/* Define to the type of a signed integer type wide enough to hold a pointer,
   if such a type exists, and if the system does not define it. */
/* #undef intptr_t */

/* Define to `unsigned int' if <sys/types.h> does not define. */
/* #undef size_t */

/* Define to the type of an unsigned integer type wide enough to hold a
   pointer, if such a type exists, and if the system does not define it. */
/* #undef uintptr_t */
