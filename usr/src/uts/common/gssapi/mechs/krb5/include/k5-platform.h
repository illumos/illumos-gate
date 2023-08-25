/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * k5-platform.h
 *
 * Copyright 2003, 2004, 2005 Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.	Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 *
 * Some platform-dependent definitions to sync up the C support level.
 * Some to a C99-ish level, some related utility code.
 *
 * Currently:
 * + make "static inline" work
 * + 64-bit types and load/store code
 * + SIZE_MAX
 * + shared library init/fini hooks
 * + consistent getpwnam/getpwuid interfaces
 */

#ifndef K5_PLATFORM_H
#define K5_PLATFORM_H

/* Solaris Kerberos */
#ifndef _KERNEL
#include <sys/types.h>

#include "autoconf.h"

/* Initialization and finalization function support for libraries.

   At top level, before the functions are defined or even declared:
   MAKE_INIT_FUNCTION(init_fn);
   MAKE_FINI_FUNCTION(fini_fn);
   Then:
   int init_fn(void) { ... }
   void fini_fn(void) { if (INITIALIZER_RAN(init_fn)) ... }
   In code, in the same file:
   err = CALL_INIT_FUNCTION(init_fn);

   To trigger or verify the initializer invocation from another file,
   a helper function must be created.

   This model handles both the load-time execution (Windows) and
   delayed execution (pthread_once) approaches, and should be able to
   guarantee in both cases that the init function is run once, in one
   thread, before other stuff in the library is done; furthermore, the
   finalization code should only run if the initialization code did.
   (Maybe I could've made the "if INITIALIZER_RAN" test implicit, via
   another function hidden in macros, but this is hairy enough
   already.)

   The init_fn and fini_fn names should be chosen such that any
   exported names staring with those names, and optionally followed by
   additional characters, fits in with any namespace constraints on
   the library in question.


   There's also PROGRAM_EXITING() currently always defined as zero.
   If there's some trivial way to find out if the fini function is
   being called because the program that the library is linked into is
   exiting, we can just skip all the work because the resources are
   about to be freed up anyways.  Generally this is likely to be the
   same as distinguishing whether the library was loaded dynamically
   while the program was running, or loaded as part of program
   startup.  On most platforms, I don't think we can distinguish these
   cases easily, and it's probably not worth expending any significant
   effort.  (Note in particular that atexit() won't do, because if the
   library is explicitly loaded and unloaded, it would have to be able
   to deregister the atexit callback function.  Also, the system limit
   on atexit callbacks may be small.)


   Implementation outline:

   Windows: MAKE_FINI_FUNCTION creates a symbol with a magic name that
   is sought at library build time, and code is added to invoke the
   function when the library is unloaded.  MAKE_INIT_FUNCTION does
   likewise, but the function is invoked when the library is loaded,
   and an extra variable is declared to hold an error code and a "yes
   the initializer ran" flag.  CALL_INIT_FUNCTION blows up if the flag
   isn't set, otherwise returns the error code.

   UNIX: MAKE_INIT_FUNCTION creates and initializes a variable with a
   name derived from the function name, containing a k5_once_t
   (pthread_once_t or int), an error code, and a pointer to the
   function.  The function itself is declared static, but the
   associated variable has external linkage.  CALL_INIT_FUNCTION
   ensures thath the function is called exactly once (pthread_once or
   just check the flag) and returns the stored error code (or the
   pthread_once error).

   (That's the basic idea.  With some debugging assert() calls and
   such, it's a bit more complicated.  And we also need to handle
   doing the pthread test at run time on systems where that works, so
   we use the k5_once_t stuff instead.)

   UNIX, with compiler support: MAKE_FINI_FUNCTION declares the
   function as a destructor, and the run time linker support or
   whatever will cause it to be invoked when the library is unloaded,
   the program ends, etc.

   UNIX, with linker support: MAKE_FINI_FUNCTION creates a symbol with
   a magic name that is sought at library build time, and linker
   options are used to mark it as a finalization function for the
   library.  The symbol must be exported.

   UNIX, no library finalization support: The finalization function
   never runs, and we leak memory.  Tough.

   DELAY_INITIALIZER will be defined by the configure script if we
   want to use k5_once instead of load-time initialization.  That'll
   be the preferred method on most systems except Windows, where we
   have to initialize some mutexes.




   For maximum flexibility in defining the macros, the function name
   parameter should be a simple name, not even a macro defined as
   another name.  The function should have a unique name, and should
   conform to whatever namespace is used by the library in question.
   (We do have export lists, but (1) they're not used for all
   platforms, and (2) they're not used for static libraries.)

   If the macro expansion needs the function to have been declared, it
   must include a declaration.  If it is not necessary for the symbol
   name to be exported from the object file, the macro should declare
   it as "static".  Hence the signature must exactly match "void
   foo(void)".  (ANSI C allows a static declaration followed by a
   non-static one; the result is internal linkage.)  The macro
   expansion has to come before the function, because gcc apparently
   won't act on "__attribute__((constructor))" if it comes after the
   function definition.

   This is going to be compiler- and environment-specific, and may
   require some support at library build time, and/or "asm"
   statements.  But through macro expansion and auxiliary functions,
   we should be able to handle most things except #pragma.

   It's okay for this code to require that the library be built
   with the same compiler and compiler options throughout, but
   we shouldn't require that the library and application use the
   same compiler.

   For static libraries, we don't really care about cleanup too much,
   since it's all memory handling and mutex allocation which will all
   be cleaned up when the program exits.  Thus, it's okay if gcc-built
   static libraries don't play nicely with cc-built executables when
   it comes to static constructors, just as long as it doesn't cause
   linking to fail.

   For dynamic libraries on UNIX, we'll use pthread_once-type support
   to do delayed initialization, so if finalization can't be made to
   work, we'll only have memory leaks in a load/use/unload cycle.  If
   anyone (like, say, the OS vendor) complains about this, they can
   tell us how to get a shared library finalization function invoked
   automatically.

   Currently there's --disable-delayed-initialization for preventing
   the initialization from being delayed on UNIX, but that's mainly
   just for testing the linker options for initialization, and will
   probably be removed at some point.  */

/* Helper macros.  */

# define JOIN__2_2(A,B) A ## _ ## _ ## B
# define JOIN__2(A,B) JOIN__2_2(A,B)

/* XXX Should test USE_LINKER_INIT_OPTION early, and if it's set,
   always provide a function by the expected name, even if we're
   delaying initialization.  */

#if defined(DELAY_INITIALIZER)

/* Run the initialization code during program execution, at the latest
   possible moment.  This means multiple threads may be active.  */
# include "k5-thread.h"
typedef struct { k5_once_t once; int error, did_run; void (*fn)(void); } k5_init_t;
# ifdef USE_LINKER_INIT_OPTION
#  define MAYBE_DUMMY_INIT(NAME)		\
	void JOIN__2(NAME, auxinit) () { }
# else
#  define MAYBE_DUMMY_INIT(NAME)
# endif
# ifdef __GNUC__
/* Do it in macro form so we get the file/line of the invocation if
   the assertion fails.  */
#  define k5_call_init_function(I)					\
	(__extension__ ({						\
		k5_init_t *k5int_i = (I);				\
		int k5int_err = k5_once(&k5int_i->once, k5int_i->fn);	\
		(k5int_err						\
		 ? k5int_err						\
		 : (assert(k5int_i->did_run != 0), k5int_i->error));	\
	    }))
#  define MAYBE_DEFINE_CALLINIT_FUNCTION
# else
#  define MAYBE_DEFINE_CALLINIT_FUNCTION			\
	static int k5_call_init_function(k5_init_t *i)	\
	{							\
	    int err;						\
	    err = k5_once(&i->once, i->fn);			\
	    if (err)						\
		return err;					\
	    assert (i->did_run != 0);				\
	    return i->error;					\
	}
# endif
# define MAKE_INIT_FUNCTION(NAME)				\
	static int NAME(void);					\
	MAYBE_DUMMY_INIT(NAME)					\
	/* forward declaration for use in initializer */	\
	static void JOIN__2(NAME, aux) (void);			\
	static k5_init_t JOIN__2(NAME, once) =			\
		{ K5_ONCE_INIT, 0, 0, JOIN__2(NAME, aux) };	\
	MAYBE_DEFINE_CALLINIT_FUNCTION				\
	static void JOIN__2(NAME, aux) (void)			\
	{							\
	    JOIN__2(NAME, once).did_run = 1;			\
	    JOIN__2(NAME, once).error = NAME();			\
	}							\
	/* so ';' following macro use won't get error */	\
	static int NAME(void)
# define CALL_INIT_FUNCTION(NAME)	\
	k5_call_init_function(& JOIN__2(NAME, once))
/* This should be called in finalization only, so we shouldn't have
   multiple active threads mucking around in our library at this
   point.  So ignore the once_t object and just look at the flag.

   XXX Could we have problems with memory coherence between processors
   if we don't invoke mutex/once routines?  Probably not, the
   application code should already be coordinating things such that
   the library code is not in use by this point, and memory
   synchronization will be needed there.  */
# define INITIALIZER_RAN(NAME)	\
	(JOIN__2(NAME, once).did_run && JOIN__2(NAME, once).error == 0)

# define PROGRAM_EXITING()		(0)

#elif defined(__GNUC__) && !defined(_WIN32) && defined(CONSTRUCTOR_ATTR_WORKS)

/* Run initializer at load time, via GCC/C++ hook magic.  */

# ifdef USE_LINKER_INIT_OPTION
     /* Both gcc and linker option??  Favor gcc.  */
#  define MAYBE_DUMMY_INIT(NAME)		\
	void JOIN__2(NAME, auxinit) () { }
# else
#  define MAYBE_DUMMY_INIT(NAME)
# endif

typedef struct { int error; unsigned char did_run; } k5_init_t;
# define MAKE_INIT_FUNCTION(NAME)		\
	MAYBE_DUMMY_INIT(NAME)			\
	static k5_init_t JOIN__2(NAME, ran)	\
		= { 0, 2 };			\
	static void JOIN__2(NAME, aux)(void)	\
	    __attribute__((constructor));	\
	static int NAME(void);			\
	static void JOIN__2(NAME, aux)(void)	\
	{					\
	    JOIN__2(NAME, ran).error = NAME();	\
	    JOIN__2(NAME, ran).did_run = 3;	\
	}					\
	static int NAME(void)
# define CALL_INIT_FUNCTION(NAME)		\
	(JOIN__2(NAME, ran).did_run == 3	\
	 ? JOIN__2(NAME, ran).error		\
	 : (abort(),0))
# define INITIALIZER_RAN(NAME)	(JOIN__2(NAME,ran).did_run == 3 && JOIN__2(NAME, ran).error == 0)

# define PROGRAM_EXITING()		(0)

#elif defined(USE_LINKER_INIT_OPTION) || defined(_WIN32)

/* Run initializer at load time, via linker magic, or in the
   case of WIN32, win_glue.c hard-coded knowledge.  */
typedef struct { int error; unsigned char did_run; } k5_init_t;
# define MAKE_INIT_FUNCTION(NAME)		\
	static k5_init_t JOIN__2(NAME, ran)	\
		= { 0, 2 };			\
	static int NAME(void);			\
	void JOIN__2(NAME, auxinit)()		\
	{					\
	    JOIN__2(NAME, ran).error = NAME();	\
	    JOIN__2(NAME, ran).did_run = 3;	\
	}					\
	static int NAME(void)
# define CALL_INIT_FUNCTION(NAME)		\
	(JOIN__2(NAME, ran).did_run == 3	\
	 ? JOIN__2(NAME, ran).error		\
	 : (abort(),0))
# define INITIALIZER_RAN(NAME)	\
	(JOIN__2(NAME, ran).error == 0)

# define PROGRAM_EXITING()		(0)

#else

# error "Don't know how to do load-time initializers for this configuration."

# define PROGRAM_EXITING()		(0)

#endif



#if defined(USE_LINKER_FINI_OPTION) || defined(_WIN32)
/* If we're told the linker option will be used, it doesn't really
   matter what compiler we're using.  Do it the same way
   regardless.  */

# ifdef __hpux

     /* On HP-UX, we need this auxiliary function.  At dynamic load or
	unload time (but *not* program startup and termination for
	link-time specified libraries), the linker-indicated function
	is called with a handle on the library and a flag indicating
	whether it's being loaded or unloaded.

	The "real" fini function doesn't need to be exported, so
	declare it static.

	As usual, the final declaration is just for syntactic
	convenience, so the top-level invocation of this macro can be
	followed by a semicolon.  */

#  include <dl.h>
#  define MAKE_FINI_FUNCTION(NAME)					    \
	static void NAME(void);						    \
	void JOIN__2(NAME, auxfini)(shl_t, int); /* silence gcc warnings */ \
	void JOIN__2(NAME, auxfini)(shl_t h, int l) { if (!l) NAME(); }	    \
	static void NAME(void)

# else /* not hpux */

#  define MAKE_FINI_FUNCTION(NAME)	\
	void NAME(void)

# endif

#elif defined(__GNUC__) && defined(DESTRUCTOR_ATTR_WORKS)
/* If we're using gcc, if the C++ support works, the compiler should
   build executables and shared libraries that support the use of
   static constructors and destructors.  The C compiler supports a
   function attribute that makes use of the same facility as C++.

   XXX How do we know if the C++ support actually works?  */
# define MAKE_FINI_FUNCTION(NAME)	\
	static void NAME(void) __attribute__((destructor))

#elif !defined(SHARED)

/* In this case, we just don't care about finalization.

   The code will still define the function, but we won't do anything
   with it.  Annoying: This may generate unused-function warnings.  */

# define MAKE_FINI_FUNCTION(NAME)	\
	static void NAME(void)

#else

# error "Don't know how to do unload-time finalization for this configuration."

#endif

#endif /* !_KERNEL */


/* 64-bit support: krb5_ui_8 and krb5_int64.

   This should move to krb5.h eventually, but without the namespace
   pollution from the autoconf macros.  */
#if defined(HAVE_STDINT_H) || defined(HAVE_INTTYPES_H)
# ifdef HAVE_STDINT_H
#  include <stdint.h>
# endif
# ifdef HAVE_INTTYPES_H
#  include <inttypes.h>
# endif
# define INT64_TYPE int64_t
# define UINT64_TYPE uint64_t
#elif defined(_WIN32)
# define INT64_TYPE signed __int64
# define UINT64_TYPE unsigned __int64
#else /* not Windows, and neither stdint.h nor inttypes.h */
# define INT64_TYPE signed long long
# define UINT64_TYPE unsigned long long
#endif

#ifndef _KERNEL
#include <limits.h>
#endif /* !_KERNEL */
#ifndef SIZE_MAX
# define SIZE_MAX ((size_t)((size_t)0 - 1))
#endif


/* Read and write integer values as (unaligned) octet strings in
   specific byte orders.

   Add per-platform optimizations later if needed.  (E.g., maybe x86
   unaligned word stores and gcc/asm instructions for byte swaps,
   etc.)  */

/* Solaris Kerberos: To avoid problems with lint the following
   functions can be found in separate header files. */
#if 0
static void
store_16_be (unsigned int val, unsigned char *p)
{
    p[0] = (val >>  8) & 0xff;
    p[1] = (val      ) & 0xff;
}
static void
store_16_le (unsigned int val, unsigned char *p)
{
    p[1] = (val >>  8) & 0xff;
    p[0] = (val      ) & 0xff;
}
static void
store_32_be (unsigned int val, unsigned char *p)
{
    p[0] = (val >> 24) & 0xff;
    p[1] = (val >> 16) & 0xff;
    p[2] = (val >>  8) & 0xff;
    p[3] = (val      ) & 0xff;
}
static void
store_32_le (unsigned int val, unsigned char *p)
{
    p[3] = (val >> 24) & 0xff;
    p[2] = (val >> 16) & 0xff;
    p[1] = (val >>  8) & 0xff;
    p[0] = (val      ) & 0xff;
}
static void
store_64_be (UINT64_TYPE val, unsigned char *p)
{
    p[0] = (unsigned char)((val >> 56) & 0xff);
    p[1] = (unsigned char)((val >> 48) & 0xff);
    p[2] = (unsigned char)((val >> 40) & 0xff);
    p[3] = (unsigned char)((val >> 32) & 0xff);
    p[4] = (unsigned char)((val >> 24) & 0xff);
    p[5] = (unsigned char)((val >> 16) & 0xff);
    p[6] = (unsigned char)((val >>  8) & 0xff);
    p[7] = (unsigned char)((val      ) & 0xff);
}
static void
store_64_le (UINT64_TYPE val, unsigned char *p)
{
    p[7] = (unsigned char)((val >> 56) & 0xff);
    p[6] = (unsigned char)((val >> 48) & 0xff);
    p[5] = (unsigned char)((val >> 40) & 0xff);
    p[4] = (unsigned char)((val >> 32) & 0xff);
    p[3] = (unsigned char)((val >> 24) & 0xff);
    p[2] = (unsigned char)((val >> 16) & 0xff);
    p[1] = (unsigned char)((val >>  8) & 0xff);
    p[0] = (unsigned char)((val      ) & 0xff);
}
static unsigned short
load_16_be (unsigned char *p)
{
    return (p[1] | (p[0] << 8));
}
static unsigned short
load_16_le (unsigned char *p)
{
    return (p[0] | (p[1] << 8));
}
static  unsigned int
load_32_be (unsigned char *p)
{
    return (p[3] | (p[2] << 8) | (p[1] << 16) | (p[0] << 24));
}
static  unsigned int
load_32_le (unsigned char *p)
{
    return (p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}
static UINT64_TYPE
load_64_be (unsigned char *p)
{
    return ((UINT64_TYPE)load_32_be(p) << 32) | load_32_be(p+4);
}
static UINT64_TYPE
load_64_le (unsigned char *p)
{
    return ((UINT64_TYPE)load_32_le(p+4) << 32) | load_32_le(p);
}
#endif

/* Make the interfaces to getpwnam and getpwuid consistent.
   Model the wrappers on the POSIX thread-safe versions, but
   use the unsafe system versions if the safe ones don't exist
   or we can't figure out their interfaces.  */
/* SUNW15resync - just have Solaris relevant ones */

#define k5_getpwnam_r(NAME, REC, BUF, BUFSIZE, OUT)  \
         (*(OUT) = getpwnam_r(NAME,REC,BUF,BUFSIZE), *(OUT) == NULL ? -1 : 0)

#define k5_getpwuid_r(UID, REC, BUF, BUFSIZE, OUT)  \
        (*(OUT) = getpwuid_r(UID,REC,BUF,BUFSIZE), *(OUT) == NULL ? -1 : 0)

/* Return true if the snprintf return value RESULT reflects a buffer
   overflow for the buffer size SIZE.

   We cast the result to unsigned int for two reasons.  First, old
   implementations of snprintf (such as the one in Solaris 9 and
   prior) return -1 on a buffer overflow.  Casting the result to -1
   will convert that value to UINT_MAX, which should compare larger
   than any reasonable buffer size.  Second, comparing signed and
   unsigned integers will generate warnings with some compilers, and
   can have unpredictable results, particularly when the relative
   widths of the types is not known (size_t may be the same width as
   int or larger).
*/
#define SNPRINTF_OVERFLOW(result, size) \
    ((unsigned int)(result) >= (size_t)(size))

#endif /* K5_PLATFORM_H */
