/*
 * f i c l . h
 * Forth Inspired Command Language
 * Author: John Sadler (john_sadler@alum.mit.edu)
 * Created: 19 July 1997
 * Dedicated to RHS, in loving memory
 * $Id: ficl.h,v 1.25 2010/10/03 09:52:12 asau Exp $
 */
/*
 * Copyright (c) 1997-2001 John Sadler (john_sadler@alum.mit.edu)
 * All rights reserved.
 *
 * Get the latest Ficl release at http://ficl.sourceforge.net
 *
 * I am interested in hearing from anyone who uses Ficl. If you have
 * a problem, a success story, a defect, an enhancement request, or
 * if you would like to contribute to the Ficl release, please
 * contact me by email at the address above.
 *
 * L I C E N S E  and  D I S C L A I M E R
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef	_FICL_H
#define	_FICL_H
/*
 * Ficl (Forth-inspired command language) is an ANS Forth
 * interpreter written in C. Unlike traditional Forths, this
 * interpreter is designed to be embedded into other systems
 * as a command/macro/development prototype language.
 *
 * Where Forths usually view themselves as the center of the system
 * and expect the rest of the system to be coded in Forth, Ficl
 * acts as a component of the system. It is easy to export
 * code written in C or ASM to Ficl in the style of TCL, or to invoke
 * Ficl code from a compiled module. This allows you to do incremental
 * development in a way that combines the best features of threaded
 * languages (rapid development, quick code/test/debug cycle,
 * reasonably fast) with the best features of C (everyone knows it,
 * easier to support large blocks of code, efficient, type checking).
 *
 * Ficl provides facilities for interoperating
 * with programs written in C: C functions can be exported to Ficl,
 * and Ficl commands can be executed via a C calling interface. The
 * interpreter is re-entrant, so it can be used in multiple instances
 * in a multitasking system. Unlike Forth, Ficl's outer interpreter
 * expects a text block as input, and returns to the caller after each
 * text block, so the "data pump" is somewhere in external code. This
 * is more like TCL than Forth, which usually expects to be at the center
 * of the system, requesting input at its convenience. Each Ficl virtual
 * machine can be bound to a different I/O channel, and is independent
 * of all others in in the same address space except that all virtual
 * machines share a common dictionary (a sort or open symbol table that
 * defines all of the elements of the language).
 *
 * Code is written in ANSI C for portability.
 *
 * Summary of Ficl features and constraints:
 * - Standard: Implements the ANSI Forth CORE word set and part
 *   of the CORE EXT word-set, SEARCH and SEARCH EXT, TOOLS and
 *   TOOLS EXT, LOCAL and LOCAL ext and various extras.
 * - Extensible: you can export code written in Forth, C,
 *   or asm in a straightforward way. Ficl provides open
 *   facilities for extending the language in an application
 *   specific way. You can even add new control structures!
 * - Ficl and C can interact in two ways: Ficl can encapsulate
 *   C code, or C code can invoke Ficl code.
 * - Thread-safe, re-entrant: The shared system dictionary
 *   uses a locking mechanism that you can either supply
 *   or stub out to provide exclusive access. Each Ficl
 *   virtual machine has an otherwise complete state, and
 *   each can be bound to a separate I/O channel (or none at all).
 * - Simple encapsulation into existing systems: a basic implementation
 *   requires three function calls (see the example program in testmain.c).
 * - ROMable: Ficl is designed to work in RAM-based and ROM code / RAM data
 *   environments. It does require somewhat more memory than a pure
 *   ROM implementation because it builds its system dictionary in
 *   RAM at startup time.
 * - Written an ANSI C to be as simple as I can make it to understand,
 *   support, debug, and port. Compiles without complaint at /Az /W4
 *   (require ANSI C, max warnings) under Microsoft VC++ 5.
 * - Does full 32 bit math (but you need to implement
 *   two mixed precision math primitives (see sysdep.c))
 * - Indirect threaded interpreter is not the fastest kind of
 *   Forth there is (see pForth 68K for a really fast subroutine
 *   threaded interpreter), but it's the cleanest match to a
 *   pure C implementation.
 *
 * P O R T I N G   F i c l
 *
 * To install Ficl on your target system, you need an ANSI C compiler
 * and its runtime library. Inspect the system dependent macros and
 * functions in sysdep.h and sysdep.c and edit them to suit your
 * system. For example, INT16 is a short on some compilers and an
 * int on others. Check the default CELL alignment controlled by
 * FICL_ALIGN. If necessary, add new definitions of ficlMalloc, ficlFree,
 * ficlLockDictionary, and ficlCallbackDefaultTextOut to work with your
 * operating system.  Finally, use testmain.c as a guide to installing the
 * Ficl system and one or more virtual machines into your code. You do not
 * need to include testmain.c in your build.
 *
 * T o   D o   L i s t
 *
 * 1. Unimplemented system dependent CORE word: key
 * 2. Ficl uses the PAD in some CORE words - this violates the standard,
 *    but it's cleaner for a multithreaded system. I'll have to make a
 *    second pad for reference by the word PAD to fix this.
 *
 * F o r   M o r e   I n f o r m a t i o n
 *
 * Web home of Ficl
 *   http://ficl.sourceforge.net
 * Check this website for Forth literature (including the ANSI standard)
 *   http://www.taygeta.com/forthlit.html
 * and here for software and more links
 *   http://www.taygeta.com/forth.html
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef STAND
#include <stand.h>
#include <sys/stdint.h>
#include <sys/linker_set.h>
#else
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

extern void pager_open(void);
extern int pager_output(const char *);
extern void pager_close(void);
#endif
#include <setjmp.h>
#include <stdarg.h>

/*
 * Put all your local defines in ficllocal.h,
 * rather than editing the makefile/project/etc.
 * ficllocal.h will always ship as an inert file.
 */

#include "ficllocal.h"
#include "ficlplatform/unix.h"

/*
 *
 * B U I L D   C O N T R O L S
 *
 * First, the FICL_WANT_* settings.
 * These are all optional settings that you may or may not
 * want Ficl to use.
 *
 */

/*
 * FICL_WANT_MINIMAL
 * If set to nonzero, build the smallest possible Ficl interpreter.
 */
#if !defined(FICL_WANT_MINIMAL)
#define	FICL_WANT_MINIMAL		(0)
#endif

#if FICL_WANT_MINIMAL
#define	FICL_WANT_SOFTWORDS		(0)
#define	FICL_WANT_FILE			(0)
#define	FICL_WANT_FLOAT			(0)
#define	FICL_WANT_USER			(0)
#define	FICL_WANT_LOCALS		(0)
#define	FICL_WANT_DEBUGGER		(0)
#define	FICL_WANT_OOP			(0)
#define	FICL_WANT_PLATFORM		(0)
#define	FICL_WANT_MULTITHREADED		(0)
#define	FICL_WANT_EXTENDED_PREFIX	(0)

#define	FICL_ROBUST			(0)

#endif /* FICL_WANT_MINIMAL */

/*
 * FICL_WANT_PLATFORM
 * Includes words defined in ficlCompilePlatform
 * (see ficlplatform/win32.c and ficlplatform/unix.c for example)
 */
#if !defined(FICL_WANT_PLATFORM)
#define	FICL_WANT_PLATFORM	(1)
#endif /* FICL_WANT_PLATFORM */

/*
 * FICL_WANT_LZ4_SOFTCORE
 * If nonzero, the softcore words are stored compressed
 * with patent-unencumbered LZ4 compression.
 * This results in a smaller Ficl interpreter, and adds
 * only a *tiny* runtime speed hit.
 *
 * Original LZ77 contributed by Larry Hastings.
 * Updated to LZ4 which is even more space efficient.
 */
#if !defined(FICL_WANT_LZ4_SOFTCORE)
#define	FICL_WANT_LZ4_SOFTCORE	(1)
#endif /* FICL_WANT_LZ4_SOFTCORE */

/*
 * FICL_WANT_FILE
 * Includes the FILE and FILE-EXT wordset and associated code.
 * Turn this off if you do not have a file system!
 * Contributed by Larry Hastings
 */
#if !defined(FICL_WANT_FILE)
#define	FICL_WANT_FILE	(0)
#endif /* FICL_WANT_FILE */

/*
 * FICL_WANT_FLOAT
 * Includes a floating point stack for the VM, and words to do float operations.
 * Contributed by Guy Carver
 */
#if !defined(FICL_WANT_FLOAT)
#define	FICL_WANT_FLOAT	(1)
#endif /* FICL_WANT_FLOAT */

/*
 * FICL_WANT_DEBUGGER
 * Inludes a simple source level debugger
 */
#if !defined(FICL_WANT_DEBUGGER)
#define	FICL_WANT_DEBUGGER	(1)
#endif /* FICL_WANT_DEBUGGER */

/*
 * FICL_EXTENDED_PREFIX
 * Enables a bunch of extra prefixes in prefix.c
 * and prefix.fr (if included as part of softcore.c)
 */
#if !defined(FICL_WANT_EXTENDED_PREFIX)
#define	FICL_WANT_EXTENDED_PREFIX	(1)
#endif /* FICL_WANT_EXTENDED_PREFIX */

/*
 * FICL_WANT_USER
 * Enables user variables: per-instance variables bound to the VM.
 * Kind of like thread-local storage. Could be implemented in a
 * VM private dictionary, but I've chosen the lower overhead
 * approach of an array of CELLs instead.
 */
#if !defined(FICL_WANT_USER)
#define	FICL_WANT_USER	(1)
#endif /* FICL_WANT_USER */

/*
 * FICL_WANT_LOCALS
 * Controls the creation of the LOCALS wordset
 * and a private dictionary for local variable compilation.
 */
#if !defined FICL_WANT_LOCALS
#define	FICL_WANT_LOCALS	(1)
#endif /* FICL_WANT_LOCALS */

/*
 * FICL_WANT_OOP
 * Inludes object oriented programming support (in softwords)
 * OOP support requires locals and user variables!
 */
#if !defined(FICL_WANT_OOP)
#define	FICL_WANT_OOP	((FICL_WANT_LOCALS) && (FICL_WANT_USER))
#endif /* FICL_WANT_OOP */

/*
 * FICL_WANT_SOFTWORDS
 * Controls inclusion of all softwords in softcore.c.
 */
#if !defined(FICL_WANT_SOFTWORDS)
#define	FICL_WANT_SOFTWORDS	(1)
#endif /* FICL_WANT_SOFTWORDS */

/*
 * FICL_WANT_MULTITHREADED
 * Enables dictionary mutual exclusion wia the
 * ficlLockDictionary() system dependent function.
 *
 * Note: this implementation is experimental and poorly
 * tested. Further, it's unnecessary unless you really
 * intend to have multiple SESSIONS (poor choice of name
 * on my part) - that is, threads that modify the dictionary
 * at the same time.
 */
#if !defined FICL_WANT_MULTITHREADED
#define	FICL_WANT_MULTITHREADED	(0)
#endif /* FICL_WANT_MULTITHREADED */

/*
 * FICL_WANT_OPTIMIZE
 * Do you want to optimize for size, or for speed?
 * Note that this doesn't affect Ficl very much one way
 * or the other at the moment.
 * Contributed by Larry Hastings
 */
#define	FICL_OPTIMIZE_FOR_SPEED	(1)
#define	FICL_OPTIMIZE_FOR_SIZE	(2)
#if !defined(FICL_WANT_OPTIMIZE)
#define	FICL_WANT_OPTIMIZE FICL_OPTIMIZE_FOR_SPEED
#endif /* FICL_WANT_OPTIMIZE */

/*
 * FICL_WANT_VCALL
 * Ficl OO support for calling vtable methods.  Win32 only.
 * Contributed by Guy Carver
 */
#if !defined(FICL_WANT_VCALL)
#define	FICL_WANT_VCALL	(0)
#endif /* FICL_WANT_VCALL */

/*
 * P L A T F O R M   S E T T I N G S
 *
 * The FICL_PLATFORM_* settings.
 * These indicate attributes about the local platform.
 */

/*
 * FICL_PLATFORM_OS
 * String constant describing the current hardware architecture.
 */
#if !defined(FICL_PLATFORM_ARCHITECTURE)
#define	FICL_PLATFORM_ARCHITECTURE	"unknown"
#endif

/*
 * FICL_PLATFORM_OS
 * String constant describing the current operating system.
 */
#if !defined(FICL_PLATFORM_OS)
#define	FICL_PLATFORM_OS	"unknown"
#endif

/*
 * FICL_PLATFORM_HAS_2INTEGER
 * Indicates whether or not the current architecture
 * supports a native double-width integer type.
 * If you set this to 1 in your ficlplatform/ *.h file,
 * you *must* create typedefs for the following two types:
 *        ficl2Unsigned
 *        ficl2Integer
 * If this is set to 0, Ficl will implement double-width
 * integer math in C, which is both bigger *and* slower
 * (the double whammy!).  Make sure your compiler really
 * genuinely doesn't support native double-width integers
 * before setting this to 0.
 */
#if !defined(FICL_PLATFORM_HAS_2INTEGER)
#define	FICL_PLATFORM_HAS_2INTEGER	(0)
#endif

/*
 * FICL_PLATFORM_HAS_FTRUNCATE
 * Indicates whether or not the current platform provides
 * the ftruncate() function (available on most UNIXes).
 * This function is necessary to provide the complete
 * File-Access wordset.
 *
 * If your platform does not have ftruncate() per se,
 * but does have some method of truncating files, you
 * should be able to implement ftruncate() yourself and
 * set this constant to 1.  For an example of this see
 * "ficlplatform/win32.c".
 */
#if !defined(FICL_PLATFORM_HAS_FTRUNCATE)
#define	FICL_PLATFORM_HAS_FTRUNCATE	(0)
#endif

/*
 * FICL_PLATFORM_INLINE
 * Must be defined, should be a function prototype type-modifying
 * keyword that makes a function "inline".  Ficl does not assume
 * that the local platform supports inline functions; it therefore
 * only uses "inline" where "static" would also work, and uses "static"
 * in the absence of another keyword.
 */
#if !defined FICL_PLATFORM_INLINE
#define	FICL_PLATFORM_INLINE	inline
#endif /* !defined FICL_PLATFORM_INLINE */

/*
 * FICL_PLATFORM_EXTERN
 * Must be defined, should be a keyword used to declare
 * a function prototype as being a genuine prototype.
 * You should only have to fiddle with this setting if
 * you're not using an ANSI-compliant compiler, in which
 * case, good luck!
 */
#if !defined FICL_PLATFORM_EXTERN
#define	FICL_PLATFORM_EXTERN	extern
#endif /* !defined FICL_PLATFORM_EXTERN */

/*
 * FICL_PLATFORM_BASIC_TYPES
 *
 * If not defined yet,
 */
#if !defined(FICL_PLATFORM_BASIC_TYPES)
typedef char ficlInteger8;
typedef unsigned char ficlUnsigned8;
typedef short ficlInteger16;
typedef unsigned short ficlUnsigned16;
typedef long ficlInteger32;
typedef unsigned long ficlUnsigned32;

typedef ficlInteger32 ficlInteger;
typedef ficlUnsigned32 ficlUnsigned;
typedef float ficlFloat;

#endif /* !defined(FICL_PLATFORM_BASIC_TYPES) */

/*
 * FICL_ROBUST enables bounds checking of stacks and the dictionary.
 * This will detect stack over and underflows and dictionary overflows.
 * Any exceptional condition will result in an assertion failure.
 * (As generated by the ANSI assert macro)
 * FICL_ROBUST == 1 --> stack checking in the outer interpreter
 * FICL_ROBUST == 2 also enables checking in many primitives
 */

#if !defined FICL_ROBUST
#define	FICL_ROBUST	(2)
#endif /* FICL_ROBUST */

/*
 * FICL_DEFAULT_STACK_SIZE Specifies the default size (in CELLs) of
 * a new virtual machine's stacks, unless overridden at
 * create time.
 */
#if !defined FICL_DEFAULT_STACK_SIZE
#define	FICL_DEFAULT_STACK_SIZE	(128)
#endif

/*
 * FICL_DEFAULT_DICTIONARY_SIZE specifies the number of ficlCells to allocate
 * for the system dictionary by default. The value
 * can be overridden at startup time as well.
 */
#if !defined FICL_DEFAULT_DICTIONARY_SIZE
#define	FICL_DEFAULT_DICTIONARY_SIZE	(12288)
#endif

/*
 * FICL_DEFAULT_ENVIRONMENT_SIZE specifies the number of cells
 * to allot for the environment-query dictionary.
 */
#if !defined FICL_DEFAULT_ENVIRONMENT_SIZE
#define	FICL_DEFAULT_ENVIRONMENT_SIZE	(512)
#endif

/*
 * FICL_MAX_WORDLISTS specifies the maximum number of wordlists in
 * the dictionary search order. See Forth DPANS sec 16.3.3
 * (file://dpans16.htm#16.3.3)
 */
#if !defined FICL_MAX_WORDLISTS
#define	FICL_MAX_WORDLISTS	(16)
#endif

/*
 * FICL_MAX_PARSE_STEPS controls the size of an array in the FICL_SYSTEM
 * structure that stores pointers to parser extension functions. I would
 * never expect to have more than 8 of these, so that's the default limit.
 * Too many of these functions will probably exact a nasty performance penalty.
 */
#if !defined FICL_MAX_PARSE_STEPS
#define	FICL_MAX_PARSE_STEPS	(8)
#endif

/*
 * Maximum number of local variables per definition.
 * This only affects the size of the locals dictionary,
 * and there's only one per entire ficlSystem, so it
 * doesn't make sense to be a piker here.
 */
#if (!defined(FICL_MAX_LOCALS)) && FICL_WANT_LOCALS
#define	FICL_MAX_LOCALS	(64)
#endif

/*
 * The pad is a small scratch area for text manipulation. ANS Forth
 * requires it to hold at least 84 characters.
 */
#if !defined FICL_PAD_SIZE
#define	FICL_PAD_SIZE	(256)
#endif

/*
 * ANS Forth requires that a word's name contain {1..31} characters.
 */
#if !defined FICL_NAME_LENGTH
#define	FICL_NAME_LENGTH	(31)
#endif

/*
 * Default size of hash table. For most uniform
 * performance, use a prime number!
 */
#if !defined FICL_HASH_SIZE
#define	FICL_HASH_SIZE	(241)
#endif

/*
 * Default number of USER flags.
 */
#if (!defined(FICL_USER_CELLS)) && FICL_WANT_USER
#define	FICL_USER_CELLS	(16)
#endif

/*
 * Forward declarations... read on.
 */
struct ficlWord;
typedef struct ficlWord ficlWord;
struct ficlVm;
typedef struct ficlVm ficlVm;
struct ficlDictionary;
typedef struct ficlDictionary ficlDictionary;
struct ficlSystem;
typedef struct ficlSystem ficlSystem;
struct ficlSystemInformation;
typedef struct ficlSystemInformation ficlSystemInformation;
struct ficlCallback;
typedef struct ficlCallback ficlCallback;
struct ficlCountedString;
typedef struct ficlCountedString ficlCountedString;
struct ficlString;
typedef struct ficlString ficlString;


/*
 * System dependent routines:
 * Edit the implementations in your appropriate ficlplatform/ *.c to be
 * compatible with your runtime environment.
 *
 * ficlCallbackDefaultTextOut sends a zero-terminated string to the
 *	default output device - used for system error messages.
 *
 * ficlMalloc(), ficlRealloc() and ficlFree() have the same semantics
 * as the functions malloc(), realloc(), and free() from the standard C library.
 */
FICL_PLATFORM_EXTERN void ficlCallbackDefaultTextOut(ficlCallback *callback,
    char *text);
FICL_PLATFORM_EXTERN void *ficlMalloc(size_t size);
FICL_PLATFORM_EXTERN void  ficlFree(void *p);
FICL_PLATFORM_EXTERN void *ficlRealloc(void *p, size_t size);

/*
 * the Good Stuff starts here...
 */
#define	FICL_VERSION	"4.1.0"
#define	FICL_VERSION_MAJOR	4
#define	FICL_VERSION_MINOR	1

#if !defined(FICL_PROMPT)
#define	FICL_PROMPT		"ok> "
#endif

/*
 * ANS Forth requires false to be zero, and true to be the ones
 * complement of false... that unifies logical and bitwise operations
 * nicely.
 */
#define	FICL_TRUE	((unsigned long)~(0L))
#define	FICL_FALSE	(0)
#define	FICL_BOOL(x)	((x) ? FICL_TRUE : FICL_FALSE)


#if !defined FICL_IGNORE	/* Macro to silence unused param warnings */
#define	FICL_IGNORE(x)	(void)x
#endif /*  !defined FICL_IGNORE */

#if !defined NULL
#define	NULL	((void *)0)
#endif

/*
 * 2integer structures
 */
#if FICL_PLATFORM_HAS_2INTEGER

#define	FICL_2INTEGER_SET(high, low, doublei)	\
	((doublei) = (ficl2Integer)(((ficlUnsigned)(low)) | \
	(((ficl2Integer)(high)) << FICL_BITS_PER_CELL)))
#define	FICL_2UNSIGNED_SET(high, low, doubleu)	\
	((doubleu) = ((ficl2Unsigned)(low)) | \
	(((ficl2Unsigned)(high)) << FICL_BITS_PER_CELL))
#define	FICL_2UNSIGNED_GET_LOW(doubleu)	\
	((ficlUnsigned)(doubleu & ((((ficl2Integer)1) << \
	FICL_BITS_PER_CELL) - 1)))
#define	FICL_2UNSIGNED_GET_HIGH(doubleu)	\
	((ficlUnsigned)(doubleu >> FICL_BITS_PER_CELL))
#define	FICL_2UNSIGNED_NOT_ZERO(doubleu)	((doubleu) != 0)

#define	FICL_INTEGER_TO_2INTEGER(i, doublei)	((doublei) = (i))
#define	FICL_UNSIGNED_TO_2UNSIGNED(u, doubleu)	((doubleu) = (u))

#define	ficl2IntegerIsNegative(doublei)	((doublei) < 0)
#define	ficl2IntegerNegate(doublei)	(-(doublei))

#define	ficl2IntegerMultiply(x, y)	\
	(((ficl2Integer)(x)) * ((ficl2Integer)(y)))
#define	ficl2IntegerDecrement(x)	(((ficl2Integer)(x)) - 1)

#define	ficl2UnsignedAdd(x, y)	(((ficl2Unsigned)(x)) + ((ficl2Unsigned)(y)))
#define	ficl2UnsignedSubtract(x, y)	\
	(((ficl2Unsigned)(x)) - ((ficl2Unsigned)(y)))
#define	ficl2UnsignedMultiply(x, y)	\
	(((ficl2Unsigned)(x)) * ((ficl2Unsigned)(y)))
#define	ficl2UnsignedMultiplyAccumulate(u, mul, add)	(((u) * (mul)) + (add))
#define	ficl2UnsignedArithmeticShiftLeft(x)	((x) << 1)
#define	ficl2UnsignedArithmeticShiftRight(x)	((x) >> 1)
#define	ficl2UnsignedCompare(x, y)	ficl2UnsignedSubtract(x, y)
#define	ficl2UnsignedOr(x, y)	((x) | (y))

#else /* FICL_PLATFORM_HAS_2INTEGER */

typedef struct
{
	ficlUnsigned high;
	ficlUnsigned low;
} ficl2Unsigned;

typedef struct
{
	ficlInteger high;
	ficlInteger low;
} ficl2Integer;


#define	FICL_2INTEGER_SET(hi, lo, doublei)	\
	{ ficl2Integer x; x.low = (lo); x.high = (hi); (doublei) = x; }
#define	FICL_2UNSIGNED_SET(hi, lo, doubleu)	\
	{ ficl2Unsigned x; x.low = (lo); x.high = (hi); (doubleu) = x; }
#define	FICL_2UNSIGNED_GET_LOW(doubleu)	((doubleu).low)
#define	FICL_2UNSIGNED_GET_HIGH(doubleu)	((doubleu).high)
#define	FICL_2UNSIGNED_NOT_ZERO(doubleu) ((doubleu).high || (doubleu).low)

#define	FICL_INTEGER_TO_2INTEGER(i, doublei)	\
	{ ficlInteger __x = (ficlInteger)(i);	\
	FICL_2INTEGER_SET((__x < 0) ? -1L : 0, __x, doublei) }
#define	FICL_UNSIGNED_TO_2UNSIGNED(u, doubleu)	\
	FICL_2UNSIGNED_SET(0, u, doubleu)

FICL_PLATFORM_EXTERN int ficl2IntegerIsNegative(ficl2Integer x);
FICL_PLATFORM_EXTERN ficl2Integer ficl2IntegerNegate(ficl2Integer x);

FICL_PLATFORM_EXTERN ficl2Integer ficl2IntegerMultiply(ficlInteger x,
    ficlInteger y);
FICL_PLATFORM_EXTERN ficl2Integer ficl2IntegerDecrement(ficl2Integer x);

FICL_PLATFORM_EXTERN ficl2Unsigned ficl2UnsignedAdd(ficl2Unsigned x,
    ficl2Unsigned y);
FICL_PLATFORM_EXTERN ficl2Unsigned ficl2UnsignedSubtract(ficl2Unsigned x,
    ficl2Unsigned y);
FICL_PLATFORM_EXTERN ficl2Unsigned ficl2UnsignedMultiply(ficlUnsigned x,
    ficlUnsigned y);
FICL_PLATFORM_EXTERN ficl2Unsigned
    ficl2UnsignedMultiplyAccumulate(ficl2Unsigned u, ficlUnsigned mul,
    ficlUnsigned add);
FICL_PLATFORM_EXTERN ficl2Unsigned
    ficl2UnsignedArithmeticShiftLeft(ficl2Unsigned x);
FICL_PLATFORM_EXTERN ficl2Unsigned
    ficl2UnsignedArithmeticShiftRight(ficl2Unsigned x);
FICL_PLATFORM_EXTERN int ficl2UnsignedCompare(ficl2Unsigned x,
    ficl2Unsigned y);
FICL_PLATFORM_EXTERN ficl2Unsigned
    ficl2UnsignedOr(ficl2Unsigned x, ficl2Unsigned y);

#endif /* FICL_PLATFORM_HAS_2INTEGER */

/*
 * These structures represent the result of division.
 */
typedef struct
{
	ficl2Unsigned quotient;
	ficlUnsigned remainder;
} __attribute__((may_alias)) ficl2UnsignedQR;

typedef struct
{
	ficl2Integer quotient;
	ficlInteger remainder;
} __attribute__((may_alias)) ficl2IntegerQR;


#define	FICL_2INTEGERQR_TO_2UNSIGNEDQR(doubleiqr)	\
	(*(ficl2UnsignedQR *)(&(doubleiqr)))
#define	FICL_2UNSIGNEDQR_TO_2INTEGERQR(doubleuqr)	\
	(*(ficl2IntegerQR *)(&(doubleuqr)))

/*
 * 64 bit integer math support routines: multiply two UNS32s
 * to get a 64 bit product, & divide the product by an UNS32
 * to get an UNS32 quotient and remainder. Much easier in asm
 * on a 32 bit CPU than in C, which usually doesn't support
 * the double length result (but it should).
 */
FICL_PLATFORM_EXTERN ficl2IntegerQR
    ficl2IntegerDivideFloored(ficl2Integer num, ficlInteger den);
FICL_PLATFORM_EXTERN ficl2IntegerQR
    ficl2IntegerDivideSymmetric(ficl2Integer num, ficlInteger den);

FICL_PLATFORM_EXTERN ficl2UnsignedQR
    ficl2UnsignedDivide(ficl2Unsigned q, ficlUnsigned y);

/*
 * A ficlCell is the main storage type. It must be large enough
 * to contain a pointer or a scalar. In order to accommodate
 * 32 bit and 64 bit processors, use abstract types for int,
 * unsigned, and float.
 *
 * A ficlUnsigned, ficlInteger, and ficlFloat *MUST* be the same
 * size as a "void *" on the target system.  (Sorry, but that's
 * a design constraint of FORTH.)
 */
typedef union ficlCell
{
    ficlInteger i;
    ficlUnsigned u;
#if (FICL_WANT_FLOAT)
    ficlFloat f;
#endif
    void *p;
    void (*fn)(void);
} __attribute__((may_alias)) ficlCell;


#define	FICL_BITS_PER_CELL	(sizeof (ficlCell) * 8)

/*
 * FICL_PLATFORM_ALIGNMENT is the number of bytes to which
 * the dictionary pointer address must be aligned. This value
 * is usually either 2 or 4, depending on the memory architecture
 * of the target system; 4 is safe on any 16 or 32 bit
 * machine.  8 would be appropriate for a 64 bit machine.
 */
#if !defined FICL_PLATFORM_ALIGNMENT
#define	FICL_PLATFORM_ALIGNMENT	(4)
#endif

/*
 * PTRtoCELL is a cast through void * intended to satisfy the
 * most outrageously pedantic compiler... (I won't mention
 * its name)
 */
#define	FICL_POINTER_TO_CELL(p)	((ficlCell *)(void *)p)

/*
 * FORTH defines the "counted string" data type.  This is
 * a "Pascal-style" string, where the first byte is an unsigned
 * count of characters, followed by the characters themselves.
 * The Ficl structure for this is ficlCountedString.
 * Ficl also often zero-terminates them so that they work with the
 * usual C runtime library string functions... strlen(), strcmp(),
 * and the like.  (Belt & suspenders?  You decide.)
 *
 * The problem is, this limits strings to 255 characters, which
 * can be a bit constricting to us wordy types.  So FORTH only
 * uses counted strings for backwards compatibility, and all new
 * words are "c-addr u" style, where the address and length are
 * stored separately, and the length is a full unsigned "cell" size.
 * (For more on this trend, see DPANS94 section A.3.1.3.4.)
 * Ficl represents this with the ficlString structure.  Note that
 * these are frequently *not* zero-terminated!  Don't depend on
 * it--that way lies madness.
 */

struct ficlCountedString
{
    ficlUnsigned8 length;
    char text[1];
};

#define	FICL_COUNTED_STRING_GET_LENGTH(cs)	((cs).length)
#define	FICL_COUNTED_STRING_GET_POINTER(cs)	((cs).text)

#define	FICL_COUNTED_STRING_MAX	(256)
#define	FICL_POINTER_TO_COUNTED_STRING(p)	((ficlCountedString *)(void *)p)

struct ficlString
{
    ficlUnsigned length;
    char *text;
};


#define	FICL_STRING_GET_LENGTH(fs)	((fs).length)
#define	FICL_STRING_GET_POINTER(fs)	((fs).text)
#define	FICL_STRING_SET_LENGTH(fs, l)	((fs).length = (ficlUnsigned)(l))
#define	FICL_STRING_SET_POINTER(fs, p)	((fs).text = (char *)(p))
#define	FICL_STRING_SET_FROM_COUNTED_STRING(string, countedstring)	\
	{(string).text = (countedstring).text;	\
	(string).length = (countedstring).length; }
/*
 * Init a FICL_STRING from a pointer to a zero-terminated string
 */
#define	FICL_STRING_SET_FROM_CSTRING(string, cstring) \
	{(string).text = (cstring); (string).length = strlen(cstring); }

/*
 * Ficl uses this little structure to hold the address of
 * the block of text it's working on and an index to the next
 * unconsumed character in the string. Traditionally, this is
 * done by a Text Input Buffer, so I've called this struct TIB.
 *
 * Since this structure also holds the size of the input buffer,
 * and since evaluate requires that, let's put the size here.
 * The size is stored as an end-pointer because that is what the
 * null-terminated string aware functions find most easy to deal
 * with.
 * Notice, though, that nobody really uses this except evaluate,
 * so it might just be moved to ficlVm instead. (sobral)
 */
typedef struct
{
    ficlInteger index;
    char *end;
    char *text;
} ficlTIB;

/*
 * Stacks get heavy use in Ficl and Forth...
 * Each virtual machine implements two of them:
 * one holds parameters (data), and the other holds return
 * addresses and control flow information for the virtual
 * machine. (Note: C's automatic stack is implicitly used,
 * but not modeled because it doesn't need to be...)
 * Here's an abstract type for a stack
 */
typedef struct ficlStack
{
    ficlUnsigned size;	/* size of the stack, in cells */
    ficlCell *frame;	/* link reg for stack frame */
    ficlCell *top;	/* stack pointer */
    ficlVm *vm;		/* used for debugging */
    char *name;		/* used for debugging */
    ficlCell base[1];	/* Top of stack */
} ficlStack;

/*
 * Stack methods... many map closely to required Forth words.
 */
FICL_PLATFORM_EXTERN ficlStack *
    ficlStackCreate(ficlVm *vm, char *name, unsigned nCells);
FICL_PLATFORM_EXTERN void ficlStackDestroy(ficlStack *stack);
FICL_PLATFORM_EXTERN int ficlStackDepth(ficlStack *stack);
FICL_PLATFORM_EXTERN void ficlStackDrop(ficlStack *stack, int n);
FICL_PLATFORM_EXTERN ficlCell ficlStackFetch(ficlStack *stack, int n);
FICL_PLATFORM_EXTERN ficlCell ficlStackGetTop(ficlStack *stack);
FICL_PLATFORM_EXTERN void ficlStackPick(ficlStack *stack, int n);
FICL_PLATFORM_EXTERN ficlCell ficlStackPop(ficlStack *stack);
FICL_PLATFORM_EXTERN void ficlStackPush(ficlStack *stack, ficlCell c);
FICL_PLATFORM_EXTERN void ficlStackReset(ficlStack *stack);
FICL_PLATFORM_EXTERN void ficlStackRoll(ficlStack *stack, int n);
FICL_PLATFORM_EXTERN void ficlStackSetTop(ficlStack *stack, ficlCell c);
FICL_PLATFORM_EXTERN void ficlStackStore(ficlStack *stack, int n, ficlCell c);

#if FICL_WANT_LOCALS
FICL_PLATFORM_EXTERN void ficlStackLink(ficlStack *stack, int nCells);
FICL_PLATFORM_EXTERN void ficlStackUnlink(ficlStack *stack);
#endif /* FICL_WANT_LOCALS */

FICL_PLATFORM_EXTERN void *ficlStackPopPointer(ficlStack *stack);
FICL_PLATFORM_EXTERN ficlUnsigned ficlStackPopUnsigned(ficlStack *stack);
FICL_PLATFORM_EXTERN ficlInteger ficlStackPopInteger(ficlStack *stack);
FICL_PLATFORM_EXTERN void ficlStackPushPointer(ficlStack *stack, void *ptr);
FICL_PLATFORM_EXTERN void
	ficlStackPushUnsigned(ficlStack *stack, ficlUnsigned u);
FICL_PLATFORM_EXTERN void ficlStackPushInteger(ficlStack *stack, ficlInteger i);

#if (FICL_WANT_FLOAT)
FICL_PLATFORM_EXTERN ficlFloat ficlStackPopFloat(ficlStack *stack);
FICL_PLATFORM_EXTERN void ficlStackPushFloat(ficlStack *stack, ficlFloat f);
#endif

FICL_PLATFORM_EXTERN void
	ficlStackPush2Integer(ficlStack *stack, ficl2Integer i64);
FICL_PLATFORM_EXTERN ficl2Integer ficlStackPop2Integer(ficlStack *stack);
FICL_PLATFORM_EXTERN void
	ficlStackPush2Unsigned(ficlStack *stack, ficl2Unsigned u64);
FICL_PLATFORM_EXTERN ficl2Unsigned ficlStackPop2Unsigned(ficlStack *stack);

#if FICL_ROBUST >= 1
FICL_PLATFORM_EXTERN void
	ficlStackCheck(ficlStack *stack, int popCells, int pushCells);
#define	FICL_STACK_CHECK(stack, popCells, pushCells)	\
	ficlStackCheck(stack, popCells, pushCells)
#else /* FICL_ROBUST >= 1 */
#define	FICL_STACK_CHECK(stack, popCells, pushCells)
#endif /* FICL_ROBUST >= 1 */

typedef ficlInteger (*ficlStackWalkFunction)(void *constant, ficlCell *cell);
FICL_PLATFORM_EXTERN void
	ficlStackWalk(ficlStack *stack, ficlStackWalkFunction callback,
	void *context, ficlInteger bottomToTop);
FICL_PLATFORM_EXTERN void ficlStackDisplay(ficlStack *stack,
	ficlStackWalkFunction callback, void *context);

typedef ficlWord **ficlIp; /* the VM's instruction pointer */
typedef void (*ficlPrimitive)(ficlVm *vm);
typedef void (*ficlOutputFunction)(ficlCallback *callback, char *text);

/*
 * Each VM has a placeholder for an output function -
 * this makes it possible to have each VM do I/O
 * through a different device. If you specify no
 * ficlOutputFunction, it defaults to ficlCallbackDefaultTextOut.
 *
 * You can also set a specific handler just for errors.
 * If you don't specify one, it defaults to using textOut.
 */

struct ficlCallback
{
    void *context;
    ficlOutputFunction textOut;
    ficlOutputFunction errorOut;
    ficlSystem *system;
    ficlVm *vm;
};

FICL_PLATFORM_EXTERN void
    ficlCallbackTextOut(ficlCallback *callback, char *text);
FICL_PLATFORM_EXTERN void
    ficlCallbackErrorOut(ficlCallback *callback, char *text);

/*
 * For backwards compatibility.
 */
typedef void
(*ficlCompatibilityOutputFunction)(ficlVm *vm, char *text, int newline);
FICL_PLATFORM_EXTERN void
    ficlCompatibilityTextOutCallback(ficlCallback *callback, char *text,
    ficlCompatibilityOutputFunction oldFunction);

/*
 * Starting with Ficl 4.0, Ficl uses a "switch-threaded" inner loop,
 * where each primitive word is represented with a numeric constant,
 * and words are (more or less) arrays of these constants.  In Ficl
 * these constants are an enumerated type called ficlInstruction.
 */
enum ficlInstruction
{
#define	FICL_TOKEN(token, description) token,
#define	FICL_INSTRUCTION_TOKEN(token, description, flags) token,
#include "ficltokens.h"
#undef	FICL_TOKEN
#undef	FICL_INSTRUCTION_TOKEN

	ficlInstructionLast,

	ficlInstructionFourByteTrick = 0x10000000
};
typedef intptr_t ficlInstruction;

/*
 * The virtual machine (VM) contains the state for one interpreter.
 * Defined operations include:
 * Create & initialize
 * Delete
 * Execute a block of text
 * Parse a word out of the input stream
 * Call return, and branch
 * Text output
 * Throw an exception
 */

struct ficlVm
{
	ficlCallback callback;
	ficlVm *link;		/* Ficl keeps a VM list for simple teardown */
	jmp_buf *exceptionHandler; /* crude exception mechanism... */
	short restart;		/* Set TRUE to restart runningWord */
	ficlIp ip;		/* instruction pointer */
		/* address of currently running word (often just *(ip-1) ) */
	ficlWord *runningWord;
	ficlUnsigned state;	/* compiling or interpreting */
	ficlUnsigned base;	/* number conversion base */
	ficlStack *dataStack;
	ficlStack *returnStack;	/* return stack */
#if FICL_WANT_FLOAT
	ficlStack *floatStack;	/* float stack (optional) */
#endif
	ficlCell sourceId; /* -1 if EVALUATE, 0 if normal input, >0 if a file */
	ficlTIB	 tib;		/* address of incoming text string  */
#if FICL_WANT_USER
	ficlCell user[FICL_USER_CELLS];
#endif
	char pad[FICL_PAD_SIZE];	/* the scratch area (see above) */
};

/*
 * Each VM operates in one of two non-error states: interpreting
 * or compiling. When interpreting, words are simply executed.
 * When compiling, most words in the input stream have their
 * addresses inserted into the word under construction. Some words
 * (known as IMMEDIATE) are executed in the compile state, too.
 */
/* values of STATE */
#define	FICL_VM_STATE_INTERPRET	(0)
#define	FICL_VM_STATE_COMPILE	(1)

/*
 * Exit codes for vmThrow
 */
/* tell ficlVmExecuteXT to exit inner loop */
#define	FICL_VM_STATUS_INNER_EXIT	(-256)
/* hungry - normal exit */
#define	FICL_VM_STATUS_OUT_OF_TEXT	(-257)
/* word needs more text to succeed -- re-run it */
#define	FICL_VM_STATUS_RESTART		(-258)
/* user wants to quit */
#define	FICL_VM_STATUS_USER_EXIT	(-259)
/* interpreter found an error */
#define	FICL_VM_STATUS_ERROR_EXIT	(-260)
/* debugger breakpoint */
#define	FICL_VM_STATUS_BREAK		(-261)
/* like FICL_VM_STATUS_ERROR_EXIT -- abort */
#define	FICL_VM_STATUS_ABORT		(-1)
/* like FICL_VM_STATUS_ERROR_EXIT -- abort" */
#define	FICL_VM_STATUS_ABORTQ		(-2)
/* like FICL_VM_STATUS_ERROR_EXIT, but leave dataStack & base alone */
#define	FICL_VM_STATUS_QUIT		(-56)

FICL_PLATFORM_EXTERN void ficlVmBranchRelative(ficlVm *vm, int offset);
FICL_PLATFORM_EXTERN ficlVm *
ficlVmCreate(ficlVm *vm, unsigned nPStack, unsigned nRStack);
FICL_PLATFORM_EXTERN void ficlVmDestroy(ficlVm *vm);
FICL_PLATFORM_EXTERN ficlDictionary *ficlVmGetDictionary(ficlVm *vm);
FICL_PLATFORM_EXTERN char *
ficlVmGetString(ficlVm *vm, ficlCountedString *spDest, char delimiter);
FICL_PLATFORM_EXTERN ficlString ficlVmGetWord(ficlVm *vm);
FICL_PLATFORM_EXTERN ficlString ficlVmGetWord0(ficlVm *vm);
FICL_PLATFORM_EXTERN int ficlVmGetWordToPad(ficlVm *vm);
FICL_PLATFORM_EXTERN void ficlVmInnerLoop(ficlVm *vm, ficlWord *word);
FICL_PLATFORM_EXTERN ficlString ficlVmParseString(ficlVm *vm, char delimiter);
FICL_PLATFORM_EXTERN ficlString
ficlVmParseStringEx(ficlVm *vm, char delimiter, char fSkipLeading);
FICL_PLATFORM_EXTERN ficlCell ficlVmPop(ficlVm *vm);
FICL_PLATFORM_EXTERN void ficlVmPush(ficlVm *vm, ficlCell c);
FICL_PLATFORM_EXTERN void ficlVmPopIP(ficlVm *vm);
FICL_PLATFORM_EXTERN void ficlVmPushIP(ficlVm *vm, ficlIp newIP);
FICL_PLATFORM_EXTERN void ficlVmQuit(ficlVm *vm);
FICL_PLATFORM_EXTERN void ficlVmReset(ficlVm *vm);
FICL_PLATFORM_EXTERN void
ficlVmSetTextOut(ficlVm *vm, ficlOutputFunction textOut);
FICL_PLATFORM_EXTERN void ficlVmThrow(ficlVm *vm, int except);
FICL_PLATFORM_EXTERN void ficlVmThrowError(ficlVm *vm, char *fmt, ...);
FICL_PLATFORM_EXTERN void
ficlVmThrowErrorVararg(ficlVm *vm, char *fmt, va_list list);
FICL_PLATFORM_EXTERN void ficlVmTextOut(ficlVm *vm, char *text);
FICL_PLATFORM_EXTERN void ficlVmErrorOut(ficlVm *vm, char *text);

#define	ficlVmGetContext(vm)		((vm)->callback.context)
#define	ficlVmGetDataStack(vm)		((vm)->dataStack)
#define	ficlVmGetFloatStack(vm)		((vm)->floatStack)
#define	ficlVmGetReturnStack(vm)	((vm)->returnStack)
#define	ficlVmGetRunningWord(vm)	((vm)->runningWord)

FICL_PLATFORM_EXTERN void ficlVmDisplayDataStack(ficlVm *vm);
FICL_PLATFORM_EXTERN void ficlVmDisplayDataStackSimple(ficlVm *vm);
FICL_PLATFORM_EXTERN void ficlVmDisplayReturnStack(ficlVm *vm);
#if FICL_WANT_FLOAT
FICL_PLATFORM_EXTERN void ficlVmDisplayFloatStack(ficlVm *vm);
#endif /* FICL_WANT_FLOAT */

/*
 * f i c l E v a l u a t e
 * Evaluates a block of input text in the context of the
 * specified interpreter. Also sets SOURCE-ID properly.
 *
 * PLEASE USE THIS FUNCTION when throwing a hard-coded
 * string to the Ficl interpreter.
 */
FICL_PLATFORM_EXTERN int ficlVmEvaluate(ficlVm *vm, char *s);

/*
 * f i c l V m E x e c *
 * Evaluates a block of input text in the context of the
 * specified interpreter. Emits any requested output to the
 * interpreter's output function. If the input string is NULL
 * terminated, you can pass -1 as nChars rather than count it.
 * Execution returns when the text block has been executed,
 * or an error occurs.
 * Returns one of the FICL_VM_STATUS_... codes defined in ficl.h:
 * FICL_VM_STATUS_OUT_OF_TEXT is the normal exit condition
 * FICL_VM_STATUS_ERROR_EXIT means that the interpreter encountered a syntax
 *	error and the vm has been reset to recover (some or all
 *      of the text block got ignored
 * FICL_VM_STATUS_USER_EXIT means that the user executed the "bye" command
 *      to shut down the interpreter. This would be a good
 *      time to delete the vm, etc -- or you can ignore this
 *      signal.
 * FICL_VM_STATUS_ABORT and FICL_VM_STATUS_ABORTQ are generated by 'abort'
 *	 and 'abort"' commands.
 * Preconditions: successful execution of ficlInitSystem,
 *      Successful creation and init of the VM by ficlNewVM (or equivalent)
 *
 * If you call ficlExec() or one of its brothers, you MUST
 * ensure vm->sourceId was set to a sensible value.
 * ficlExec() explicitly DOES NOT manage SOURCE-ID for you.
 */
FICL_PLATFORM_EXTERN int ficlVmExecuteString(ficlVm *vm, ficlString s);
FICL_PLATFORM_EXTERN int ficlVmExecuteXT(ficlVm *vm, ficlWord *pWord);
FICL_PLATFORM_EXTERN void
ficlVmExecuteInstruction(ficlVm *vm, ficlInstruction i);
FICL_PLATFORM_EXTERN void ficlVmExecuteWord(ficlVm *vm, ficlWord *pWord);
FICL_PLATFORM_EXTERN int ficlExecFD(ficlVm *vm, int fd);

FICL_PLATFORM_EXTERN void
ficlVmDictionaryAllot(ficlVm *vm, ficlDictionary *dictionary, int n);
FICL_PLATFORM_EXTERN void
ficlVmDictionaryAllotCells(ficlVm *vm, ficlDictionary *dictionary, int cells);

FICL_PLATFORM_EXTERN int ficlVmParseWord(ficlVm *vm, ficlString s);

/*
 * TIB access routines...
 * ANS forth seems to require the input buffer to be represented
 * as a pointer to the start of the buffer, and an index to the
 * next character to read.
 * PushTib points the VM to a new input string and optionally
 *  returns a copy of the current state
 * PopTib restores the TIB state given a saved TIB from PushTib
 * GetInBuf returns a pointer to the next unused char of the TIB
 */
FICL_PLATFORM_EXTERN void
ficlVmPushTib(ficlVm *vm, char *text, ficlInteger nChars, ficlTIB *pSaveTib);
FICL_PLATFORM_EXTERN void ficlVmPopTib(ficlVm *vm, ficlTIB *pTib);
#define	ficlVmGetInBuf(vm)	((vm)->tib.text + (vm)->tib.index)
#define	ficlVmGetInBufLen(vm)	((vm)->tib.end - (vm)->tib.text)
#define	ficlVmGetInBufEnd(vm)	((vm)->tib.end)
#define	ficlVmGetTibIndex(vm)	((vm)->tib.index)
#define	ficlVmSetTibIndex(vm, i)	((vm)->tib.index = i)
#define	ficlVmUpdateTib(vm, str)	\
	((vm)->tib.index = (str) - (vm)->tib.text)

#if FICL_ROBUST >= 1
FICL_PLATFORM_EXTERN void
ficlVmDictionaryCheck(ficlVm *vm, ficlDictionary *dictionary, int n);
FICL_PLATFORM_EXTERN void
ficlVmDictionarySimpleCheck(ficlVm *vm, ficlDictionary *dictionary, int n);
#define	FICL_VM_DICTIONARY_CHECK(vm, dictionary, n)	\
	ficlVmDictionaryCheck(vm, dictionary, n)
#define	FICL_VM_DICTIONARY_SIMPLE_CHECK(vm, dictionary, n)	\
	ficlVmDictionarySimpleCheck(vm, dictionary, n)
#else
#define	FICL_VM_DICTIONARY_CHECK(vm, dictionary, n)
#define	FICL_VM_DICTIONARY_SIMPLE_CHECK(vm, dictionary, n)
#endif /* FICL_ROBUST >= 1 */

FICL_PLATFORM_EXTERN void ficlPrimitiveLiteralIm(ficlVm *vm);

/*
 * A FICL_CODE points to a function that gets called to help execute
 * a word in the dictionary. It always gets passed a pointer to the
 * running virtual machine, and from there it can get the address
 * of the parameter area of the word it's supposed to operate on.
 * For precompiled words, the code is all there is. For user defined
 * words, the code assumes that the word's parameter area is a list
 * of pointers to the code fields of other words to execute, and
 * may also contain inline data. The first parameter is always
 * a pointer to a code field.
 */

/*
 * Ficl models memory as a contiguous space divided into
 * words in a linked list called the dictionary.
 * A ficlWord starts each entry in the list.
 * Version 1.02: space for the name characters is allotted from
 * the dictionary ahead of the word struct, rather than using
 * a fixed size array for each name.
 */
struct ficlWord
{
    struct ficlWord *link;	/* Previous word in the dictionary */
    ficlUnsigned16 hash;
		/* Immediate, Smudge, Compile-only, IsOjbect, Instruction */
    ficlUnsigned8 flags;
    ficlUnsigned8 length;	/* Number of chars in word name */
    char *name;			/* First nFICLNAME chars of word name */
    ficlPrimitive code;		/* Native code to execute the word */
    ficlInstruction semiParen;	/* Native code to execute the word */
    ficlCell param[1];		/* First data cell of the word */
};

/*
 * ficlWord.flag bitfield values:
 */

/*
 * FICL_WORD_IMMEDIATE:
 * This word is always executed immediately when
 * encountered, even when compiling.
 */
#define	FICL_WORD_IMMEDIATE	(1)

/*
 * FICL_WORD_COMPILE_ONLY:
 * This word is only valid during compilation.
 * Ficl will throw a runtime error if this word executed
 * while not compiling.
 */
#define	FICL_WORD_COMPILE_ONLY	(2)

/*
 * FICL_WORD_SMUDGED
 * This word's definition is in progress.
 * The word is hidden from dictionary lookups
 * until it is "un-smudged".
 */
#define	FICL_WORD_SMUDGED	(4)

/*
 * FICL_WORD_OBJECT
 * This word is an object or object member variable.
 * (Currently only used by "my=[".)
 */
#define	FICL_WORD_OBJECT	(8)

/*
 * FICL_WORD_INSTRUCTION
 * This word represents a ficlInstruction, not a normal word.
 * param[0] is the instruction.
 * When compiled, Ficl will simply copy over the instruction,
 * rather than executing the word as normal.
 *
 * (Do *not* use this flag for words that need their PFA pushed
 * before executing!)
 */
#define	FICL_WORD_INSTRUCTION	(16)

/*
 * FICL_WORD_COMPILE_ONLY_IMMEDIATE
 * Most words that are "immediate" are also
 * "compile-only".
 */
#define	FICL_WORD_COMPILE_ONLY_IMMEDIATE	\
	(FICL_WORD_IMMEDIATE | FICL_WORD_COMPILE_ONLY)
#define	FICL_WORD_DEFAULT	(0)

/*
 * Worst-case size of a word header: FICL_NAME_LENGTH chars in name
 */
#define	FICL_CELLS_PER_WORD	\
	((sizeof (ficlWord) + FICL_NAME_LENGTH + sizeof (ficlCell)) \
	/ (sizeof (ficlCell)))

FICL_PLATFORM_EXTERN int ficlWordIsImmediate(ficlWord *word);
FICL_PLATFORM_EXTERN int ficlWordIsCompileOnly(ficlWord *word);

#if FICL_ROBUST >= 1
FICL_PLATFORM_EXTERN void
ficlCallbackAssert(ficlCallback *callback, int expression,
    char *expressionString, char *filename, int line);
#define	FICL_ASSERT(callback, expression)	\
(ficlCallbackAssert((callback), (expression) != 0, \
#expression, __FILE__, __LINE__))
#else
#define	FICL_ASSERT(callback, expression)
#endif /* FICL_ROBUST >= 1 */

#define	FICL_VM_ASSERT(vm, expression)	\
	FICL_ASSERT((ficlCallback *)(vm), (expression))
#define	FICL_SYSTEM_ASSERT(system, expression)	\
	FICL_ASSERT((ficlCallback *)(system), (expression))

/*
 * Generally useful string manipulators omitted by ANSI C...
 * ltoa complements strtol
 */

FICL_PLATFORM_EXTERN int ficlIsPowerOfTwo(ficlUnsigned u);
FICL_PLATFORM_EXTERN char *
ficlLtoa(ficlInteger value, char *string, int radix);
FICL_PLATFORM_EXTERN char *
ficlUltoa(ficlUnsigned value, char *string, int radix);
FICL_PLATFORM_EXTERN char ficlDigitToCharacter(int value);
FICL_PLATFORM_EXTERN char *ficlStringReverse(char *string);
FICL_PLATFORM_EXTERN char *ficlStringSkipSpace(char *s, char *end);
FICL_PLATFORM_EXTERN char *ficlStringCaseFold(char *s);
FICL_PLATFORM_EXTERN int ficlStrincmp(char *s1, char *s2, ficlUnsigned length);
FICL_PLATFORM_EXTERN void *ficlAlignPointer(void *ptr);

/*
 * Ficl hash table - variable size.
 * assert(size > 0)
 * If size is 1, the table degenerates into a linked list.
 * A WORDLIST (see the search order word set in DPANS) is
 * just a pointer to a FICL_HASH in this implementation.
 */
typedef struct ficlHash
{
    struct ficlHash *link;	/* link to parent class wordlist for OO */
    char *name;		/* optional pointer to \0 terminated wordlist name */
    unsigned size;		/* number of buckets in the hash */
    ficlWord *table[1];
} ficlHash;

FICL_PLATFORM_EXTERN void ficlHashForget(ficlHash *hash, void *where);
FICL_PLATFORM_EXTERN ficlUnsigned16 ficlHashCode(ficlString s);
FICL_PLATFORM_EXTERN void ficlHashInsertWord(ficlHash *hash, ficlWord *word);
FICL_PLATFORM_EXTERN ficlWord *
ficlHashLookup(ficlHash *hash, ficlString name, ficlUnsigned16 hashCode);
FICL_PLATFORM_EXTERN void ficlHashReset(ficlHash *hash);

/*
 * A Dictionary is a linked list of FICL_WORDs. It is also Ficl's
 * memory model. Description of fields:
 *
 * here -- points to the next free byte in the dictionary. This
 *	pointer is forced to be CELL-aligned before a definition is added.
 *	Do not assume any specific alignment otherwise - Use dictAlign().
 *
 * smudge -- pointer to word currently being defined (or last defined word)
 *	If the definition completes successfully, the word will be
 *	linked into the hash table. If unsuccessful, dictUnsmudge
 *	uses this pointer to restore the previous state of the dictionary.
 *	Smudge prevents unintentional recursion as a side-effect: the
 *	dictionary search algo examines only completed definitions, so a
 *	word cannot invoke itself by name. See the Ficl word "recurse".
 *	NOTE: smudge always points to the last word defined. IMMEDIATE
 *	makes use of this fact. Smudge is initially NULL.
 *
 * forthWordlist -- pointer to the default wordlist (FICL_HASH).
 *	This is the initial compilation list, and contains all
 *	Ficl's precompiled words.
 *
 * compilationWordlist -- compilation wordlist - initially equal to
 * forthWordlist wordlists  -- array of pointers to wordlists.
 *	Managed as a stack.
 *	Highest index is the first list in the search order.
 * wordlistCount   -- number of lists in wordlists. wordlistCount-1 is the
 *	highest filled slot in wordlists, and points to the first wordlist
 *	in the search order
 * size -- number of cells in the dictionary (total)
 * base -- start of data area. Must be at the end of the struct.
 */
struct ficlDictionary
{
    ficlCell *here;
    void *context; /* for your use, particularly with ficlDictionaryLock() */
    ficlWord *smudge;
    ficlHash *forthWordlist;
    ficlHash *compilationWordlist;
    ficlHash *wordlists[FICL_MAX_WORDLISTS];
    int wordlistCount;
    unsigned size;		/* Number of cells in dictionary (total) */
    ficlSystem *system;		/* used for debugging */
    ficlCell base[1];		/* Base of dictionary memory */
};

FICL_PLATFORM_EXTERN void
ficlDictionaryAbortDefinition(ficlDictionary *dictionary);
FICL_PLATFORM_EXTERN void ficlDictionaryAlign(ficlDictionary *dictionary);
FICL_PLATFORM_EXTERN void
ficlDictionaryAllot(ficlDictionary *dictionary, int n);
FICL_PLATFORM_EXTERN void
ficlDictionaryAllotCells(ficlDictionary *dictionary, int nCells);
FICL_PLATFORM_EXTERN void
ficlDictionaryAppendCell(ficlDictionary *dictionary, ficlCell c);
FICL_PLATFORM_EXTERN void
ficlDictionaryAppendCharacter(ficlDictionary *dictionary, char c);
FICL_PLATFORM_EXTERN void
ficlDictionaryAppendUnsigned(ficlDictionary *dictionary, ficlUnsigned u);
FICL_PLATFORM_EXTERN void *
ficlDictionaryAppendData(ficlDictionary *dictionary, void *data,
    ficlInteger length);
FICL_PLATFORM_EXTERN char *
ficlDictionaryAppendString(ficlDictionary *dictionary, ficlString s);
FICL_PLATFORM_EXTERN ficlWord *
ficlDictionaryAppendWord(ficlDictionary *dictionary, ficlString name,
    ficlPrimitive pCode, ficlUnsigned8 flags);
FICL_PLATFORM_EXTERN ficlWord *
ficlDictionaryAppendPrimitive(ficlDictionary *dictionary, char *name,
    ficlPrimitive pCode, ficlUnsigned8 flags);
FICL_PLATFORM_EXTERN ficlWord *
ficlDictionaryAppendInstruction(ficlDictionary *dictionary, char *name,
    ficlInstruction i, ficlUnsigned8 flags);

FICL_PLATFORM_EXTERN ficlWord *
ficlDictionaryAppendConstantInstruction(ficlDictionary *dictionary,
    ficlString name, ficlInstruction instruction, ficlInteger value);
FICL_PLATFORM_EXTERN ficlWord *
ficlDictionaryAppend2ConstantInstruction(ficlDictionary *dictionary,
    ficlString name, ficlInstruction instruction, ficl2Integer value);

FICL_PLATFORM_EXTERN ficlWord *
ficlDictionaryAppendConstant(ficlDictionary *dictionary, char *name,
    ficlInteger value);
FICL_PLATFORM_EXTERN ficlWord *
ficlDictionaryAppend2Constant(ficlDictionary *dictionary, char *name,
    ficl2Integer value);
#define	ficlDictionaryAppendConstantPointer(dictionary, name, pointer)	\
	(ficlDictionaryAppendConstant(dictionary, name, (ficlInteger)pointer))
#if FICL_WANT_FLOAT
FICL_PLATFORM_EXTERN ficlWord *
ficlDictionaryAppendFConstant(ficlDictionary *dictionary, char *name,
    ficlFloat value);
FICL_PLATFORM_EXTERN ficlWord *
ficlDictionaryAppendF2Constant(ficlDictionary *dictionary, char *name,
    ficlFloat value);
#endif /* FICL_WANT_FLOAT */


FICL_PLATFORM_EXTERN ficlWord *
ficlDictionarySetConstantInstruction(ficlDictionary *dictionary,
    ficlString name, ficlInstruction instruction, ficlInteger value);
FICL_PLATFORM_EXTERN ficlWord *
ficlDictionarySet2ConstantInstruction(ficlDictionary *dictionary,
    ficlString name, ficlInstruction instruction, ficl2Integer value);

FICL_PLATFORM_EXTERN ficlWord *
ficlDictionarySetConstant(ficlDictionary *dictionary, char *name,
    ficlInteger value);
#define	ficlDictionarySetConstantPointer(dictionary, name, pointer) \
	(ficlDictionarySetConstant(dictionary, name, (ficlInteger)pointer))

FICL_PLATFORM_EXTERN ficlWord *
ficlDictionarySet2Constant(ficlDictionary *dictionary, char *name,
    ficl2Integer value);
FICL_PLATFORM_EXTERN ficlWord *
ficlDictionarySetConstantString(ficlDictionary *dictionary, char *name,
    char *value);
FICL_PLATFORM_EXTERN ficlWord *
ficlDictionarySetPrimitive(ficlDictionary *dictionary, char *name,
    ficlPrimitive code, ficlUnsigned8 flags);
FICL_PLATFORM_EXTERN ficlWord *
ficlDictionarySetInstruction(ficlDictionary *dictionary, char *name,
    ficlInstruction i, ficlUnsigned8 flags);
#if FICL_WANT_FLOAT
FICL_PLATFORM_EXTERN ficlWord *
ficlDictionarySetFConstant(ficlDictionary *dictionary, char *name,
    ficlFloat value);
FICL_PLATFORM_EXTERN ficlWord *
ficlDictionarySetF2Constant(ficlDictionary *dictionary, char *name,
    ficlFloat value);
#endif /* FICL_WANT_FLOAT */

FICL_PLATFORM_EXTERN int
ficlDictionaryCellsAvailable(ficlDictionary *dictionary);
FICL_PLATFORM_EXTERN int ficlDictionaryCellsUsed(ficlDictionary *dictionary);
FICL_PLATFORM_EXTERN ficlDictionary *
ficlDictionaryCreate(ficlSystem *system, unsigned nCELLS);
FICL_PLATFORM_EXTERN ficlDictionary *
ficlDictionaryCreateHashed(ficlSystem *system, unsigned nCells, unsigned nHash);
FICL_PLATFORM_EXTERN ficlHash *
ficlDictionaryCreateWordlist(ficlDictionary *dictionary, int nBuckets);
FICL_PLATFORM_EXTERN void ficlDictionaryDestroy(ficlDictionary *dictionary);
FICL_PLATFORM_EXTERN void
ficlDictionaryEmpty(ficlDictionary *dictionary, unsigned nHash);
FICL_PLATFORM_EXTERN int
ficlDictionaryIncludes(ficlDictionary *dictionary, void *p);
FICL_PLATFORM_EXTERN ficlWord *
ficlDictionaryLookup(ficlDictionary *dictionary, ficlString name);
FICL_PLATFORM_EXTERN void
ficlDictionaryResetSearchOrder(ficlDictionary *dictionary);
FICL_PLATFORM_EXTERN void
ficlDictionarySetFlags(ficlDictionary *dictionary, ficlUnsigned8 set);
FICL_PLATFORM_EXTERN void
ficlDictionaryClearFlags(ficlDictionary *dictionary, ficlUnsigned8 clear);
FICL_PLATFORM_EXTERN void
ficlDictionarySetImmediate(ficlDictionary *dictionary);
FICL_PLATFORM_EXTERN void
ficlDictionaryUnsmudge(ficlDictionary *dictionary);
FICL_PLATFORM_EXTERN ficlCell *ficlDictionaryWhere(ficlDictionary *dictionary);

FICL_PLATFORM_EXTERN int
ficlDictionaryIsAWord(ficlDictionary *dictionary, ficlWord *word);
FICL_PLATFORM_EXTERN void
ficlDictionarySee(ficlDictionary *dictionary, ficlWord *word,
    ficlCallback *callback);
FICL_PLATFORM_EXTERN ficlWord *
ficlDictionaryFindEnclosingWord(ficlDictionary *dictionary, ficlCell *cell);

/*
 * Stub function for dictionary access control - does nothing
 * by default, user can redefine to guarantee exclusive dictionary
 * access to a single thread for updates. All dictionary update code
 * must be bracketed as follows:
 * ficlLockDictionary(dictionary, FICL_TRUE); // any non-zero value will do
 * <code that updates dictionary>
 * ficlLockDictionary(dictionary, FICL_FALSE);
 *
 * Returns zero if successful, nonzero if unable to acquire lock
 * before timeout (optional - could also block forever)
 *
 * NOTE: this function must be implemented with lock counting
 * semantics: nested calls must behave properly.
 */
#if FICL_MULTITHREAD
FICL_PLATFORM_EXTERN int
	ficlDictionaryLock(ficlDictionary *dictionary, short lockIncrement);
#else
#define	ficlDictionaryLock(dictionary, lock) (void)0 /* ignore */
#endif

/*
 * P A R S E   S T E P
 * (New for 2.05)
 * See words.c: interpWord
 * By default, Ficl goes through two attempts to parse each token from its
 * input stream: it first attempts to match it with a word in the dictionary,
 * and if that fails, it attempts to convert it into a number. This mechanism
 * is now extensible by additional steps. This allows extensions like floating
 * point and double number support to be factored cleanly.
 *
 * Each parse step is a function that receives the next input token as a
 * STRINGINFO. If the parse step matches the token, it must apply semantics
 * to the token appropriate to the present value of VM.state (compiling or
 * interpreting), and return FICL_TRUE.
 * Otherwise it returns FICL_FALSE. See words.c: isNumber for an example
 *
 * Note: for the sake of efficiency, it's a good idea both to limit the number
 * of parse steps and to code each parse step so that it rejects tokens that
 * do not match as quickly as possible.
 */

typedef int (*ficlParseStep)(ficlVm *vm, ficlString s);

/*
 * FICL_BREAKPOINT record.
 * oldXT - if NULL, this breakpoint is unused. Otherwise it stores the xt
 * that the breakpoint overwrote. This is restored to the dictionary when the
 * BP executes or gets cleared
 * address - the location of the breakpoint (address of the instruction that
 *           has been replaced with the breakpoint trap
 * oldXT  - The original contents of the location with the breakpoint
 * Note: address is NULL when this breakpoint is empty
 */
typedef struct ficlBreakpoint
{
	void *address;
	ficlWord *oldXT;
} ficlBreakpoint;


/*
 * F I C L _ S Y S T E M
 * The top level data structure of the system - ficl_system ties a list of
 * virtual machines with their corresponding dictionaries. Ficl 3.0 added
 * support for multiple Ficl systems, allowing multiple concurrent sessions
 * to separate dictionaries with some constraints.
 * Note: the context pointer is there to provide context for applications.
 * It is copied to each VM's context field as that VM is created.
 */
struct ficlSystemInformation
{
    int size;			/* structure size tag for versioning */
		/* Initializes VM's context pointer - for application use */
    void *context;
    int dictionarySize;		/* Size of system's Dictionary, in cells */
    int stackSize;		/* Size of all stacks created, in cells */
    ficlOutputFunction textOut;		/* default textOut function */
    ficlOutputFunction errorOut;	/* textOut function used for errors */
    int environmentSize;	/* Size of Environment dictionary, in cells */
};

#define	ficlSystemInformationInitialize(x)	\
	{ memset((x), 0, sizeof (ficlSystemInformation)); \
	(x)->size = sizeof (ficlSystemInformation); }

struct ficlSystem
{
    ficlCallback callback;
    ficlSystem *link;
    ficlVm *vmList;
    ficlDictionary *dictionary;
    ficlDictionary *environment;

    ficlWord *interpreterLoop[3];
    ficlWord *parseList[FICL_MAX_PARSE_STEPS];

    ficlWord *exitInnerWord;
    ficlWord *interpretWord;

#if FICL_WANT_LOCALS
    ficlDictionary *locals;
    ficlInteger   localsCount;
    ficlCell *localsFixup;
#endif

    ficlInteger stackSize;

    ficlBreakpoint breakpoint;
};

#define	ficlSystemGetContext(system)	((system)->context)

/*
 * External interface to Ficl...
 */
/*
 * f i c l S y s t e m C r e a t e
 * Binds a global dictionary to the interpreter system and initializes
 * the dictionary to contain the ANSI CORE wordset.
 * You can specify the address and size of the allocated area.
 * You can also specify the text output function at creation time.
 * After that, Ficl manages it.
 * First step is to set up the static pointers to the area.
 * Then write the "precompiled" portion of the dictionary in.
 * The dictionary needs to be at least large enough to hold the
 * precompiled part. Try 1K cells minimum. Use "words" to find
 * out how much of the dictionary is used at any time.
 */
FICL_PLATFORM_EXTERN ficlSystem *ficlSystemCreate(ficlSystemInformation *fsi);

/*
 * f i c l S y s t e m D e s t r o y
 * Deletes the system dictionary and all virtual machines that
 * were created with ficlNewVM (see below). Call this function to
 * reclaim all memory used by the dictionary and VMs.
 */
FICL_PLATFORM_EXTERN void ficlSystemDestroy(ficlSystem *system);

/*
 * Create a new VM from the heap, and link it into the system VM list.
 * Initializes the VM and binds default sized stacks to it. Returns the
 * address of the VM, or NULL if an error occurs.
 * Precondition: successful execution of ficlInitSystem
 */
FICL_PLATFORM_EXTERN ficlVm   *ficlSystemCreateVm(ficlSystem *system);

/*
 * Force deletion of a VM. You do not need to do this
 * unless you're creating and discarding a lot of VMs.
 * For systems that use a constant pool of VMs for the life
 * of the system, ficltermSystem takes care of VM cleanup
 * automatically.
 */
FICL_PLATFORM_EXTERN void ficlSystemDestroyVm(ficlVm *vm);


/*
 * Returns the address of the most recently defined word in the system
 * dictionary with the given name, or NULL if no match.
 * Precondition: successful execution of ficlInitSystem
 */
FICL_PLATFORM_EXTERN ficlWord *ficlSystemLookup(ficlSystem *system, char *name);

/*
 * f i c l G e t D i c t
 * Utility function - returns the address of the system dictionary.
 * Precondition: successful execution of ficlInitSystem
 */
ficlDictionary *ficlSystemGetDictionary(ficlSystem *system);
ficlDictionary *ficlSystemGetEnvironment(ficlSystem *system);
#if FICL_WANT_LOCALS
ficlDictionary *ficlSystemGetLocals(ficlSystem *system);
#endif

/*
 * f i c l C o m p i l e C o r e
 * Builds the ANS CORE wordset into the dictionary - called by
 * ficlInitSystem - no need to waste dictionary space by doing it again.
 */
FICL_PLATFORM_EXTERN void ficlSystemCompileCore(ficlSystem *system);
FICL_PLATFORM_EXTERN void ficlSystemCompilePrefix(ficlSystem *system);
FICL_PLATFORM_EXTERN void ficlSystemCompileSearch(ficlSystem *system);
FICL_PLATFORM_EXTERN void ficlSystemCompileSoftCore(ficlSystem *system);
FICL_PLATFORM_EXTERN void ficlSystemCompileTools(ficlSystem *system);
FICL_PLATFORM_EXTERN void ficlSystemCompileFile(ficlSystem *system);
#if FICL_WANT_FLOAT
FICL_PLATFORM_EXTERN void ficlSystemCompileFloat(ficlSystem *system);
FICL_PLATFORM_EXTERN int ficlVmParseFloatNumber(ficlVm *vm, ficlString s);
#endif /* FICL_WANT_FLOAT */
#if FICL_WANT_PLATFORM
FICL_PLATFORM_EXTERN void ficlSystemCompilePlatform(ficlSystem *system);
#endif /* FICL_WANT_PLATFORM */
FICL_PLATFORM_EXTERN void ficlSystemCompileExtras(ficlSystem *system);


FICL_PLATFORM_EXTERN int ficlVmParsePrefix(ficlVm *vm, ficlString s);

#if FICL_WANT_LOCALS
FICL_PLATFORM_EXTERN ficlWord *ficlSystemLookupLocal(ficlSystem *system,
    ficlString name);
#endif

/*
 * from words.c...
 */
FICL_PLATFORM_EXTERN int ficlVmParseNumber(ficlVm *vm, ficlString s);
FICL_PLATFORM_EXTERN void ficlPrimitiveTick(ficlVm *vm);
FICL_PLATFORM_EXTERN void ficlPrimitiveParseStepParen(ficlVm *vm);
#if FICL_WANT_LOCALS
FICL_PLATFORM_EXTERN void ficlLocalParen(ficlVm *vm, int isDouble, int isFloat);
#endif /* FICL_WANT_LOCALS */

/*
 * Appends a parse step function to the end of the parse list (see
 * FICL_PARSE_STEP notes in ficl.h for details). Returns 0 if successful,
 * nonzero if there's no more room in the list. Each parse step is a word in
 * the dictionary. Precompiled parse steps can use (PARSE-STEP) as their
 * CFA - see parenParseStep in words.c.
 */
FICL_PLATFORM_EXTERN int ficlSystemAddParseStep(ficlSystem *system,
    ficlWord *word); /* ficl.c */
FICL_PLATFORM_EXTERN void ficlSystemAddPrimitiveParseStep(ficlSystem *system,
    char *name, ficlParseStep pStep);

/*
 * From tools.c
 */

/*
 * The following supports SEE and the debugger.
 */
typedef enum
{
    FICL_WORDKIND_BRANCH,
    FICL_WORDKIND_BRANCH0,
    FICL_WORDKIND_COLON,
    FICL_WORDKIND_CONSTANT,
    FICL_WORDKIND_2CONSTANT,
    FICL_WORDKIND_CREATE,
    FICL_WORDKIND_DO,
    FICL_WORDKIND_DOES,
    FICL_WORDKIND_LITERAL,
    FICL_WORDKIND_2LITERAL,
#if FICL_WANT_FLOAT
    FICL_WORDKIND_FLITERAL,
#endif /* FICL_WANT_FLOAT */
    FICL_WORDKIND_LOOP,
    FICL_WORDKIND_OF,
    FICL_WORDKIND_PLOOP,
    FICL_WORDKIND_PRIMITIVE,
    FICL_WORDKIND_QDO,
    FICL_WORDKIND_STRING_LITERAL,
    FICL_WORDKIND_CSTRING_LITERAL,
#if FICL_WANT_USER
    FICL_WORDKIND_USER,
#endif
    FICL_WORDKIND_VARIABLE,
    FICL_WORDKIND_INSTRUCTION,
    FICL_WORDKIND_INSTRUCTION_WORD,
    FICL_WORDKIND_INSTRUCTION_WITH_ARGUMENT
} ficlWordKind;

ficlWordKind   ficlWordClassify(ficlWord *word);

#if FICL_WANT_FILE
/*
 * Used with File-Access wordset.
 */
#define	FICL_FAM_READ	1
#define	FICL_FAM_WRITE	2
#define	FICL_FAM_APPEND	4
#define	FICL_FAM_BINARY	8

#define	FICL_FAM_OPEN_MODE(fam)	\
	((fam) & (FICL_FAM_READ | FICL_FAM_WRITE | FICL_FAM_APPEND))

typedef struct ficlFile
{
    FILE *f;
    char filename[256];
} ficlFile;

#if defined(FICL_PLATFORM_HAS_FTRUNCATE)
FICL_PLATFORM_EXTERN int ficlFileTruncate(ficlFile *ff, ficlUnsigned size);
#endif

FICL_PLATFORM_EXTERN int ficlFileStatus(char *filename, int *status);
FICL_PLATFORM_EXTERN long ficlFileSize(ficlFile *ff);
#endif

/* Support for linker set inclusions. */
#ifdef STAND
typedef void ficlCompileFcn(ficlSystem *);

#define	FICL_COMPILE_SET(func)  \
	DATA_SET(Xficl_compile_set, func)
SET_DECLARE(Xficl_compile_set, ficlCompileFcn);
#endif	/* STAND */

#ifdef __cplusplus
}
#endif

#endif /* _FICL_H */
