/*
 *	'\\' has a special meaning on phase 2 if and only if it is immediately
 * followed by '\n'.  In any other position it's left alone as any other
 * character.
 *
 * [5.1.1.2(1.2)]:
 *   Each instance of a backslash character (\) immediately followed by
 *   a new-line character is deleted, splicing physical source lines to
 *   form logical source lines.  Only the last backslash on any physical
 *   source line shall be eligible for being part of such a splice.
 *   A source file that is not empty shall end in a new-line character,
 *   which shall not be immediately preceded by a backslash character
 *   before any such splicing takes place.
 *
 * Note that this happens on the phase 2, before we even think of any
 * tokens.  In other words, splicing is ignorant of and transparent for
 * the rest of tokenizer.
 */

/*
 * check-name: phase2-backslash
 * check-command: sparse -E $file
 *
 * check-output-start

"\a"
1
D
'\a'
 * check-output-end
 *
 * check-error-start
preprocessor/phase2-backslash.c:68:0: warning: backslash-newline at end of file
 * check-error-end
 */

#define A(x) #x
#define B(x) A(x)
/* This should result in "\a" */
B(\a)

#define C\
 1
/* This should give 1 */
C

#define D\
1
/* And this should give D, since '\n' is removed and we get no whitespace */
D

#define E '\\
a'
/* This should give '\a' - with no warnings issued */
E

/* This should give nothing */
// junk \
more junk

/* This should also give nothing */
/\
* comment *\
/

/* And this should complain since final newline should not be eaten by '\\' */
\
