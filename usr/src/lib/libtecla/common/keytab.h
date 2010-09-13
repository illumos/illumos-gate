#ifndef keytab_h
#define keytab_h

/*
 * Copyright (c) 2000, 2001, 2002, 2003, 2004 by Martin C. Shepherd.
 * 
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, and/or sell copies of the Software, and to permit persons
 * to whom the Software is furnished to do so, provided that the above
 * copyright notice(s) and this permission notice appear in all copies of
 * the Software and that both the above copyright notice(s) and this
 * permission notice appear in supporting documentation.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
 * OF THIRD PARTY RIGHTS. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * HOLDERS INCLUDED IN THIS NOTICE BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL
 * INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 * Except as contained in this notice, the name of a copyright holder
 * shall not be used in advertising or otherwise to promote the sale, use
 * or other dealings in this Software without prior written authorization
 * of the copyright holder.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "libtecla.h"

/*-----------------------------------------------------------------------*
 * This module defines a binary-search symbol table of key-bindings.     *
 *-----------------------------------------------------------------------*/

/*
 * All key-binding functions are defined as follows.
 *
 * Input:
 *  gl    GetLine *  The resource object of this library.
 *  count     int    A positive repeat count specified by the user,
 *                   or 1. Action functions should ignore this if
 *                   repeating the action multiple times isn't
 *                   appropriate.
 *  data     void *  A pointer to action-specific data,
 *                   cast to (void *).
 * Output:
 *  return    int    0 - OK.
 *                   1 - Error.
 */
#define KT_KEY_FN(fn) int (fn)(GetLine *gl, int count, void *data)

typedef KT_KEY_FN(KtKeyFn);

/*
 * Allow the association of arbitrary callback data with each action
 * function.
 */
typedef struct {
  KtKeyFn *fn;          /* The acion function */
  void *data;           /* A pointer to arbitrary data to be passed to */
                        /*  fn() whenever it is called. */
} KtAction;

/*
 * Enumerate the possible sources of key-bindings in order of decreasing
 * priority.
 */
typedef enum {
  KTB_USER,         /* This is a binding being set by the user */
  KTB_NORM,         /* This is the default binding set by the library */
  KTB_TERM,         /* This is a binding taken from the terminal settings */
/* The following entry must always be last */
  KTB_NBIND         /* The number of binding sources listed above */
} KtBinder;

/*
 * Define an entry of a key-binding binary symbol table.
 */
typedef struct {
  char *keyseq;                /* The key sequence that triggers the macro */
  int nc;                      /* The number of characters in keyseq[] */
  KtAction actions[KTB_NBIND]; /* Bindings from different sources */
  int binder;                  /* The index of the highest priority element */
                               /*  of actions[] that has been assigned an */
                               /*  action function, or -1 if none have. */
} KeySym;

/*
 * Provide an opaque type alias to the symbol table container.
 */
typedef struct KeyTab KeyTab;

/*
 * Create a new symbol table.
 */
KeyTab *_new_KeyTab(void);

/*
 * Delete the symbol table.
 */
KeyTab *_del_KeyTab(KeyTab *kt);

int _kt_set_keybinding(KeyTab *kt, KtBinder binder,
		       const char *keyseq, const char *action);
int _kt_set_keyfn(KeyTab *kt, KtBinder binder, const char *keyseq,
		  KtKeyFn *fn, void *data);

int _kt_set_action(KeyTab *kt, const char *action, KtKeyFn *fn, void *data);

/*
 * Lookup the function that implements a given action.
 */
int _kt_lookup_action(KeyTab *kt, const char *action,
		      KtKeyFn **fn, void **data);

typedef enum {
  KT_EXACT_MATCH,   /* An exact match was found */
  KT_AMBIG_MATCH,   /* An ambiguous match was found */
  KT_NO_MATCH,      /* No match was found */
  KT_BAD_MATCH      /* An error occurred while searching */
} KtKeyMatch;

KtKeyMatch _kt_lookup_keybinding(KeyTab *kt, const char *binary_keyseq,
				 int nc, KeySym **matches, int *nmatch);

/*
 * Remove all key bindings that came from a specified source.
 */
void _kt_clear_bindings(KeyTab *kt, KtBinder binder);

/*
 * When installing an array of keybings each binding is defined by
 * an element of the following type:
 */
typedef struct {
  const char *keyseq;   /* The sequence of keys that trigger this binding */
  const char *action;   /* The name of the action function that is triggered */
} KtKeyBinding;

/*
 * Merge an array of bindings with existing bindings.
 */
int _kt_add_bindings(KeyTab *kt, KtBinder binder, const KtKeyBinding *bindings,
		     unsigned n);

/*
 * Get information about the last error in this module.
 */
const char *_kt_last_error(KeyTab *kt);

#endif
