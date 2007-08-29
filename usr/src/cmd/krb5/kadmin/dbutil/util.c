#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 *	Openvision retains the copyright to derivative works of
 *	this source code.  Do *NOT* create a derivative of this
 *	source code before consulting with your legal department.
 *	Do *NOT* integrate *ANY* of this source code into another
 *	product before consulting with your legal department.
 *
 *	For further information, read the top-level Openvision
 *	copyright which is contained in the top-level MIT Kerberos
 *	copyright.
 *
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 */


/*
 * admin/edit/util.c
 *
 * Copyright 1992 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * Utilities for kdb5_edit.
 * 
 * Some routines derived from code contributed by the Sandia National
 * Laboratories.  Sandia National Laboratories also makes no
 * representations about the suitability of the modifications, or
 * additions to this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 * 
 */

#include <k5-int.h>
#include "./kdb5_edit.h"

#ifndef HAVE_STRSTR
char *
strstr(s1, s2)
char *s1;
char *s2;
{
   int s2len;
   int i;
   char *temp_ptr;

   temp_ptr = s1;
   for ( i = 0; i < strlen(s1); i++) {
        if (memcmp(temp_ptr, s2, strlen(s2)) == 0) return(temp_ptr);
        temp_ptr += 1;
   }
   return ((char *) 0);
}
#endif	/* HAVE_STRSTR */

void
parse_token(token_in, must_be_first_char, num_tokens, tokens_out)
char *token_in;
int  *must_be_first_char;
int  *num_tokens;
char *tokens_out;
{
    int i, j;
    int token_count = 0;

    i = 0;
    j = 0;

	/* Eliminate Up Front Asterisks */
    *must_be_first_char = 1;
    for (i = 0; token_in[i] == '*'; i++) {
	*must_be_first_char = 0;
    }

    if (i == strlen(token_in)) {
	*num_tokens = 0;
	return;
    }

	/* Fill first token_out */
    token_count++;
    while ((token_in[i] != '*') && (token_in[i] != '\0')) {
	tokens_out[j] = token_in[i];
        j++;
	i++;
    }

    if (i == strlen(token_in)) {
	tokens_out[j] = '\0';
	*num_tokens = token_count;
	return;
    }

	/* Then All Subsequent Tokens */
    while (i < strlen(token_in)) {
	if (token_in[i] == '*') {
	   token_count++;
	   tokens_out[j] = '\t';
	} else {
	   tokens_out[j] = token_in[i];
	}
	i++;
	j++;
    }
    tokens_out[j] = '\0';

    if (tokens_out[j - 1] == '\t') {
	token_count--;
	tokens_out[j - 1] = '\0';
    }

    *num_tokens = token_count;
    return;
}

int
check_for_match(search_field, must_be_first_character, chk_entry, 
		num_tokens, type)
int must_be_first_character;
char *search_field;
krb5_db_entry *chk_entry;
int num_tokens;
int type;
{
    char token1[256];
    char *found1;
    char token2[256];
    char *found2;
    char token3[256];
    char *found3;
    char *local_entry;

    local_entry = chk_entry->princ->data[type].data;

    token1[0] = token2[0] = token3[0] = '\0';

    (void) sscanf(search_field, "%s\t%s\t%s", token1, token2, token3);

    found1 = strstr(local_entry, token1);

    if (must_be_first_character && (found1 != local_entry)) return(0);

    if (found1 && (num_tokens == 1)) return(1);

    if (found1 && (num_tokens > 1)) {
	found2 = strstr(local_entry, token2);
	if (found2 && (found2 > found1) && (num_tokens == 2)) return(1);
    }

    if ((found2 > found1) && (num_tokens == 3)) {
	found3 = strstr(local_entry, token3);
       	if (found3 && (found3 > found2) && (found2 > found1)) return(1);
    }
    return(0);
}

