#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 * 
 * All rights reserved.
 * 
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <gssapiP_krb5.h>

/* from the token, flags is stored directly. nctypes/ctypes is
   allocated and returns the length and list of ctypes in the token.
   noptions/options lists all the options which the caller cares
   about.  Those which are present in the token are filled in; the
   order and length are not changed.  If an error is returned, the
   option list is in an indeterminate state. */

OM_uint32
kg2_parse_token(minor_status, ptr, token_length, flags, nctypes, ctypes,
		noptions, options, kmsg, mic)
     OM_uint32 *minor_status;
     unsigned char *ptr;
     int token_length;
     krb5_ui_4 *flags;
     int *nctypes; /* OUT */
     krb5_cksumtype **ctypes; /* OUT */
     int noptions; 
     struct kg2_option *options; /* INOUT */
     krb5_data *kmsg;
     krb5_data *mic;
{
    int field_length, i;
    int opt_id;

    *ctypes = 0;

    /* read the flags */

    if (token_length < 4)
	goto defective;
    *flags = (ptr[0]<<24) | (ptr[1]<<16) | (ptr[2]<<8) | ptr[3];
    ptr += 4;
    token_length -= 4;

    /* read out the token list */

    if (token_length < 2)
	goto defective;
    field_length = (ptr[0]<<8) | ptr[1];
    ptr += 2;
    token_length -= 2;

    *nctypes = field_length;

    if (*nctypes == 0) {
	*minor_status = 0;
	return(GSS_S_DEFECTIVE_TOKEN);
    }

    if ((*ctypes = (krb5_cksumtype *)
	 malloc((*nctypes) * sizeof(krb5_cksumtype))) == NULL) {
	*minor_status = ENOMEM;
	return(GSS_S_FAILURE);
    }

    for (i=0; i<field_length; i++) {
	if (token_length < 4)
	    goto defective;

	(*ctypes)[i] = (krb5_cksumtype) ((ptr[0]<<24) | (ptr[1]<<16) |
				      (ptr[2]<<8) | ptr[3]);
	ptr += 4;
	token_length -= 4;
    }

    do {
	if (token_length < 4)
	    goto defective;
	opt_id = (ptr[0]<<8) | ptr[1];
	field_length = (ptr[2]<<8) | ptr[3];
	ptr += 4;
	token_length -= 4;

	if (token_length < field_length)
	    goto defective;

	for (i=0; i<noptions; i++) {
	    if (options[i].option_id = opt_id) {
		options[i].length = field_length;
		options[i].data = ptr;
	    	break;
	    }
	}
	    
	ptr += field_length;
	token_length -= field_length;
    } while (opt_id);

    if (token_length < 2)
	goto defective;
    field_length = (ptr[0]<<8) | ptr[1];
    ptr += 2;
    token_length -= 2;

    if (token_length < field_length)
	goto defective;

    kmsg->length = field_length;
    kmsg->data = (char *) ptr;

    ptr += field_length;
    token_length -= field_length;

    /* if there's anything left, assume it's a mic.  the mic isn't
       necessarily present */

    if (mic && token_length) {
	if (token_length < 2)
	    goto defective;
	field_length = (ptr[0]<<8) | ptr[1];
	ptr += 2;
	token_length -= 2;

	if (token_length < field_length)
	    goto defective;

	mic->length = field_length;
	mic->data = (char *) ptr;

	ptr += field_length;
	token_length -= field_length;
    } else if (mic) {
	mic->length = 0;
	mic->data = (char *) ptr;
    }

    if (token_length)
	goto defective;

    return(GSS_S_COMPLETE);

defective:
    if (*ctypes)
	free(*ctypes);

    *minor_status = 0;
    return(GSS_S_DEFECTIVE_TOKEN);
}
    
/* nc1/c1 will be modified to contain the intersection of the
   two lists. */

void
kg2_intersect_ctypes(nc1, c1, nc2, c2)
     int *nc1;
     krb5_cksumtype *c1;
     int nc2;
     const krb5_cksumtype *c2;
{
    int i, j, count;
    krb5_cksumtype tmp;

    count = 0;

    for (i=0; i<*nc1; i++) {
	/* first, check to make sure that c1[i] isn't a duplicate in c1 */
	for (j=0; j<i; j++)
	    if (c1[i] == c1[j])
		break;
	if (j<i)
	    continue;
	/* check if c1[i] is in c2.  If it is, keep it by swapping
	   it into c1[count] and incrementing count.  If count < i, then
	   that field has already been looked at and skipped as
	   not intersecting, which is ok. */

	for (j=0; j<nc2; j++)
	    if (c1[i] == c2[j])
		break;
	if ((j<nc2) && (count != i)) {
	    tmp = c1[count];
	    c1[count] = c1[i];
	    c1[i] = tmp;
	}
	count++;
    }

    *nc1 = count;
}

