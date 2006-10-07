/*
 * kadmin/passwd/kpasswd.h
 *
 * Copyright 2001 by the Massachusetts Institute of Technology.
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
 *
 * Prototypes for the kpasswd program callback functions.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#ifndef __KPASSWD_H__
#define __KPASSWD_H__

int kpasswd(krb5_context context, int argc, char *argv[]);

long read_old_password(krb5_context context, char *password, 
		       unsigned int *pwsize);

long read_new_password(void *server_handle, char *password, 
		       unsigned int *pwsize, char *msg_ret, 
		       int msg_len, krb5_principal princ);

void display_intro_message(const char *fmt_string, const char *arg_string);

#endif /* __KPASSWD_H__ */


