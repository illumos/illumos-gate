/*
 * lib/krb5/ccache/file/cc-int.h
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * This file contains constant and function declarations used in the
 * file-based credential cache routines.
 */

#ifndef __KRB5_CCACHE_H__
#define __KRB5_CCACHE_H__

#include "k5-int.h"

krb5_boolean
krb5int_cc_creds_match_request(krb5_context, krb5_flags whichfields, krb5_creds *mcreds, krb5_creds *creds);

int
krb5int_cc_initialize(void);

void
krb5int_cc_finalize(void);

extern k5_mutex_t krb5int_mcc_mutex;
extern k5_mutex_t krb5int_krcc_mutex;
extern k5_mutex_t krb5int_cc_file_mutex;

#endif /* __KRB5_CCACHE_H__ */
