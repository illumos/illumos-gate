/*
 * lib/krb5/os/osconfig.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * Definition of default configuration parameters.
 *
 * ***** WARNING *****
 * These globals are internal library interfaces and are not
 * supported.  Do not use them in any production code, as they will be
 * removed from the library in the future.
 */

#include "k5-int.h"

char *krb5_defkeyname  = DEFAULT_KEYTAB_NAME;

unsigned int krb5_max_dgram_size = MAX_DGRAM_SIZE;
unsigned int krb5_max_skdc_timeout = MAX_SKDC_TIMEOUT;
unsigned int krb5_skdc_timeout_shift = SKDC_TIMEOUT_SHIFT;
unsigned int krb5_skdc_timeout_1 = SKDC_TIMEOUT_1;

char *krb5_default_pwd_prompt1 = DEFAULT_PWD_STRING1;
char *krb5_default_pwd_prompt2 = DEFAULT_PWD_STRING2;

