#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * include/cm.h
 *
 * Copyright 2002 by the Massachusetts Institute of Technology.
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
 */

struct select_state {
    int max, nfds;
    fd_set rfds, wfds, xfds;
    struct timeval end_time;	/* magic: tv_sec==0 => never time out */
};

/* Select state flags.  */
#define SSF_READ	0x01
#define SSF_WRITE	0x02
#define SSF_EXCEPTION	0x04

krb5_error_code krb5int_cm_call_select (const struct select_state *,
					struct select_state *, int *);
