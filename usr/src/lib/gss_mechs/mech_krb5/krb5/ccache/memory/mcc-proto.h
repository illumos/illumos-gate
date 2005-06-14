/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * lib/krb5/ccache/memory/mcc-proto.h
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
 * Prototypes for Memory-based credentials cache
 */


#ifndef KRB5_MCC_PROTO__
#define KRB5_MCC_PROTO__

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* mcc_close.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_close
	PROTOTYPE((krb5_context, krb5_ccache id ));

/* mcc_destry.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_destroy 
	PROTOTYPE((krb5_context, krb5_ccache id ));

/* mcc_eseq.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_end_seq_get 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_cc_cursor *cursor ));

/* mcc_gennew.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_generate_new 
	PROTOTYPE((krb5_context, krb5_ccache *id ));

/* mcc_getnam.c */
char * KRB5_CALLCONV krb5_mcc_get_name 
	PROTOTYPE((krb5_context, krb5_ccache id ));

/* mcc_gprin.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_get_principal 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_principal *princ ));

/* mcc_init.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_initialize 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_principal princ ));

/* mcc_nseq.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_next_cred 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_cc_cursor *cursor , 
		   krb5_creds *creds ));

/* mcc_reslv.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_resolve 
	PROTOTYPE((krb5_context, krb5_ccache *id , const char *residual ));

/* mcc_retrv.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_retrieve 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_flags whichfields , 
		   krb5_creds *mcreds , 
		   krb5_creds *creds ));

/* mcc_sseq.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_start_seq_get 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_cc_cursor *cursor ));

/* mcc_store.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_store 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_creds *creds ));

/* mcc_sflags.c */
krb5_error_code KRB5_CALLCONV krb5_mcc_set_flags 
	PROTOTYPE((krb5_context, krb5_ccache id , krb5_flags flags ));

/* mcc_ops.c */
extern krb5_cc_ops krb5_mcc_ops;
krb5_error_code krb5_change_cache
   PROTOTYPE(());
#endif /* KRB5_MCC_PROTO__ */
