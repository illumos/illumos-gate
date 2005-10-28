/*
 * lib/krb5/ccache/file/fcc-proto.h
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
 * Prototypes for File-based credentials cache
 */


#ifndef KRB5_FCC_PROTO__
#define KRB5_FCC_PROTO__

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* fcc_close.c */
KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_close
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id ));

/* fcc_defnam.c */
char * krb5_fcc_default_name 
        KRB5_PROTOTYPE((krb5_context));

/* fcc_destry.c */
KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_destroy 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id ));

/* fcc_eseq.c */
KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_end_seq_get 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_cc_cursor *cursor ));

/* fcc_gennew.c */
KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_generate_new 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache *id ));

/* fcc_getnam.c */
KRB5_DLLIMP char * KRB5_CALLCONV krb5_fcc_get_name 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id ));

/* fcc_gprin.c */
KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_get_principal 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_principal *princ ));

/* fcc_init.c */
KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_initialize 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_principal princ ));

/* fcc_nseq.c */
KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_next_cred 
        KRB5_PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_cc_cursor *cursor , 
		   krb5_creds *creds ));

/* fcc_read.c */
krb5_error_code krb5_fcc_read
        KRB5_PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_pointer buf,
		   int len));
krb5_error_code krb5_fcc_read_principal 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_principal *princ ));
krb5_error_code krb5_fcc_read_keyblock 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_keyblock *keyblock ));
krb5_error_code krb5_fcc_read_data 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_data *data ));
krb5_error_code krb5_fcc_read_int32 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_int32 *i ));
krb5_error_code krb5_fcc_read_ui_2 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_ui_2 *i ));
krb5_error_code krb5_fcc_read_octet 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_octet *i ));
krb5_error_code krb5_fcc_read_times 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_ticket_times *t ));
krb5_error_code krb5_fcc_read_addrs 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache, krb5_address ***));
krb5_error_code krb5_fcc_read_addr 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache, krb5_address *));
krb5_error_code krb5_fcc_read_authdata 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache , krb5_authdata ***));
krb5_error_code krb5_fcc_read_authdatum 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache , krb5_authdata *));

/* fcc_reslv.c */
KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_resolve 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache *id , const char *residual ));

/* fcc_retrv.c */
KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_retrieve 
        KRB5_PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_flags whichfields , 
		   krb5_creds *mcreds , 
		   krb5_creds *creds ));

/* fcc_sseq.c */
KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_start_seq_get 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_cc_cursor *cursor ));

/* fcc_store.c */
KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_store 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_creds *creds ));

/* fcc_skip.c */
krb5_error_code krb5_fcc_skip_header
        KRB5_PROTOTYPE((krb5_context, krb5_ccache));
krb5_error_code krb5_fcc_skip_principal 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id ));

/* fcc_sflags.c */
KRB5_DLLIMP krb5_error_code KRB5_CALLCONV krb5_fcc_set_flags 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_flags flags ));

/* fcc_ops.c */
KRB5_DLLIMP extern krb5_cc_ops krb5_cc_file_ops;
krb5_error_code krb5_change_cache
   KRB5_PROTOTYPE((void));


/* fcc_write.c */
krb5_error_code krb5_fcc_write 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_pointer buf , int len ));
krb5_error_code krb5_fcc_store_principal 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_principal princ ));
krb5_error_code krb5_fcc_store_keyblock 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_keyblock *keyblock ));
krb5_error_code krb5_fcc_store_data 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_data *data ));
krb5_error_code krb5_fcc_store_int32 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_int32 i ));
krb5_error_code krb5_fcc_store_ui_2 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_int32 i ));
krb5_error_code krb5_fcc_store_octet 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_int32 i ));
krb5_error_code krb5_fcc_store_times 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache id , krb5_ticket_times *t ));
krb5_error_code krb5_fcc_store_addrs 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache , krb5_address ** ));
krb5_error_code krb5_fcc_store_addr 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache , krb5_address * ));
krb5_error_code krb5_fcc_store_authdata 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache , krb5_authdata **));
krb5_error_code krb5_fcc_store_authdatum 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache , krb5_authdata *));

/* fcc_errs.c */
krb5_error_code krb5_fcc_interpret 
        KRB5_PROTOTYPE((krb5_context, int ));

/* fcc_maybe.c */
krb5_error_code krb5_fcc_close_file 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache));
krb5_error_code krb5_fcc_open_file 
        KRB5_PROTOTYPE((krb5_context, krb5_ccache, int));

#endif /* KRB5_FCC_PROTO__ */
