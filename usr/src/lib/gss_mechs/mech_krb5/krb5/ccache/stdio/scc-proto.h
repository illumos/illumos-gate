/*
 * lib/krb5/ccache/stdio/scc-proto.h
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


#ifndef KRB5_SCC_PROTO__
#define KRB5_SCC_PROTO__

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* scc_close.c */
krb5_error_code krb5_scc_close 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id ));

/* scc_defnam.c */
char *krb5_scc_default_name 
	PROTOTYPE((krb5_context));

/* scc_destry.c */
krb5_error_code krb5_scc_destroy 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id ));

/* scc_eseq.c */
krb5_error_code krb5_scc_end_seq_get 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_cc_cursor *cursor ));

/* scc_gennew.c */
krb5_error_code krb5_scc_generate_new 
	PROTOTYPE((krb5_context, 
		   krb5_ccache *id ));

/* scc_getnam.c */
char *krb5_scc_get_name 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id ));

/* scc_gprin.c */
krb5_error_code krb5_scc_get_principal 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_principal *princ ));

/* scc_init.c */
krb5_error_code krb5_scc_initialize 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_principal princ ));

/* scc_maybe.c */
krb5_error_code krb5_scc_close_file 
	PROTOTYPE((krb5_context, 
		   krb5_ccache));
krb5_error_code krb5_scc_open_file 
	PROTOTYPE((krb5_context, 
		   krb5_ccache,
		   int));

/* scc_nseq.c */
krb5_error_code krb5_scc_next_cred 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_cc_cursor *cursor , 
		   krb5_creds *creds ));

/* scc_read.c */
krb5_error_code krb5_scc_read
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_pointer buf,
		   int len));
krb5_error_code krb5_scc_read_principal 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_principal *princ ));
krb5_error_code krb5_scc_read_keyblock 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_keyblock *keyblock ));
krb5_error_code krb5_scc_read_data 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_data *data ));
krb5_error_code krb5_scc_read_int32 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_int32 *i ));
krb5_error_code krb5_scc_read_ui_2 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_ui_2 *i ));
krb5_error_code krb5_scc_read_octet 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_octet *i ));
krb5_error_code krb5_scc_read_times 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_ticket_times *t ));
krb5_error_code krb5_scc_read_addrs 
	PROTOTYPE((krb5_context, 
		   krb5_ccache, 
		   krb5_address ***));
krb5_error_code krb5_scc_read_addr 
	PROTOTYPE((krb5_context, 
		   krb5_ccache, 
		   krb5_address *));
krb5_error_code krb5_scc_read_authdata 
	PROTOTYPE((krb5_context, 
		   krb5_ccache, 
		   krb5_authdata***));
krb5_error_code krb5_scc_read_authdatum 
	PROTOTYPE((krb5_context, 
		   krb5_ccache, 
		   krb5_authdata*));

/* scc_reslv.c */
krb5_error_code krb5_scc_resolve 
	PROTOTYPE((krb5_context, 
		   krb5_ccache *id , 
		   const char *residual ));

/* scc_retrv.c */
krb5_error_code krb5_scc_retrieve 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_flags whichfields , 
		   krb5_creds *mcreds , 
		   krb5_creds *creds ));

/* scc_sseq.c */
krb5_error_code krb5_scc_start_seq_get 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_cc_cursor *cursor ));

/* scc_store.c */
krb5_error_code krb5_scc_store 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_creds *creds ));

/* scc_skip.c */
krb5_error_code krb5_scc_skip_header
	PROTOTYPE((krb5_context, krb5_ccache));
krb5_error_code krb5_scc_skip_principal 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id ));

/* scc_sflags.c */
krb5_error_code krb5_scc_set_flags 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_flags flags ));

/* scc_ops.c */
extern krb5_cc_ops krb5_scc_ops;

/* scc_write.c */
krb5_error_code krb5_scc_write 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_pointer buf , 
		   int len ));
krb5_error_code krb5_scc_store_principal 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_principal princ ));
krb5_error_code krb5_scc_store_keyblock 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_keyblock *keyblock ));
krb5_error_code krb5_scc_store_data 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_data *data ));
krb5_error_code krb5_scc_store_int32 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_int32 i ));
krb5_error_code krb5_scc_store_ui_2 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_int32 i ));
krb5_error_code krb5_scc_store_octet 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_int32 i ));
krb5_error_code krb5_scc_store_times 
	PROTOTYPE((krb5_context, 
		   krb5_ccache id , 
		   krb5_ticket_times *t ));
krb5_error_code krb5_scc_store_addrs 
	PROTOTYPE((krb5_context, 
		   krb5_ccache , 
		   krb5_address ** ));
krb5_error_code krb5_scc_store_addr 
	PROTOTYPE((krb5_context, 
		   krb5_ccache , 
		   krb5_address * ));
krb5_error_code krb5_scc_store_authdata 
	PROTOTYPE((krb5_context, 
		   krb5_ccache, 
		   krb5_authdata **));
krb5_error_code krb5_scc_store_authdatum 
	PROTOTYPE((krb5_context, 
		   krb5_ccache, 
		   krb5_authdata *));

/* scc_errs.c */
krb5_error_code krb5_scc_interpret 
	PROTOTYPE((krb5_context, 
		   int ));

#endif /* KRB5_SCC_PROTO__ */
