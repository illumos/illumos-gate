/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * lib/krb5/keytab/file/ktfile.h
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
 * This header file contains information needed by internal routines
 * of the file-based ticket cache implementation.
 */

#ifndef	_KRB5_KTFILE
#define	_KRB5_KTFILE

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/mman.h>

/*
 * Constants
 */
#define IGNORE_VNO 0
#define IGNORE_ENCTYPE 0

#define KRB5_KT_VNO_1	0x0501	/* krb v5, keytab version 1 (DCE compat) */
#define KRB5_KT_VNO	0x0502	/* krb v5, keytab version 2 (standard)  */

#define KRB5_KT_DEFAULT_VNO KRB5_KT_VNO

/* 
 * Types
 */
typedef struct _krb5_ktfile_data {
    char *name;			/* Name of the file */
    char *datap;		/* ptr to the file data */
    int	version;		/* Version number of keytab */
    offset_t offset;		/* current offset into the data buffer */
    size_t filesize;		/* size of original file */
    size_t bufsize;		/* total size of data buffer */
    uchar_t writable:1;		/* Was the file opened for writing? */
} krb5_ktfile_data;

/*
 * Macros
 */
#define KTPRIVATE(id) ((krb5_ktfile_data *)(id)->data)
#define KTFILENAME(id) (((krb5_ktfile_data *)(id)->data)->name)
/*
#define KTFILEP(id) (((krb5_ktfile_data *)(id)->data)->openf)
*/
#define	KTDATAP(id) (((krb5_ktfile_data *)(id)->data)->datap)
#define KTVERSION(id) (((krb5_ktfile_data *)(id)->data)->version)
#define	KTOFFSET(id) (((krb5_ktfile_data *)(id)->data)->offset)

extern struct _krb5_kt_ops krb5_ktf_ops;
extern struct _krb5_kt_ops krb5_ktf_writable_ops;

krb5_error_code KRB5_CALLCONV krb5_ktfile_resolve 
	(krb5_context,
		   const char *,
		   krb5_keytab *);

krb5_error_code KRB5_CALLCONV krb5_ktfile_wresolve 
	(krb5_context,
		   const char *,
		   krb5_keytab *);

krb5_error_code KRB5_CALLCONV krb5_ktfile_get_name 
	(krb5_context,
		   krb5_keytab,
		   char *,
		   int);

krb5_error_code KRB5_CALLCONV krb5_ktfile_close 
	(krb5_context,
		   krb5_keytab);

krb5_error_code KRB5_CALLCONV krb5_ktfile_get_entry 
	(krb5_context,
		   krb5_keytab,
		   krb5_const_principal,
		   krb5_kvno,
		   krb5_enctype,
		   krb5_keytab_entry *);

krb5_error_code KRB5_CALLCONV krb5_ktfile_start_seq_get 
	(krb5_context,
		   krb5_keytab,
		   krb5_kt_cursor *);

krb5_error_code KRB5_CALLCONV krb5_ktfile_get_next 
	(krb5_context,
		   krb5_keytab,
		   krb5_keytab_entry *,
		   krb5_kt_cursor *);

krb5_error_code KRB5_CALLCONV krb5_ktfile_end_get 
	(krb5_context,
		   krb5_keytab,
		   krb5_kt_cursor *);

/* routines to be included on extended version (write routines) */
krb5_error_code KRB5_CALLCONV krb5_ktfile_add 
	(krb5_context,
		   krb5_keytab,
		   krb5_keytab_entry *);

krb5_error_code KRB5_CALLCONV krb5_ktfile_remove 
	(krb5_context,
		   krb5_keytab,
		   krb5_keytab_entry *);

krb5_error_code krb5_ktfileint_openr 
	(krb5_context,
		   krb5_keytab);

krb5_error_code krb5_ktfileint_openw 
	(krb5_context,
		   krb5_keytab);

krb5_error_code krb5_ktfileint_close 
	(krb5_context,
		   krb5_keytab);

krb5_error_code krb5_ktfileint_read_entry 
	(krb5_context,
		   krb5_keytab,
		   krb5_keytab_entry *);

krb5_error_code krb5_ktfileint_write_entry 
	(krb5_context,
		   krb5_keytab,
		   krb5_keytab_entry *);

krb5_error_code krb5_ktfileint_delete_entry 
	(krb5_context,
		   krb5_keytab,
                   krb5_int32);

krb5_error_code krb5_ktfileint_internal_read_entry 
	(krb5_context,
		   krb5_keytab,
		   krb5_keytab_entry *,
                   krb5_int32 *);

krb5_error_code krb5_ktfileint_size_entry 
	(krb5_context,
		   krb5_keytab_entry *,
                   krb5_int32 *);

krb5_error_code krb5_ktfileint_find_slot 
	(krb5_context,
		   krb5_keytab,
                   krb5_int32 *,
                   krb5_int32 *);


#endif /* _KRB5_KTFILE */
