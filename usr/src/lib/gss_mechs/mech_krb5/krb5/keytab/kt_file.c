/*
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * lib/krb5/keytab/kt_file.c
 *
 * Copyright 1990,1991,1995 by the Massachusetts Institute of Technology.
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
 */

#include "k5-int.h"
#include <stdio.h>
#include <locale.h>
#include <syslog.h>

/*
 * Information needed by internal routines of the file-based ticket
 * cache implementation.
 */


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
    FILE *openf;		/* open file, if any. */
    char iobuf[BUFSIZ];		/* so we can zap it later */
    int	version;		/* Version number of keytab */
    k5_mutex_t lock;		/* Protect openf, version */
} krb5_ktfile_data;

/*
 * Macros
 */
#define KTPRIVATE(id) ((krb5_ktfile_data *)(id)->data)
#define KTFILENAME(id) (((krb5_ktfile_data *)(id)->data)->name)
#define KTFILEP(id) (((krb5_ktfile_data *)(id)->data)->openf)
#define KTFILEBUFP(id) (((krb5_ktfile_data *)(id)->data)->iobuf)
#define KTVERSION(id) (((krb5_ktfile_data *)(id)->data)->version)
#define KTLOCK(id) k5_mutex_lock(&((krb5_ktfile_data *)(id)->data)->lock)
#define KTUNLOCK(id) k5_mutex_unlock(&((krb5_ktfile_data *)(id)->data)->lock)
#define KTCHECKLOCK(id) k5_mutex_assert_locked(&((krb5_ktfile_data *)(id)->data)->lock)

extern const struct _krb5_kt_ops krb5_ktf_ops;
extern const struct _krb5_kt_ops krb5_ktf_writable_ops;

extern krb5_boolean KRB5_CALLCONV
__krb5_principal_compare_case_ins(krb5_context context,
    krb5_const_principal princ1, krb5_const_principal princ2);

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
		   unsigned int);

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


/*
 * This is an implementation specific resolver.  It returns a keytab id
 * initialized with file keytab routines.
 */

krb5_error_code KRB5_CALLCONV
krb5_ktfile_resolve(krb5_context context, const char *name, krb5_keytab *id)
{
    krb5_ktfile_data *data;
    krb5_error_code err;

    if ((*id = (krb5_keytab) malloc(sizeof(**id))) == NULL)
	return(ENOMEM);

    (*id)->ops = &krb5_ktf_ops;
    if ((data = (krb5_ktfile_data *)malloc(sizeof(krb5_ktfile_data))) == NULL) {
	krb5_xfree(*id);
	return(ENOMEM);
    }

    err = k5_mutex_init(&data->lock);
    if (err) {
	krb5_xfree(data);
	krb5_xfree(*id);
	return err;
    }

    if ((data->name = (char *)calloc(strlen(name) + 1, sizeof(char))) == NULL) {
	k5_mutex_destroy(&data->lock);
	krb5_xfree(data);
	krb5_xfree(*id);
	return(ENOMEM);
    }

    (void) strcpy(data->name, name);
    data->openf = 0;
    data->version = 0;

    (*id)->data = (krb5_pointer)data;
    (*id)->magic = KV5M_KEYTAB;
    return(0);
}


/*
 * "Close" a file-based keytab and invalidate the id.  This means
 * free memory hidden in the structures.
 */

krb5_error_code KRB5_CALLCONV
krb5_ktfile_close(krb5_context context, krb5_keytab id)
  /*
   * This routine is responsible for freeing all memory allocated
   * for this keytab.  There are no system resources that need
   * to be freed nor are there any open files.
   *
   * This routine should undo anything done by krb5_ktfile_resolve().
   */
{
    krb5_xfree(KTFILENAME(id));
    zap(KTFILEBUFP(id), BUFSIZ);
    k5_mutex_destroy(&((krb5_ktfile_data *)id->data)->lock);
    krb5_xfree(id->data);
    id->ops = 0;
    krb5_xfree(id);
    return (0);
}

/*
 * This is the get_entry routine for the file based keytab implementation.
 * It opens the keytab file, and either retrieves the entry or returns
 * an error.
 */

krb5_error_code KRB5_CALLCONV
krb5_ktfile_get_entry(krb5_context context, krb5_keytab id,
		      krb5_const_principal principal, krb5_kvno kvno,
		      krb5_enctype enctype, krb5_keytab_entry *entry)
{
    krb5_keytab_entry cur_entry, new_entry;
    krb5_error_code kerror = 0;
    int found_wrong_kvno = 0;
    krb5_boolean similar;
    int kvno_offset = 0;

    kerror = KTLOCK(id);
    if (kerror)
	return kerror;

    /* Open the keyfile for reading */
    if ((kerror = krb5_ktfileint_openr(context, id))) {
	KTUNLOCK(id);
	return(kerror);
    }

    /*
     * For efficiency and simplicity, we'll use a while true that
     * is exited with a break statement.
     */
    cur_entry.principal = 0;
    cur_entry.vno = 0;
    cur_entry.key.contents = 0;

    while (TRUE) {
	if ((kerror = krb5_ktfileint_read_entry(context, id, &new_entry)))
	    break;

	/* by the time this loop exits, it must either free cur_entry,
	   and copy new_entry there, or free new_entry.  Otherwise, it
	   leaks. */

	/* if the principal isn't the one requested, free new_entry
	   and continue to the next. */

	/*
	 * Solaris Kerberos: MS Interop requires that case insensitive
	 * comparisons of service and host components are performed for key
	 * table lookup, etc.  Only called if the private environment variable
	 * MS_INTEROP is defined.
	 */
	if (krb5_getenv("MS_INTEROP")) {
	  if (!__krb5_principal_compare_case_ins(context, principal,
	    new_entry.principal)) {
	    	krb5_kt_free_entry(context, &new_entry);
	    	continue;
	  }
	} else if (!krb5_principal_compare(context, principal,
	  new_entry.principal)) {
	    krb5_kt_free_entry(context, &new_entry);
	    continue;
	}

	/* if the enctype is not ignored and doesn't match, free new_entry
	   and continue to the next */

	if (enctype != IGNORE_ENCTYPE) {
	    if ((kerror = krb5_c_enctype_compare(context, enctype,
						 new_entry.key.enctype,
						 &similar))) {
		krb5_kt_free_entry(context, &new_entry);
		break;
	    }

	    if (!similar) {
		krb5_kt_free_entry(context, &new_entry);
		continue;
	    }
	    /*
	     * Coerce the enctype of the output keyblock in case we
	     * got an inexact match on the enctype.
	     */
	    new_entry.key.enctype = enctype;

	}

	if (kvno == IGNORE_VNO) {
	    /* if this is the first match, or if the new vno is
	       bigger, free the current and keep the new.  Otherwise,
	       free the new. */
	    /* A 1.2.x keytab contains only the low 8 bits of the key
	       version number.  Since it can be much bigger, and thus
	       the 8-bit value can wrap, we need some heuristics to
	       figure out the "highest" numbered key if some numbers
	       close to 255 and some near 0 are used.

	       The heuristic here:

	       If we have any keys with versions over 240, then assume
	       that all version numbers 0-127 refer to 256+N instead.
	       Not perfect, but maybe good enough?  */

#define M(VNO) (((VNO) - kvno_offset + 256) % 256)

	    if (new_entry.vno > 240)
		kvno_offset = 128;
	    if (! cur_entry.principal ||
		M(new_entry.vno) > M(cur_entry.vno)) {
		krb5_kt_free_entry(context, &cur_entry);
		cur_entry = new_entry;
	    } else {
		krb5_kt_free_entry(context, &new_entry);
	    }
	} else {
	    /* if this kvno matches, free the current (will there ever
	       be one?), keep the new, and break out.  Otherwise, remember
	       that we were here so we can return the right error, and
	       free the new */
	    /* Yuck.  The krb5-1.2.x keytab format only stores one byte
	       for the kvno, so we're toast if the kvno requested is
	       higher than that.  Short-term workaround: only compare
	       the low 8 bits.  */

	    if (new_entry.vno == (kvno & 0xff)) {
		krb5_kt_free_entry(context, &cur_entry);
		cur_entry = new_entry;
		break;
	    } else {
		found_wrong_kvno++;
		krb5_kt_free_entry(context, &new_entry);
	    }
	}
    }

    if (kerror == KRB5_KT_END) {
	 if (cur_entry.principal)
	      kerror = 0;
	 else if (found_wrong_kvno)
	      kerror = KRB5_KT_KVNONOTFOUND;
	 else
	      kerror = KRB5_KT_NOTFOUND;
    }
    if (kerror) {
	(void) krb5_ktfileint_close(context, id);
	KTUNLOCK(id);
	krb5_kt_free_entry(context, &cur_entry);
	return kerror;
    }
    if ((kerror = krb5_ktfileint_close(context, id)) != 0) {
	KTUNLOCK(id);
	krb5_kt_free_entry(context, &cur_entry);
	return kerror;
    }
    KTUNLOCK(id);
    *entry = cur_entry;
    return 0;
}

/*
 * Get the name of the file containing a file-based keytab.
 */

krb5_error_code KRB5_CALLCONV
krb5_ktfile_get_name(krb5_context context, krb5_keytab id, char *name, unsigned int len)
  /*
   * This routine returns the name of the name of the file associated with
   * this file-based keytab.  name is zeroed and the filename is truncated
   * to fit in name if necessary.  The name is prefixed with PREFIX:, so that
   * trt will happen if the name is passed back to resolve.
   */
{
    memset(name, 0, len);

    if (len < strlen(id->ops->prefix)+2)
	return(KRB5_KT_NAME_TOOLONG);
    strcpy(name, id->ops->prefix);
    name += strlen(id->ops->prefix);
    name[0] = ':';
    name++;
    len -= strlen(id->ops->prefix)+1;

    /* Solaris Kerberos */
    if (len < strlen(KTFILENAME(id))+1)
	return(KRB5_KT_NAME_TOOLONG);
    strcpy(name, KTFILENAME(id));
    /* strcpy will NUL-terminate the destination */

    return(0);
}

/*
 * krb5_ktfile_start_seq_get()
 */

krb5_error_code KRB5_CALLCONV
krb5_ktfile_start_seq_get(krb5_context context, krb5_keytab id, krb5_kt_cursor *cursorp)
{
    krb5_error_code retval;
    long *fileoff;

    retval = KTLOCK(id);
    if (retval)
	return retval;

    if ((retval = krb5_ktfileint_openr(context, id))) {
	KTUNLOCK(id);
	return retval;
    }

    if (!(fileoff = (long *)malloc(sizeof(*fileoff)))) {
	krb5_ktfileint_close(context, id);
	KTUNLOCK(id);
	return ENOMEM;
    }
    *fileoff = ftell(KTFILEP(id));
    *cursorp = (krb5_kt_cursor)fileoff;
    KTUNLOCK(id);

    return 0;
}

/*
 * krb5_ktfile_get_next()
 */

krb5_error_code KRB5_CALLCONV
krb5_ktfile_get_next(krb5_context context, krb5_keytab id, krb5_keytab_entry *entry, krb5_kt_cursor *cursor)
{
    long *fileoff = (long *)*cursor;
    krb5_keytab_entry cur_entry;
    krb5_error_code kerror;

    kerror = KTLOCK(id);
    if (kerror)
	return kerror;
    if (KTFILEP(id) == NULL) {
	KTUNLOCK(id);
	return KRB5_KT_IOERR;
    }
    if (fseek(KTFILEP(id), *fileoff, 0) == -1) {
	KTUNLOCK(id);
	return KRB5_KT_END;
    }
    if ((kerror = krb5_ktfileint_read_entry(context, id, &cur_entry))) {
	KTUNLOCK(id);
	return kerror;
    }
    *fileoff = ftell(KTFILEP(id));
    *entry = cur_entry;
    KTUNLOCK(id);
    return 0;
}

/*
 * krb5_ktfile_end_get()
 */

krb5_error_code KRB5_CALLCONV
krb5_ktfile_end_get(krb5_context context, krb5_keytab id, krb5_kt_cursor *cursor)
{
    krb5_error_code kerror;

    krb5_xfree(*cursor);
    KTLOCK(id);
    kerror = krb5_ktfileint_close(context, id);
    KTUNLOCK(id);
    return kerror;
}

/*
 * ser_ktf.c - Serialize keytab file context for subsequent reopen.
 */

static const char ktfile_def_name[] = ".";

/*
 * Routines to deal with externalizing krb5_keytab for [WR]FILE: variants.
 *	krb5_ktf_keytab_size();
 *	krb5_ktf_keytab_externalize();
 *	krb5_ktf_keytab_internalize();
 */
static krb5_error_code krb5_ktf_keytab_size
	(krb5_context, krb5_pointer, size_t *);
static krb5_error_code krb5_ktf_keytab_externalize
	(krb5_context, krb5_pointer, krb5_octet **, size_t *);
static krb5_error_code krb5_ktf_keytab_internalize
	(krb5_context,krb5_pointer *, krb5_octet **, size_t *);

/*
 * Serialization entry for this type.
 */
const krb5_ser_entry krb5_ktfile_ser_entry = {
    KV5M_KEYTAB,			/* Type			*/
    krb5_ktf_keytab_size,		/* Sizer routine	*/
    krb5_ktf_keytab_externalize,	/* Externalize routine	*/
    krb5_ktf_keytab_internalize		/* Internalize routine	*/
};

/*
 * krb5_ktf_keytab_size()	- Determine the size required to externalize
 *				  this krb5_keytab variant.
 */
static krb5_error_code
krb5_ktf_keytab_size(krb5_context kcontext, krb5_pointer arg, size_t *sizep)
{
    krb5_error_code	kret;
    krb5_keytab		keytab;
    size_t		required;
    krb5_ktfile_data	*ktdata;

    kret = EINVAL;
    if ((keytab = (krb5_keytab) arg)) {
	/*
	 * Saving FILE: variants of krb5_keytab requires at minimum:
	 *	krb5_int32	for KV5M_KEYTAB
	 *	krb5_int32	for length of keytab name.
	 *	krb5_int32	for file status.
	 *	krb5_int32	for file position.
	 *	krb5_int32	for file position.
	 *	krb5_int32	for version.
	 *	krb5_int32	for KV5M_KEYTAB
	 */
	required = sizeof(krb5_int32) * 7;
	if (keytab->ops && keytab->ops->prefix)
	    required += (strlen(keytab->ops->prefix)+1);

	/*
	 * The keytab name is formed as follows:
	 *	<prefix>:<name>
	 * If there's no name, we use a default name so that we have something
	 * to call krb5_keytab_resolve with.
	 */
	ktdata = (krb5_ktfile_data *) keytab->data;
	required += strlen((ktdata && ktdata->name) ?
			   ktdata->name : ktfile_def_name);
	kret = 0;

	if (!kret)
	    *sizep += required;
    }
    return(kret);
}

/*
 * krb5_ktf_keytab_externalize()	- Externalize the krb5_keytab.
 */
static krb5_error_code
krb5_ktf_keytab_externalize(krb5_context kcontext, krb5_pointer arg, krb5_octet **buffer, size_t *lenremain)
{
    krb5_error_code	kret;
    krb5_keytab		keytab;
    size_t		required;
    krb5_octet		*bp;
    size_t		remain;
    krb5_ktfile_data	*ktdata;
    krb5_int32		file_is_open;
    krb5_int64		file_pos;
    char		*ktname;
    size_t		namelen;
    const char		*fnamep;

    required = 0;
    bp = *buffer;
    remain = *lenremain;
    kret = EINVAL;
    if ((keytab = (krb5_keytab) arg)) {
	kret = ENOMEM;
	if (!krb5_ktf_keytab_size(kcontext, arg, &required) &&
	    (required <= remain)) {
	    /* Our identifier */
	    (void) krb5_ser_pack_int32(KV5M_KEYTAB, &bp, &remain);

	    ktdata = (krb5_ktfile_data *) keytab->data;
	    file_is_open = 0;
	    file_pos = 0;

	    /* Calculate the length of the name */
	    namelen = (keytab->ops && keytab->ops->prefix) ?
		strlen(keytab->ops->prefix)+1 : 0;
	    if (ktdata && ktdata->name)
		fnamep = ktdata->name;
	    else
		fnamep = ktfile_def_name;
	    namelen += (strlen(fnamep)+1);

	    if ((ktname = (char *) malloc(namelen))) {
		/* Format the keytab name. */
		if (keytab->ops && keytab->ops->prefix)
		    sprintf(ktname, "%s:%s", keytab->ops->prefix, fnamep);

		else
		    strcpy(ktname, fnamep);

		/* Fill in the file-specific keytab information. */
		if (ktdata) {
		    if (ktdata->openf) {
			long	fpos;
			int	fflags = 0;

			file_is_open = 1;
#if !defined(_WIN32)
			fflags = fcntl(fileno(ktdata->openf), F_GETFL, 0);
			if (fflags > 0)
			    file_is_open |= ((fflags & O_ACCMODE) << 1);
#else
			file_is_open = 0;
#endif
			fpos = ftell(ktdata->openf);
			file_pos = fpos; /* XX range check? */
		    }
		}

		/* Put the length of the file name */
		(void) krb5_ser_pack_int32((krb5_int32) strlen(ktname),
					   &bp, &remain);

		/* Put the name */
		(void) krb5_ser_pack_bytes((krb5_octet *) ktname,
					   strlen(ktname),
					   &bp, &remain);

		/* Put the file open flag */
		(void) krb5_ser_pack_int32(file_is_open, &bp, &remain);

		/* Put the file position */
		(void) krb5_ser_pack_int64(file_pos, &bp, &remain);

		/* Put the version */
		(void) krb5_ser_pack_int32((krb5_int32) ((ktdata) ?
							 ktdata->version : 0),
					   &bp, &remain);

		/* Put the trailer */
		(void) krb5_ser_pack_int32(KV5M_KEYTAB, &bp, &remain);
		kret = 0;
		*buffer = bp;
		*lenremain = remain;
		free(ktname);
	    }
	}
    }
    return(kret);
}

/*
 * krb5_ktf_keytab_internalize()	- Internalize the krb5_ktf_keytab.
 */
static krb5_error_code
krb5_ktf_keytab_internalize(krb5_context kcontext, krb5_pointer *argp, krb5_octet **buffer, size_t *lenremain)
{
    krb5_error_code	kret;
    krb5_keytab		keytab;
    krb5_int32		ibuf;
    krb5_octet		*bp;
    size_t		remain;
    char		*ktname;
    krb5_ktfile_data	*ktdata;
    krb5_int32		file_is_open;
    krb5_int64		foff;

    bp = *buffer;
    remain = *lenremain;
    kret = EINVAL;
    /* Read our magic number */
    if (krb5_ser_unpack_int32(&ibuf, &bp, &remain))
	ibuf = 0;
    if (ibuf == KV5M_KEYTAB) {
	kret = ENOMEM;

	/* Get the length of the keytab name */
	kret = krb5_ser_unpack_int32(&ibuf, &bp, &remain);

	if (!kret &&
	    (ktname = (char *) malloc((size_t) (ibuf+1))) &&
	    !(kret = krb5_ser_unpack_bytes((krb5_octet *) ktname,
					   (size_t) ibuf,
					   &bp, &remain))) {
	    ktname[ibuf] = '\0';
	    kret = krb5_kt_resolve(kcontext, ktname, &keytab);
	    if (!kret) {
		kret = ENOMEM;
		ktdata = (krb5_ktfile_data *) keytab->data;
		if (!ktdata) {
		    /* XXX */
		    keytab->data = (void *) malloc(sizeof(krb5_ktfile_data));
		    ktdata = (krb5_ktfile_data *) keytab->data;
		    memset(ktdata, 0, sizeof(krb5_ktfile_data));
		    if (strchr(ktname, (int) ':'))
			ktdata->name = strdup(strchr(ktname, (int) ':')+1);
		    else
			ktdata->name = strdup(ktname);
		}
		if (ktdata) {
		    if (remain >= (sizeof(krb5_int32)*5)) {
			(void) krb5_ser_unpack_int32(&file_is_open,
						     &bp, &remain);
			(void) krb5_ser_unpack_int64(&foff, &bp, &remain);
			(void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
			ktdata->version = (int) ibuf;

			(void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
			if (ibuf == KV5M_KEYTAB) {
			    if (file_is_open) {
				int 	fmode;
				long	fpos;

#if !defined(_WIN32)
				fmode = (file_is_open >> 1) & O_ACCMODE;
#else
				fmode = 0;
#endif
				if (fmode)
				    kret = krb5_ktfileint_openw(kcontext,
								keytab);
				else
				    kret = krb5_ktfileint_openr(kcontext,
								keytab);
				if (!kret) {
				    fpos = foff; /* XX range check? */
				    fseek(KTFILEP(keytab), fpos, SEEK_SET);
				}
			    }
			    kret = 0;
			}
			else
			    kret = EINVAL;
		    }
		}
		if (kret) {
		    if (keytab->data) {
			if (KTFILENAME(keytab))
			    krb5_xfree(KTFILENAME(keytab));
			krb5_xfree(keytab->data);
		    }
		    krb5_xfree(keytab);
		}
		else {
		    *buffer = bp;
		    *lenremain = remain;
		    *argp = (krb5_pointer) keytab;
		}
	    }
	    free(ktname);
	}
    }
    return(kret);
}

/*
 * This is an implementation specific resolver.  It returns a keytab id
 * initialized with file keytab routines.
 */

krb5_error_code KRB5_CALLCONV
krb5_ktfile_wresolve(krb5_context context, const char *name, krb5_keytab *id)
{
    krb5_ktfile_data *data;
    krb5_error_code err;

    if ((*id = (krb5_keytab) malloc(sizeof(**id))) == NULL)
	return(ENOMEM);

    (*id)->ops = &krb5_ktf_writable_ops;
    if ((data = (krb5_ktfile_data *)malloc(sizeof(krb5_ktfile_data))) == NULL) {
	krb5_xfree(*id);
	return(ENOMEM);
    }

    err = k5_mutex_init(&data->lock);
    if (err) {
	krb5_xfree(data);
	krb5_xfree(*id);
	return err;
    }

    if ((data->name = (char *)calloc(strlen(name) + 1, sizeof(char))) == NULL) {
	k5_mutex_destroy(&data->lock);
	krb5_xfree(data);
	krb5_xfree(*id);
	return(ENOMEM);
    }

    (void) strcpy(data->name, name);
    data->openf = 0;
    data->version = 0;

    (*id)->data = (krb5_pointer)data;
    (*id)->magic = KV5M_KEYTAB;
    return(0);
}


/*
 * krb5_ktfile_add()
 */

krb5_error_code KRB5_CALLCONV
krb5_ktfile_add(krb5_context context, krb5_keytab id, krb5_keytab_entry *entry)
{
    krb5_error_code retval;

    retval = KTLOCK(id);
    if (retval)
	return retval;
    if ((retval = krb5_ktfileint_openw(context, id))) {
	KTUNLOCK(id);
	return retval;
    }
    if (fseek(KTFILEP(id), 0, 2) == -1) {
	KTUNLOCK(id);
	return KRB5_KT_END;
    }
    retval = krb5_ktfileint_write_entry(context, id, entry);
    krb5_ktfileint_close(context, id);
    KTUNLOCK(id);
    return retval;
}

/*
 * krb5_ktfile_remove()
 */

krb5_error_code KRB5_CALLCONV
krb5_ktfile_remove(krb5_context context, krb5_keytab id, krb5_keytab_entry *entry)
{
    krb5_keytab_entry   cur_entry;
    krb5_error_code     kerror;
    krb5_int32          delete_point;

    kerror = KTLOCK(id);
    if (kerror)
	return kerror;

    if ((kerror = krb5_ktfileint_openw(context, id))) {
	KTUNLOCK(id);
	return kerror;
    }

    /*
     * For efficiency and simplicity, we'll use a while true that
     * is exited with a break statement.
     */
    while (TRUE) {
	if ((kerror = krb5_ktfileint_internal_read_entry(context, id,
							 &cur_entry,
							 &delete_point)))
  	    break;

	if ((entry->vno == cur_entry.vno) &&
            (entry->key.enctype == cur_entry.key.enctype) &&
	    krb5_principal_compare(context, entry->principal, cur_entry.principal)) {
	    /* found a match */
            krb5_kt_free_entry(context, &cur_entry);
	    break;
	}
	krb5_kt_free_entry(context, &cur_entry);
    }

    if (kerror == KRB5_KT_END)
	kerror = KRB5_KT_NOTFOUND;

    if (kerror) {
	(void) krb5_ktfileint_close(context, id);
	KTUNLOCK(id);
	return kerror;
    }

    kerror = krb5_ktfileint_delete_entry(context, id, delete_point);

    if (kerror) {
	(void) krb5_ktfileint_close(context, id);
    } else {
        kerror = krb5_ktfileint_close(context, id);
    }
    KTUNLOCK(id);
    return kerror;
}

/*
 * krb5_ktf_ops
 */

const struct _krb5_kt_ops krb5_ktf_ops = {
    0,
    "FILE", 	/* Prefix -- this string should not appear anywhere else! */
    krb5_ktfile_resolve,
    krb5_ktfile_get_name,
    krb5_ktfile_close,
    krb5_ktfile_get_entry,
    krb5_ktfile_start_seq_get,
    krb5_ktfile_get_next,
    krb5_ktfile_end_get,
    0,
    0,
    &krb5_ktfile_ser_entry
};

/*
 * krb5_ktf_writable_ops
 */

const struct _krb5_kt_ops krb5_ktf_writable_ops = {
    0,
    "WRFILE", 	/* Prefix -- this string should not appear anywhere else! */
    krb5_ktfile_wresolve,
    krb5_ktfile_get_name,
    krb5_ktfile_close,
    krb5_ktfile_get_entry,
    krb5_ktfile_start_seq_get,
    krb5_ktfile_get_next,
    krb5_ktfile_end_get,
    krb5_ktfile_add,
    krb5_ktfile_remove,
    &krb5_ktfile_ser_entry
};

/*
 * krb5_kt_dfl_ops
 */

const krb5_kt_ops krb5_kt_dfl_ops = {
    0,
    "FILE", 	/* Prefix -- this string should not appear anywhere else! */
    krb5_ktfile_resolve,
    krb5_ktfile_get_name,
    krb5_ktfile_close,
    krb5_ktfile_get_entry,
    krb5_ktfile_start_seq_get,
    krb5_ktfile_get_next,
    krb5_ktfile_end_get,
    0,
    0,
    &krb5_ktfile_ser_entry
};

/*
 * lib/krb5/keytab/file/ktf_util.c
 *
 * Copyright (c) Hewlett-Packard Company 1991
 * Released to the Massachusetts Institute of Technology for inclusion
 * in the Kerberos source code distribution.
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
 * This function contains utilities for the file based implementation of
 * the keytab.  There are no public functions in this file.
 *
 * This file is the only one that has knowledge of the format of a
 * keytab file.
 *
 * The format is as follows:
 *
 * <file format vno>
 * <record length>
 * principal timestamp vno key
 * <record length>
 * principal timestamp vno key
 * ....
 *
 * A length field (sizeof(krb5_int32)) exists between entries.  When this
 * length is positive it indicates an active entry, when negative a hole.
 * The length indicates the size of the block in the file (this may be
 * larger than the size of the next record, since we are using a first
 * fit algorithm for re-using holes and the first fit may be larger than
 * the entry we are writing).  Another (compatible) implementation could
 * break up holes when allocating them to smaller entries to minimize
 * wasted space.  (Such an implementation should also coalesce adjacent
 * holes to reduce fragmentation).  This implementation does neither.
 *
 * There are no separators between fields of an entry.
 * A principal is a length-encoded array of length-encoded strings.  The
 * length is a krb5_int16 in each case.  The specific format, then, is
 * multiple entries concatinated with no separators.  An entry has this
 * exact format:
 *
 * sizeof(krb5_int16) bytes for number of components in the principal;
 * then, each component listed in ordser.
 * For each component, sizeof(krb5_int16) bytes for the number of bytes
 * in the component, followed by the component.
 * sizeof(krb5_int32) for the principal type (for KEYTAB V2 and higher)
 * sizeof(krb5_int32) bytes for the timestamp
 * sizeof(krb5_octet) bytes for the key version number
 * sizeof(krb5_int16) bytes for the enctype
 * sizeof(krb5_int32) bytes for the key length, followed by the key
 */

#ifndef SEEK_SET
#define SEEK_SET 0
#define SEEK_CUR 1
#endif

typedef krb5_int16  krb5_kt_vno;

#define krb5_kt_default_vno ((krb5_kt_vno)KRB5_KT_DEFAULT_VNO)

#define xfwrite(a, b, c, d) fwrite((char *)a, b, (unsigned) c, d)
#define xfread(a, b, c, d) fread((char *)a, b, (unsigned) c, d)

#ifdef ANSI_STDIO
/* Solaris Kerberos */
static char *const fopen_mode_rbplus= "rb+F";
static char *const fopen_mode_rb = "rbF";
#else
/* Solaris Kerberos */
static char *const fopen_mode_rbplus= "r+F";
static char *const fopen_mode_rb = "rF";
#endif

static krb5_error_code
krb5_ktfileint_open(krb5_context context, krb5_keytab id, int mode)
{
    krb5_error_code kerror;
    krb5_kt_vno kt_vno;
    int writevno = 0;

    KTCHECKLOCK(id);
    errno = 0;
    KTFILEP(id) = fopen(KTFILENAME(id),
			(mode == KRB5_LOCKMODE_EXCLUSIVE) ?
			  fopen_mode_rbplus : fopen_mode_rb);
    if (!KTFILEP(id)) {
	if ((mode == KRB5_LOCKMODE_EXCLUSIVE) && (errno == ENOENT)) {
	    /* try making it first time around */
            krb5_create_secure_file(context, KTFILENAME(id));
	    errno = 0;
	    KTFILEP(id) = fopen(KTFILENAME(id), fopen_mode_rbplus);
	    if (!KTFILEP(id))
		goto report_errno;
	    writevno = 1;
	} else {
        report_errno:
            switch (errno) {
            case 0:
                /* XXX */
                return EMFILE;
            case ENOENT:
                krb5_set_error_message(context, ENOENT,
				       /* Solaris Kerberos - added dgettext */
                                       dgettext(TEXT_DOMAIN,
					   "Key table file '%s' not found"),
                                       KTFILENAME(id));
                return ENOENT;
            default:
                return errno;
            }
        }
    }
    if ((kerror = krb5_lock_file(context, fileno(KTFILEP(id)), mode))) {
	(void) fclose(KTFILEP(id));
	KTFILEP(id) = 0;
	return kerror;
    }
    /* assume ANSI or BSD-style stdio */
    setbuf(KTFILEP(id), KTFILEBUFP(id));

    /* get the vno and verify it */
    if (writevno) {
	kt_vno = htons(krb5_kt_default_vno);
	KTVERSION(id) = krb5_kt_default_vno;
	if (!xfwrite(&kt_vno, sizeof(kt_vno), 1, KTFILEP(id))) {
	    kerror = errno;
	    (void) krb5_unlock_file(context, fileno(KTFILEP(id)));
	    (void) fclose(KTFILEP(id));
	    return kerror;
	}
    } else {
	/* gotta verify it instead... */
	if (!xfread(&kt_vno, sizeof(kt_vno), 1, KTFILEP(id))) {
	    if (feof(KTFILEP(id)))
		kerror = KRB5_KEYTAB_BADVNO;
	    else
		kerror = errno;
	    (void) krb5_unlock_file(context, fileno(KTFILEP(id)));
	    (void) fclose(KTFILEP(id));
	    return kerror;
	}
	kt_vno = KTVERSION(id) = ntohs(kt_vno);
	if ((kt_vno != KRB5_KT_VNO) &&
	    (kt_vno != KRB5_KT_VNO_1)) {
	    (void) krb5_unlock_file(context, fileno(KTFILEP(id)));
	    (void) fclose(KTFILEP(id));
	    return KRB5_KEYTAB_BADVNO;
	}
    }
    return 0;
}

krb5_error_code
krb5_ktfileint_openr(krb5_context context, krb5_keytab id)
{
    return krb5_ktfileint_open(context, id, KRB5_LOCKMODE_SHARED);
}

krb5_error_code
krb5_ktfileint_openw(krb5_context context, krb5_keytab id)
{
    return krb5_ktfileint_open(context, id, KRB5_LOCKMODE_EXCLUSIVE);
}

krb5_error_code
krb5_ktfileint_close(krb5_context context, krb5_keytab id)
{
    krb5_error_code kerror;

    KTCHECKLOCK(id);
    if (!KTFILEP(id))
	return 0;
    kerror = krb5_unlock_file(context, fileno(KTFILEP(id)));
    (void) fclose(KTFILEP(id));
    KTFILEP(id) = 0;
    return kerror;
}

krb5_error_code
krb5_ktfileint_delete_entry(krb5_context context, krb5_keytab id, krb5_int32 delete_point)
{
    krb5_int32  size;
    krb5_int32  len;
    char        iobuf[BUFSIZ];

    KTCHECKLOCK(id);
    if (fseek(KTFILEP(id), delete_point, SEEK_SET)) {
        return errno;
    }
    if (!xfread(&size, sizeof(size), 1, KTFILEP(id))) {
        return KRB5_KT_END;
    }
    if (KTVERSION(id) != KRB5_KT_VNO_1)
	size = ntohl(size);

    if (size > 0) {
        krb5_int32 minus_size = -size;
	if (KTVERSION(id) != KRB5_KT_VNO_1)
	    minus_size = htonl(minus_size);

        if (fseek(KTFILEP(id), delete_point, SEEK_SET)) {
            return errno;
        }

        if (!xfwrite(&minus_size, sizeof(minus_size), 1, KTFILEP(id))) {
            return KRB5_KT_IOERR;
        }

        if (size < BUFSIZ) {
            len = size;
        } else {
            len = BUFSIZ;
        }

        memset(iobuf, 0, (size_t) len);
        while (size > 0) {
            xfwrite(iobuf, 1, (size_t) len, KTFILEP(id));
            size -= len;
            if (size < len) {
                len = size;
            }
        }

        return krb5_sync_disk_file(context, KTFILEP(id));
    }

    return 0;
}

krb5_error_code
krb5_ktfileint_internal_read_entry(krb5_context context, krb5_keytab id, krb5_keytab_entry *ret_entry, krb5_int32 *delete_point)
{
    krb5_octet vno;
    krb5_int16 count;
    unsigned int u_count, u_princ_size;
    krb5_int16 enctype;
    krb5_int16 princ_size;
    register int i;
    krb5_int32 size;
    krb5_int32 start_pos;
    krb5_error_code error;
    char	*tmpdata;
    krb5_data	*princ;

    KTCHECKLOCK(id);
    memset(ret_entry, 0, sizeof(krb5_keytab_entry));
    ret_entry->magic = KV5M_KEYTAB_ENTRY;

    /* fseek to synchronise buffered I/O on the key table. */

    if (fseek(KTFILEP(id), 0L, SEEK_CUR) < 0)
    {
        return errno;
    }

    do {
        *delete_point = ftell(KTFILEP(id));
        if (!xfread(&size, sizeof(size), 1, KTFILEP(id))) {
            return KRB5_KT_END;
        }
	if (KTVERSION(id) != KRB5_KT_VNO_1)
		size = ntohl(size);

        if (size < 0) {
            if (fseek(KTFILEP(id), -size, SEEK_CUR)) {
                return errno;
            }
        }
    } while (size < 0);

    if (size == 0) {
        return KRB5_KT_END;
    }

    start_pos = ftell(KTFILEP(id));

    /* deal with guts of parsing... */

    /* first, int16 with #princ components */
    if (!xfread(&count, sizeof(count), 1, KTFILEP(id)))
	return KRB5_KT_END;
    if (KTVERSION(id) == KRB5_KT_VNO_1) {
	    count -= 1;		/* V1 includes the realm in the count */
    } else {
	    count = ntohs(count);
    }
    if (!count || (count < 0))
	return KRB5_KT_END;
    ret_entry->principal = (krb5_principal)malloc(sizeof(krb5_principal_data));
    if (!ret_entry->principal)
        return ENOMEM;

    u_count = count;
    ret_entry->principal->magic = KV5M_PRINCIPAL;
    ret_entry->principal->length = u_count;
    ret_entry->principal->data = (krb5_data *)
                                 calloc(u_count, sizeof(krb5_data));
    if (!ret_entry->principal->data) {
	free(ret_entry->principal);
	ret_entry->principal = 0;
	return ENOMEM;
    }

    /* Now, get the realm data */
    if (!xfread(&princ_size, sizeof(princ_size), 1, KTFILEP(id))) {
	    error = KRB5_KT_END;
	    goto fail;
    }
    if (KTVERSION(id) != KRB5_KT_VNO_1)
	    princ_size = ntohs(princ_size);
    if (!princ_size || (princ_size < 0)) {
	    error = KRB5_KT_END;
	    goto fail;
    }
    u_princ_size = princ_size;

    krb5_princ_set_realm_length(context, ret_entry->principal, u_princ_size);
    tmpdata = malloc(u_princ_size+1);
    if (!tmpdata) {
	    error = ENOMEM;
	    goto fail;
    }
    if (fread(tmpdata, 1, u_princ_size, KTFILEP(id)) != (size_t) princ_size) {
	    free(tmpdata);
	    error = KRB5_KT_END;
	    goto fail;
    }
    tmpdata[princ_size] = 0;	/* Some things might be expecting null */
				/* termination...  ``Be conservative in */
				/* what you send out'' */
    krb5_princ_set_realm_data(context, ret_entry->principal, tmpdata);

    for (i = 0; i < count; i++) {
	princ = krb5_princ_component(context, ret_entry->principal, i);
	if (!xfread(&princ_size, sizeof(princ_size), 1, KTFILEP(id))) {
	    error = KRB5_KT_END;
	    goto fail;
        }
	if (KTVERSION(id) != KRB5_KT_VNO_1)
	    princ_size = ntohs(princ_size);
	if (!princ_size || (princ_size < 0)) {
	    error = KRB5_KT_END;
	    goto fail;
        }

	u_princ_size = princ_size;
	princ->length = u_princ_size;
	princ->data = malloc(u_princ_size+1);
	if (!princ->data) {
	    error = ENOMEM;
	    goto fail;
        }
	if (!xfread(princ->data, sizeof(char), u_princ_size, KTFILEP(id))) {
	    error = KRB5_KT_END;
	    goto fail;
        }
	princ->data[princ_size] = 0; /* Null terminate */
    }

    /* read in the principal type, if we can get it */
    if (KTVERSION(id) != KRB5_KT_VNO_1) {
	    if (!xfread(&ret_entry->principal->type,
			sizeof(ret_entry->principal->type), 1, KTFILEP(id))) {
		    error = KRB5_KT_END;
		    goto fail;
	    }
	    ret_entry->principal->type = ntohl(ret_entry->principal->type);
    }

    /* read in the timestamp */
    if (!xfread(&ret_entry->timestamp, sizeof(ret_entry->timestamp), 1, KTFILEP(id))) {
	error = KRB5_KT_END;
	goto fail;
    }
    if (KTVERSION(id) != KRB5_KT_VNO_1)
	ret_entry->timestamp = ntohl(ret_entry->timestamp);

    /* read in the version number */
    if (!xfread(&vno, sizeof(vno), 1, KTFILEP(id))) {
	error = KRB5_KT_END;
	goto fail;
    }
    ret_entry->vno = (krb5_kvno)vno;

    /* key type */
    if (!xfread(&enctype, sizeof(enctype), 1, KTFILEP(id))) {
	error = KRB5_KT_END;
	goto fail;
    }
    ret_entry->key.enctype = (krb5_enctype)enctype;

    if (KTVERSION(id) != KRB5_KT_VNO_1)
	ret_entry->key.enctype = ntohs(ret_entry->key.enctype);

    /* key contents */
    ret_entry->key.magic = KV5M_KEYBLOCK;

    if (!xfread(&count, sizeof(count), 1, KTFILEP(id))) {
	error = KRB5_KT_END;
	goto fail;
    }
    if (KTVERSION(id) != KRB5_KT_VNO_1)
	count = ntohs(count);
    if (!count || (count < 0)) {
	error = KRB5_KT_END;
	goto fail;
    }

    u_count = count;
    ret_entry->key.length = u_count;

    ret_entry->key.contents = (krb5_octet *)malloc(u_count);
    if (!ret_entry->key.contents) {
	error = ENOMEM;
	goto fail;
    }
    if (!xfread(ret_entry->key.contents, sizeof(krb5_octet), count,
		KTFILEP(id))) {
	error = KRB5_KT_END;
	goto fail;
    }

    /*
     * Reposition file pointer to the next inter-record length field.
     */
    fseek(KTFILEP(id), start_pos + size, SEEK_SET);
    return 0;
fail:

    for (i = 0; i < krb5_princ_size(context, ret_entry->principal); i++) {
	    princ = krb5_princ_component(context, ret_entry->principal, i);
	    if (princ->data)
		    free(princ->data);
    }
    free(ret_entry->principal->data);
    ret_entry->principal->data = 0;
    free(ret_entry->principal);
    ret_entry->principal = 0;
    return error;
}

krb5_error_code
krb5_ktfileint_read_entry(krb5_context context, krb5_keytab id, krb5_keytab_entry *entryp)
{
    krb5_int32 delete_point;

    return krb5_ktfileint_internal_read_entry(context, id, entryp, &delete_point);
}

krb5_error_code
krb5_ktfileint_write_entry(krb5_context context, krb5_keytab id, krb5_keytab_entry *entry)
{
    krb5_octet vno;
    krb5_data *princ;
    krb5_int16 count, size, enctype;
    krb5_error_code retval = 0;
    krb5_timestamp timestamp;
    krb5_int32	princ_type;
    krb5_int32  size_needed;
    krb5_int32  commit_point;
    int		i;

    KTCHECKLOCK(id);
    retval = krb5_ktfileint_size_entry(context, entry, &size_needed);
    if (retval)
        return retval;
    retval = krb5_ktfileint_find_slot(context, id, &size_needed, &commit_point);
    if (retval)
        return retval;

    /* fseek to synchronise buffered I/O on the key table. */
    /* XXX Without the weird setbuf crock, can we get rid of this now?  */
    if (fseek(KTFILEP(id), 0L, SEEK_CUR) < 0)
    {
        return errno;
    }

    if (KTVERSION(id) == KRB5_KT_VNO_1) {
	    count = (krb5_int16) krb5_princ_size(context, entry->principal) + 1;
    } else {
	    count = htons((u_short) krb5_princ_size(context, entry->principal));
    }

    if (!xfwrite(&count, sizeof(count), 1, KTFILEP(id))) {
    abend:
	return KRB5_KT_IOERR;
    }
    size = krb5_princ_realm(context, entry->principal)->length;
    if (KTVERSION(id) != KRB5_KT_VNO_1)
	    size = htons(size);
    if (!xfwrite(&size, sizeof(size), 1, KTFILEP(id))) {
	    goto abend;
    }
    if (!xfwrite(krb5_princ_realm(context, entry->principal)->data, sizeof(char),
		 krb5_princ_realm(context, entry->principal)->length, KTFILEP(id))) {
	    goto abend;
    }

    count = (krb5_int16) krb5_princ_size(context, entry->principal);
    for (i = 0; i < count; i++) {
	princ = krb5_princ_component(context, entry->principal, i);
	size = princ->length;
	if (KTVERSION(id) != KRB5_KT_VNO_1)
		size = htons(size);
	if (!xfwrite(&size, sizeof(size), 1, KTFILEP(id))) {
	    goto abend;
	}
	if (!xfwrite(princ->data, sizeof(char), princ->length, KTFILEP(id))) {
	    goto abend;
	}
    }

    /*
     * Write out the principal type
     */
    if (KTVERSION(id) != KRB5_KT_VNO_1) {
	    princ_type = htonl(krb5_princ_type(context, entry->principal));
	    if (!xfwrite(&princ_type, sizeof(princ_type), 1, KTFILEP(id))) {
		    goto abend;
	    }
    }

    /*
     * Fill in the time of day the entry was written to the keytab.
     */
    if (krb5_timeofday(context, &entry->timestamp)) {
        entry->timestamp = 0;
    }
    if (KTVERSION(id) == KRB5_KT_VNO_1)
	    timestamp = entry->timestamp;
    else
	    timestamp = htonl(entry->timestamp);
    if (!xfwrite(&timestamp, sizeof(timestamp), 1, KTFILEP(id))) {
	goto abend;
    }

    /* key version number */
    vno = (krb5_octet)entry->vno;
    if (!xfwrite(&vno, sizeof(vno), 1, KTFILEP(id))) {
	goto abend;
    }
    /* key type */
    if (KTVERSION(id) == KRB5_KT_VNO_1)
	    enctype = entry->key.enctype;
    else
	    enctype = htons(entry->key.enctype);
    if (!xfwrite(&enctype, sizeof(enctype), 1, KTFILEP(id))) {
	goto abend;
    }
    /* key length */
    if (KTVERSION(id) == KRB5_KT_VNO_1)
	    size = entry->key.length;
    else
	    size = htons(entry->key.length);
    if (!xfwrite(&size, sizeof(size), 1, KTFILEP(id))) {
	goto abend;
    }
    if (!xfwrite(entry->key.contents, sizeof(krb5_octet),
		 entry->key.length, KTFILEP(id))) {
	goto abend;
    }

    if (fflush(KTFILEP(id)))
	goto abend;

    retval = krb5_sync_disk_file(context, KTFILEP(id));

    if (retval) {
        return retval;
    }

    if (fseek(KTFILEP(id), commit_point, SEEK_SET)) {
        return errno;
    }
    if (KTVERSION(id) != KRB5_KT_VNO_1)
	    size_needed = htonl(size_needed);
    if (!xfwrite(&size_needed, sizeof(size_needed), 1, KTFILEP(id))) {
        goto abend;
    }
    if (fflush(KTFILEP(id)))
	goto abend;
    retval = krb5_sync_disk_file(context, KTFILEP(id));

    return retval;
}

/*
 * Determine the size needed for a file entry for the given
 * keytab entry.
 */
krb5_error_code
krb5_ktfileint_size_entry(krb5_context context, krb5_keytab_entry *entry, krb5_int32 *size_needed)
{
    krb5_int16 count;
    krb5_int32 total_size, i;
    krb5_error_code retval = 0;

    count = (krb5_int16) krb5_princ_size(context, entry->principal);

    total_size = sizeof(count);
    total_size += krb5_princ_realm(context, entry->principal)->length + (sizeof(krb5_int16));

    for (i = 0; i < count; i++) {
	    total_size += krb5_princ_component(context, entry->principal,i)->length
		    + (sizeof(krb5_int16));
    }

    total_size += sizeof(entry->principal->type);
    total_size += sizeof(entry->timestamp);
    total_size += sizeof(krb5_octet);
    total_size += sizeof(krb5_int16);
    total_size += sizeof(krb5_int16) + entry->key.length;

    *size_needed = total_size;
    return retval;
}

/*
 * Find and reserve a slot in the file for an entry of the needed size.
 * The commit point will be set to the position in the file where the
 * the length (sizeof(krb5_int32) bytes) of this node should be written
 * when commiting the write.  The file position left as a result of this
 * call is the position where the actual data should be written.
 *
 * The size_needed argument may be adjusted if we find a hole that is
 * larger than the size needed.  (Recall that size_needed will be used
 * to commit the write, but that this field must indicate the size of the
 * block in the file rather than the size of the actual entry)
 */
krb5_error_code
krb5_ktfileint_find_slot(krb5_context context, krb5_keytab id, krb5_int32 *size_needed, krb5_int32 *commit_point)
{
    krb5_int32      size;
    krb5_int32      remainder;
    krb5_int32      zero_point;
    krb5_kt_vno     kt_vno;
    krb5_boolean    found = FALSE;
    char            iobuf[BUFSIZ];

    KTCHECKLOCK(id);
    /*
     * Skip over file version number
     */
    if (fseek(KTFILEP(id), 0, SEEK_SET)) {
        return errno;
    }
    if (!xfread(&kt_vno, sizeof(kt_vno), 1, KTFILEP(id))) {
        return KRB5_KT_IOERR;
    }

    while (!found) {
        *commit_point = ftell(KTFILEP(id));
        if (!xfread(&size, sizeof(size), 1, KTFILEP(id))) {
            /*
             * Hit the end of file, reserve this slot.
             */
            size = 0;

            /* fseek to synchronise buffered I/O on the key table. */
	    /* XXX Without the weird setbuf hack, can we nuke this now?  */
            if (fseek(KTFILEP(id), 0L, SEEK_CUR) < 0)
            {
                return errno;
            }

#ifdef notdef
	    /* We don't have to do this because htonl(0) == 0 */
	    if (KTVERSION(id) != KRB5_KT_VNO_1)
		    size = htonl(size);
#endif

            if (!xfwrite(&size, sizeof(size), 1, KTFILEP(id))) {
                return KRB5_KT_IOERR;
            }
            found = TRUE;
        }

	if (KTVERSION(id) != KRB5_KT_VNO_1)
		size = ntohl(size);

        if (size > 0) {
            if (fseek(KTFILEP(id), size, SEEK_CUR)) {
                return errno;
            }
        } else if (!found) {
            size = -size;
            if (size >= *size_needed) {
                *size_needed = size;
                found = TRUE;
            } else if (size > 0) {
                /*
                 * The current hole is not large enough, so skip it
                 */
                if (fseek(KTFILEP(id), size, SEEK_CUR)) {
                    return errno;
                }
            } else {

                 /* fseek to synchronise buffered I/O on the key table. */

                 if (fseek(KTFILEP(id), 0L, SEEK_CUR) < 0)
                 {
                     return errno;
                 }

                /*
                 * Found the end of the file (marked by a 0 length buffer)
                 * Make sure we zero any trailing data.
                 */
                zero_point = ftell(KTFILEP(id));
                while ((size = xfread(iobuf, 1, sizeof(iobuf), KTFILEP(id)))) {
                    if (size != sizeof(iobuf)) {
                        remainder = size % sizeof(krb5_int32);
                        if (remainder) {
                            size += sizeof(krb5_int32) - remainder;
                        }
                    }

                    if (fseek(KTFILEP(id), 0L, SEEK_CUR) < 0)
                    {
                        return errno;
                    }

                    memset(iobuf, 0, (size_t) size);
                    xfwrite(iobuf, 1, (size_t) size, KTFILEP(id));
		    fflush(KTFILEP(id));
                    if (feof(KTFILEP(id))) {
                        break;
                    }

                    if (fseek(KTFILEP(id), 0L, SEEK_CUR) < 0)
                    {
                        return errno;
                    }

                }
                if (fseek(KTFILEP(id), zero_point, SEEK_SET)) {
                    return errno;
                }
            }
        }
    }

    return 0;
}
