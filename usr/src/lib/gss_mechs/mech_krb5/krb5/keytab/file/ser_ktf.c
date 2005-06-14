/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/keytab/file/ser_ktf.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
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

/*
 * ser_ktf.c - Serialize keytab file context for subsequent reopen.
 */
#include <k5-int.h>
#include "ktfile.h"

static const char ktfile_def_name[] = ".";

/*
 * Routines to deal with externalizing krb5_keytab for [WR]FILE: variants.
 *	krb5_ktf_keytab_size();
 *	krb5_ktf_keytab_externalize();
 *	krb5_ktf_keytab_internalize();
 */
static krb5_error_code krb5_ktf_keytab_size
	KRB5_PROTOTYPE((krb5_context, krb5_pointer, size_t *));
static krb5_error_code krb5_ktf_keytab_externalize
	KRB5_PROTOTYPE((krb5_context, krb5_pointer, krb5_octet **, size_t *));
static krb5_error_code krb5_ktf_keytab_internalize
	KRB5_PROTOTYPE((krb5_context,krb5_pointer *, krb5_octet **, size_t *));

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
/*ARGSUSED*/
static krb5_error_code
krb5_ktf_keytab_size(kcontext, arg, sizep)
    krb5_context	kcontext;
    krb5_pointer	arg;
    size_t		*sizep;
{
    krb5_error_code	kret;
    krb5_keytab		keytab;
    size_t		required;
    krb5_ktfile_data	*ktdata;

    kret = EINVAL;
    if ((keytab = (krb5_keytab) arg) != NULL) {
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
krb5_ktf_keytab_externalize(kcontext, arg, buffer, lenremain)
    krb5_context	kcontext;
    krb5_pointer	arg;
    krb5_octet		**buffer;
    size_t		*lenremain;
{
    krb5_error_code	kret;
    krb5_keytab		keytab;
    size_t		required;
    krb5_octet		*bp;
    size_t		remain;
    krb5_ktfile_data	*ktdata;
    krb5_int32		file_is_open;
    krb5_int32		file_pos[2];
    char		*ktname;
    size_t		namelen;
    char		*fnamep;

    required = 0;
    bp = *buffer;
    remain = *lenremain;
    kret = EINVAL;
    if ((keytab = (krb5_keytab) arg) != NULL) {
	kret = ENOMEM;
	if (!krb5_ktf_keytab_size(kcontext, arg, &required) &&
	    (required <= remain)) {
	    /* Our identifier */
	    (void) krb5_ser_pack_int32(KV5M_KEYTAB, &bp, &remain);

	    ktdata = (krb5_ktfile_data *) keytab->data;
	    file_is_open = 0;
	    file_pos[0] = 0;
	    file_pos[1] = 0;

	    /* Calculate the length of the name */
	    namelen = (keytab->ops && keytab->ops->prefix) ?
		strlen(keytab->ops->prefix)+1 : 0;
	    if (ktdata && ktdata->name)
		fnamep = ktdata->name;
	    else
		fnamep = (char *) ktfile_def_name;
	    namelen += (strlen(fnamep)+1);

	    if ((ktname = (char *) malloc(namelen))) {
		/* Format the keytab name. */
		if (keytab->ops && keytab->ops->prefix)
		    sprintf(ktname, "%s:%s", keytab->ops->prefix, fnamep);

		else
		    strcpy(ktname, fnamep);

		/* Fill in the file-specific keytab information. */
		if (ktdata) {
		    if (ktdata->datap != NULL) {
			long	fpos;
			int	fflags = 0;

			file_is_open = 1;
#if 0
#if !defined( macintosh) && !defined(_MSDOS) && !defined(_WIN32)
			fflags = fcntl(fileno(ktdata->openf), F_GETFL, 0);
			if (fflags > 0)
			    file_is_open |= ((fflags & O_ACCMODE) << 1);
#else
			file_is_open = 0;
#endif
			fpos = ftell(ktdata->openf);
#else
			fpos = ktdata->offset;
#endif

#if	SIZEOF_LONG == 4
			file_pos[0] = fpos;
#else	/* SIZEOF_LONG == 4 */
			file_pos[0] = fpos & 0xffffffff;
			file_pos[1] = (fpos >> 32) & 0xffffffff;
#endif	/* SIZEOF_LONG == 4 */
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
		(void) krb5_ser_pack_int32(file_pos[0], &bp, &remain);
		(void) krb5_ser_pack_int32(file_pos[1], &bp, &remain);

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
krb5_ktf_keytab_internalize(kcontext, argp, buffer, lenremain)
    krb5_context	kcontext;
    krb5_pointer	*argp;
    krb5_octet		**buffer;
    size_t		*lenremain;
{
    krb5_error_code	kret;
    krb5_keytab		keytab;
    krb5_int32		ibuf;
    krb5_octet		*bp;
    size_t		remain;
    char		*ktname;
    krb5_ktfile_data	*ktdata;
    krb5_int32		file_is_open;
    krb5_int32		foffbuf[2];

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
			(void) krb5_ser_unpack_int32(&foffbuf[0],
						     &bp, &remain);
			(void) krb5_ser_unpack_int32(&foffbuf[1],
						     &bp, &remain);
			(void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
			ktdata->version = (int) ibuf;

			(void) krb5_ser_unpack_int32(&ibuf, &bp, &remain);
			if (ibuf == KV5M_KEYTAB) {
			    if (file_is_open) {
				int 	fmode;
				long	fpos;

#if !defined( macintosh) && !defined(_MSDOS) && !defined(_WIN32)
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
#if	SIZEOF_LONG == 4
				    fpos = foffbuf[0];
#else	/* SIZEOF_LONG == 4 */
				    fpos = foffbuf[0] | ((long) foffbuf[1] << 32);
#endif	/* SIZEOF_LONG == 4 */
				    ktdata->offset = fpos;
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
