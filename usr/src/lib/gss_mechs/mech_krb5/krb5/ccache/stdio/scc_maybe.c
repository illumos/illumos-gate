/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * lib/krb5/ccache/stdio/scc_maybe.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Copyright 1995 by Cygnus Support.
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
 * This file contains the source code for conditional open/close calls.
 */

#include "scc.h"
#include <k5-int.h>

#ifdef macintosh
/*
 * Kludge for the Macintosh, since fopen doesn't set errno, but open
 * does...
 */
static FILE *my_fopen(char *path, char *mode)
{
	int	fd, open_flags;
	FILE	*f;

	f = fopen(path, mode);
	if (f)
		return f;
	/*
	 * OK, fopen failed; let's try to figure out why....
	 */
	if (strchr(mode, '+'))
		open_flags = O_RDWR;
	else if (strchr(mode, 'w') || strchr(mode, 'a'))
		open_flags = O_WRONLY;
	else
		open_flags = O_RDONLY;
	if (strchr(mode, 'a'))
		open_flags  |= O_APPEND;

	fd = open(path, open_flags);
	if (fd == -1)
		return NULL;
	/*
	 * fopen failed, but open succeeded?   W*E*I*R*D.....
	 */
	close(fd);
	errno = KRB5_CC_IO;
	
	return NULL;
}
#endif

krb5_error_code
krb5_scc_close_file (context, id)
   krb5_context context;
    krb5_ccache id;
{
     krb5_scc_data *data;
     int ret;
     krb5_error_code retval;

     data = (krb5_scc_data *) id->data;
     if (data->file == (FILE *) NULL)
	 return KRB5_FCC_INTERNAL;
#ifdef ultrix
     errno = 0;
#endif
     ret = fflush (data->file);
#ifdef ultrix
     /* their LIBC refuses to allow an fflush() of a read-only buffer!
	We patch around it by only calling it an error if errno is set by a
	(failed) syscall */
     if (ret == EOF && !errno) ret = 0;
#endif
     memset (data->stdio_buffer, 0, sizeof (data->stdio_buffer));
     if (ret == EOF) {
	  int errsave = errno;
	  (void) krb5_unlock_file(context, fileno(data->file));
	  (void) fclose (data->file);
	  data->file = 0;
	  return krb5_scc_interpret (context, errsave);
     }
     retval = krb5_unlock_file(context, fileno(data->file));
     ret = fclose (data->file);
     data->file = 0;
     if (retval)
	 return retval;
     else
     return ret ? krb5_scc_interpret (context, errno) : 0;
}

krb5_error_code
krb5_scc_open_file (context, id, mode)
    krb5_context context;
    krb5_ccache id;
    int mode;
{
    krb5_os_context os_ctx = (krb5_os_context) context->os_context;
    krb5_scc_data *data = (krb5_scc_data *) id->data;
    char fvno_bytes[2];		/* In nework byte order */
    krb5_ui_2 scc_tag;
    krb5_ui_2 scc_taglen;
    krb5_ui_2 scc_hlen;
    FILE *f;
    char *open_flag;
    krb5_error_code retval = 0;

    if (data->file) {
	/* Don't know what state it's in; shut down and start anew.  */
	(void) krb5_unlock_file(context, fileno(data->file));
	(void) fclose (data->file);
	data->file = 0;
    }
#ifdef ANSI_STDIO
    switch(mode) {
    case SCC_OPEN_AND_ERASE:
	unlink(data->filename);
	/* XXX should do an exclusive open here, but no way to do */
	/* this under stdio */
	open_flag = "wb+";
	break;
    case SCC_OPEN_RDWR:
	open_flag = "rb+";
	break;
    case SCC_OPEN_RDONLY:
    default:
	open_flag = "rb";
	break;
    }
#else
    switch(mode) {
    case SCC_OPEN_AND_ERASE:
	unlink(data->filename);
	/* XXX should do an exclusive open here, but no way to do */
	/* this under stdio */
	open_flag = "w+";
	break;
    case SCC_OPEN_RDWR:
	open_flag = "r+";
	break;
    case SCC_OPEN_RDONLY:
    default:
	open_flag = "r";
	break;
    }
#endif

#ifdef macintosh
    f = my_fopen (data->filename, open_flag);
#else
    f = fopen (data->filename, open_flag);
#endif
    if (!f)
	return krb5_scc_interpret (context, errno);
#ifdef HAVE_SETVBUF
    setvbuf(f, data->stdio_buffer, _IOFBF, sizeof (data->stdio_buffer));
#else
    setbuf (f, data->stdio_buffer);
#endif
    switch (mode) {
    case SCC_OPEN_RDONLY:
	if ((retval = krb5_lock_file(context,fileno(f),KRB5_LOCKMODE_SHARED))){
	    (void) fclose(f);
	    return retval;
	}
	break;
    case SCC_OPEN_RDWR:
    case SCC_OPEN_AND_ERASE:
	if ((retval = krb5_lock_file(context, fileno(f),
				     KRB5_LOCKMODE_EXCLUSIVE))) {
	    (void) fclose(f);
	    return retval;
	}
	break;
    }
    if (mode == SCC_OPEN_AND_ERASE) {
	/* write the version number */

	data->file = f;
	data->version = context->scc_default_format;
	retval = krb5_scc_store_ui_2(context, id, data->version);
	if (retval) goto done;

	if (data->version == KRB5_SCC_FVNO_4) {
	    scc_hlen = 0;

	    if (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID)
                 scc_hlen += (2*sizeof(krb5_ui_2) + 2*sizeof(krb5_int32));

	    /* Write header length */
	    retval = krb5_scc_store_ui_2(context, id, (krb5_int32)scc_hlen);
	    if (retval) goto done;

	    if (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID) {
		/* Write time offset tag */
		scc_tag = SCC_TAG_DELTATIME;
		scc_taglen = 2*sizeof(krb5_int32);

		retval = krb5_scc_store_ui_2(context,id,(krb5_int32)scc_tag);
		if (retval) goto done;
		retval = krb5_scc_store_ui_2(context,id,(krb5_int32)scc_taglen);
		if (retval) goto done;
		retval = krb5_scc_store_int32(context,id,os_ctx->time_offset);
		if (retval) goto done;
		retval = krb5_scc_store_int32(context,id,os_ctx->usec_offset);
		if (retval) goto done;
	    }
	}
	goto done;
    }

    /* verify a valid version number is there */
    if (!fread((char *)fvno_bytes, sizeof(fvno_bytes), 1, f))
    {
	retval = KRB5_CC_FORMAT;
	goto done;
    }
    data->version = (fvno_bytes[0] << 8) + fvno_bytes[1];
    if ((data->version != KRB5_SCC_FVNO_1) &&
	(data->version != KRB5_SCC_FVNO_2) &&
	(data->version != KRB5_SCC_FVNO_3) &&
	(data->version != KRB5_SCC_FVNO_4))
    {
	retval = KRB5_CCACHE_BADVNO;
	goto done;
    }

    data->file = f;

    if (data->version == KRB5_SCC_FVNO_4) {
	char buf[1024];

	if (krb5_scc_read_ui_2(context, id, &scc_hlen) ||
	    (scc_hlen > sizeof(buf)))
	{
	    retval = KRB5_CC_FORMAT;
	    goto done;
	}
	
	while (scc_hlen) {
	    if ((scc_hlen < (2*sizeof(krb5_ui_2))) ||
		krb5_scc_read_ui_2(context, id, &scc_tag) ||
		krb5_scc_read_ui_2(context, id, &scc_taglen) ||
		(scc_taglen > (scc_hlen - 2*sizeof(krb5_ui_2))))
	    {
		retval = KRB5_CC_FORMAT;
		goto done;
	    }

	    switch (scc_tag) {
	    case SCC_TAG_DELTATIME:
		if (scc_taglen != 2*sizeof(krb5_int32)) {
		    retval = KRB5_CC_FORMAT;
		    goto done;
		}
                 if (!(context->library_options & KRB5_LIBOPT_SYNC_KDCTIME) ||
                     (os_ctx->os_flags & KRB5_OS_TOFFSET_VALID))
                 {
                     if (krb5_scc_read(context, id, buf, scc_taglen)) {
                         retval = KRB5_CC_FORMAT;
                         goto done;
                     }
                     break;
                 }
                 if (krb5_scc_read_int32(context, id, &os_ctx->time_offset) ||
                     krb5_scc_read_int32(context, id, &os_ctx->usec_offset))
                 {
                     retval = KRB5_CC_FORMAT;
                     goto done;
                 }
                 os_ctx->os_flags =
                     ((os_ctx->os_flags & ~KRB5_OS_TOFFSET_TIME) |
                      KRB5_OS_TOFFSET_VALID);
                 break;
	    default:
                 if (scc_taglen && krb5_scc_read(context,id,buf,scc_taglen)) {
                     retval = KRB5_CC_FORMAT;
                     goto done;
                 }
                 break;
	    }
	    scc_hlen -= (2*sizeof(krb5_ui_2) + scc_taglen);
	}
    }

done:
    if (retval)
	if (f) {
	    data->file = 0;
	    (void) krb5_unlock_file(context, fileno(f));
	    (void) fclose(f);
	}
    return retval;
}
