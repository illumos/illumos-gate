/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 * 
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include "gssapiP_krb5.h"
#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

/* Checksumming the channel bindings always uses plain MD5.  */
krb5_error_code
kg_checksum_channel_bindings(context, cb, cksum, bigend)
     krb5_context context;
     gss_channel_bindings_t cb;
     krb5_checksum *cksum;
     int bigend;
{
   size_t len;
   char *buf = 0;
   char *ptr;
   size_t sumlen;
   krb5_data plaind;
   krb5_error_code code;
   void *temp;

   /* initialize the the cksum */
   code = krb5_c_checksum_length(context, CKSUMTYPE_RSA_MD5, &sumlen);
   if (code)
       return(code);

   cksum->checksum_type = CKSUMTYPE_RSA_MD5;
   cksum->length = sumlen;
 
   /* generate a buffer full of zeros if no cb specified */

   if (cb == GSS_C_NO_CHANNEL_BINDINGS) {
       if ((cksum->contents = (krb5_octet *) xmalloc(cksum->length)) == NULL) {
	   return(ENOMEM);
       }
       memset(cksum->contents, '\0', cksum->length);
       return(0);
   }

   /* create the buffer to checksum into */

   len = (sizeof(krb5_int32)*5+
	  cb->initiator_address.length+
	  cb->acceptor_address.length+
	  cb->application_data.length);

   if ((buf = (char *) xmalloc(len)) == NULL)
      return(ENOMEM);

   /* helper macros.  This code currently depends on a long being 32
      bits, and htonl dtrt. */

   ptr = buf;

   TWRITE_INT(ptr, cb->initiator_addrtype, bigend);
   TWRITE_BUF(ptr, cb->initiator_address, bigend);
   TWRITE_INT(ptr, cb->acceptor_addrtype, bigend);
   TWRITE_BUF(ptr, cb->acceptor_address, bigend);
   TWRITE_BUF(ptr, cb->application_data, bigend);

   /* checksum the data */

   plaind.length = len;
   plaind.data = buf;

#if 0
   /*
    * SUNW15resync
    * MIT 1.5-6 seems/is wrong here in 2 ways
    *   - why free then alloc contents again?
    *   - calling krb5_free_checksum_contents results in cksum->length
    *     getting set to 0 which causes ftp to fail
    * so lets stick w/oldey-but-goodey code.
    */
   code = krb5_c_make_checksum(context, CKSUMTYPE_RSA_MD5, 0, 0,
			       &plaind, cksum);
   if (code)
       goto cleanup;

   if ((temp = xmalloc(cksum->length)) == NULL) {
       krb5_free_checksum_contents(context, cksum);
       code = ENOMEM;
       goto cleanup;
   }

   memcpy(temp, cksum->contents, cksum->length);
   krb5_free_checksum_contents(context, cksum);
   cksum->contents = (krb5_octet *)temp;
   /* SUNW15resync - need to reset cksum->length here */

   /* success */
 cleanup:
   if (buf)
       xfree(buf);
#endif /* 0 */

   if (code = krb5_c_make_checksum(context, CKSUMTYPE_RSA_MD5, 0, 0, 
                                   &plaind, cksum)) { 
      xfree(cksum->contents); /* SUNW15resync -just in case not already free */
      xfree(buf); 
      return(code); 
   } 
 
   /* success */ 
 
   xfree(buf); 
   return code;
}
