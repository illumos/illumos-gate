/*
 * Copyright 1996-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  glue routine for gss_release_buffer
 */

#include <gssapiP_generic.h>

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

OM_uint32
generic_gss_release_buffer (minor_status,
			    buffer)
     OM_uint32 *		minor_status;
     gss_buffer_t		buffer;
{
    if (minor_status)
	*minor_status = 0;

    /* if buffer is NULL, return */

    if (buffer == GSS_C_NO_BUFFER)
	return(GSS_S_COMPLETE);

    if ((buffer->length) &&
	(buffer->value)) {
	free(buffer->value);
	buffer->length = 0;
	buffer->value = NULL;
    }

    return (GSS_S_COMPLETE);
}
