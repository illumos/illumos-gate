/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1985, 1989 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "ftp_var.h"
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

void
user_gss_error(OM_uint32 maj_stat, OM_uint32 min_stat, char *errstr)
{
	OM_uint32 gmaj_stat, gmin_stat;
	gss_buffer_desc msg;
	OM_uint32 msg_ctx = 0;
	int display_error = 0;

	/* Print the major status error from GSS */
	while (!msg_ctx) {
	    gmaj_stat = gss_display_status(&gmin_stat, maj_stat,
		GSS_C_GSS_CODE, GSS_C_NULL_OID, &msg_ctx, &msg);
	    if ((gmaj_stat == GSS_S_COMPLETE)||
		(gmaj_stat == GSS_S_CONTINUE_NEEDED)) {
		/* display error messages only once */
		if ((debug) || (!display_error)) {
		    (void) fprintf(stderr, "GSSAPI error major: %s\n",
			(char *)msg.value);
		    display_error = 1;
		}
		(void) gss_release_buffer(&gmin_stat, &msg);
	    }
	    if (gmaj_stat != GSS_S_CONTINUE_NEEDED)
		break;
	}

	/* Print the minor status error from the mech */
	msg_ctx = 0;
	display_error = 0;
	if (min_stat)
	    while (!msg_ctx) {
		gmaj_stat = gss_display_status(&gmin_stat, min_stat,
		    GSS_C_MECH_CODE, GSS_C_NULL_OID, &msg_ctx, &msg);
		if ((gmaj_stat == GSS_S_COMPLETE)||
		    (gmaj_stat == GSS_S_CONTINUE_NEEDED)) {
		    /* display error messages only once */
		    if ((!display_error) || (!debug)) {
			(void) fprintf(stderr, "GSSAPI error minor: %s\n",
			    (char *)msg.value);
			display_error = 1;
		    }
		    (void) gss_release_buffer(&gmin_stat, &msg);
		}
		if (gmaj_stat != GSS_S_CONTINUE_NEEDED)
			break;
	    }

	if (debug) {
	    (void) fprintf(stderr, "GSSAPI error: %s\n", errstr);
	}
}
