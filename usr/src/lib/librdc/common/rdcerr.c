/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/types.h>
#include <stdio.h>
#include <errno.h>
#include <libintl.h>
#include <locale.h>
#include <stdlib.h>
#include <stdarg.h>

#include <sys/nsctl/rdcerr.h>
#include <sys/nsctl/cfg.h>

#include <sys/unistat/spcs_dtrinkets.h>
#include <sys/unistat/spcs_etrinkets.h>
#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_u.h>
#include <sys/unistat/spcs_s_impl.h>
#include <sys/unistat/spcs_errors.h>


int rdc_severity;
char *rdc_error_str;
char err[RDC_ERR_SIZE];

void
rdc_set_error(spcs_s_info_t *ustatus, int context, int severity,
    char *errorstr, ...)
{
	char msg[1024];
	va_list ap;

	bzero(err, RDC_ERR_SIZE);
	switch (context) {
	case RDC_INTERNAL:
		rdc_severity = severity;
		if (errorstr) {
			va_start(ap, errorstr);
			vsprintf(err, errorstr, ap);
			va_end(ap);
		}
		rdc_error_str = dgettext("librdc", err ? err : "");
		break;

	case RDC_OS:
		rdc_severity = severity ? severity : RDC_FATAL;
		rdc_error_str =  strerror(errno);
		break;

	case RDC_SPCS:
		rdc_severity = severity ? severity : RDC_FATAL;
		rdc_error_str = spcs_s_string(*ustatus, msg);
		break;

	case RDC_DSCFG:
		rdc_error_str = cfg_error(&rdc_severity);
		break;

	default:
		break;
	}

	spcs_log("librdc", NULL, dgettext("librdc", "%s"),
	    rdc_error_str ? rdc_error_str : "");

}

char *
rdc_error(int *severity)
{
	if (severity != NULL)
		*severity = rdc_severity;
	return (rdc_error_str ? rdc_error_str : "");
}
