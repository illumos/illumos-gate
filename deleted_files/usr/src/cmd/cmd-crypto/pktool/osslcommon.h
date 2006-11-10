/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PKTOOL_OSSLCOMMON_H
#define	_PKTOOL_OSSLCOMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/x509.h>

extern void		PKTOOL_setup_openssl(void);
extern unsigned char	*PKTOOL_X509_keyid_get0(X509 *x, int *len);
extern unsigned char	*PKTOOL_X509_subject_name(X509 *x, int *len);
extern unsigned char	*PKTOOL_X509_issuer_name(X509 *x, int *len);
extern unsigned char	*PKTOOL_X509_serial_number(X509 *x, int *len);
extern unsigned char	*PKTOOL_X509_cert_value(X509 *x, int *len);
extern int		PKTOOL_cvt_ossltime(ASN1_TIME *t, char *buf);

#ifdef	__cplusplus
}
#endif

#endif /* _PKTOOL_OSSLCOMMON_H */
