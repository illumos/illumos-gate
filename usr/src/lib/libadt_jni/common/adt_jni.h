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
 * adt_jni.h
 *
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * This is a private interface.
 *
 * Most of the interfaces provided by adt_jni.c are
 * defined in ../com/sun/audit/AuditSession.h because
 * of basic JNI architecture.
 */

#ifndef _ADT_JNI_H
#define	_ADT_JNI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <jni.h>
#include <libintl.h>
#include <locale.h>

#ifdef	__cplusplus
extern "C" {
#endif

int  j2c_pointer(JNIEnv *env, jbyteArray jpointer, caddr_t *cpointer);
void c2j_pointer(JNIEnv *env, caddr_t cpointer, jbyteArray *jpointer);
void local_throw(JNIEnv *env, const char *exception, const char *why);

#define	I18N_SETUP setlocale(LC_MESSAGES, "");\
	(void) textdomain(TEXT_DOMAIN)

#ifdef	__cplusplus
}
#endif

#endif	/* _ADT_JNI_H */
