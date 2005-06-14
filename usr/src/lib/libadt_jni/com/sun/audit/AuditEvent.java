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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * ident	"%Z%%M%	%I%	%E% SMI"
 *
 * Automatically generated code; do not edit
 */
package com.sun.audit;

public class AuditEvent {
	protected AuditSession sh;	// associated session object

	public AuditEvent(AuditSession auSession)
	    throws Error
	{

		sh = auSession;
	}

	// See the subclasses of AuditEvent for mapping message codes
	// to events

	// adt_fail_pam

	public static final int ADT_FAIL_PAM = 2000;

	// adt_fail_value

	public static final int ADT_FAIL_VALUE = 1000;
	// Attribute update
	public static final int ADT_FAIL_VALUE_PW_ATTR = 1000;
	// Password update
	public static final int ADT_FAIL_VALUE_PW = 1001;
	// bad username
	public static final int ADT_FAIL_VALUE_USERNAME = 1002;
	// bad auth.
	public static final int ADT_FAIL_VALUE_AUTH = 1003;
	// bad uid
	public static final int ADT_FAIL_VALUE_UID = 1004;
	// unknown failure
	public static final int ADT_FAIL_VALUE_UNKNOWN = 1005;
	// password expired
	public static final int ADT_FAIL_VALUE_EXPIRED = 1006;
	// Account is locked
	public static final int ADT_FAIL_VALUE_ACCOUNT_LOCKED = 1007;
	// Bad dial up
	public static final int ADT_FAIL_VALUE_BAD_DIALUP = 1008;
	// Invalid ID
	public static final int ADT_FAIL_VALUE_BAD_ID = 1009;
	// Invalid password
	public static final int ADT_FAIL_VALUE_BAD_PW = 1010;
	// Not on console
	public static final int ADT_FAIL_VALUE_CONSOLE = 1011;
	// Too many failed attempts
	public static final int ADT_FAIL_VALUE_MAX_TRIES = 1012;
	// Protocol failure
	public static final int ADT_FAIL_VALUE_PROTOCOL_FAILURE = 1013;
	// Excluded user
	public static final int ADT_FAIL_VALUE_EXCLUDED_USER = 1014;
	// No anonymous
	public static final int ADT_FAIL_VALUE_ANON_USER = 1015;
	// Invalid command
	public static final int ADT_FAIL_VALUE_BAD_CMD = 1016;
	// Standard input not a tty line
	public static final int ADT_FAIL_VALUE_BAD_TTY = 1017;
	// Program failure
	public static final int ADT_FAIL_VALUE_PROGRAM = 1018;
	// chdir to home directory
	public static final int ADT_FAIL_VALUE_CHDIR_FAILED = 1019;
	// Input line too long.
	public static final int ADT_FAIL_VALUE_INPUT_OVERFLOW = 1020;
	// login device override
	public static final int ADT_FAIL_VALUE_DEVICE_PERM = 1021;
	// authorization bypass
	public static final int ADT_FAIL_VALUE_AUTH_BYPASS = 1022;
	// login disabled
	public static final int ADT_FAIL_VALUE_LOGIN_DISABLED = 1023;

	// adt_login_text

	// Deprecated message list
	// 
	public static final int ADT_LOGIN_NO_MSG = 0;
	// Account is locked
	public static final int ADT_LOGIN_ACCOUNT_LOCKED = 1;
	// Bad dial up
	public static final int ADT_LOGIN_BAD_DIALUP = 2;
	// Invalid ID
	public static final int ADT_LOGIN_BAD_ID = 3;
	// Invalid password
	public static final int ADT_LOGIN_BAD_PW = 4;
	// Not on console
	public static final int ADT_LOGIN_CONSOLE = 5;
	// Too many failed attempts
	public static final int ADT_LOGIN_MAX_TRIES = 6;
	// Protocol failure
	public static final int ADT_LOGIN_PROTOCOL_FAILURE = 7;
	// Excluded user
	public static final int ADT_LOGIN_EXCLUDED_USER = 8;
	// No anonymous
	public static final int ADT_LOGIN_ANON_USER = 9;

}
