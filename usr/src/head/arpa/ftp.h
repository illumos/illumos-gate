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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef _ARPA_FTP_H
#define	_ARPA_FTP_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Definitions for FTP
 * See RFC-765
 */

/*
 * Reply codes.
 */
#define	PRELIM		1	/* positive preliminary */
#define	COMPLETE	2	/* positive completion */
#define	CONTINUE	3	/* positive intermediate */
#define	TRANSIENT	4	/* transient negative completion */
#define	ERROR		5	/* permanent negative completion */

/*
 * Type codes
 */
#define	TYPE_A		1	/* ASCII */
#define	TYPE_E		2	/* EBCDIC */
#define	TYPE_I		3	/* image */
#define	TYPE_L		4	/* local byte size */
#ifdef FTP_NAMES
char *typenames[] =
{"0", "ASCII", "EBCDIC", "Image", "Local"};
#endif

/*
 * Form codes
 */
#define	FORM_N		1	/* non-print */
#define	FORM_T		2	/* telnet format effectors */
#define	FORM_C		3	/* carriage control (ASA) */
#ifdef FTP_NAMES
char *formnames[] =
{"0", "Nonprint", "Telnet", "Carriage-control"};
#endif

/*
 * Structure codes
 */
#define	STRU_F		1	/* file (no record structure) */
#define	STRU_R		2	/* record structure */
#define	STRU_P		3	/* page structure */
#ifdef FTP_NAMES
char *strunames[] =
{"0", "File", "Record", "Page"};
#endif

/*
 * Mode types
 */
#define	MODE_S		1	/* stream */
#define	MODE_B		2	/* block */
#define	MODE_C		3	/* compressed */
#ifdef FTP_NAMES
char *modenames[] =
{"0", "Stream", "Block", "Compressed"};
#endif

/*
 * Authentication types
 */
#define	AUTHTYPE_NONE   0
#define	AUTHTYPE_GSSAPI 1
#ifdef  FTP_NAMES
char *authtypenames[] = {
	"NONE", "GSSAPI", 0
};
#define	GSS_AUTHTYPE_NAME(x)	authtypenames[x]
#endif

/*
 * Protection levels
 */
#define	PROT_C		1	/* no integrity; no encryption */
#define	PROT_S		2	/*    integrity; no encryption */
#define	PROT_P		3	/*    integrity;    encryption */
#define	PROT_E		4	/* no integrity;    encryption */
#ifdef	FTP_NAMES
char *protnames[] =
	{"0", "Clear", "Safe", "Private", "Confidential"};
#endif

/*
 * Record Tokens
 */
#define	REC_ESC		'\377'	/* Record-mode Escape */
#define	REC_EOR		'\001'	/* Record-mode End-of-Record */
#define	REC_EOF		'\002'	/* Record-mode End-of-File */

/*
 * Block Header
 */
#define	BLK_EOR		0x80	/* Block is End-of-Record */
#define	BLK_EOF		0x40	/* Block is End-of-File */
#define	BLK_ERRORS	0x20	/* Block is suspected of containing errors */
#define	BLK_RESTART	0x10	/* Block is Restart Marker */

#define	BLK_BYTECOUNT	2	/* Bytes in this block */

#ifdef	__cplusplus
}
#endif

#endif /* _ARPA_FTP_H */
