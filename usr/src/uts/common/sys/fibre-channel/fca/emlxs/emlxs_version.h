/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2012 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_EMLXS_VERSION_H
#define	_EMLXS_VERSION_H

#ifdef	__cplusplus
extern "C" {
#endif
#define	EMLXS_COPYRIGHT		"Copyright (c) 2004-2012 Emulex. " \
				    "All rights reserved."


#define	EMLXS_VERSION		"2.80.8.0"
#define	EMLXS_DATE_MINUTE	"45"	/* 00-59 */
#define	EMLXS_DATE_HOUR		"15"	/* 00-23 */
#define	EMLXS_DATE_DAY		"17"	/* 00-31 */
#define	EMLXS_DATE_MONTH	"09"	/* 01-12 */
#define	EMLXS_DATE_YEAR		"2012"	/* YYYY  */

#define	EMLXS_REVISION		EMLXS_DATE_YEAR "." EMLXS_DATE_MONTH "." \
				    EMLXS_DATE_DAY "." EMLXS_DATE_HOUR "." \
				    EMLXS_DATE_MINUTE
#define	EMLXS_NAME		""DRIVER_NAME" FCA v" EMLXS_DATE_YEAR \
				    EMLXS_DATE_MONTH EMLXS_DATE_DAY "-" \
				    EMLXS_VERSION
#define	EMLXS_LABEL		"Emulex-S s" VERSION "-" EMLXS_ARCH " " \
				    MACH " v" EMLXS_VERSION
#define	EMLXS_FW_NAME		""DRIVER_NAME" FW v" EMLXS_DATE_YEAR \
				    EMLXS_DATE_MONTH EMLXS_DATE_DAY "-" \
				    EMLXS_VERSION

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_VERSION_H */
