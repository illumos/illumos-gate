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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * HEADER: dat_sr_parser.h
 *
 * PURPOSE: static registry (SR) parser inteface declarations
 *
 * $Id: udat_sr_parser.h,v 1.1 2003/07/31 14:04:19 jlentini Exp $
 */

#ifndef _DAT_SR_PARSER_H_
#define	_DAT_SR_PARSER_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <dat_osd.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *
 * Function Declarations
 *
 */

/*
 * The static registry exports the same interface regardless of
 * platform. The particular implementation of dat_sr_load() is
 * found with other platform dependent sources.
 */

extern DAT_RETURN
dat_sr_load(void);

#ifdef	__cplusplus
}
#endif

#endif /* _DAT_SR_PARSER_H_ */
