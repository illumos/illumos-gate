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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file is used to verify that the standalone's external dependencies
 * haven't changed in a way that'll break things that use it.
 */

void mdb_free(void) {}
void mdb_snprintf(void) {}
void mdb_iob_vsnprintf(void) {}
void mdb_zalloc(void) {}
void strcmp(void) {}
void strlen(void) {}
void strlcat(void) {}
void strncpy(void) {}
void strncmp(void) {}
void memcpy(void) {}
void _memcpy(void) {}
