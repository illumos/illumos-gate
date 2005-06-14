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
 * Copyright 1987 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * Integer, short and long representations of audit event classes
 * used by audit mechanism.
 *
 * audit.h must be included before this include file. AU_* values
 * are defined in audit.h.
 */

#ifndef _auevents_h
#define _auevents_h

#define AU_ALL AU_DREAD|AU_DWRITE|AU_DACCESS|AU_DCREATE|AU_LOGIN|AU_SREAD|AU_SCTL  |AU_MINPRIV|AU_MAJPRIV|AU_ADMIN|AU_ASSIGN

struct event_cl {
	unsigned int event_mask;
	char *event_sname;
	char *event_lname;
} event_class[] ={
	AU_DREAD,	"dr",	"data_read",
	AU_DWRITE,	"dw",	"data_write",
	AU_DACCESS,	"da",	"data_access_change",
	AU_DCREATE,	"dc",	"data_create",
	AU_LOGIN,	"lo",	"login_logout",
	AU_SREAD,	"sr",	"spooler_read",
	AU_SCTL,	"sc",	"spooler_control",
	AU_MINPRIV,	"p0",	"minor_privilege",
	AU_MAJPRIV,	"p1",	"major_privilege",
	AU_ADMIN,	"ad",	"administrative",
	AU_ASSIGN,	"as",	"device_assign",
	AU_ALL,		"all",	"all"
};

#endif /*!_auevents_h*/
