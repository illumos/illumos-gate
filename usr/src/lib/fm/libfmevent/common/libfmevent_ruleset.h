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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _LIBFMEVENT_RULESET_H
#define	_LIBFMEVENT_RULESET_H

/*
 * Event Rulesets.  A ruleset is selected by a (namespace, subsystem)
 * combination, which together we call a "ruleset" selection for that
 * namespace.  The strings can be any ascii string not including
 * control characters or DEL.
 *
 * Selection of a ruleset determines how a "raw" event that we publish
 * using the libfmevent publication interfaces is post-processed into
 * a full protocol event.
 *
 * New rulesets must follow the FMA Event Registry and Portfolio Review
 * process.  At this time only FMEV_RULESET_SMF and FMEV_RULESET_ON_SUNOS
 * rulesets are adopted by that process - the others listed here are
 * experimental.
 */

#define	FMEV_MAX_RULESET_LEN	31

#define	FMEV_RS_SEPARATOR		"\012"
#define	FMEV_MKRS(v, s)			FMEV_V_##v FMEV_RS_SEPARATOR s

/*
 * Namespaces
 */
#define	FMEV_V_ALL		"*"
#define	FMEV_V_SOLARIS_ON	"solaris-osnet"	/* Solaris ON Consolidation */

/*
 * Generic and namespace-agnostic rulesets
 */
#define	FMEV_RULESET_UNREGISTERED	FMEV_MKRS(ALL, "unregistered")
#define	FMEV_RULESET_DEFAULT		FMEV_RULESET_UNREGISTERED
#define	FMEV_RULESET_SMF		FMEV_MKRS(ALL, "smf")

/*
 * Solaris ON rulesets
 */
#define	FMEV_RULESET_ON_EREPORT		FMEV_MKRS(SOLARIS_ON, "ereport")
#define	FMEV_RULESET_ON_SUNOS		FMEV_MKRS(SOLARIS_ON, "sunos")
#define	FMEV_RULESET_ON_PRIVATE		FMEV_MKRS(SOLARIS_ON, "private")

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif /* _LIBFMEVENT_RULESET_H */
