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
 * Copyright 1998-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_INET_IPSECAH_H
#define	_INET_IPSECAH_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL
/* Named Dispatch Parameter Management Structure */
typedef struct ipsecahpparam_s {
	uint_t	ipsecah_param_min;
	uint_t	ipsecah_param_max;
	uint_t	ipsecah_param_value;
	char	*ipsecah_param_name;
} ipsecahparam_t;

#endif	/* _KERNEL */

/*
 * For now, only provide "aligned" version of header.
 * If aligned version is needed, we'll go with the naming conventions then.
 */

typedef struct ah {
	uint8_t ah_nexthdr;
	uint8_t ah_length;
	uint16_t ah_reserved;
	uint32_t ah_spi;
	uint32_t ah_replay;
} ah_t;

#define	AH_BASELEN	12
#define	AH_TOTAL_LEN(ah)	(((ah)->ah_length << 2) + AH_BASELEN - \
					sizeof ((ah)->ah_replay))

/* "Old" AH, without replay.  For 1827-29 compatibility. */

typedef struct ahold {
	uint8_t ah_nexthdr;
	uint8_t ah_length;
	uint16_t ah_reserved;
	uint32_t ah_spi;
} ahold_t;

#define	AHOLD_BASELEN	8
#define	AHOLD_TOTAL_LEN(ah)	(((ah)->ah_length << 2) + AH_BASELEN)

#ifdef	__cplusplus
}
#endif

#endif /* _INET_IPSECAH_H */
