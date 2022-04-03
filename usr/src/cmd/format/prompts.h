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
 * Copyright 1991-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PROMPTS_H
#define	_PROMPTS_H

#ifdef	__cplusplus
extern "C" {
#endif


int	get_ncyl(void);
uint64_t	get_mlba(void);
int	get_acyl(int n_cyls);
int	get_pcyl(int n_cyls, int p_cyls);
int	get_nhead(void);
int	get_phead(int n_heads, ulong_t *option);
int	get_nsect(void);
int	get_psect(ulong_t *option);
int	get_bpt(int n_sects, ulong_t *option);
int	get_rpm(void);
int	get_fmt_time(ulong_t *option);
int	get_cyl_skew(ulong_t *option);
int	get_trk_skew(ulong_t *option);
int	get_trks_zone(ulong_t *option);
int	get_atrks(ulong_t *option);
int	get_asect(ulong_t *option);
int	get_cache(ulong_t *option);
int	get_threshold(ulong_t *option);
int	get_min_prefetch(ulong_t *option);
int	get_max_prefetch(int min_prefetch, ulong_t *option);
int	get_bps(void);
char	*get_asciilabel(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _PROMPTS_H */
