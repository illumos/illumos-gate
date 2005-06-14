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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
	  /* from UCB 4.1 80/12/21 */

/*
 * calloc - allocate and clear memory block
 */
#define CHARPERINT (sizeof(int)/sizeof(char))
#define NULL 0
#ifdef	S5EMUL
#define	ptr_t	void*
#else
#define	ptr_t	char*
#endif

ptr_t
calloc(num, size)
	unsigned num, size;
{
	register ptr_t mp;
	ptr_t	malloc();

	num *= size;
	mp = malloc(num);
	if (mp == NULL)
		return(NULL);
	bzero(mp, num);
	return ((ptr_t)(mp));
}

cfree(p, num, size)
	ptr_t p;
	unsigned num, size;
{
	free(p);
}
