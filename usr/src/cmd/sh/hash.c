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
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	"hash.h"
#include	"defs.h"

#define STRCMP(A, B)	(cf(A, B) != 0)
#define FACTOR 	 		035761254233	/* Magic multiplication factor */
#define TABLENGTH		64				/* must be multiple of 2 */
#define LOG2LEN			6				/* log2 of TABLENGTH */

/*
    NOTE: The following algorithm only works on machines where
    the results of multiplying two integers is the least
    significant part of the double word integer required to hold
    the result.  It is adapted from Knuth, Volume 3, section 6.4.
*/

#define hash(str)		(int)(((unsigned)(crunch(str) * FACTOR)) >> shift)
struct node
{
	ENTRY item;
	struct node *next;
};

static struct node	**last;
static struct node	*next;
static struct node 	**table;

static unsigned int 	bitsper;		/* Bits per byte */
static unsigned int	shift;

static unsigned int crunch();

void
hcreate(void)
{
	unsigned char c = (unsigned char)~0;			/* A byte full of 1's */
	int j;

	table = (struct node **)alloc(TABLENGTH * sizeof(struct node *));

	for (j=0; j < TABLENGTH; ++j)  
	{
		table[j] = 0;
	}

	bitsper = 0;

	while (c)		
	{
		c = (unsigned int)c >> 1;
		bitsper++;
	}

	shift = (bitsper * sizeof(int)) - LOG2LEN;
}


void hscan(uscan)	
	void	(*uscan)();
{
	struct node		*p, *nxt;
	int				j;

	for (j=0; j < TABLENGTH; ++j)
	{
		p = table[j];
		while (p)
		{
			nxt = p->next;
			(*uscan)(&p->item);
			p = nxt;
		}
	}
}



ENTRY *
hfind(str)
	unsigned char	*str;
{
	struct node 	*p;
	struct node 	**q;
	unsigned int 	i;
	int 			res;		

	i = hash(str);

	if(table[i] == 0)
	{			
		last = &table[i];
		next = 0;
		return(0);
	}
	else 
	{
		q = &table[i];
		p = table[i];
		while (p != 0 && (res = STRCMP(str, p->item.key))) 
		{
			q = &(p->next);
			p = p->next;
		}

		if (p != 0 && res == 0)	
			return(&(p->item));
		else
		{
			last = q;
			next = p;
			return(0);
		}
	}
}

ENTRY *
henter(item)
	ENTRY item;
{
	struct node	*p = (struct node *)alloc(sizeof(struct node));

	p->item = item;
	*last = p;
	p->next = next;
	return(&(p->item));
}


static unsigned int 
crunch(key)	
	unsigned char	*key;
{
	unsigned int 	sum = 0;	
	int s;

	for (s = 0; *key; s++)				/* Simply add up the bytes */
		sum += *key++;

	return(sum + s);
}

