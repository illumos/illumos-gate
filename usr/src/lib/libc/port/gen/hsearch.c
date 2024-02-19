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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Compile time switches:
 *
 *  MULT - use a multiplicative hashing function.
 *  DIV - use the remainder mod table size as a hashing function.
 *  CHAINED - use a linked list to resolve collisions.
 *  OPEN - use open addressing to resolve collisions.
 *  BRENT - use Brent's modification to improve the OPEN algorithm.
 *  SORTUP - CHAINED list is sorted in increasing order.
 *  SORTDOWN - CHAINED list is sorted in decreasing order.
 *  START - CHAINED list with entries appended at front.
 *  DRIVER - compile in a main program to drive the tests.
 *  HSEARCH_DEBUG - compile some debugging printout statements.
 *  USCR - user supplied comparison routine.
 */

#pragma weak _hcreate = hcreate
#pragma weak _hdestroy = hdestroy
#pragma weak _hsearch = hsearch

#include "lint.h"
#include <mtlib.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread.h>
#include <synch.h>
#include <search.h>

typedef char *POINTER;

#define	SUCCEED		0
#define	FAIL		1
#define	TRUE		1
#define	FALSE		0
#define	repeat		for (;;)
#define	until(A)	if (A) break;

#ifdef OPEN
#undef CHAINED
#else
#ifndef CHAINED
#define	OPEN
#endif
#endif

#ifdef MULT
#undef DIV
#else
#ifndef DIV
#define	MULT
#endif
#endif

#ifdef START
#undef SORTUP
#undef SORTDOWN
#else
#ifdef SORTUP
#undef SORTDOWN
#endif
#endif

#ifdef USCR
#define	COMPARE(A, B) (* hcompar)((A), (B))
extern int (* hcompar)();
#else
#define	COMPARE(A, B) strcmp((A), (B))
#endif

#ifdef MULT
#define	SHIFT ((CHAR_BIT * sizeof (int)) - m) /* Shift factor */
#define	FACTOR 035761254233	/* Magic multiplication factor */
#define	HASH hashm		/* Multiplicative hash function */
#define	HASH2 hash2m	/* Secondary hash function */
static unsigned int hashm(POINTER);
static unsigned int hash2m(POINTER);
#else
#ifdef DIV
#define	HASH hashd		/* Division hashing routine */
#define	HASH2(A) 1		/* Secondary hash function */
static unsigned int hashd();
#endif
#endif

#ifdef CHAINED
typedef struct node {	/* Part of the linked list of entries */
	ENTRY item;
	struct node *next;
} NODE;
typedef NODE *TABELEM;
static NODE **table;	/* The address of the hash table */
static ENTRY *build();
#else
#ifdef OPEN
typedef ENTRY TABELEM;	/* What the table contains (TABle ELEMents) */
static TABELEM *table;	/* The address of the hash table */
static unsigned int count = 0;	/* Number of entries in hash table */
#endif
#endif

static unsigned int length;	/* Size of the hash table */
static unsigned int m;		/* Log base 2 of length */
static unsigned int prcnt;	/* Number of probes this item */
static mutex_t table_lock = DEFAULTMUTEX;
#define	RETURN(n)    { lmutex_unlock(&table_lock); return (n); }

/*
 * forward declarations
 */

static unsigned int crunch(POINTER);

#ifdef DRIVER
static void hdump();

main()
{
	char line[80];	/* Room for the input line */
	int i = 0;		/* Data generator */
	ENTRY *res;		/* Result of hsearch */
	ENTRY *new;		/* Test entry */

start:
	if (hcreate(5))
		printf("Length = %u, m = %u\n", length, m);
	else {
		fprintf(stderr, "Out of core\n");
		exit(FAIL);
	}
	repeat {
	hdump();
	printf("Enter a probe: ");
	until(EOF == scanf("%s", line) || strcmp(line, "quit") == 0);
#ifdef HSEARCH_DEBUG
	printf("%s, ", line);
	printf("division: %d, ", hashd(line));
	printf("multiplication: %d\n", hashm(line));
#endif
	new = (ENTRY *) malloc(sizeof (ENTRY));
	if (new == NULL) {
		fprintf(stderr, "Out of core \n");
		exit(FAIL);
	} else {
		new->key = malloc((unsigned)strlen(line) + 1);
		if (new->key == NULL) {
			fprintf(stderr, "Out of core \n");
			exit(FAIL);
		}
		(void) strcpy(new->key, line);
		new->data = malloc(sizeof (int));
		if (new->data == NULL) {
			fprintf(stderr, "Out of core \n");
			exit(FAIL);
		}
		*new->data = i++;
	}
	res = hsearch(*new, ENTER);
	printf("The number of probes required was %d\n", prcnt);
	if (res == (ENTRY *) 0)
		printf("Table is full\n");
	else {
		printf("Success: ");
		printf("Key = %s, Value = %d\n", res->key, *res->data);
	}
	}
	printf("Do you wish to start another hash table (yes/no?)");
	if (EOF == scanf("%s", line) || strcmp(line, "no") == 0)
		exit(SUCCEED);
	hdestroy();
	goto start;
}
#endif

int
hcreate(size_t size)	/* Create a hash table no smaller than size */
	/* Minimum "size" for hash table */
{
	size_t unsize;	/* Holds the shifted size */
	TABELEM *local_table;
	TABELEM *old_table;
	unsigned int local_length;
	unsigned int local_m;

	if (size == 0)
		return (FALSE);

	unsize = size;	/* +1 for empty table slot; -1 for ceiling */
	local_length = 1;	/* Maximum entries in table */
	local_m = 0;		/* Log2 length */
	while (unsize) {
		unsize >>= 1;
		local_length <<= 1;
		local_m++;
	}

	local_table = (TABELEM *) calloc(local_length, sizeof (TABELEM));

	lmutex_lock(&table_lock);
	old_table = table;
	table = local_table;
	length = local_length;
	m = local_m;
	lmutex_unlock(&table_lock);
	if (old_table != NULL)
		free(old_table);
	return (local_table != NULL);
}

void
hdestroy(void)	/* Reset the module to its initial state */
{
	POINTER local_table;

	lmutex_lock(&table_lock);
#ifdef CHAINED
	int i;
	NODE *p, *oldp;
	for (i = 0; i < length; i++) {
		if (table[i] != (NODE *)NULL) {
			p = table[i];
			while (p != (NODE *)NULL) {
				oldp = p;
				p = p -> next;
				/*
				 * This is a locking vs malloc() violation.
				 * Fortunately, it is not actually compiled.
				 */
				free(oldp);
			}
		}
	}
#endif
	local_table = (POINTER)table;
	table = 0;
#ifdef OPEN
	count = 0;
#endif
	lmutex_unlock(&table_lock);
	free(local_table);
}

#ifdef OPEN
/*
 * Hash search of a fixed-capacity table.  Open addressing used to
 *  resolve collisions.  Algorithm modified from Knuth, Volume 3,
 *  section 6.4, algorithm D.  Labels flag corresponding actions.
 */

/* Find or insert the item into the table */
ENTRY
*hsearch(ENTRY item, ACTION action)
	/* "item" to be inserted or found */
	/* action: FIND or ENTER */
{
	unsigned int i;	/* Insertion index */
	unsigned int c;	/* Secondary probe displacement */

	lmutex_lock(&table_lock);
	prcnt = 1;

/* D1: */
	i = HASH(item.key);	/* Primary hash on key */
#ifdef HSEARCH_DEBUG
	if (action == ENTER)
		printf("hash = %o\n", i);
#endif

/* D2: */
	if (table[i].key == NULL)	/* Empty slot? */
		goto D6;
	else if (COMPARE(table[i].key, item.key) == 0)	/* Match? */
		RETURN(&table[i]);

/* D3: */
	c = HASH2(item.key);	/* No match => compute secondary hash */
#ifdef HSEARCH_DEBUG
	if (action == ENTER)
		printf("hash2 = %o\n", c);
#endif

D4:
	i = (i + c) % length;	/* Advance to next slot */
	prcnt++;

/* D5: */
	if (table[i].key == NULL)	/* Empty slot? */
		goto D6;
	else if (COMPARE(table[i].key, item.key) == 0)	/* Match? */
		RETURN(&table[i])
	else
		goto D4;

D6:	if (action == FIND)		/* Insert if requested */
		RETURN((ENTRY *) NULL);
	if (count == (length - 1))	/* Table full? */
		RETURN((ENTRY *) 0);

#ifdef BRENT
/*
 * Brent's variation of the open addressing algorithm.  Do extra
 * work during insertion to speed retrieval.  May require switching
 * of previously placed items.  Adapted from Knuth, Volume 3, section
 * 4.6 and Brent's article in CACM, volume 10, #2, February 1973.
 */

	{
	unsigned int p0 = HASH(item.key);   /* First probe index */
	unsigned int c0 = HASH2(item.key);  /* Main branch increment */
	unsigned int r = prcnt - 1; /* Current minimum distance */
	unsigned int j;		/* Counts along main branch */
	unsigned int k;		/* Counts along secondary branch */
	unsigned int curj;	/* Current best main branch site */
	unsigned int curpos;	/* Current best table index */
	unsigned int pj;	/* Main branch indices */
	unsigned int cj;	/* Secondary branch increment distance */
	unsigned int pjk;	/* Secondary branch probe indices */

	if (prcnt >= 3) {
		for (j = 0; j < prcnt; j++) {   /* Count along main branch */
			pj = (p0 + j * c0) % length; /* New main branch index */
			cj = HASH2(table[pj].key); /* Secondary branch incr. */
			for (k = 1; j+k <= r; k++) {
					/* Count on secondary branch */
				pjk = (pj + k * cj) % length;
					/* Secondary probe */
				if (table[pjk].key == NULL) {
					/* Improvement found */
					r = j + k; /* Decrement upper bound */
					curj = pj; /* Save main probe index */
					curpos = pjk;
						/* Save secondeary index */
				}
			}
		}
		if (r != prcnt - 1) {	/* If an improvement occurred */
			table[curpos] = table[curj]; /* Old key to new site */
#ifdef HSEARCH_DEBUG
			printf("Switch curpos = %o, curj = %o, oldi = %o\n",
				curj, curpos, i);
#endif
			i = curj;
		}
	}
	}
#endif
	count++;			/* Increment table occupancy count */
	table[i] = item;		/* Save item */

	lmutex_unlock(&table_lock);
	return (&table[i]);		/* Address of item is returned */
}
#endif

#ifdef USCR
#ifdef DRIVER
static int
compare(a, b)
POINTER a;
POINTER b;
{
    return (strcmp(a, b));
}

int (* hcompar)() = compare;
#endif
#endif

#ifdef CHAINED
#ifdef SORTUP
#define	STRCMP(A, B) (COMPARE((A), (B)) > 0)
#else
#ifdef SORTDOWN
#define	STRCMP(A, B) (COMPARE((A), (B)) < 0)
#else
#define	STRCMP(A, B) (COMPARE((A), (B)) != 0)
#endif
#endif

ENTRY
*hsearch(item, action)	/* Chained search with sorted lists */
ENTRY item;		/* Item to be inserted or found */
ACTION action;		/* FIND or ENTER */
{
	NODE *p;		/* Searches through the linked list */
	NODE **q;		/* Where to store the pointer to a new NODE */
	unsigned int i;		/* Result of hash */
	int res;		/* Result of string comparison */

	lmutex_lock(&table_lock);
	prcnt = 1;

	i = HASH(item.key);	/* Table[i] contains list head */

	if (table[i] == (NODE*)NULL) { /* List has not yet been begun */
		if (action == FIND)
			RETURN((ENTRY *) NULL);
		else
			RETURN(build(&table[i], (NODE *) NULL, item));
	} else {		/* List is not empty */
		q = &table[i];
		p = table[i];
		while (p != NULL && (res = STRCMP(item.key, p->item.key))) {
			prcnt++;
			q = &(p->next);
			p = p->next;
		}

		if (p != NULL && res == 0)	/* Item has been found */
			RETURN(&(p->item));
		else {			/* Item is not yet on list */
			if (action == FIND)
				RETURN((ENTRY *) NULL);
			else
#ifdef START
				RETURN(build(&table[i], table[i], item));
#else
				RETURN(build(q, p, item));
#endif
		}
	}
}

static ENTRY
*build(last, next, item)
NODE **last;		/* Where to store in last list item */
NODE *next;		/* Link to next list item */
ENTRY item;		/* Item to be kept in node */
{
	/*
	 * This is a locking vs malloc() violation.
	 * Fortunately, it is not actually compiled.
	 */
	NODE *p = (NODE *) malloc(sizeof (NODE));

	if (p != NULL) {
		p->item = item;
		*last = p;
		p->next = next;
		return (&(p->item));
	} else
		return (NULL);
}
#endif

#ifdef DIV
static unsigned int
hashd(key)		/* Division hashing scheme */
POINTER key;		/* Key to be hashed */
{
    return (crunch(key) % length);
}
#else
#ifdef MULT
/*
 *  NOTE: The following algorithm only works on machines where
 *  the results of multiplying two integers is the least
 *  significant part of the double word integer required to hold
 *  the result.  It is adapted from Knuth, Volume 3, section 6.4.
 */

static unsigned int
hashm(POINTER key)	/* Multiplication hashing scheme */
	/* "key" to be hashed */
{
	return ((int)(((unsigned)(crunch(key) * FACTOR)) >> SHIFT));
}

/*
 * Secondary hashing, for use with multiplicitive hashing scheme.
 * Adapted from Knuth, Volume 3, section 6.4.
 */

static unsigned int
hash2m(POINTER key)	/* Secondary hashing routine */
	/* "key" is the string to be hashed */
{
    return (((unsigned int)((crunch(key) * FACTOR) << m) >> SHIFT) | 1);
}
#endif
#endif

/* PJ Weinberger's hash function */
static unsigned int
crunch(POINTER key)	/* Convert multicharacter key to unsigned int */
{
	unsigned int h = 0;
	unsigned int g;
	unsigned char *p = (unsigned char *)key;

	for (; *p; p++) {
		h = (h << 4) + *p;
		g = h & 0xf0000000;
		if (g != 0) {
			h ^= (g >> 24);
			h ^= g;
		}
	}
	return (h);
}

#ifdef DRIVER
static void
hdump()			/* Dumps loc, data, probe count, key */
{
	unsigned int i;	/* Counts table slots */
#ifdef OPEN
	unsigned int sum = 0;	/* Counts probes */
#else
#ifdef CHAINED
	NODE *a;		/* Current Node on list */
#endif
#endif

	for (i = 0; i < length; i++)
#ifdef OPEN
		if (table[i].key == NULL)
			printf("%o.\t-,\t-,\t(NULL)\n", i);
		else {
			unsigned int oldpr = prcnt;
				/* Save current probe count */

			hsearch(table[i], FIND);
			sum += prcnt;
			printf("%o.\t%d,\t%d,\t%s\n", i,
			    *table[i].data, prcnt, table[i].key);
			prcnt = oldpr;
		}
	printf("Total probes = %d\n", sum);
#else
#ifdef CHAINED
	if (table[i] == NULL)
		printf("%o.\t-,\t-,\t(NULL)\n", i);
	else {
		printf("%o.", i);
		for (a = table[i]; a != NULL; a = a->next)
			printf("\t%d,\t%#0.4x,\t%s\n",
			    *a->item.data, a, a->item.key);
	}
#endif
#endif
}
#endif
