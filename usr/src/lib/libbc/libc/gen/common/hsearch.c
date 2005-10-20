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
 * Copyright 1996 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/
/* Compile time switches:

   MULT - use a multiplicative hashing function.
   DIV - use the remainder mod table size as a hashing function.
   CHAINED - use a linked list to resolve collisions.
   OPEN - use open addressing to resolve collisions.
   BRENT - use Brent's modification to improve the OPEN algorithm.
   SORTUP - CHAINED list is sorted in increasing order.
   SORTDOWN - CHAINED list is sorted in decreasing order.
   START - CHAINED list with entries appended at front.
   DRIVER - compile in a main program to drive the tests.
   DEBUG - compile some debugging printout statements.
   USCR - user supplied comparison routine.
*/

#include <stdio.h>
#include <limits.h>
#include <malloc.h>
#include <string.h>

#define SUCCEED		0
#define FAIL		1
#define TRUE		1
#define FALSE		0
#define repeat		for(;;)
#define until(A)	if(A) break;

#ifdef OPEN
#    undef CHAINED
#else
#ifndef CHAINED
#    define OPEN
#endif
#endif

#ifdef MULT
#    undef DIV
#else
#ifndef DIV
#    define MULT
#endif
#endif

#ifdef START
#    undef SORTUP
#    undef SORTDOWN
#else
#ifdef SORTUP
#    undef SORTDOWN
#endif
#endif

#ifdef USCR
#    define COMPARE(A, B) (* hcompar)((A), (B))
     extern int (* hcompar)();
#else
#    define COMPARE(A, B) strcmp((A), (B))
#endif

#ifdef MULT
#    define SHIFT ((bitsper * sizeof(int)) - m) /* Shift factor */
#    define FACTOR 035761254233	/* Magic multiplication factor */
#    define HASH hashm		/* Multiplicative hash function */
#    define HASH2 hash2m	/* Secondary hash function */
static unsigned int bitsper;	/* Bits per byte */
static unsigned int hashm();
static unsigned int hash2m();
#else
#ifdef DIV
#    define HASH hashd		/* Division hashing routine */
#    define HASH2(A) 1		/* Secondary hash function */
static unsigned int hashd();
#endif
#endif

typedef enum {
    FIND,		/* Find, if present */
    ENTER		/* Find; enter if not present */
} ACTION;
typedef char *POINTER;
typedef struct entry {	/* Hash table entry */
    POINTER key;
    POINTER data;
} ENTRY;

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

int hcreate();
void hdestroy();
ENTRY *hsearch();
static unsigned int crunch();

#ifdef DRIVER
static void hdump();

main()
{
    char line[80];	/* Room for the input line */
    int i = 0;		/* Data generator */
    ENTRY *res;		/* Result of hsearch */
    ENTRY *new;		/* Test entry */

    if(hcreate(5))
	printf("Length = %u, m = %u\n", length, m);
    else {
	fprintf(stderr, "Out of core\n");
	exit(FAIL);
    }

    repeat {
	hdump();
	printf("Enter a probe: ");
	until (EOF == scanf("%s", line));
#ifdef DEBUG
	printf("%s, ", line);
	printf("division: %d, ", hashd(line));
	printf("multiplication: %d\n", hashm(line));
#endif
	new = (ENTRY *) malloc(sizeof(ENTRY));
	if(new == NULL) {
	    fprintf(stderr, "Out of core \n");
	    exit(FAIL);
	}
	else {
	    new->key = malloc((unsigned) strlen(line) + 1);
	    if(new->key == NULL) {
		fprintf(stderr, "Out of core \n");
		exit(FAIL);
	    }
	    strcpy(new->key, line);
	    new->data = malloc(sizeof(int));
	    if(new->data == NULL) {
		fprintf(stderr, "Out of core \n");
		exit(FAIL);
	    }
	    *new->data = i++;
	}
	res = hsearch(*new, ENTER);
	printf("The number of probes required was %d\n", prcnt);
	if(res == (ENTRY *) 0)
	    printf("Table is full\n");
	else {
	    printf("Success: ");
	    printf("Key = %s, Value = %d\n", res->key, *res->data);
	}
    }
    exit(SUCCEED);
}
#endif

/*
 * Create a hash table no smaller than size
 *
 *	size:	Minimum size for hash table
 */
int
hcreate(int size)		
{
    unsigned int unsize;	/* Holds the shifted size */

    if(size <= 0)
	return(FALSE);

    unsize = size;	/* +1 for empty table slot; -1 for ceiling */
    length = 1;		/* Maximum entries in tabbe */
    m = 0;		/* Log2 length */
    while(unsize) {
	unsize >>= 1;
	length <<= 1;
	m++;
    }

    table = (TABELEM *) calloc(length, sizeof(TABELEM));
    return (table != NULL);
}

void
hdestroy(void)	/* Reset the module to its initial state */
{
    free((POINTER) table);
#ifdef OPEN
    count = 0;
#endif
}

#ifdef OPEN
/* Hash search of a fixed-capacity table.  Open addressing used to
   resolve collisions.  Algorithm modified from Knuth, Volume 3,
   section 6.4, algorithm D.  Labels flag corresponding actions.
*/

/*
 * Find or insert the item into the table
 *
 *	item:	Item to be inserted or found
 *	action:	FIND or ENTER
 */
ENTRY *
hsearch(ENTRY item, ACTION action)
{
    unsigned int i;	/* Insertion index */
    unsigned int c;	/* Secondary probe displacement */

    prcnt = 1;

/* D1: */ 
    i = HASH(item.key);	/* Primary hash on key */
#ifdef DEBUG
    if(action == ENTER)
	printf("hash = %o\n", i);
#endif

/* D2: */
    if(table[i].key == NULL)	/* Empty slot? */
	goto D6;
    else if(COMPARE(table[i].key, item.key) == 0)	/* Match? */
	return(&table[i]);

/* D3: */
    c = HASH2(item.key);	/* No match => compute secondary hash */
#ifdef DEBUG
    if(action == ENTER)
	printf("hash2 = %o\n", c);
#endif

D4: 
    i = (i + c) % length;	/* Advance to next slot */
    prcnt++;

/* D5: */
    if(table[i].key == NULL)	/* Empty slot? */
	goto D6;
    else if(COMPARE(table[i].key, item.key) == 0)	/* Match? */
	return(&table[i]);
    else
	goto D4;

D6: if(action == FIND)		/* Insert if requested */
	return((ENTRY *) NULL);
    if(count == (length - 1))	/* Table full? */
	return((ENTRY *) 0);

#ifdef BRENT
/* Brent's variation of the open addressing algorithm.  Do extra
   work during insertion to speed retrieval.  May require switching
   of previously placed items.  Adapted from Knuth, Volume 3, section
   4.6 and Brent's article in CACM, volume 10, #2, February 1973.
*/

    {   unsigned int p0 = HASH(item.key);   /* First probe index */
	unsigned int c0 = HASH2(item.key);  /* Main branch increment */
	unsigned int r = prcnt - 1; /* Current minimum distance */
	unsigned int j;         /* Counts along main branch */
	unsigned int k;         /* Counts along secondary branch */
	unsigned int curj;      /* Current best main branch site */
	unsigned int curpos;    /* Current best table index */
	unsigned int pj;        /* Main branch indices */
	unsigned int cj;        /* Secondary branch increment distance*/
	unsigned int pjk;       /* Secondary branch probe indices */

	if(prcnt >= 3) {
	    for(j = 0; j < prcnt; j++) {   /* Count along main branch */
		pj = (p0 + j * c0) % length; /* New main branch index */
		cj = HASH2(table[pj].key); /* Secondary branch incr. */
		for(k=1; j+k <= r; k++) { /* Count on secondary branch*/
		    pjk = (pj + k * cj) % length; /* Secondary probe */
		    if(table[pjk].key == NULL) { /* Improvement found */
		        r = j + k;	/* Decrement upper bound */
		        curj = pj;	/* Save main probe index */
		        curpos = pjk;	/* Save secondeary index */
		    }
		}
	    }
	    if(r != prcnt - 1) {       /* If an improvement occurred */
		table[curpos] = table[curj]; /* Old key to new site */
#ifdef DEBUG
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
    return(&table[i]);		/* Address of item is returned */
}
#endif

#ifdef USCR
#    ifdef DRIVER
static int
compare(POINTER a, POINTER b)
{
    return (strcmp(a, b));
}

int (* hcompar)() = compare;
#    endif
#endif

#ifdef CHAINED
#    ifdef SORTUP
#        define STRCMP(A, B) (COMPARE((A), (B)) > 0)
#    else
#    ifdef SORTDOWN
#        define STRCMP(A, B) (COMPARE((A), (B)) < 0)
#    else
#        define STRCMP(A, B) (COMPARE((A), (B)) != 0)
#    endif
#    endif

/*
 * Chained search with sorted lists
 *
 *	item:	Item to be inserted or found
 *	action: FIND or ENTER
 */
ENTRY *
hsearch(ENTRY item, ACTION action)
{
    NODE *p;		/* Searches through the linked list */
    NODE **q;		/* Where to store the pointer to a new NODE */
    unsigned int i;	/* Result of hash */
    int res;		/* Result of string comparison */

    prcnt = 1;

    i = HASH(item.key);	/* Table[i] contains list head */

    if(table[i] == (NODE*)NULL) { /* List has not yet been begun */
	if(action == FIND)
	    return((ENTRY *) NULL);
	else
	    return(build(&table[i], (NODE *) NULL, item));
    }
    else {			/* List is not empty */
	q = &table[i];
	p = table[i];
	while(p != NULL && (res = STRCMP(item.key, p->item.key))) {
	    prcnt++;
	    q = &(p->next);
	    p = p->next;
	}

	if(p != NULL && res == 0)	/* Item has been found */
	    return(&(p->item));
	else {			/* Item is not yet on list */
	    if(action == FIND)
		return((ENTRY *) NULL);
	    else
#ifdef START
		return(build(&table[i], table[i], item));
#else
		return(build(q, p, item));
#endif
	}
    }
}

/*
 *	last:		Where to store in last list item
 *	next:		Link to next list item
 *	item:		Item to be kept in node
 */
static ENTRY *
build(NODE **last, NODE *next, ENTRY item)
{
    NODE *p = (NODE *) malloc(sizeof(NODE));

    if(p != NULL) {
	p->item = item;
	*last = p;
	p->next = next;
	return(&(p->item));
    }
    else
	return(NULL);
}
#endif

#ifdef DIV
/*
 * Division hashing scheme
 *
 *	key:	Key to be hashed
 */
static unsigned int
hashd(POINTER key)		
{
    return (crunch(key) % length);
}
#else
#ifdef MULT
/*
 *    NOTE: The following algorithm only works on machines where
 *    the results of multiplying two integers is the least
 *    significant part of the double word integer required to hold
 *    the result.  It is adapted from Knuth, Volume 3, section 6.4.
 */

/*
 * Multiplication hashing scheme
 *
 *	key:	Key to be hashed
 */
static unsigned int
hashm(POINTER key)
{
    static int first = TRUE;	/* TRUE on the first call only */

    if(first) {		/* Compute the number of bits in a byte */
	unsigned char c = UCHAR_MAX;	/* A byte full of 1's */
	bitsper = 0;
	while(c) {		/* Shift until no more 1's */
	    c >>= 1;
	    bitsper++;		/* Count number of shifts */
	}
	first = FALSE;
    }
    return ((int) (((unsigned) (crunch(key) * FACTOR)) >> SHIFT));
}

/*
 * Secondary hashing, for use with multiplicitive hashing scheme.
 * Adapted from Knuth, Volume 3, section 6.4.
 */

/*
 * Secondary hashing routine
 *
 *	key:	String to be hashed
 */
static unsigned int
hash2m(POINTER key)
{
    return ((int) (((unsigned) ((crunch(key) * FACTOR) << m) >> SHIFT) | 1));
}
#endif
#endif

/* Convert multicharacter key to unsigned int */
static unsigned int
crunch(POINTER key)
{
    unsigned int sum = 0;	/* Results */
    int s;			/* Length of the key */

    for(s = 0; *key; s++)	/* Simply add up the bytes */
	sum += *key++;

    return (sum + s);
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

    for(i = 0; i < length; i++)
#ifdef OPEN
	if(table[i].key == NULL)
	    printf("%o.\t-,\t-,\t(NULL)\n", i);
	else {
	    unsigned int oldpr = prcnt; /* Save current probe count */
	    hsearch(table[i], FIND);
	    sum += prcnt;
	    printf("%o.\t%d,\t%d,\t%s\n", i,
		*table[i].data, prcnt, table[i].key);
	    prcnt = oldpr;
	}
    printf("Total probes = %d\n", sum);
#else
#ifdef CHAINED
	if(table[i] == NULL)
	    printf("%o.\t-,\t-,\t(NULL)\n", i);
	else {
	    printf("%o.", i);
	    for(a = table[i]; a != NULL; a = a->next)
		printf("\t%d,\t%#0.4x,\t%s\n",
		    *a->item.data, a, a->item.key);
	}
#endif
#endif
}
#endif
