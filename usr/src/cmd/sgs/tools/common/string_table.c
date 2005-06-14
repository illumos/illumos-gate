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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <string_table.h>
#include <stdlib.h>
#include <strings.h>
#include <sgs.h>
#include <stdio.h>



/*
 * This file provides the interfaces to build a Str_tbl suitable
 * for use by either the sgsmsg system or a standard ELF
 * SHT_STRTAB.
 *
 * There are two modes which can be used when constructing a
 * string table:
 *
 *	st_new(0)
 *		standard string table - no compression.  This is the
 *		traditional method and fast
 *
 *	st_new(FLG_STNEW_COMPRESS)
 *		build a compressed string table which both
 *		eliminates duplicate strings and permits
 *		strings with common suffixes (atexit vs. exit) to
 *		overlap in the table.  This provides space
 *		savings for many string tables.
 *
 * These string tables are now built with a common interface in a
 * two-pass manner, the first pass it to find all of the strings
 * required for the string-table and to calculate the size that
 * will be required for the final string table.
 *
 * The second pass allocates the string table and populates the
 * strings into the table and returns the offsets the strings
 * have been assigned.
 *
 * The calling sequence to build and populate a string table is:
 *
 *		st_new();		// initialize strtab
 *
 *		st_insert(st1);		// first pass of strings ...
 *					// calculates size required for
 *					// string table
 *
 *		st_delstring(st?);	// remove string previously
 *					// inserted
 *
 *		st_insert(stN);
 *
 *		st_getstrtab_sz();	// freezes strtab and computes
 *					// size of table.
 *
 *		st_setstrbuf();		// associates a final destination
 *					// for the string table
 *
 *		st_setstring(st1);	// populate the string table
 *		...			// offsets are based off of second
 *					// pass	through the string table
 *		st_setstring(stN);
 *
 *		st_destroy();		// tear down string table
 *					// structures.
 *
 * String Suffix Compression Algorithm:
 *
 *   Here's a quick high level overview of the Suffix String
 *   compression algorithm used.  First - the heart of the algorithm
 *   is a Hash table list which represents a dictionary of all unique
 *   strings inserted into the string table.  The hash function for
 *   this table is a standard string hash except that the hash starts
 *   at the last character in the string (&str[n - 1]) and works towards
 *   the first character in the function (&str[0]).  As we compute the
 *   HASH value for a given string, we also compute the hash values
 *   for all of the possible suffix strings for that string.
 *
 *   As we compute the hash - at each character see if the current
 *   suffix string for that hash is already present in the table.  If
 *   it is, and the string is a master string.  Then change that
 *   string to a suffix string of the new string being inserted.
 *
 *   When the final hash value is found (hash for str[0...n]), check
 *   to see if it is in the hash table - if so increment the reference
 *   count for the string.  If it is not yet in the table, insert a
 *   new hash table entry for a master string.
 *
 *   The above method will find all suffixes of a given string given
 *   that the strings are inserted from shortest to longest.  That is
 *   why this is a two phase method, we first collect all of the
 *   strings and store them based off of their length in a nice AVL tree.
 *   Once all of the strings have been submitted we then start the
 *   hash table build by traversing the AVL tree in order and
 *   inserting the strings from shortest to longest as described
 *   above.
 *
 */

/* LINTLIBRARY */


int
strlen_compare(const void *elem1, const void *elem2)
{
	uint_t	l1, l2;
	l1 = ((Stringelem *)elem1)->se_stlen;
	l2 = ((Stringelem *)elem2)->se_stlen;

	if (l1 == l2)
		return (0);
	if (l2 < l1)
		return (1);

	return (-1);
}

/*
 * Return a initialized Str_tbl - returns NULL on failure.
 *
 * stflags:
 *
 *	FLG_STNEW_COMPRESS - build a compressed string table
 *
 */
Str_tbl *
st_new(uint_t stflags)
{
	Str_tbl	*stp;

	if ((stp = calloc(sizeof (Str_tbl), 1)) == 0)
		return (0);

	/*
	 * Start with a leading '\0' - it's tradition.
	 */
	stp->st_stringsize = stp->st_fullstringsize = stp->st_nextoff = 1;

	/*
	 * Do we compress this string table
	 */
	if ((stflags & FLG_STNEW_COMPRESS) == 0)
		return (stp);

	stp->st_flags |= FLG_STTAB_COMPRESS;
	if ((stp->st_strtree = calloc(sizeof (avl_tree_t), 1)) == 0) {
		return (0);
	}

	avl_create(stp->st_strtree, &strlen_compare, sizeof (Stringelem),
		SGSOFFSETOF(Stringelem, se_avlnode));

	return (stp);
}

/*
 * Tear down a String_Table structure.
 */
void
st_destroy(Str_tbl *stp)
{
	Str_hash	*sthash, *psthash;
	Str_master	*mstr, *pmstr;
	uint_t		i;

	/*
	 * cleanup the master strings
	 */
	for (mstr = stp->st_mstrlist, pmstr = 0; mstr;
	    mstr = mstr->sm_next) {
		if (pmstr)
			free(pmstr);
		pmstr = mstr;
	}
	if (pmstr)
		free(pmstr);

	if (stp->st_hashbcks) {
		for (i = 0; i < stp->st_hbckcnt; i++) {
			for (sthash = stp->st_hashbcks[i], psthash = 0;
			    sthash; sthash = sthash->hi_next) {
				if (psthash)
					free(psthash);
				psthash = sthash;
			}
			if (psthash)
				free(psthash);
		}
		free(stp->st_hashbcks);
	}
	free(stp);
}




/*
 * Remove a previously inserted string from the Str_tbl
 */
int
st_delstring(Str_tbl *stp, const char *str)
{
	uint_t		stlen;
	Stringelem	qstelem;
	Stringelem	*stelem;
	Stringlist	*stlist, *pstlist;

	/*
	 * String table can't have been cooked
	 */
	assert((stp->st_flags & FLG_STTAB_COOKED) == 0);

	stlen = (uint_t)strlen(str);
	stp->st_fullstringsize -= stlen + 1;

	if ((stp->st_flags & FLG_STTAB_COMPRESS) == 0)
		return (0);

	qstelem.se_stlen = stlen;
	if ((stelem = avl_find(stp->st_strtree, &qstelem, 0)) == NULL) {
		/*
		 * no strings of this length recorded, let alone
		 * this specific string - someone goofed.
		 */
		return (-1);
	}

	pstlist = 0;
	for (stlist = stelem->se_strlist; stlist; stlist = stlist->sl_next) {
		if (strcmp(str, stlist->sl_string) == 0)
			break;
		pstlist = stlist;
	}

	if (stlist == 0) {
		/*
		 * string was not found
		 */
		return (-1);
	}

	if (pstlist == 0) {
		/*
		 * String is first on list.
		 */
		stelem->se_strlist = stlist->sl_next;
	} else {
		/*
		 * remove string from list.
		 */
		pstlist->sl_next = stlist->sl_next;
	}

	free(stlist);
	return (0);
}


/*
 * Insert a new string into the Str_tbl
 */
int
st_insert(Str_tbl *stp, const char *str)
{
	uint_t	stlen;
	Stringelem	qstelem;
	Stringelem	*stelem;
	Stringlist	*strlist;
	avl_index_t	where;

	/*
	 * String table can't have been cooked
	 */
	assert((stp->st_flags & FLG_STTAB_COOKED) == 0);
	stlen = (uint_t)strlen(str);
	/*
	 * Null strings always point to the head of the string
	 * table - no reason to keep searching.
	 */
	if (stlen == 0)
		return (0);

	stp->st_fullstringsize += stlen + 1;
	stp->st_stringcnt++;

	if ((stp->st_flags & FLG_STTAB_COMPRESS) == 0)
		return (0);

	qstelem.se_stlen = strlen(str);
	if ((stelem = avl_find(stp->st_strtree, &qstelem,
	    &where)) == NULL) {
		if ((stelem = calloc(sizeof (Stringelem), 1)) == 0)
			return (-1);
		stelem->se_stlen = qstelem.se_stlen;
		avl_insert(stp->st_strtree, stelem, where);
	}
	if ((strlist = malloc(sizeof (Stringlist))) == 0)
		return (-1);

	strlist->sl_string = str;
	strlist->sl_next = stelem->se_strlist;
	stelem->se_strlist = strlist;

	return (0);
}


/*
 * For a given string - copy it into the buffer associated with
 * the string table - and return the offset it has been assigned.
 *
 * If a value of '-1' is returned - the string was not found in
 * the Str_tbl.
 */
int
st_setstring(Str_tbl *stp, const char *str, uint_t *stoff)
{
	uint_t		stlen;
	uint_t		hashval;
	Str_hash	*sthash;
	Str_master	*mstr;
	int		i;

	/*
	 * String table *must* have been previously cooked
	 */
	assert(stp->st_strbuf);

	assert(stp->st_flags & FLG_STTAB_COOKED);
	stlen = (uint_t)strlen(str);
	/*
	 * Null string always points to head of string table
	 */
	if (stlen == 0) {
		*stoff = 0;
		return (0);
	}

	if ((stp->st_flags & FLG_STTAB_COMPRESS) == 0) {
		uint_t		_stoff;

		stlen++;	/* count for trailing '\0' */
		_stoff = stp->st_nextoff;
		/*
		 * Have we overflowed our assigned buffer?
		 */
		if ((_stoff + stlen) > stp->st_fullstringsize)
			return (-1);
		memcpy(stp->st_strbuf + _stoff, str, stlen);
		*stoff = _stoff;
		stp->st_nextoff += stlen;
		return (0);
	}

	/*
	 * Calculate reverse hash for string
	 */
	hashval = HASHSEED;
	for (i = stlen; i >= 0; i--) {
		hashval = ((hashval << 5) + hashval) +
			str[i];			/* h = ((h * 33) + c) */
	}

	for (sthash = stp->st_hashbcks[hashval % stp->st_hbckcnt]; sthash;
	    sthash = sthash->hi_next) {
		if (sthash->hi_hashval == hashval) {
			const char	*hstr;

			hstr = &sthash->hi_mstr->sm_str[
			    sthash->hi_mstr->sm_stlen -
			    sthash->hi_stlen];
			if (strcmp(str, hstr) == 0) {
				break;
			}
		}
	}

	/*
	 * Did we find the string?
	 */
	if (sthash == 0)
		return (-1);

	/*
	 * Has this string been copied into the string table?
	 */
	mstr = sthash->hi_mstr;
	if (mstr->sm_stoff == 0) {
		uint_t	mstlen = mstr->sm_stlen + 1;
		mstr->sm_stoff = stp->st_nextoff;
		/*
		 * Have we overflowed our assigned buffer?
		 */
		if ((mstr->sm_stoff + mstlen) > stp->st_fullstringsize)
			return (-1);
		memcpy(stp->st_strbuf + mstr->sm_stoff, mstr->sm_str,
			mstlen);
		stp->st_nextoff += mstlen;
	}
	/*
	 * Calculate offset of (sub)string
	 */
	*stoff = mstr->sm_stoff + mstr->sm_stlen - sthash->hi_stlen;

	return (0);
}


static int
st_hash_insert(Str_tbl *stp, const char *str, uint_t stlen)
{
	int		i;
	uint_t		hashval = HASHSEED;
	uint_t		bckcnt = stp->st_hbckcnt;
	Str_hash	**hashbcks = stp->st_hashbcks;
	Str_hash	*sthash;
	Str_master	*mstr = 0;

	/*
	 * We use a classic 'Bernstein k=33' hash function.  But
	 * instead of hashing from the start of the string to the
	 * end, we do it in reverse.
	 *
	 * This way - we are essentially building all of the
	 * suffix hashvalues as we go.  We can check to see if
	 * any suffixes already exist in the tree as we generate
	 * the hash.
	 */
	for (i = stlen; i >= 0; i--) {

		hashval = ((hashval << 5) + hashval) +
			str[i];			/* h = ((h * 33) + c) */
		for (sthash = hashbcks[hashval % bckcnt];
		    sthash; sthash = sthash->hi_next) {

			if (sthash->hi_hashval == hashval) {
				const char	*hstr;
				Str_master	*_mstr;

				_mstr = sthash->hi_mstr;
				hstr = &_mstr->sm_str[_mstr->sm_stlen -
				    sthash->hi_stlen];
				if (strcmp(&str[i], hstr) == 0) {
					if (i == 0) {
						/*
						 * Entry already in table,
						 * increment refcnt and get
						 * out.
						 */
						sthash->hi_refcnt++;
						return (0);
					} else {
						/*
						 * If this 'suffix' is
						 * presently a 'master' string,
						 * then take over it's record.
						 */
						if (sthash->hi_stlen ==
						    _mstr->sm_stlen) {
							/*
							 * we should only do
							 * this once.
							 */
							assert(mstr == 0);
							mstr = _mstr;
						}
					}
				}
			}
		}
	}


	/*
	 * Do we need a new master string, or can we take over
	 * one we already found in the table?
	 */
	if (mstr == 0) {
		/*
		 * allocate a new master string
		 */
		if ((mstr = calloc(sizeof (Str_hash), 1)) == 0)
			return (-1);
		mstr->sm_next = stp->st_mstrlist;
		stp->st_mstrlist = mstr;
		stp->st_stringsize += stlen + 1;
	} else {
		/*
		 * We are taking over a existing master string,
		 * the stringsize only increments by the
		 * difference between the currnet string and the
		 * previous master.
		 */
		assert(stlen > mstr->sm_stlen);
		stp->st_stringsize += stlen - mstr->sm_stlen;
	}

	if ((sthash = calloc(sizeof (Str_hash), 1)) == 0)
		return (-1);

	mstr->sm_hashval = sthash->hi_hashval = hashval;
	mstr->sm_stlen = sthash->hi_stlen = stlen;
	mstr->sm_str = str;
	sthash->hi_refcnt = 1;
	sthash->hi_mstr = mstr;

	/*
	 * Insert string element into head of hash list
	 */
	hashval = hashval % bckcnt;
	sthash->hi_next = hashbcks[hashval];
	hashbcks[hashval] = sthash;
	return (0);
}

/*
 * Return amount of space required for the string table.
 */
uint_t
st_getstrtab_sz(Str_tbl *stp)
{
	assert(stp->st_fullstringsize > 0);

	if ((stp->st_flags & FLG_STTAB_COMPRESS) == 0) {
		stp->st_flags |= FLG_STTAB_COOKED;
		return (stp->st_fullstringsize);
	}


	if ((stp->st_flags & FLG_STTAB_COOKED) == 0) {
		Stringelem	*stelem;
		void		*cookie;

		stp->st_flags |= FLG_STTAB_COOKED;
		/*
		 * allocate a hash table about the size of # of
		 * strings input.
		 */
		stp->st_hbckcnt = findprime(stp->st_stringcnt);
		if ((stp->st_hashbcks =
		    calloc(sizeof (Str_hash), stp->st_hbckcnt)) == NULL)
			return (0);

		/*
		 * We now walk all of the strings in the list,
		 * from shortest to longest, and insert them into
		 * the hashtable.
		 */
		if ((stelem = avl_first(stp->st_strtree)) == NULL) {
			/*
			 * Is it possible we have a empty string table,
			 * if so - the table still conains '\0'
			 * so still return the size.
			 */
			if (avl_numnodes(stp->st_strtree) == 0) {
				assert(stp->st_stringsize == 1);
				return (stp->st_stringsize);
			}
			return (0);
		}
		while (stelem) {
			Stringlist	*strlist, *pstrlist;

			/*
			 * Walk the string lists and insert them
			 * into the hash list.  Once a string is
			 * inserted we no longer need it's entry,
			 * so free it
			 */
			for (strlist = stelem->se_strlist, pstrlist = 0;
			    strlist; strlist = strlist->sl_next) {
				if (st_hash_insert(stp, strlist->sl_string,
				    stelem->se_stlen) == -1)
					return (0);
				if (pstrlist)
					free(pstrlist);
			}
			free(pstrlist);
			stelem->se_strlist = 0;
			stelem = AVL_NEXT(stp->st_strtree, stelem);
		}

		/*
		 * Now that all of the strings have been freed,
		 * go ahead and quickly re-walk the AVL tree and
		 * free all of the AVL nodes.
		 *
		 * avl_destroy_nodes() beats avl_remove() because
		 * avl_remove will 'ballance' the tree as nodes
		 * are deleted - we just want to tear the whole
		 * thing down now.
		 */
		cookie = NULL;
		while ((stelem = avl_destroy_nodes(stp->st_strtree,
		    &cookie)) != NULL)
			free(stelem);
		avl_destroy(stp->st_strtree);
		free(stp->st_strtree);
		stp->st_strtree = 0;
	}

	assert(stp->st_stringsize > 0);
	assert(stp->st_fullstringsize >= stp->st_stringsize);

	return (stp->st_stringsize);
}

/*
 * Associate a buffer with the string table.
 */
const char *
st_getstrbuf(Str_tbl *stp)
{
	return (stp->st_strbuf);
}

int
st_setstrbuf(Str_tbl *stp, char *stbuf, uint_t bufsize)
{
	assert(stp->st_flags & FLG_STTAB_COOKED);

	if ((stp->st_flags & FLG_STTAB_COMPRESS) == 0) {
		if (bufsize < stp->st_fullstringsize)
			return (-1);
	} else {
		if (bufsize < stp->st_stringsize)
			return (-1);
	}

	stp->st_strbuf = stbuf;
#ifdef	DEBUG
	/*
	 * for debug builds - start with a stringtable filled in
	 * with '0xff'.  This makes it very easy to find wholes
	 * which we failed to fill in - in the strtab.
	 */
	memset(stbuf, 0xff, bufsize);
	stbuf[0] = '\0';
#else
	memset(stbuf, 0x0, bufsize);
#endif
	return (0);
}
