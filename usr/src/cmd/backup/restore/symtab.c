/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1996,1998,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * These routines maintain the symbol table which tracks the state
 * of the file system being restored. They provide lookup by either
 * name or inode number. They also provide for creation, deletion,
 * and renaming of entries. Because of the dynamic nature of pathnames,
 * names should not be saved, but always constructed just before they
 * are needed, by calling "myname".
 */

#include "restore.h"
#include <limits.h>

/*
 * The following variables define the inode symbol table.
 * The primary hash table is dynamically allocated based on
 * the number of inodes in the file system (maxino), scaled by
 * HASHFACTOR. The variable "entry" points to the hash table;
 * the variable "entrytblsize" indicates its size (in entries).
 */
#define	HASHFACTOR 5
static struct entry **entry;
static uint_t entrytblsize;

#ifdef __STDC__
static void addino(ino_t, struct entry *);
static struct entry *lookupparent(char *);
static void removeentry(struct entry *);
#else
static void addino();
static struct entry *lookupparent();
static void removeentry();
#endif

/*
 * Look up an entry by inode number
 */
struct entry *
lookupino(inum)
	ino_t inum;
{
	struct entry *ep;

	if (inum < ROOTINO || inum >= maxino)
		return (NIL);
	for (ep = entry[inum % entrytblsize]; ep != NIL; ep = ep->e_next)
		if (ep->e_ino == inum)
			return (ep);
	return (NIL);
}

/*
 * We now ignore inodes that are out of range.  This
 * allows us to attempt to proceed in the face of
 * a corrupted archive, albeit with future complaints
 * about failed inode lookups.  We only complain once
 * about range problems, to avoid irritating the user
 * without providing any useful information.  Failed
 * lookups have the bogus name, which is useful, so
 * they always happen.
 */
static int complained_about_range = 0;

/*
 * Add an entry into the entry table
 */
static void
addino(inum, np)
	ino_t inum;
	struct entry *np;
{
	struct entry **epp;

	if (inum < ROOTINO || inum >= maxino) {
		if (!complained_about_range) {
			panic(gettext("%s: out of range %d\n"),
			    "addino", inum);
			complained_about_range = 1;
		}
		return;
	}
	epp = &entry[inum % entrytblsize];
	np->e_ino = inum;
	np->e_next = *epp;
	*epp = np;
	if (dflag)
		for (np = np->e_next; np != NIL; np = np->e_next)
			if (np->e_ino == inum)
				badentry(np, gettext("duplicate inum"));
}

/*
 * Delete an entry from the entry table.  We assume our caller
 * arranges for the necessary memory reclamation, if needed.
 */
void
deleteino(inum)
	ino_t inum;
{
	struct entry *next;
	struct entry **prev;

	if (inum < ROOTINO || inum >= maxino) {
		if (!complained_about_range) {
			panic(gettext("%s: out of range %d\n"),
			    "deleteino", inum);
			complained_about_range = 1;
		}
		return;
	}

	prev = &entry[inum % entrytblsize];
	for (next = *prev; next != NIL; next = next->e_next) {
		if (next->e_ino == inum) {
			next->e_ino = 0;
			*prev = next->e_next;
			return;
		}
		prev = &next->e_next;
	}
}

/*
 * Look up an entry by name.
 *	NOTE: this function handles "complex" pathnames (as returned
 *	by myname()) for extended file attributes.  The name string
 *	provided to this function should be terminated with *two*
 *	NULL characters.
 */
struct entry *
lookupname(name)
	char *name;
{
	struct entry *ep;
	char *np, *cp;
	char buf[MAXPATHLEN];

	if (strlen(name) > (sizeof (buf) - 1)) {
		(void) fprintf(stderr, gettext("%s: ignoring too-long name\n"),
		    "lookupname");
		return (NIL);
	}

	cp = name;
	for (ep = lookupino(ROOTINO); ep != NIL; ep = ep->e_entries) {
		np = buf;
		while (*cp != '/' && *cp != '\0')
			*np++ = *cp++;
		*np = '\0';
		for (; ep != NIL; ep = ep->e_sibling)
			if (strcmp(ep->e_name, buf) == 0)
				break;
		if (*cp++ == '\0') {
			if (*cp != '\0') {
				ep = ep->e_xattrs;
				/*
				 * skip over the "./" prefix on all
				 * extended attribute paths
				 */
				cp += 2;
			}
			if (*cp == '\0')
				return (ep);
		}
		if (ep == NIL)
			break;
	}
	return (NIL);
}

/*
 * Look up the parent of a pathname.  This routine accepts complex
 * names so the provided name argument must terminate with two NULLs.
 */
static struct entry *
lookupparent(name)
	char *name;
{
	struct entry *ep;
	char *tailindex, savechar, *lastpart;
	int xattrparent = 0;

	/* find the last component of the complex name */
	lastpart = name;
	LASTPART(lastpart);
	tailindex = strrchr(lastpart, '/');
	if (tailindex == 0) {
		if (lastpart == name)
			return (NIL);
		/*
		 * tailindex normaly points to the '/' character
		 * dividing the path, but in the case of an extended
		 * attribute transition it will point to the NULL
		 * separator in front of the attribute path.
		 */
		tailindex = lastpart - 1;
		xattrparent = 1;
	} else {
		*tailindex = '\0';
	}
	savechar = *(tailindex+1);
	*(tailindex+1) = '\0';
	ep = lookupname(name);
	if (ep != NIL && !xattrparent && ep->e_type != NODE)
		panic(gettext("%s is not a directory\n"), name);
	if (!xattrparent) *tailindex = '/';
	*(tailindex+1) = savechar;
	return (ep);
}

/*
 * Determine the current pathname of a node or leaf.
 * The returned pathname will be multiple strings with NULL separators:
 *
 *	./<path>/entry\0<path>/attrentry\0<path>/...\0\0
 *	^	        ^		  ^	    ^
 *   return pntr    entry attr	    recursive attr  terminator
 *
 * Guaranteed to return a name that fits within MAXCOMPLEXLEN and is
 * terminated with two NULLs.
 */
char *
myname(ep)
	struct entry *ep;
{
	char *cp;
	struct entry *root = lookupino(ROOTINO);
	static char namebuf[MAXCOMPLEXLEN];

	cp = &namebuf[MAXCOMPLEXLEN - 3];
	*(cp + 1) = '\0';
	*(cp + 2) = '\0';
	while (cp > &namebuf[ep->e_namlen]) {
		cp -= ep->e_namlen;
		bcopy(ep->e_name, cp, (size_t)ep->e_namlen);
		if (ep == root)
			return (cp);
		if (ep->e_flags & XATTRROOT)
			*(--cp) = '\0';
		else
			*(--cp) = '/';
		ep = ep->e_parent;
	}
	panic(gettext("%s%s: pathname too long\n"), "...", cp);
	return (cp);
}

/*
 * Unused symbol table entries are linked together on a freelist
 * headed by the following pointer.
 */
static struct entry *freelist = NIL;

/*
 * add an entry to the symbol table
 */
struct entry *
addentry(name, inum, type)
	char *name;
	ino_t inum;
	int type;
{
	struct entry *np, *ep;
	char *cp;

	if (freelist != NIL) {
		np = freelist;
		freelist = np->e_next;
		(void) bzero((char *)np, (size_t)sizeof (*np));
	} else {
		np = (struct entry *)calloc(1, sizeof (*np));
		if (np == NIL) {
			(void) fprintf(stderr,
			    gettext("no memory to extend symbol table\n"));
			done(1);
		}
	}
	np->e_type = type & ~(LINK|ROOT);
	if (inattrspace)
		np->e_flags |= XATTR;
	ep = lookupparent(name);
	if (ep == NIL) {
		if (inum != ROOTINO || lookupino(ROOTINO) != NIL) {
			(void) fprintf(stderr, gettext(
			    "%s: bad name %s\n"), "addentry", name);
			assert(0);
			done(1);
		}
		np->e_name = savename(name);
		/* LINTED: savename guarantees that strlen fits in e_namlen */
		np->e_namlen = strlen(name);
		np->e_parent = np;
		addino(ROOTINO, np);
		return (np);
	}

	if (np->e_flags & XATTR) {
		/*
		 * skip to the last part of the complex string: it
		 * containes the extended attribute file name.
		 */
		LASTPART(name);
	}
	cp = strrchr(name, '/');
	if (cp == NULL)
		cp = name;
	else
		cp++;

	np->e_name = savename(cp);
	/* LINTED: savename guarantees that strlen will fit */
	np->e_namlen = strlen(np->e_name);
	np->e_parent = ep;
	/*
	 * Extended attribute root directories must be linked to their
	 * "parents" via the e_xattrs field.  Other entries are simply
	 * added to their parent directories e_entries list.
	 */
	if ((type & ROOT) && (np->e_flags & XATTR)) {
		/* link this extended attribute root dir to its "parent" */
		ep->e_xattrs = np;
	} else {
		/* add this entry to the entry list of the parent dir */
		np->e_sibling = ep->e_entries;
		ep->e_entries = np;
	}
	if (type & LINK) {
		ep = lookupino(inum);
		if (ep == NIL) {
			/* XXX just bail on this one and continue? */
			(void) fprintf(stderr,
			    gettext("link to non-existent name\n"));
			done(1);
		}
		np->e_ino = inum;
		np->e_links = ep->e_links;
		ep->e_links = np;
	} else if (inum != 0) {
		ep = lookupino(inum);
		if (ep != NIL)
			panic(gettext("duplicate entry\n"));
		else
			addino(inum, np);
	}
	return (np);
}

/*
 * delete an entry from the symbol table
 */
void
freeentry(ep)
	struct entry *ep;
{
	struct entry *np;
	ino_t inum;

	if ((ep->e_flags & REMOVED) == 0)
		badentry(ep, gettext("not marked REMOVED"));
	if (ep->e_type == NODE) {
		if (ep->e_links != NIL)
			badentry(ep, gettext("freeing referenced directory"));
		if (ep->e_entries != NIL)
			badentry(ep, gettext("freeing non-empty directory"));
	}
	if (ep->e_ino != 0) {
		np = lookupino(ep->e_ino);
		if (np == NIL)
			badentry(ep, gettext("lookupino failed"));
		if (np == ep) {
			inum = ep->e_ino;
			deleteino(inum);
			if (ep->e_links != NIL)
				addino(inum, ep->e_links);
		} else {
			for (; np != NIL; np = np->e_links) {
				if (np->e_links == ep) {
					np->e_links = ep->e_links;
					break;
				}
			}
			if (np == NIL)
				badentry(ep, gettext("link not found"));
		}
	}
	removeentry(ep);
	freename(ep->e_name);
	ep->e_next = freelist;
	freelist = ep;
}

/*
 * Relocate an entry in the tree structure
 */
void
moveentry(ep, newname)
	struct entry *ep;
	char *newname;
{
	struct entry *np;
	char *cp;

	np = lookupparent(newname);
	if (np == NIL)
		badentry(ep, gettext("cannot move ROOT"));
	if (np != ep->e_parent) {
		removeentry(ep);
		ep->e_parent = np;
		ep->e_sibling = np->e_entries;
		np->e_entries = ep;
	}
	/* find the last component of the complex name */
	LASTPART(newname);
	cp = strrchr(newname, '/') + 1;
	if (cp == (char *)1)
		cp = newname;
	freename(ep->e_name);
	ep->e_name = savename(cp);
	/* LINTED: savename guarantees that strlen will fit */
	ep->e_namlen = strlen(cp);
	if (strcmp(gentempname(ep), ep->e_name) == 0) {
		/* LINTED: result fits in a short */
		ep->e_flags |= TMPNAME;
	} else {
		/* LINTED: result fits in a short */
		ep->e_flags &= ~TMPNAME;
	}
}

/*
 * Remove an entry in the tree structure
 */
static void
removeentry(ep)
	struct entry *ep;
{
	struct entry *np;

	np = ep->e_parent;
	if (ep->e_flags & XATTRROOT) {
		if (np->e_xattrs == ep)
			np->e_xattrs = NIL;
		else
			badentry(ep, gettext(
				"parent does not reference this xattr tree"));
	} else if (np->e_entries == ep) {
		np->e_entries = ep->e_sibling;
	} else {
		for (np = np->e_entries; np != NIL; np = np->e_sibling) {
			if (np->e_sibling == ep) {
				np->e_sibling = ep->e_sibling;
				break;
			}
		}
		if (np == NIL)
			badentry(ep, gettext(
				"cannot find entry in parent list"));
	}
}

/*
 * Table of unused string entries, sorted by length.
 *
 * Entries are allocated in STRTBLINCR sized pieces so that names
 * of similar lengths can use the same entry. The value of STRTBLINCR
 * is chosen so that every entry has at least enough space to hold
 * a "struct strtbl" header. Thus every entry can be linked onto an
 * apprpriate free list.
 *
 * NB. The macro "allocsize" below assumes that "struct strhdr"
 *	has a size that is a power of two. Also, an extra byte is
 *	allocated for the string to provide space for the two NULL
 *	string terminator required for extended attribute paths.
 */
struct strhdr {
	struct strhdr *next;
};

#define	STRTBLINCR	((size_t)sizeof (struct strhdr))
#define	allocsize(size)	(((size) + 2 + STRTBLINCR - 1) & ~(STRTBLINCR - 1))

static struct strhdr strtblhdr[allocsize(MAXCOMPLEXLEN) / STRTBLINCR];

/*
 * Allocate space for a name. It first looks to see if it already
 * has an appropriate sized entry, and if not allocates a new one.
 */
char *
savename(name)
	char *name;
{
	struct strhdr *np;
	size_t len, as;
	char *cp;

	if (name == NULL) {
		(void) fprintf(stderr, gettext("bad name\n"));
		done(1);
	}
	len = strlen(name);
	if (len > MAXPATHLEN) {
		(void) fprintf(stderr, gettext("name too long\n"));
		done(1);
	}
	as = allocsize(len);
	np = strtblhdr[as / STRTBLINCR].next;
	if (np != NULL) {
		strtblhdr[as / STRTBLINCR].next = np->next;
		cp = (char *)np;
	} else {
		/* Note that allocsize() adds 2 for the trailing \0s */
		cp = malloc(as);
		if (cp == NULL) {
			(void) fprintf(stderr,
			    gettext("no space for string table\n"));
			done(1);
		}
	}
	(void) strcpy(cp, name);
	/* add an extra null for complex (attribute) name support */
	cp[len+1] = '\0';
	return (cp);
}

/*
 * Free space for a name. The resulting entry is linked onto the
 * appropriate free list.
 */
void
freename(name)
	char *name;
{
	struct strhdr *tp, *np;

	/* NULL case should never happen, but might as well be careful */
	if (name != NULL) {
		tp = &strtblhdr[allocsize(strlen(name)) / STRTBLINCR];
		/*LINTED [name points to at least sizeof (struct strhdr)]*/
		np = (struct strhdr *)name;
		np->next = tp->next;
		tp->next = np;
	}
}

/*
 * Useful quantities placed at the end of a dumped symbol table.
 */
struct symtableheader {
	int	volno;
	uint_t	stringsize;
	uint_t	entrytblsize;
	time_t	dumptime;
	time_t	dumpdate;
	ino_t	maxino;
	uint_t	ntrec;
};

/*
 * dump a snapshot of the symbol table
 */
void
dumpsymtable(filename, checkpt)
	char *filename;
	int checkpt;
{
	struct entry *ep, *tep;
	ino_t i;
	struct entry temp, *tentry;
	int mynum = 1;
	uint_t stroff;
	FILE *fp;
	struct symtableheader hdr;

	vprintf(stdout, gettext("Check pointing the restore\n"));
	if ((fp = safe_fopen(filename, "w", 0600)) == (FILE *)NULL) {
		perror("fopen");
		(void) fprintf(stderr,
		    gettext("cannot create save file %s for symbol table\n"),
		    filename);
		done(1);
	}
	clearerr(fp);
	/*
	 * Assign an index to each entry
	 * Write out the string entries
	 */
	for (i = ROOTINO; i < maxino; i++) {
		for (ep = lookupino(i); ep != NIL; ep = ep->e_links) {
			ep->e_index = mynum++;
			(void) fwrite(ep->e_name, sizeof (ep->e_name[0]),
			    (size_t)allocsize(ep->e_namlen), fp);
		}
	}
	/*
	 * Convert e_name pointers to offsets, other pointers
	 * to indices, and output
	 */
	tep = &temp;
	stroff = 0;
	for (i = ROOTINO; !ferror(fp) && i < maxino; i++) {
		for (ep = lookupino(i);
		    !ferror(fp) && ep != NIL;
		    ep = ep->e_links) {
			bcopy((char *)ep, (char *)tep, sizeof (*tep));
			/* LINTED: type pun ok */
			tep->e_name = (char *)stroff;
			stroff += allocsize(ep->e_namlen);
			tep->e_parent = (struct entry *)ep->e_parent->e_index;
			if (ep->e_links != NIL)
				tep->e_links =
					(struct entry *)ep->e_links->e_index;
			if (ep->e_sibling != NIL)
				tep->e_sibling =
					(struct entry *)ep->e_sibling->e_index;
			if (ep->e_entries != NIL)
				tep->e_entries =
					(struct entry *)ep->e_entries->e_index;
			if (ep->e_xattrs != NIL)
				tep->e_xattrs =
					(struct entry *)ep->e_xattrs->e_index;
			if (ep->e_next != NIL)
				tep->e_next =
					(struct entry *)ep->e_next->e_index;
			(void) fwrite((char *)tep, sizeof (*tep), 1, fp);
		}
	}
	/*
	 * Convert entry pointers to indices, and output
	 */
	for (i = 0; !ferror(fp) && i < (ino_t)entrytblsize; i++) {
		if (entry[i] == NIL)
			tentry = NIL;
		else
			tentry = (struct entry *)entry[i]->e_index;
		(void) fwrite((char *)&tentry, sizeof (tentry), 1, fp);
	}

	if (!ferror(fp)) {
		/* Ought to have a checksum or magic number */
		hdr.volno = checkpt;
		hdr.maxino = maxino;
		hdr.entrytblsize = entrytblsize;
		hdr.stringsize = stroff;
		hdr.dumptime = dumptime;
		hdr.dumpdate = dumpdate;
		hdr.ntrec = ntrec;
		(void) fwrite((char *)&hdr, sizeof (hdr), 1, fp);
	}

	if (ferror(fp)) {
		perror("fwrite");
		panic(gettext("output error to file %s writing symbol table\n"),
		    filename);
	}
	(void) fclose(fp);
}

/*
 * Initialize a symbol table from a file
 */
void
initsymtable(filename)
	char *filename;
{
	char *base;
	off64_t tblsize;
	struct entry *ep;
	struct entry *baseep, *lep;
	struct symtableheader hdr;
	struct stat64 stbuf;
	uint_t i;
	int fd;

	vprintf(stdout, gettext("Initialize symbol table.\n"));
	if (filename == NULL) {
		if ((maxino / HASHFACTOR) > UINT_MAX) {
			(void) fprintf(stderr,
			    gettext("file system too large\n"));
			done(1);
		}
		/* LINTED: result fits in entrytblsize */
		entrytblsize = maxino / HASHFACTOR;
		entry = (struct entry **)
			/* LINTED entrytblsize fits in a size_t */
			calloc((size_t)entrytblsize, sizeof (*entry));
		if (entry == (struct entry **)NULL) {
			(void) fprintf(stderr,
			    gettext("no memory for entry table\n"));
			done(1);
		}
		ep = addentry(".", ROOTINO, NODE);
		/* LINTED: result fits in a short */
		ep->e_flags |= NEW;
		return;
	}
	if ((fd = open(filename, O_RDONLY|O_LARGEFILE)) < 0) {
		perror("open");
		(void) fprintf(stderr,
		    gettext("cannot open symbol table file %s\n"), filename);
		done(1);
	}
	if (fstat64(fd, &stbuf) < 0) {
		perror("stat");
		(void) fprintf(stderr,
		    gettext("cannot stat symbol table file %s\n"), filename);
		(void) close(fd);
		done(1);
	}
	/*
	 * The symbol table file is too small so say we can't read it.
	 */
	if (stbuf.st_size < sizeof (hdr)) {
		(void) fprintf(stderr,
		    gettext("cannot read symbol table file %s\n"), filename);
		(void) close(fd);
		done(1);
	}
	tblsize = stbuf.st_size - sizeof (hdr);
	if (tblsize > ULONG_MAX) {
		(void) fprintf(stderr,
		    gettext("symbol table file too large\n"));
		(void) close(fd);
		done(1);
	}
	/* LINTED tblsize fits in a size_t */
	base = calloc((size_t)sizeof (char), (size_t)tblsize);
	if (base == NULL) {
		(void) fprintf(stderr,
		    gettext("cannot allocate space for symbol table\n"));
		(void) close(fd);
		done(1);
	}
	/* LINTED tblsize fits in a size_t */
	if (read(fd, base, (size_t)tblsize) < 0 ||
	    read(fd, (char *)&hdr, sizeof (hdr)) < 0) {
		perror("read");
		(void) fprintf(stderr,
		    gettext("cannot read symbol table file %s\n"), filename);
		(void) close(fd);
		done(1);
	}
	(void) close(fd);
	switch (command) {
	case 'r':
	case 'M':
		/*
		 * For normal continuation, insure that we are using
		 * the next incremental tape
		 */
		if (hdr.dumpdate != dumptime) {
			if (hdr.dumpdate < dumptime)
				(void) fprintf(stderr, gettext(
					"Incremental volume too low\n"));
			else
				(void) fprintf(stderr, gettext(
					"Incremental volume too high\n"));
			done(1);
		}
		break;
	case 'R':
		/*
		 * For restart, insure that we are using the same tape
		 */
		curfile.action = SKIP;
		dumptime = hdr.dumptime;
		dumpdate = hdr.dumpdate;
		if (!bflag)
			newtapebuf(hdr.ntrec);
		getvol(hdr.volno);
		break;
	default:
		(void) fprintf(stderr,
		    gettext("initsymtable called from command %c\n"),
		    (uchar_t)command);
		done(1);
		/*NOTREACHED*/
	}
	maxino = hdr.maxino;
	entrytblsize = hdr.entrytblsize;
	/*LINTED [pointer cast alignment]*/
	entry = (struct entry **)
	    (base + tblsize - (entrytblsize * sizeof (*entry)));
	if (((ulong_t)entry % 4) != 0) {
		(void) fprintf(stderr,
		    gettext("Symbol table file corrupted\n"));
		done(1);
	}
	/*LINTED [rvalue % 4 == 0] */
	baseep = (struct entry *)
	    (base + hdr.stringsize - sizeof (*baseep));
	if (((ulong_t)baseep % 4) != 0) {
		(void) fprintf(stderr,
		    gettext("Symbol table file corrupted\n"));
		done(1);
	}
	lep = (struct entry *)entry;
	for (i = 0; i < entrytblsize; i++) {
		if (entry[i] == NIL)
			continue;
		entry[i] = &baseep[(long)entry[i]];
	}
	for (ep = &baseep[1]; ep < lep; ep++) {
		ep->e_name = base + (long)ep->e_name;
		ep->e_parent = &baseep[(long)ep->e_parent];
		if (ep->e_sibling != NIL)
			ep->e_sibling = &baseep[(long)ep->e_sibling];
		if (ep->e_links != NIL)
			ep->e_links = &baseep[(long)ep->e_links];
		if (ep->e_entries != NIL)
			ep->e_entries = &baseep[(long)ep->e_entries];
		if (ep->e_xattrs != NIL)
			ep->e_xattrs = &baseep[(long)ep->e_xattrs];
		if (ep->e_next != NIL)
			ep->e_next = &baseep[(long)ep->e_next];
	}
}
