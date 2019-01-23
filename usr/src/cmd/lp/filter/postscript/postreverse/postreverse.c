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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include "postreverse.h"

/*
 * This version of postreverse should parse any Adobe DSC conforming
 * PostScript file and most that are not conforming, but minimally have the
 * page (%%Page:) and trailer (%%Trailer) comments in them at the begining of
 * the line.
 *
 * If a document cannot be parsed (no page and trailer comments), it is passed
 * through untouched.  If you look through the code you will find that it
 * doesn't ever look for the PostScript magic (%!).  This is because it
 * assumes that PostScript is sent in.  If PostScript is in sent in, it will
 * still attempt to parse it based on DSC page and trailer comments as if it
 * were postscript.
 *
 * flow goes as follows:
 *		1)  get command line options (including parsing a page
 *			list if supplied)
 *		2)  if no filename is supplied in command line, copy
 *			stdin to temp file.
 *		3)  parse the document:
 *			start from begining looking for a DSC page comment
 *			(that is the header) start from the end looking for
 *			a DSC trailer comment (that is the trailer) start from
 *			the header until the trailer looking for DSC page
 *			comments. Each one signifies a new page.
 *			start from the header until the trailer looking for BSD
 *			global comments. Each one violates page independence and
 *			will be stored so it can be printed after the header and
 *			before any pages.
 *		4)  print the document: if there is no header, trailer, or
 *			pages, print it from start to end unaltered if they all
 *			exist, print the header, pages, and trailer the pages
 *			are compared against a page list before being printed,
 *			and are reversed if the reverse flag has been set.
 *			If global definitions were found in the pages of a
 *			document, they are printed after the header and before
 *			the pages.
 */

static void *
nmalloc(size_t size)
{
	void *ret = malloc(size);

	if (!ret) {
		(void) fprintf(stderr,
			"postreverse : malloc() failed : Out of memory\n");
		exit(2);
	}
	return (ret);
}

static void *
nrealloc(void *ptr, size_t size)
{
	void *ret = realloc(ptr, size);

	if (!ret) {
		(void) fprintf(stderr,
			"postreverse : realloc() failed - Out of memory\n");
		exit(2);
	}
	return (ret);
}

/*
 * nstrlen() provides the same functionality as strlen() while also checking
 * that the pointer does not cross the end of file.
 *
 * Returns the number of non-NULL bytes in string argument.
 */

static size_t
nstrlen(const char *s, char *bptr)
{
	const char *s0 = s;

	while (s < bptr && *s != '\0')
		s++;
	return (s - s0);
}

/*
 * nstrstr() provides the same functionality as strstr() while also checking
 * that the pointers do not cross the end of the file.
 *
 * nstrstr() locates the first occurrence in the string as1 of the sequence of
 * characters (excluding the terminating null character) in the string as2.
 * nstrstr() returns a pointer to the located string, or a null pointer if
 * the string is not found. If as2 is "", the function returns as1.
 */

static char *
nstrstr(const char *as1, const char *as2, char *bptr)
{
	const char *s1, *s2;
	const char *tptr;
	char c;

	s1 = as1;
	s2 = as2;

	if (s2 == NULL || *s2 == '\0')
		return ((char *)s1);
	c = *s2;

	while (s1 < bptr && *s1)
		if (*s1++ == c) {
			tptr = s1;
			while ((s1 < bptr) &&
				(c = *++s2) == *s1++ && c);
			if (c == 0)
				return ((char *)tptr - 1);
			s1 = tptr;
			s2 = as2;
			c = *s2;
		}
	return (NULL);
}


/*
 * caddr_t strrstr(caddr_t as1, caddr_t as2 char *bptr1)
 *      return the address of the beginning of the last occruence of as2
 *      in as1 or NULL if not found
 */
caddr_t
strrstr(caddr_t s1, caddr_t s2, char *bptr)
{
	char *t1, *t2;
	char c;


	t1 = s1 + nstrlen(s1, bptr) - 1;
	t2 = s2 + nstrlen(s2, bptr) - 1;

	if (t2 == NULL || *t2 == '\0')
		return ((char *)t1);
	c = *t2;

	while (s1 <= t1)
		if (*t1-- == c) {
			while ((c = *--t2) == *t1-- && t2 > s2);
			if (t2 <= s2)
				return ((char *)t1 + 1);
			t2 = s2 + nstrlen(s2, bptr) - 1;
			c = *t2;
		}
	return (NULL);
}

/*
 * Copy stdin to a temp file and return the name
 */
char *
StdinToFile()
{
	char *fileName = tmpnam(NULL);
	int fd;
	int count;
	char buf[BUFSIZ];

	if ((fd = open(fileName, O_RDWR | O_CREAT | O_EXCL, 0600)) < 0) {
		fprintf(stderr, "open(%s): %s\n", fileName,
			strerror(errno));
		return (NULL);
	}
	while ((count = read(0, buf, sizeof (buf))) > 0)
		if (write(fd, buf, count) != count) {
			fprintf(stderr, "write(%d, 0x%x, %d): %s\n", fd, buf,
				count, strerror(errno));
			close(fd);
			unlink(fileName);
			return (NULL);
		}
	return (fileName);
}

/*
 * Usage(char *name) - program usage
 */
void
Usage(char *name)
{
	fprintf(stderr, "Usage: %s [ -o list ] [ -r ] [ filename ]\n", name);
	exit(1);
}


/*
 * int **ParsePageList(char *list)
 *    This will parse as string #,#,#-#,#... into an array of pointers
 *  to integers.  This array will contain all numbers in the list including
 *  those int the range #-#.  The list returned is NULL terminated.
 *  It uses 2 passes to build the list.  pass 1 counts the # of ints and
 *  allocates the space, and pass 2 fills in the list.
 */
int **
ParsePageList(char *list)
{
	int **pageList = NULL;
	int pass = 0;

	if (list == NULL)
		return (NULL);

	while (pass++ < 2) {
		char *page;
		char *tmplist;
		int size = 0;

		tmplist = strdup(list);
		page = strtok(tmplist, ",");

		do {
			int start, end;
			char *s1 = page, *s2;

			if (s2 = strchr(page, '-')) {
				*s2++ = '\0';
				start = atoi(s1);
				end = atoi(s2);
				if (end < start) {
					int tmp = end;

					end = start;
					start = tmp;
				}
			} else
				start = end = atoi(s1);

			while (start <= end)
				if (pass == 1)
				/* count the pages for allocation */
					size++, start++;
				else {	/* fill in the page list */
					int *tmp = (int *)nmalloc(sizeof (int));
					*tmp = start++;
					pageList[size++] = tmp;
				}
		} while (page = strtok(NULL, ","));
		free(tmplist);
		if (pass == 1)
			pageList = (int **)calloc(sizeof (int *), (size + 1));
	}
	return (pageList);
}


/*
 * int PageIsListed(int page, int **pageList)
 *    returns 1 if the pagelist is empty or if the page is in the
 *  NULL terminated pageList.  returns 0 if the page is not listed
 */
int
PageIsListed(int page, int **pageList)
{
	int count = 0;

	if (!pageList)
		return (1);

	for (count = 0; pageList[count] != NULL; count++)
		if (*pageList[count] == page)
			return (1);
	return (0);
}


/*
 * Writes the document Header to the fd
 */
int
WriteDocumentHeader(int fd, DOCUMENT * d)
{
	if (d) {
		HEADER *h = d->header;

		if (h)
			return (write(fd, h->start, h->size));
	}
	errno = EINVAL;
	return (-1);
}

/*
 * Writes the document global block to the fd
 */
int
WriteGlobal(int fd, GLOBAL * g)
{
	if (g)
		return (write(fd, g->start, g->size));
	errno = EINVAL;
	return (-1);
}

/*
 * Writes the document Trailer to the fd
 */
int
WriteDocumentTrailer(int fd, DOCUMENT * d)
{
	if (d) {
		TRAILER *t = d->trailer;

		if (t)
			return (write(fd, t->start, t->size));
	}
	errno = EINVAL;
	return (-1);
}

/*
 * Writes the document page to the fd
 */
int
WritePage(int fd, PAGE * p, int global, char *bptr)
{
	if (p) {
		caddr_t ptr1;

		if (((ptr1 = nstrstr(p->start, PS_BEGIN_GLOBAL, bptr))
			!= NULL) && (ptr1 < p->start + p->size) &&
			    (global != 0)) {
			/* BeginGlobal/EndGlobal in the page... */
			write(fd, p->start, ptr1 - p->start);
			ptr1 = nstrstr(ptr1, PS_END_GLOBAL, bptr);
			ptr1 += nstrlen(PS_END_GLOBAL, bptr);
			return (write(fd, ptr1, (p->size - (ptr1 - p->start))));
		} else
			return (write(fd, p->start, p->size));
	}
	errno = EINVAL;
	return (-1);
}

/*
 * Writes out the document pages in pageList (or all if NULL) and reverse
 * the output if reverse == 1
 */
void
WriteDocument(DOCUMENT * document, int reverse, int **pageList)
{
	int count = 0;
	int prnindex;

	if (document->header && document->trailer && document->page) {
		WriteDocumentHeader(1, document);

		if (document->global != NULL) {
			while (document->global[count] != NULL) {
				GLOBAL *global = document->global[count++];

				if (global)
					WriteGlobal(1, global);
			}
		}
		count = reverse ? (document->pages-1) : 0;

		for (prnindex = 0; prnindex < document->pages; prnindex++) {
			PAGE *page = document->page[count];

			if (page && PageIsListed(page->number, pageList))
				WritePage(1, page, document->global != NULL,
					document->start + document->size);

			count = reverse ? count - 1 : count + 1;
		}

		WriteDocumentTrailer(1, document);
	} else {
		write(1, document->start, document->size);
	}
}

/*
 * get a document header from document and return a pointer to a HEADER
 * structure.
 */
HEADER *
DocumentHeader(DOCUMENT * document)
{
	HEADER *header;
	caddr_t start;

	header = (HEADER *) nmalloc(sizeof (*header));
	memset(header, 0, sizeof (*header));
	if (start = nstrstr(document->start, PS_PAGE,
			    document->start + document->size)) {
		header->label = "Document Header";
		header->start = document->start;
		header->size = (start - document->start + 1);
	} else {
		free(header);
		header = NULL;
	}
	return (header);
}


/*
 * get a document trailer from document and return a pointer to a trailer
 * structure.
 */
TRAILER *
DocumentTrailer(DOCUMENT * document)
{
	TRAILER *trailer;

	trailer = (TRAILER *) nmalloc(sizeof (*trailer));
	memset(trailer, 0, sizeof (trailer));
	if (trailer->start = strrstr(document->start, PS_TRAILER,
		document->start + document->size)) {
		trailer->label = "Document Trailer";
		trailer->start += 1;
		trailer->size = nstrlen(trailer->start,
			document->start + document->size);
	} else {
		free(trailer);
		trailer = NULL;
	}
	return (trailer);
}

GLOBAL **
DocumentGlobals(DOCUMENT * document)
{
	GLOBAL **globals = NULL, *global;
	caddr_t start, ptr1;
	int count = 0;
	char *bptr = document->start + document->size;
	long allocated_slots = 0;
	caddr_t global_end;

	start = nstrstr(document->start, PS_PAGE, bptr);
	if (start != NULL) {
		for (ptr1 = nstrstr(start, PS_BEGIN_GLOBAL, bptr); ptr1 != NULL;
			ptr1 = nstrstr(++ptr1, PS_BEGIN_GLOBAL, bptr)) {
			count++;

			global = (GLOBAL *) nmalloc(sizeof (GLOBAL));
			if ((global_end = nstrstr(++ptr1, PS_END_GLOBAL, bptr))
				== NULL) {
				fprintf(stderr,
					"DSC violation: %%%%BeginGlobal "
						"with no %%%%EndGlobal\n");
				exit(-1);
			}
			memset(global, 0, sizeof (GLOBAL));
			global->start = ptr1;
			global->size = strchr(++global_end, '\n') - ptr1 + 1;

			if (count > allocated_slots) {
				globals = (GLOBAL **) nrealloc(globals,
					(allocated_slots + BLOCKSIZE) *
						sizeof (GLOBAL *));
				memset(globals +
					allocated_slots * sizeof (GLOBAL *), 0,
						BLOCKSIZE *
							sizeof (GLOBAL *));
				allocated_slots += BLOCKSIZE;
			}

			globals[count - 1] = global;
			ptr1 = global->start + global->size;
		}
	}
	return (globals);
}


/*
 * get the pages from a document and return a pointer a list of PAGE
 * structures.
 */
PAGE **
DocumentPages(DOCUMENT * document)
{
	PAGE **pages = NULL, *page;
	caddr_t ptr1, page_end;
	char *bptr = document->start + document->size;
	long allocated_slots = 0;
	long no_pages = 0;
	long number;
	char *label, *tmp, *tmp_end;

	for (ptr1 = nstrstr(document->start, PS_PAGE, bptr); ptr1 != NULL;
	    ptr1 = nstrstr(++ptr1, PS_PAGE, bptr)) {
		no_pages++;

		if (no_pages > allocated_slots) {
			pages = (PAGE **) nrealloc(pages,
			    (allocated_slots + BLOCKSIZE) * sizeof (PAGE *));
			memset(pages + allocated_slots, 0,
			    BLOCKSIZE * sizeof (PAGE *));
			allocated_slots += BLOCKSIZE;
		}
		page = (PAGE *) nmalloc(sizeof (PAGE));
		label = NULL;
		number = -1;

		/* page start & end */
		if ((page_end = nstrstr(++ptr1, PS_PAGE, bptr)) == NULL)
			if (document->trailer)
				page_end = document->trailer->start - 1;
			else
				page_end = document->start + document->size;

		/* page label & number */
		if (tmp = strchr(ptr1, ' ')) {

			if (tmp_end = strchr(++tmp, ' ')) {
				label = (char *)nmalloc((tmp_end - tmp) + 1);
				memset(label, 0, (tmp_end - tmp) + 1);
				strncpy(label, tmp, (tmp_end - tmp));
				number = atol(++tmp_end);
			}
		}
		memset(page, 0, sizeof (PAGE));
		page->label = label;
		page->number = number;
		page->start = ptr1;
		page->size = page_end - ptr1 + 1;

		pages[document->pages++] = page;
	}
	return (pages);
}

/*
 * parse a document and return a pointer to a DOCUMENT structure
 */
DOCUMENT *
DocumentParse(char *name)
{
	DOCUMENT *document = NULL;
	int fd;
	struct stat st;

	if (stat(name, &st) < 0) {
		fprintf(stderr, "stat(%s): %s\n", name, strerror(errno));
		return (NULL);
	}
	if (st.st_size == 0) {
		fprintf(stderr, "%s: empty file\n", name);
		return (NULL);
	}
	if ((fd = open(name, O_RDONLY)) < 0) {
		fprintf(stderr, "open(%s, O_RDONLY): %s\n", name,
			strerror(errno));
		return (NULL);
	}
	document = (DOCUMENT *) nmalloc(sizeof (DOCUMENT));
	memset(document, 0, sizeof (DOCUMENT));
	if ((document->start = mmap((void *)0, (size_t)st.st_size, PROT_READ,
		MAP_SHARED, fd, (off_t)0)) == MAP_FAILED) {
		fprintf(stderr, "mmap(0, %ld, PROT_READ,"
			" MAP_SHARED, %d, 0): %s\n",
				st.st_size, fd, strerror(errno));
		free(document);
		document = NULL;
	} else {
		/* order in important */
		document->name = strdup(name);
		document->size = nstrlen(document->start,
			document->start + st.st_size);
		document->header = DocumentHeader(document);
		document->trailer = DocumentTrailer(document);
		document->page = DocumentPages(document);
		document->global = DocumentGlobals(document);
	}
	close(fd);
	return (document);
}


#if defined(DEBUG)
/*
 * Print out the contents of the document structure
 */
void
PrintDocumentInfo(DOCUMENT * d)
{
	if (d) {
		printf("Document:\n\tname:  %s\n\tstart: 0x%x\n\tsize:  %ld\n",
			d->name, d->start, d->size);
		if (d->header) {
			HEADER *h = d->header;

			printf("\tHeader: %s (0x%x, %ld)\n",
				h->label, h->start, h->size);
		}
		if (d->global) {
			int count = 0;

			while (d->global[count++] != NULL);
			printf("\tDSC violating BeginGlobals: %d\n", count);
		}
		if (d->page) {
			PAGE *p;
			int count = 0;

			printf("\tPages: (%d)\n", d->pages);
			for (p = d->page[0]; p != NULL; p = d->page[++count])
				printf("\t\t %4d (%s) - (0x%x, %ld)\n",
					p->number,
						(p->label ? p->label : "Page"),
							p->start, p->size);
		}
		if (d->trailer) {
			TRAILER *t = d->trailer;

			printf("\tTrailer: %s (0x%x, %ld)\n",
				t->label, t->start, t->size);
		}
	}
}
#endif				/* DEBUG */


int
main(int ac, char *av[])
{
	DOCUMENT *document;
	char *fileName = NULL;
	char *programName = NULL;
	char *unlinkFile = NULL;
	int reversePages = 1;
	int **pageList = NULL;
	int option;

	if (programName = strrchr(av[0], '/'))
		programName++;
	else
		programName = av[0];

	while ((option = getopt(ac, av, "o:r")) != EOF)
		switch (option) {
		case 'o':
			pageList = ParsePageList(optarg);
			break;
		case 'r':
			reversePages = 0;
			break;
		case '?':
			Usage(programName);
			break;
		default:
			fprintf(stderr, "missing case for option %c\n", option);
			Usage(programName);
			break;
		}

	ac -= optind;
	av += optind;

	switch (ac) {
	case 0:
		unlinkFile = fileName = StdinToFile();
		break;
	case 1:
		fileName = av[0];
		break;
	default:
		Usage(programName);
	}

	if ((document = DocumentParse(fileName)) == NULL) {
		fprintf(stderr, "Unable to parse document (%s)\n", fileName);
		exit(0);
	}
#if defined(DEBUG) && defined(NOTDEF)
	PrintDocumentInfo(document);
#endif				/* DEBUG */

	WriteDocument(document, reversePages, pageList);

	if (unlinkFile)
		unlink(unlinkFile);

	return (0);
}
