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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ctype.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/byteorder.h>
#if SHARE
#include <sys/ipc.h>
#include <sys/shm.h>
#define	ERR  -1
#endif
#include "invlib.h"
#include "library.h"

#define	DEBUG		0	/* debugging code and realloc messages */
#define	BLOCKSIZE	2 * BUFSIZ	/* logical block size */
#define	LINEMAX		1000	/* sorted posting line max size */
#define	POSTINC		10000	/* posting buffer size increment */
#define	SEP		' '	/* sorted posting field separator */
#define	SETINC		100	/* posting set size increment */
#define	STATS		0	/* print statistics */
#define	SUPERINC	10000	/* super index size increment */
#define	TERMMAX		512	/* term max size */
#define	VERSION		1	/* inverted index format version */
#define	ZIPFSIZE	200	/* zipf curve size */
#define	FREAD	"r"		/* fopen for reading */
#define	FREADP	"r+"		/* fopen for update */
#define	FWRITE	"w"		/* fopen truncate or create for writing */
#define	FWRITEP	"w+"		/* fopen truncate or create for update */

extern	char	*argv0;	/* command name (must be set in main function) */

int	invbreak;

#if STATS
int	showzipf;	/* show postings per term distribution */
#endif

static	POSTING	*item, *enditem, *item1 = NULL, *item2 = NULL;
static	unsigned setsize1, setsize2;
static	long	numitems, totterm, zerolong;
static	char	*indexfile, *postingfile;
static	FILE	*outfile, *fpost;
static	unsigned supersize = SUPERINC, supintsize;
static	int	numpost, numlogblk, amtused, nextpost,
		lastinblk, numinvitems;
static	POSTING	*POST, *postptr;
static	unsigned long	*SUPINT, *supint, nextsupfing;
static	char	*SUPFING, *supfing;
static	char	thisterm[TERMMAX];
static	union {
	long	invblk[BLOCKSIZE / sizeof (long)];
	char	chrblk[BLOCKSIZE];
} logicalblk;

#if DEBUG || STATS
static	long	totpost;
#endif

#if STATS
static	int	zipf[ZIPFSIZE + 1];
#endif

static void invcannotalloc(size_t n);
static void invcannotopen(char *file);
static void invcannotwrite(char *file);
static int invnewterm(void);
static int boolready(void);

long
invmake(char *invname, char *invpost, FILE *infile)
{
	unsigned char	*s;
	long	num;
	int	i;
	long	fileindex;
	unsigned postsize = POSTINC * sizeof (POSTING);
	unsigned long	*intptr;
	char	line[LINEMAX];
	long	tlong;
	PARAM	param;
	POSTING	posting;
#if STATS
	int	j;
	unsigned maxtermlen = 0;
#endif
	/* output file */
	if ((outfile = vpfopen(invname, FWRITEP)) == NULL) {
		invcannotopen(invname);
		return (0);
	}
	indexfile = invname;
	(void) fseek(outfile, (long)BUFSIZ, 0);

	/* posting file  */
	if ((fpost = vpfopen(invpost, FWRITE)) == NULL) {
		invcannotopen(invpost);
		return (0);
	}
	postingfile = invpost;
	nextpost = 0;
	/* get space for the postings list */
	if ((POST = (POSTING *)malloc(postsize)) == NULL) {
		invcannotalloc(postsize);
		return (0);
	}
	postptr = POST;
	/* get space for the superfinger (superindex) */
	if ((SUPFING = malloc(supersize)) == NULL) {
		invcannotalloc(supersize);
		return (0);
	}
	supfing = SUPFING;
	supintsize = supersize / 40;
	/* also for the superfinger index */
	if ((SUPINT = malloc(supintsize * sizeof (long))) == NULL) {
		invcannotalloc(supintsize * sizeof (long));
		return (0);
	}
	supint = SUPINT;
	supint++; /* leave first term open for a count */
	/* initialize using an empty term */
	(void) strcpy(thisterm, "");
	*supint++ = 0;
	*supfing++ = ' ';
	*supfing++ = '\0';
	nextsupfing = 2;
#if DEBUG || STATS
	totpost = 0L;
#endif
	totterm = 0L;
	numpost = 1;

	/*
	 * set up as though a block had come and gone, i.e., set up for
	 * new block
	 */
	amtused = 16; /* leave no space - init 3 words + one for luck */
	numinvitems = 0;
	numlogblk = 0;
	lastinblk = BLOCKSIZE;

	/* now loop as long as more to read (till eof)  */
	while (fgets(line, LINEMAX, infile) != NULL) {
#if DEBUG || STATS
		++totpost;
#endif
		s = (unsigned char *) strchr(line, SEP);
		if (s == NULL)		/* where did this line come from ??? */
			continue;	/* workaround: just skip it */
		*s = '\0';
#if STATS
		if ((i = strlen(line)) > maxtermlen) {
			maxtermlen = i;
		}
#endif
#if DEBUG
		(void) printf("%ld: %s ", totpost, line);
		(void) fflush(stdout);
#endif
		if (strcmp(thisterm, line) == 0) {
			if (postptr + 10 > POST + postsize / sizeof (POSTING)) {
				i = postptr - POST;
				postsize += POSTINC * sizeof (POSTING);
				if ((POST = realloc(POST, postsize)) == NULL) {
					invcannotalloc(postsize);
					return (0);
				}
				postptr = i + POST;
#if DEBUG
				(void) printf("reallocated post space to %u, "
				    "totpost=%ld\n", postsize, totpost);
#endif
			}
			numpost++;
		} else {
			/* have a new term */
			if (!invnewterm()) {
				return (0);
			}
			(void) strcpy(thisterm, line);
			numpost = 1;
			postptr = POST;
			fileindex = 0;
		}
		/* get the new posting */
		num = *++s - '!';
		i = 1;
		do {
			num = BASE * num + *++s - '!';
		} while (++i < PRECISION);
		posting.lineoffset = num;
		while (++fileindex < nsrcoffset && num > srcoffset[fileindex]) {
			;
		}
		posting.fileindex = --fileindex;
		posting.type = *++s;
		num = *++s - '!';
		if (*s != '\n') {
			num = *++s - '!';
			while (*++s != '\n') {
				num = BASE * num + *s - '!';
			}
			posting.fcnoffset = num;
		} else {
			posting.fcnoffset = 0;
		}
		*postptr++ = posting;
#if DEBUG
		(void) printf("%ld %ld %ld %ld\n", posting.fileindex,
		    posting.fcnoffset, posting.lineoffset, posting.type);
		(void) fflush(stdout);
#endif
	}
	if (!invnewterm()) {
		return (0);
	}
	/* now clean up final block  */
	logicalblk.invblk[0] = numinvitems;
	/* loops pointer around to start */
	logicalblk.invblk[1] = 0;
	logicalblk.invblk[2] = numlogblk - 1;
	if (fwrite((char *)&logicalblk, BLOCKSIZE, 1, outfile) == 0) {
		goto cannotwrite;
	}
	numlogblk++;
	/* write out block to save space. what in it doesn't matter */
	if (fwrite((char *)&logicalblk, BLOCKSIZE, 1, outfile) == 0) {
		goto cannotwrite;
	}
	/* finish up the super finger */
	*SUPINT = numlogblk;
	/* add to the offsets the size of the offset pointers */
	intptr = (SUPINT + 1);
	i = (char *)supint - (char *)SUPINT;
	while (intptr < supint)
		*intptr++ += i;
	/* write out the offsets (1 for the N at start) and the super finger */
	if (fwrite((char *)SUPINT, sizeof (*SUPINT), numlogblk + 1,
	    outfile) == 0 ||
	    fwrite(SUPFING, 1, supfing - SUPFING, outfile) == 0) {
		goto cannotwrite;
	}
	/* save the size for reference later */
	nextsupfing = sizeof (long) + sizeof (long) * numlogblk +
	    (supfing - SUPFING);
	/*
	 * make sure the file ends at a logical block boundary.  This is
	 * necessary for invinsert to correctly create extended blocks
	 */
	i = nextsupfing % BLOCKSIZE;
	/* write out junk to fill log blk */
	if (fwrite(SUPFING, BLOCKSIZE - i, 1, outfile) == 0 ||
	    fflush(outfile) == EOF) {
		/* rewind doesn't check for write failure */
		goto cannotwrite;
	}
	/* write the control area */
	rewind(outfile);
	param.version = VERSION;
	param.filestat = 0;
	param.sizeblk = BLOCKSIZE;
	param.startbyte = (numlogblk + 1) * BLOCKSIZE + BUFSIZ;
	param.supsize = nextsupfing;
	param.cntlsize = BUFSIZ;
	param.share = 0;
	if (fwrite((char *)&param, sizeof (param), 1, outfile) == 0) {
		goto cannotwrite;
	}
	for (i = 0; i < 10; i++)	/* for future use */
		if (fwrite((char *)&zerolong, sizeof (zerolong),
		    1, outfile) == 0) {
			goto cannotwrite;
		}

	/* make first block loop backwards to last block */
	if (fflush(outfile) == EOF) {
		/* fseek doesn't check for write failure */
		goto cannotwrite;
	}
	/* get to second word first block */
	(void) fseek(outfile, (long)BUFSIZ + 8, 0);
	tlong = numlogblk - 1;
	if (fwrite((char *)&tlong, sizeof (tlong), 1, outfile) == 0 ||
	    fclose(outfile) == EOF) {
cannotwrite:
		invcannotwrite(invname);
		return (0);
	}
	if (fclose(fpost) == EOF) {
		invcannotwrite(postingfile);
		return (0);
	}
	--totterm;	/* don't count null term */
#if STATS
	(void) printf("logical blocks = %d, postings = %ld, terms = %ld, "
	    "max term length = %d\n", numlogblk, totpost, totterm, maxtermlen);
	if (showzipf) {
		(void) printf(
		    "\n*************   ZIPF curve  ****************\n");
		for (j = ZIPFSIZE; j > 1; j--)
			if (zipf[j])
				break;
		for (i = 1; i < j; ++i) {
			(void) printf("%3d -%6d ", i, zipf[i]);
			if (i % 6 == 0) (void) putchar('\n');
		}
		(void) printf(">%d-%6d\n", ZIPFSIZE, zipf[0]);
	}
#endif
	/* free all malloc'd memory */
	free(POST);
	free(SUPFING);
	free(SUPINT);
	return (totterm);
}

/* add a term to the data base */

static int
invnewterm(void)
{
	int	backupflag, i, j, maxback, holditems, gooditems, howfar;
	int	len, numwilluse, wdlen;
	char	*tptr, *tptr2, *tptr3;
	union {
		unsigned long	packword[2];
		ENTRY		e;
	} iteminfo;

	totterm++;
#if STATS
	/* keep zipfian info on the distribution */
	if (numpost <= ZIPFSIZE)
		zipf[numpost]++;
	else
		zipf[0]++;
#endif
	len = strlen(thisterm);
	wdlen = (len + (sizeof (long) - 1)) / sizeof (long);
	numwilluse = (wdlen + 3) * sizeof (long);
	/* new block if at least 1 item in block */
	if (numinvitems && numwilluse + amtused > BLOCKSIZE) {
		/* set up new block */
		if (supfing + 500 > SUPFING + supersize) {
			i = supfing - SUPFING;
			supersize += 20000;
			if ((SUPFING = realloc(SUPFING, supersize)) == NULL) {
				invcannotalloc(supersize);
				return (0);
			}
			supfing = i + SUPFING;
#if DEBUG
			(void) printf("reallocated superfinger space to %d, "
			    "totpost=%ld\n", supersize, totpost);
#endif
		}
		/* check that room for the offset as well */
		if ((numlogblk + 10) > supintsize) {
			i = supint - SUPINT;
			supintsize += SUPERINC;
			if ((SUPINT = realloc((char *)SUPINT,
			    supintsize * sizeof (long))) == NULL) {
				invcannotalloc(supintsize * sizeof (long));
				return (0);
			}
			supint = i + SUPINT;
#if DEBUG
			(void) printf("reallocated superfinger offset to %d, "
			    "totpost = %ld\n", supintsize * sizeof (long),
			    totpost);
#endif
		}
		/* See if backup is efficatious  */
		backupflag = 0;
		maxback = strlen(thisterm) / 10;
		holditems = numinvitems;
		if (maxback > numinvitems)
			maxback = numinvitems - 2;
		howfar = 0;
		while (--maxback > 0) {
			howfar++;
			iteminfo.packword[0] =
			    logicalblk.invblk[--holditems * 2 +
			    (sizeof (long) - 1)];
			if ((i = iteminfo.e.size / 10) < maxback) {
				maxback = i;
				backupflag = howfar;
				gooditems = holditems;
				tptr2 = logicalblk.chrblk + iteminfo.e.offset;
			}
		}
		/* see if backup will occur  */
		if (backupflag) {
			numinvitems = gooditems;
		}
		logicalblk.invblk[0] = numinvitems;
		/* set forward pointer pointing to next */
		logicalblk.invblk[1] = numlogblk + 1;
		/* set back pointer to last block */
		logicalblk.invblk[2] = numlogblk - 1;
		if (fwrite((char *)logicalblk.chrblk, 1,
		    BLOCKSIZE, outfile) == 0) {
			invcannotwrite(indexfile);
			return (0);
		}
		amtused = 16;
		numlogblk++;
		/* check if had to back up, if so do it */
		if (backupflag) {
			/* find out where the end of the new block is */
			iteminfo.packword[0] =
			    logicalblk.invblk[numinvitems * 2 + 1];
			tptr3 = logicalblk.chrblk + iteminfo.e.offset;
			/* move the index for this block */
			for (i = 3; i <= (backupflag * 2 + 2); i++) {
				logicalblk.invblk[i] =
				    logicalblk.invblk[numinvitems * 2+i];
			}
			/* move the word into the super index */
			iteminfo.packword[0] = logicalblk.invblk[3];
			iteminfo.packword[1] = logicalblk.invblk[4];
			tptr2 = logicalblk.chrblk + iteminfo.e.offset;
			(void) strncpy(supfing, tptr2, (int)iteminfo.e.size);
			*(supfing + iteminfo.e.size) = '\0';
#if DEBUG
			(void) printf("backup %d at term=%s to term=%s\n",
			    backupflag, thisterm, supfing);
#endif
			*supint++ = nextsupfing;
			nextsupfing += strlen(supfing) + 1;
			supfing += strlen(supfing) + 1;
			/* now fix up the logical block */
			tptr = logicalblk.chrblk + lastinblk;
			lastinblk = BLOCKSIZE;
			tptr2 = logicalblk.chrblk + lastinblk;
			j = tptr3 - tptr;
			while (tptr3 > tptr)
				*--tptr2 = *--tptr3;
			lastinblk -= j;
			amtused += (8 * backupflag + j);
			for (i = 3; i < (backupflag * 2 + 2); i += 2) {
				iteminfo.packword[0] = logicalblk.invblk[i];
				iteminfo.e.offset += (tptr2 - tptr3);
				logicalblk.invblk[i] = iteminfo.packword[0];
			}
			numinvitems = backupflag;
		} else { /* no backup needed */
			numinvitems = 0;
			lastinblk = BLOCKSIZE;
			/* add new term to superindex */
			(void) strcpy(supfing, thisterm);
			supfing += strlen(thisterm) + 1;
			*supint++ = nextsupfing;
			nextsupfing += strlen(thisterm) + 1;
		}
	}
	lastinblk -= (numwilluse - 8);
	iteminfo.e.offset = lastinblk;
	iteminfo.e.size = (char)len;
	iteminfo.e.space = 0;
	iteminfo.e.post = numpost;
	(void) strncpy(logicalblk.chrblk + lastinblk, thisterm, len);
	amtused += numwilluse;
	logicalblk.invblk[(lastinblk/sizeof (long))+wdlen] = nextpost;
	if ((i = postptr - POST) > 0) {
		if (fwrite((char *)POST, sizeof (POSTING), i, fpost) == 0) {
			invcannotwrite(postingfile);
			return (0);
		}
		nextpost += i * sizeof (POSTING);
	}
	logicalblk.invblk[3+2*numinvitems++] = iteminfo.packword[0];
	logicalblk.invblk[2+2*numinvitems] = iteminfo.packword[1];
	return (1);
}

static void
swap_ints(void *p, size_t sz)
{
	uint32_t *s;
	uint32_t *e = (uint32_t *)p + (sz / sizeof (uint32_t));

	for (s = p; s < e; s++)
		*s = BSWAP_32(*s);
}

static void
write_param(INVCONTROL *invcntl)
{
	if (invcntl->swap)
		swap_ints(&invcntl->param, sizeof (invcntl->param));

	rewind(invcntl->invfile);
	(void) fwrite((char *)&invcntl->param, sizeof (invcntl->param), 1,
	    invcntl->invfile);

	if (invcntl->swap)
		swap_ints(&invcntl->param, sizeof (invcntl->param));
}

static void
read_superfinger(INVCONTROL *invcntl)
{
	size_t count;

	(void) fseek(invcntl->invfile, invcntl->param.startbyte, SEEK_SET);
	(void) fread(invcntl->iindex, (int)invcntl->param.supsize,
	    1, invcntl->invfile);

	if (invcntl->swap) {
		/*
		 * The superfinger consists of a count, followed by
		 * count offsets, followed by a string table (which
		 * the offsets reference).
		 *
		 * We need to swap the count and the offsets.
		 */
		count = 1 + BSWAP_32(*(uint32_t *)invcntl->iindex);
		swap_ints(invcntl->iindex, count * sizeof (unsigned long));
	}
}

static void
read_logblock(INVCONTROL *invcntl, int block)
{
	/* note always fetch it if the file is busy */
	if ((block != invcntl->numblk) ||
	    (invcntl->param.filestat >= INVBUSY)) {
		(void) fseek(invcntl->invfile,
		    (block * invcntl->param.sizeblk) + invcntl->param.cntlsize,
		    SEEK_SET);
		invcntl->numblk = block;
		(void) fread(invcntl->logblk, (int)invcntl->param.sizeblk,
		    1, invcntl->invfile);

		if (invcntl->swap) {
			size_t count;
			ENTRY *ecur, *eend;
			uint32_t *postptr;

			/*
			 * A logblock consists of a count, a next block id,
			 * and a previous block id, followed by count
			 * ENTRYs, followed by alternating strings and
			 * offsets.
			 */
			swap_ints(invcntl->logblk, 3 * sizeof (unsigned long));

			count = *(uint32_t *)invcntl->logblk;

			ecur = (ENTRY *)((uint32_t *)invcntl->logblk + 3);
			eend = ecur + count;

			for (; ecur < eend; ecur++) {
				ecur->offset = BSWAP_16(ecur->offset);
				ecur->post = BSWAP_32(ecur->post);

				/*
				 * After the string is the posting offset.
				 */
				postptr = (uint32_t *)(invcntl->logblk +
				    ecur->offset +
				    P2ROUNDUP(ecur->size, sizeof (long)));

				*postptr = BSWAP_32(*postptr);
			}
		}
	}
}

void
read_next_posting(INVCONTROL *invcntl, POSTING *posting)
{
	(void) fread((char *)posting, sizeof (*posting), 1, invcntl->postfile);
	if (invcntl->swap) {
		posting->lineoffset = BSWAP_32(posting->lineoffset);
		posting->fcnoffset = BSWAP_32(posting->fcnoffset);
		/*
		 * fileindex is a 24-bit field, so shift it before swapping
		 */
		posting->fileindex = BSWAP_32(posting->fileindex << 8);
	}
}

int
invopen(INVCONTROL *invcntl, char *invname, char *invpost, int stat)
{
	int	read_index;

	if ((invcntl->invfile = vpfopen(invname,
	    ((stat == 0) ? FREAD : FREADP))) == NULL) {
		invcannotopen(invname);
		return (-1);
	}
	if (fread((char *)&invcntl->param, sizeof (invcntl->param), 1,
	    invcntl->invfile) == 0) {
		(void) fprintf(stderr, "%s: empty inverted file\n", argv0);
		goto closeinv;
	}
	if (invcntl->param.version != VERSION &&
	    BSWAP_32(invcntl->param.version) != VERSION) {
		(void) fprintf(stderr,
		    "%s: cannot read old index format; use -U option to "
		    "force database to rebuild\n", argv0);
		goto closeinv;
	}
	invcntl->swap = (invcntl->param.version != VERSION);
	if (invcntl->swap)
		swap_ints(&invcntl->param, sizeof (invcntl->param));

	if (stat == 0 && invcntl->param.filestat == INVALONE) {
		(void) fprintf(stderr, "%s: inverted file is locked\n", argv0);
		goto closeinv;
	}
	if ((invcntl->postfile = vpfopen(invpost,
	    ((stat == 0) ? FREAD : FREADP))) == NULL) {
		invcannotopen(invpost);
		goto closeinv;
	}
	/* allocate core for a logical block  */
	if ((invcntl->logblk = malloc(invcntl->param.sizeblk)) == NULL) {
		invcannotalloc((unsigned)invcntl->param.sizeblk);
		goto closeboth;
	}
	/* allocate for and read in superfinger  */
	read_index = 1;
	invcntl->iindex = NULL;
#if SHARE
	if (invcntl->param.share == 1) {
		key_t ftok(), shm_key;
		struct shmid_ds shm_buf;
		char	*shmat();
		int	shm_id;

		/* see if the shared segment exists */
		shm_key = ftok(invname, 2);
		shm_id = shmget(shm_key, 0, 0);
		/*
		 * Failure simply means (hopefully) that segment doesn't
		 * exist
		 */
		if (shm_id == -1) {
			/*
			 * Have to give general write permission due to AMdahl
			 * not having protected segments
			 */
			shm_id = shmget(shm_key,
			    invcntl->param.supsize + sizeof (long),
			    IPC_CREAT | 0666);
			if (shm_id == -1)
				perror("Could not create shared "
				    "memory segment");
		} else
			read_index = 0;

		if (shm_id != -1) {
			invcntl->iindex = shmat(shm_id, 0,
			    ((read_index) ? 0 : SHM_RDONLY));
			if (invcntl->iindex == (char *)ERR) {
				(void) fprintf(stderr,
				    "%s: shared memory link failed\n", argv0);
				invcntl->iindex = NULL;
				read_index = 1;
			}
		}
	}
#endif
	if (invcntl->iindex == NULL)
		invcntl->iindex = malloc(invcntl->param.supsize + 16);
	if (invcntl->iindex == NULL) {
		invcannotalloc((unsigned)invcntl->param.supsize);
		free(invcntl->logblk);
		goto closeboth;
	}
	if (read_index) {
		read_superfinger(invcntl);
	}
	invcntl->numblk = -1;
	if (boolready() == -1) {
	closeboth:
		(void) fclose(invcntl->postfile);
	closeinv:
		(void) fclose(invcntl->invfile);
		return (-1);
	}
	/* write back out the control block if anything changed */
	invcntl->param.filestat = stat;
	if (stat > invcntl->param.filestat)
		write_param(invcntl);
	return (1);
}

/* invclose must be called to wrap things up and deallocate core */
void
invclose(INVCONTROL *invcntl)
{
	/* write out the control block in case anything changed */
	if (invcntl->param.filestat > 0) {
		invcntl->param.filestat = 0;
		write_param(invcntl);
	}
	(void) fclose(invcntl->invfile);
	(void) fclose(invcntl->postfile);
#if SHARE
	if (invcntl->param.share > 0) {
		shmdt(invcntl->iindex);
		invcntl->iindex = NULL;
	}
#endif
	if (invcntl->iindex != NULL)
		free(invcntl->iindex);
	free(invcntl->logblk);
}

/* invstep steps the inverted file forward one item */
void
invstep(INVCONTROL *invcntl)
{
	if (invcntl->keypnt < (*(int *)invcntl->logblk - 1)) {
		invcntl->keypnt++;
		return;
	}

	/* move forward a block else wrap */
	read_logblock(invcntl, *(int *)(invcntl->logblk + sizeof (long)));

	invcntl->keypnt = 0;
}

/* invforward moves forward one term in the inverted file  */
int
invforward(INVCONTROL *invcntl)
{
	invstep(invcntl);
	/* skip things with 0 postings */
	while (((ENTRY *)(invcntl->logblk + 12) + invcntl->keypnt)->post == 0) {
		invstep(invcntl);
	}
	/* Check for having wrapped - reached start of inverted file! */
	if ((invcntl->numblk == 0) && (invcntl->keypnt == 0))
		return (0);
	return (1);
}

/*  invterm gets the present term from the present logical block  */
int
invterm(INVCONTROL *invcntl, char *term)
{
	ENTRY * entryptr;

	entryptr = (ENTRY *)(invcntl->logblk + 12) + invcntl->keypnt;
	(void) strncpy(term, entryptr->offset + invcntl->logblk,
	    (int)entryptr->size);
	*(term + entryptr->size) = '\0';
	return (entryptr->post);
}

/* invfind searches for an individual item in the inverted file */
long
invfind(INVCONTROL *invcntl, char *searchterm)
{
	int	imid, ilow, ihigh;
	long	num;
	int	i;
	unsigned long	*intptr, *intptr2;
	ENTRY *entryptr;

	/* make sure it is initialized via invready  */
	if (invcntl->invfile == 0)
		return (-1L);

	/* now search for the appropriate finger block */
	intptr = (unsigned long *)invcntl->iindex;

	ilow = 0;
	ihigh = *intptr++ - 1;
	while (ilow <= ihigh) {
		imid = (ilow + ihigh) / 2;
		intptr2 = intptr + imid;
		i = strcmp(searchterm, (invcntl->iindex + *intptr2));
		if (i < 0)
			ihigh = imid - 1;
		else if (i > 0)
			ilow = ++imid;
		else {
			ilow = imid + 1;
			break;
		}
	}
	/* be careful about case where searchterm is after last in this block */
	imid = (ilow) ? ilow - 1 : 0;

	/* fetch the appropriate logical block if not in core  */
	read_logblock(invcntl, imid);

srch_ext:
	/* now find the term in this block. tricky this  */
	intptr = (unsigned long *)invcntl->logblk;

	ilow = 0;
	ihigh = *intptr - 1;
	intptr += 3;
	num = 0;
	while (ilow <= ihigh) {
		imid = (ilow + ihigh) / 2;
		entryptr = (ENTRY *)intptr + imid;
		i = strncmp(searchterm, (invcntl->logblk + entryptr->offset),
		    (int)entryptr->size);
		if (i == 0)
			i = strlen(searchterm) - entryptr->size;
		if (i < 0)
			ihigh = imid - 1;
		else if (i > 0)
			ilow = ++imid;
		else {
			num = entryptr->post;
			break;
		}
	}
	/* be careful about case where searchterm is after last in this block */
	if (imid >= *(long *)invcntl->logblk) {
		invcntl->keypnt = *(long *)invcntl->logblk;
		invstep(invcntl);
		/* note if this happens the term could be in extended block */
		if (invcntl->param.startbyte <
		    invcntl->numblk * invcntl->param.sizeblk)
			goto srch_ext;
	} else
		invcntl->keypnt = imid;
	return (num);
}

#if DEBUG

/* invdump dumps the block the term parameter is in */
void
invdump(INVCONTROL *invcntl, char *term)
{
	long	i, j, n, *longptr;
	ENTRY * entryptr;
	char	temp[512], *ptr;

	/* dump superindex if term is "-"  */
	if (*term == '-') {
		j = atoi(term + 1);
		longptr = (long *)invcntl->iindex;
		n = *longptr++;
		(void) printf("Superindex dump, num blocks=%ld\n", n);
		longptr += j;
		while ((longptr <= ((long *)invcntl->iindex) + n) &&
		    invbreak == 0) {
			(void) printf("%2ld  %6ld %s\n", j++, *longptr,
			    invcntl->iindex + *longptr);
			longptr++;
		}
		return;
	} else if (*term == '#') {
		j = atoi(term + 1);
		/* fetch the appropriate logical block */
		read_logblock(invcntl, j);
	} else
		i = abs((int)invfind(invcntl, term));
	longptr = (long *)invcntl->logblk;
	n = *longptr++;
	(void) printf("Entry term to invdump=%s, postings=%ld, "
	    "forward ptr=%ld, back ptr=%ld\n", term, i, *(longptr),
	    *(longptr + 1));
	entryptr = (ENTRY *)(invcntl->logblk + 12);
	(void) printf("%ld terms in this block, block=%ld\n", n,
	    invcntl->numblk);
	(void) printf("\tterm\t\t\tposts\tsize\toffset\tspace\t1st word\n");
	for (j = 0; j < n && invbreak == 0; j++) {
		ptr = invcntl->logblk + entryptr->offset;
		(void) strncpy(temp, ptr, (int)entryptr->size);
		temp[entryptr->size] = '\0';
		ptr += (sizeof (long) *
		    (long)((entryptr->size +
		    (sizeof (long) - 1)) / sizeof (long)));
		(void) printf("%2ld  %-24s\t%5ld\t%3d\t%d\t%d\t%ld\n", j, temp,
		    entryptr->post, entryptr->size, entryptr->offset,
		    entryptr->space, *(long *)ptr);
		entryptr++;
	}
}
#endif

static int
boolready(void)
{
	numitems = 0;
	if (item1 != NULL)
		free(item1);
	setsize1 = SETINC;
	if ((item1 = (POSTING *)malloc(SETINC * sizeof (POSTING))) == NULL) {
		invcannotalloc(SETINC);
		return (-1);
	}
	if (item2 != NULL)
		free(item2);
	setsize2 = SETINC;
	if ((item2 = (POSTING *)malloc(SETINC * sizeof (POSTING))) == NULL) {
		invcannotalloc(SETINC);
		return (-1);
	}
	item = item1;
	enditem = item;
	return (0);
}

void
boolclear(void)
{
	numitems = 0;
	item = item1;
	enditem = item;
}

POSTING *
boolfile(INVCONTROL *invcntl, long *num, int bool)
{
	ENTRY	*entryptr;
	FILE	*file;
	char	*ptr;
	unsigned long	*ptr2;
	POSTING	*newitem;
	POSTING	posting;
	unsigned u;
	POSTING *newsetp, *set1p;
	long	newsetc, set1c, set2c;

	entryptr = (ENTRY *) (invcntl->logblk + 12) + invcntl->keypnt;
	ptr = invcntl->logblk + entryptr->offset;
	ptr2 = ((unsigned long *)ptr) +
	    (entryptr->size + (sizeof (long) - 1)) / sizeof (long);
	*num = entryptr->post;
	switch (bool) {
	case OR:
	case NOT:
		if (*num == 0) {
			*num = numitems;
			return (item);
		}
	}
	/* make room for the new set */
	u = 0;
	switch (bool) {
	case AND:
	case NOT:
		newsetp = set1p = item;
		break;

	case OR:
		u = enditem - item;
		/* FALLTHROUGH */
	case REVERSENOT:
		u += *num;
		if (item == item2) {
			if (u > setsize1) {
				u += SETINC;
				if ((item1 = (POSTING *) realloc(item1,
				    u * sizeof (POSTING))) == NULL) {
					goto cannotalloc;
				}
				setsize1 = u;
			}
			newitem = item1;
		} else {
			if (u > setsize2) {
				u += SETINC;
				if ((item2 = (POSTING *)realloc(item2,
				    u * sizeof (POSTING))) == NULL) {
				cannotalloc:
					invcannotalloc(u * sizeof (POSTING));
					(void) boolready();
					*num = -1;
					return (NULL);
				}
				setsize2 = u;
			}
			newitem = item2;
		}
		set1p = item;
		newsetp = newitem;
	}
	file = invcntl->postfile;
	(void) fseek(file, (long)*ptr2, SEEK_SET);
	read_next_posting(invcntl, &posting);
	newsetc = 0;
	switch (bool) {
	case OR:
		/* while something in both sets */
		set1p = item;
		newsetp = newitem;
		for (set1c = 0, set2c = 0;
		    set1c < numitems && set2c < *num; newsetc++) {
			if (set1p->lineoffset < posting.lineoffset) {
				*newsetp++ = *set1p++;
				set1c++;
			} else if (set1p->lineoffset > posting.lineoffset) {
				*newsetp++ = posting;
				read_next_posting(invcntl, &posting);
				set2c++;
			} else if (set1p->type < posting.type) {
				*newsetp++ = *set1p++;
				set1c++;
			} else if (set1p->type > posting.type) {
				*newsetp++ = posting;
				read_next_posting(invcntl, &posting);
				set2c++;
			} else {	/* identical postings */
				*newsetp++ = *set1p++;
				set1c++;
				read_next_posting(invcntl, &posting);
				set2c++;
			}
		}
		/* find out what ran out and move the rest in */
		if (set1c < numitems) {
			newsetc += numitems - set1c;
			while (set1c++ < numitems) {
				*newsetp++ = *set1p++;
			}
		} else {
			while (set2c++ < *num) {
				*newsetp++ = posting;
				newsetc++;
				read_next_posting(invcntl, &posting);
			}
		}
		item = newitem;
		break; /* end of OR */
#if 0
	case AND:
		set1c = 0;
		set2c = 0;
		while (set1c < numitems && set2c < *num) {
			if (set1p->lineoffset < posting.lineoffset) {
				set1p++;
				set1c++;
			} else if (set1p->lineoffset > posting.lineoffset) {
				read_next_posting(invcntl, &posting);
				set2c++;
			} else if (set1p->type < posting.type)  {
				*set1p++;
				set1c++;
			} else if (set1p->type > posting.type) {
				read_next_posting(invcntl, &posting);
				set2c++;
			} else {	/* identical postings */
				*newsetp++ = *set1p++;
				newsetc++;
				set1c++;
				read_next_posting(invcntl, &posting);
				set2c++;
			}
		}
		break; /* end of AND */

	case NOT:
		set1c = 0;
		set2c = 0;
		while (set1c < numitems && set2c < *num) {
			if (set1p->lineoffset < posting.lineoffset) {
				*newsetp++ = *set1p++;
				newsetc++;
				set1c++;
			} else if (set1p->lineoffset > posting.lineoffset) {
				read_next_posting(invcntl, &posting);
				set2c++;
			} else if (set1p->type < posting.type) {
				*newsetp++ = *set1p++;
				newsetc++;
				set1c++;
			} else if (set1p->type > posting.type) {
				read_next_posting(invcntl, &posting);
				set2c++;
			} else {	/* identical postings */
				set1c++;
				set1p++;
				read_next_posting(invcntl, &posting);
				set2c++;
			}
		}
		newsetc += numitems - set1c;
		while (set1c++ < numitems) {
			*newsetp++ = *set1p++;
		}
		break; /* end of NOT */

	case REVERSENOT:  /* core NOT incoming set */
		set1c = 0;
		set2c = 0;
		while (set1c < numitems && set2c < *num) {
			if (set1p->lineoffset < posting.lineoffset) {
				set1p++;
				set1c++;
			} else if (set1p->lineoffset > posting.lineoffset) {
				*newsetp++ = posting;
				read_next_posting(invcntl, &posting);
				set2c++;
			} else if (set1p->type < posting.type) {
				set1p++;
				set1c++;
			} else if (set1p->type > posting.type) {
				*newsetp++ = posting;
				read_next_posting(invcntl, &posting);
				set2c++;
			} else {	/* identical postings */
				set1c++;
				set1p++;
				read_next_posting(invcntl, &posting);
				set2c++;
			}
		}
		while (set2c++ < *num) {
			*newsetp++ = posting;
			newsetc++;
			read_next_posting(invcntl, &posting);
		}
		item = newitem;
		break; /* end of REVERSENOT  */
#endif
	}
	numitems = newsetc;
	*num = newsetc;
	enditem = (POSTING *)newsetp;
	return ((POSTING *)item);
}

#if 0
POSTING *
boolsave(int clear)
{
	int	i;
	POSTING	*ptr;
	POSTING	*oldstuff, *newstuff;

	if (numitems == 0) {
		if (clear)
			boolclear();
		return (NULL);
	}
	/*
	 * if clear then give them what we have and use (void)
	 * boolready to realloc
	 */
	if (clear) {
		ptr = item;
		/* free up the space we didn't give them */
		if (item == item1)
			item1 = NULL;
		else
			item2 = NULL;
		(void) boolready();
		return (ptr);
	}
	i = (enditem - item) * sizeof (POSTING) + 100;
	if ((ptr = (POSTING *)malloc(i))r == NULL) {
		invcannotalloc(i);
		return (ptr);
	}
	/* move present set into place  */
	oldstuff = item;
	newstuff = ptr;
	while (oldstuff < enditem)
		*newstuff++ = *oldstuff++;
	return (ptr);
}
#endif

static void
invcannotalloc(size_t n)
{
	(void) fprintf(stderr, "%s: cannot allocate %u bytes\n", argv0, n);
}

static void
invcannotopen(char *file)
{
	(void) fprintf(stderr, "%s: cannot open file %s\n", argv0, file);
}

static void
invcannotwrite(char *file)
{
	(void) perror(argv0);	/* must be first to preserve errno */
	(void) fprintf(stderr, "%s: write to file %s failed\n", argv0, file);
}
