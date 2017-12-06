/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Toomas Soome <tsoome@me.com>
 */

#include "ficl.h"

void *
ficlMalloc(size_t size)
{
	return (malloc(size));
}

void *
ficlRealloc(void *p, size_t size)
{
	return (realloc(p, size));
}

void
ficlFree(void *p)
{
	free(p);
}

void
ficlCallbackDefaultTextOut(ficlCallback *callback, char *message)
{
	FICL_IGNORE(callback);

	if (message != NULL) {
#ifdef _STANDALONE
		while (*message != 0)
			putchar((unsigned char)*(message++));
#else
		(void) fputs(message, stdout);
		(void) fflush(stdout);
#endif
	}
}

#if FICL_WANT_FILE
int
ficlFileTruncate(ficlFile *ff, ficlUnsigned size)
{
	return (ftruncate(fileno(ff->f), size));
}

int
ficlFileStatus(char *filename, int *status)
{
	struct stat statbuf;

	if (stat(filename, &statbuf) == 0) {
		*status = statbuf.st_mode;
		return (0);
	}
	*status = ENOENT;
	return (-1);
}

long
ficlFileSize(ficlFile *ff)
{
	struct stat statbuf;

	if (ff == NULL)
		return (-1);

	statbuf.st_size = -1;
	if (fstat(fileno(ff->f), &statbuf) != 0)
		return (-1);

	return (statbuf.st_size);
}
#endif
