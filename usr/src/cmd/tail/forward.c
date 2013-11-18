/*
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Edward Sze-Tyan Wang.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <port.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "extern.h"

static void rlines(FILE *, const char *fn, off_t, struct stat *);
static int show(file_info_t *);
static void set_events(file_info_t *files);

/* defines for inner loop actions */
#define	USE_SLEEP	0
#define	USE_PORT	1
#define	ADD_EVENTS	2

int port;
int action = USE_PORT;

static const file_info_t *last;

/*
 * forward -- display the file, from an offset, forward.
 *
 * There are eight separate cases for this -- regular and non-regular
 * files, by bytes or lines and from the beginning or end of the file.
 *
 * FBYTES	byte offset from the beginning of the file
 *	REG	seek
 *	NOREG	read, counting bytes
 *
 * FLINES	line offset from the beginning of the file
 *	REG	read, counting lines
 *	NOREG	read, counting lines
 *
 * RBYTES	byte offset from the end of the file
 *	REG	seek
 *	NOREG	cyclically read characters into a wrap-around buffer
 *
 * RLINES
 *	REG	mmap the file and step back until reach the correct offset.
 *	NOREG	cyclically read lines into a wrap-around array of buffers
 */
void
forward(FILE *fp, const char *fn, enum STYLE style, off_t off, struct stat *sbp)
{
	int ch;

	switch (style) {
	case FBYTES:
		if (off == 0)
			break;
		if (S_ISREG(sbp->st_mode)) {
			if (sbp->st_size < off)
				off = sbp->st_size;
			if (fseeko(fp, off, SEEK_SET) == -1) {
				ierr(fn);
				return;
			}
		} else while (off--)
			if ((ch = getc(fp)) == EOF) {
				if (ferror(fp)) {
					ierr(fn);
					return;
				}
				break;
			}
		break;
	case FLINES:
		if (off == 0)
			break;
		for (;;) {
			if ((ch = getc(fp)) == EOF) {
				if (ferror(fp)) {
					ierr(fn);
					return;
				}
				break;
			}
			if (ch == '\n' && !--off)
				break;
		}
		break;
	case RBYTES:
		if (S_ISREG(sbp->st_mode)) {
			if (sbp->st_size >= off &&
			    fseeko(fp, -off, SEEK_END) == -1) {
				ierr(fn);
				return;
			}
		} else if (off == 0) {
			while (getc(fp) != EOF)
				;
			if (ferror(fp)) {
				ierr(fn);
				return;
			}
		} else
			if (bytes(fp, fn, off))
				return;
		break;
	case RLINES:
		if (S_ISREG(sbp->st_mode))
			if (!off) {
				if (fseeko(fp, (off_t)0, SEEK_END) == -1) {
					ierr(fn);
					return;
				}
			} else
				rlines(fp, fn, off, sbp);
		else if (off == 0) {
			while (getc(fp) != EOF)
				;
			if (ferror(fp)) {
				ierr(fn);
				return;
			}
		} else
			if (lines(fp, fn, off))
				return;
		break;
	default:
		break;
	}

	while ((ch = getc(fp)) != EOF)
		if (putchar(ch) == EOF)
			oerr();
	if (ferror(fp)) {
		ierr(fn);
		return;
	}
	(void) fflush(stdout);
}

/*
 * rlines -- display the last offset lines of the file.
 */
static void
rlines(FILE *fp, const char *fn, off_t off, struct stat *sbp)
{
	struct mapinfo map;
	off_t curoff, size;
	int i;

	if ((size = sbp->st_size) == 0)
		return;
	map.start = NULL;
	map.fd = fileno(fp);
	map.mapoff = map.maxoff = size;

	/*
	 * Last char is special, ignore whether newline or not. Note that
	 * size == 0 is dealt with above, and size == 1 sets curoff to -1.
	 */
	curoff = size - 2;
	while (curoff >= 0) {
		if (curoff < map.mapoff && maparound(&map, curoff) != 0) {
			ierr(fn);
			return;
		}
		for (i = curoff - map.mapoff; i >= 0; i--)
			if (map.start[i] == '\n' && --off == 0)
				break;
		/* `i' is either the map offset of a '\n', or -1. */
		curoff = map.mapoff + i;
		if (i >= 0)
			break;
	}
	curoff++;
	if (mapprint(&map, curoff, size - curoff) != 0) {
		ierr(fn);
		exit(1);
	}

	/* Set the file pointer to reflect the length displayed. */
	if (fseeko(fp, sbp->st_size, SEEK_SET) == -1) {
		ierr(fn);
		return;
	}
	if (map.start != NULL && munmap(map.start, map.maplen)) {
		ierr(fn);
		return;
	}
}

static int
show(file_info_t *file)
{
	int ch;

	while ((ch = getc(file->fp)) != EOF) {
		if (last != file && no_files > 1) {
			if (!qflag)
				(void) printf("\n==> %s <==\n",
				    file->file_name);
			last = file;
		}
		if (putchar(ch) == EOF)
			oerr();
	}
	(void) fflush(stdout);
	if (ferror(file->fp)) {
		(void) fclose(file->fp);
		file->fp = NULL;
		ierr(file->file_name);
		return (0);
	}
	clearerr(file->fp);
	return (1);
}

static void
associate(file_info_t *file, boolean_t assoc, port_event_t *ev)
{
	char buf[64], *name;
	int i;

	if (action != USE_PORT || file->fp == NULL)
		return;

	if (!S_ISREG(file->st.st_mode)) {
		/*
		 * For FIFOs, we use PORT_SOURCE_FD as our port event source.
		 */
		if (assoc) {
			(void) port_associate(port, PORT_SOURCE_FD,
			    fileno(file->fp), POLLIN, file);
		} else {
			(void) port_dissociate(port, PORT_SOURCE_FD,
			    fileno(file->fp));
		}

		return;
	}

	bzero(&file->fobj, sizeof (file->fobj));

	if (!Fflag) {
		/*
		 * PORT_SOURCE_FILE only allows us to specify a file name, not
		 * a file descriptor.  If we are following a specific file (as
		 * opposed to a file name) and we were to specify the name of
		 * the file to port_associate() and that file were moved
		 * aside, we would not be able to reassociate an event because
		 * we would not know a name that would resolve to the new file
		 * (indeed, there might not be such a name -- the file may
		 * have been unlinked).  But there _is_ a name that we know
		 * maps to the file and doesn't change: the name of the
		 * representation of the open file descriptor in /proc.  We
		 * therefore associate with this name (and the underlying
		 * file), not the name of the file as specified at the command
		 * line.  This also has the (desirable) side-effect of
		 * insulating against FILE_RENAME_FROM and FILE_RENAME_TO
		 * events that we need to ignore to assure that we don't lose
		 * FILE_TRUNC events.
		 */
		(void) snprintf(buf,
		    sizeof (buf), "/proc/self/fd/%d", fileno(file->fp));
		name = buf;
	} else {
		name = file->file_name;
	}

	/*
	 * Note that portfs uses the address of the specified file_obj_t to
	 * tag an association; if one creates a different association with a
	 * (different) file_obj_t that happens to be at the same address,
	 * the first association will be implicitly removed.  To assure that
	 * each association has a disjoint file_obj_t, we allocate the memory
	 * for each in the file_info, not on the stack.
	 */
	file->fobj[0].fo_name = name;
	file->fobj[1].fo_name = name;

	if (assoc) {
		/*
		 * To assure that we cannot possibly drop a FILE_TRUNC event,
		 * we have two different PORT_SOURCE_FILE associations with the
		 * port:  one to get only FILE_MODIFIED events and another to
		 * get only FILE_TRUNC events.  This assures that we always
		 * have an active association for FILE_TRUNC events when the
		 * seek offset is non-zero.  Note that the association order
		 * _must_ be FILE_TRUNC followed by FILE_MODIFIED:  if a single
		 * event induces both a FILE_TRUNC and a FILE_MODIFIED (as
		 * a VE_CREATE vnode event does), we must process the
		 * FILE_TRUNC before FILE_MODIFIED -- and the order in which
		 * these are processed will be the association order.  So
		 * if we see a FILE_TRUNC, we dissociate/reassociate the
		 * FILE_MODIFIED association.
		 */
		if (ev == NULL || (ev->portev_events & FILE_TRUNC) ||
		    !(ev->portev_events & (FILE_MODIFIED | FILE_TRUNC))) {
			(void) port_associate(port, PORT_SOURCE_FILE,
			    (uintptr_t)&file->fobj[0], FILE_TRUNC, file);
			(void) port_dissociate(port, PORT_SOURCE_FILE,
			    (uintptr_t)&file->fobj[1]);
			ev = NULL;
		}

		if (ev == NULL || (ev->portev_events & FILE_MODIFIED) ||
		    !(ev->portev_events & (FILE_MODIFIED | FILE_TRUNC))) {
			(void) port_associate(port, PORT_SOURCE_FILE,
			    (uintptr_t)&file->fobj[1], FILE_MODIFIED, file);
		}
	} else {
		for (i = 0; i <= 1; i++) {
			(void) port_dissociate(port, PORT_SOURCE_FILE,
			    (uintptr_t)&file->fobj[i]);
		}
	}
}

static void
set_events(file_info_t *files)
{
	int i;
	file_info_t *file;

	for (i = 0, file = files; i < no_files; i++, file++) {
		if (! file->fp)
			continue;

		(void) fstat(fileno(file->fp), &file->st);

		associate(file, B_TRUE, NULL);
	}
}

/*
 * follow -- display the file, from an offset, forward.
 *
 */
void
follow(file_info_t *files, enum STYLE style, off_t off)
{
	int active, ev_change, i, n = -1;
	struct stat sb2;
	file_info_t *file;
	struct timespec ts;
	port_event_t ev;

	/* Position each of the files */

	file = files;
	active = 0;
	n = 0;
	for (i = 0; i < no_files; i++, file++) {
		if (file->fp) {
			active = 1;
			n++;
			if (no_files > 1 && !qflag)
				(void) printf("\n==> %s <==\n",
				    file->file_name);
			forward(file->fp, file->file_name, style, off,
			    &file->st);
			if (Fflag && fileno(file->fp) != STDIN_FILENO)
				n++;
		}
	}
	if (!Fflag && !active)
		return;

	last = --file;

	if (action == USE_PORT &&
	    (stat("/proc/self/fd", &sb2) == -1 || !S_ISDIR(sb2.st_mode) ||
	    (port = port_create()) == -1))
		action = USE_SLEEP;

	set_events(files);

	for (;;) {
		ev_change = 0;
		if (Fflag) {
			for (i = 0, file = files; i < no_files; i++, file++) {
				if (!file->fp) {
					file->fp = fopen(file->file_name, "r");
					if (file->fp != NULL &&
					    fstat(fileno(file->fp), &file->st)
					    == -1) {
						(void) fclose(file->fp);
						file->fp = NULL;
					}
					if (file->fp != NULL)
						ev_change++;
					continue;
				}
				if (fileno(file->fp) == STDIN_FILENO)
					continue;
				if (stat(file->file_name, &sb2) == -1) {
					if (errno != ENOENT)
						ierr(file->file_name);
					(void) show(file);
					(void) fclose(file->fp);
					file->fp = NULL;
					ev_change++;
					continue;
				}

				if (sb2.st_ino != file->st.st_ino ||
				    sb2.st_dev != file->st.st_dev ||
				    sb2.st_nlink == 0) {
					(void) show(file);
					associate(file, B_FALSE, NULL);
					file->fp = freopen(file->file_name, "r",
					    file->fp);
					if (file->fp != NULL) {
						(void) memcpy(&file->st, &sb2,
						    sizeof (struct stat));
					} else if (errno != ENOENT)
						ierr(file->file_name);
					ev_change++;
				}
			}
		}

		for (i = 0, file = files; i < no_files; i++, file++)
			if (file->fp && !show(file))
				ev_change++;

		if (ev_change)
			set_events(files);

		switch (action) {
		case USE_PORT:
			ts.tv_sec = 1;
			ts.tv_nsec = 0;

			/*
			 * In the -F case we set a timeout to ensure that
			 * we re-stat the file at least once every second.
			 */
			n = port_get(port, &ev, Fflag ? &ts : NULL);

			if (n == 0) {
				file = (file_info_t *)ev.portev_user;
				associate(file, B_TRUE, &ev);

				if (ev.portev_events & FILE_TRUNC)
					(void) fseek(file->fp, 0, SEEK_SET);
			}

			break;

		case USE_SLEEP:
			(void) usleep(250000);
			break;
		}
	}
}
