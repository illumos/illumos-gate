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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <synch.h>
#include <time.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "labeld.h"

#ifndef	DEBUG
#define	perror(e)
#endif	/* !DEBUG */

/*
 *	This is cloned from _nsc_trydoorcall used by the nscd client.
 *
 * Routine that actually performs the door call.
 * Note that we cache a file descriptor.  We do
 * the following to prevent disasters:
 *
 * 1) Never use 0, 1 or 2; if we get this from the open
 *    we dup it upwards.
 *
 * 2) Set the close on exec flags so descriptor remains available
 *    to child processes.
 *
 * 3) Verify that the door is still the same one we had before
 *    by using door_info on the client side.
 *
 *	Note that we never close the file descriptor if it isn't one
 *	we allocated; we check this with door info.  The rather tricky
 *	logic is designed to be fast in the normal case (fd is already
 *	allocated and is ok) while handling the case where the application
 *	closed it underneath us or where the nscd dies or re-execs itself
 *	and we're a multi-threaded application.  Note that we cannot protect
 *	the application if it closes the fd and it is multi-threaded.
 *
 *  int __call_labeld(label_door_op **dptr, int *ndata, int *adata);
 *
 *      *dptr	IN: points to arg buffer OUT: points to results buffer
 *      *ndata	IN: overall size of buffer OUT: overall size of buffer
 *      *adata	IN: size of call data OUT: size of return data
 *
 *  Note that *dptr may change if provided space as defined by *bufsize is
 *  inadequate.  In this case the door call mmaps more space and places
 *  the answer there and sets dptr to contain a pointer to the space, which
 *  should be freed with munmap.
 *
 *  Returns 0 if the door call reached the server, -1 if contact was not made.
 *
 */


static mutex_t	_door_lock = DEFAULTMUTEX;

int
__call_labeld(labeld_data_t **dptr, size_t *ndata, size_t *adata)
{
	static	int 		doorfd = -1;
	static	door_info_t 	real_door;
	struct stat		st;
	door_info_t 		my_door;
	door_arg_t		param;
	char			door_name[MAXPATHLEN];
	struct timespec		ts;
	int			busy = 0;	/* number of busy loops */

#ifdef	DEBUG
	labeld_data_t		*callptr = *dptr;
	int			buf_size = *ndata;
	int			return_size = *adata;
#endif	/* DEBUG */

	/*
	 * the first time in we try and open and validate the door.
	 * the validations are that the door must have been
	 * created with the label service door cookie and
	 * that it has the same door ID.  If any of these
	 * validations fail we refuse to use the door.
	 */
	ts.tv_sec = 0;		/* initialize nanosecond retry timer */
	ts.tv_nsec = 100;
	(void) mutex_lock(&_door_lock);

try_again:
	if (doorfd == -1) {
		int	tbc[3];
		int	i;

		(void) snprintf(door_name, sizeof (door_name), "%s%s",
		    DOOR_PATH, DOOR_NAME);
		if ((doorfd = open64(door_name, O_RDONLY, 0)) < 0) {
			(void) mutex_unlock(&_door_lock);
			perror("server door open");
			return (NOSERVER);
		}

		/*
		 * dup up the file descriptor if we have 0 - 2
		 * to avoid problems with shells stdin/out/err
		 */
		i = 0;
		while (doorfd < 3) { /* we have a reserved fd */
			tbc[i++] = doorfd;
			if ((doorfd = dup(doorfd)) < 0) {
				perror("couldn't dup");
				while (i--)
					(void) close(tbc[i]);
				doorfd = -1;
				(void) mutex_unlock(&_door_lock);
				return (NOSERVER);
			}
		}
		while (i--)
			(void) close(tbc[i]);

		/*
		 * mark this door descriptor as close on exec
		 */
		(void) fcntl(doorfd, F_SETFD, FD_CLOEXEC);
		if (door_info(doorfd, &real_door) < 0) {
			/*
			 * we should close doorfd because we just opened it
			 */
			perror("real door door_info");
			(void) close(doorfd);
			doorfd = -1;
			(void) mutex_unlock(&_door_lock);
			return (NOSERVER);
		}
		if (fstat(doorfd, &st) < 0) {
			perror("real door fstat");
			return (NOSERVER);
		}
#ifdef	DEBUG
		(void) printf("\treal door %s\n", door_name);
		(void) printf("\t\tuid = %d, gid = %d, mode = %o\n", st.st_uid,
		    st.st_gid, st.st_mode);
		(void) printf("\t\toutstanding requests = %d\n", st.st_nlink-1);
		(void) printf("\t\t pid = %d\n", real_door.di_target);
		(void) printf("\t\t procedure = %llx\n", real_door.di_proc);
		(void) printf("\t\t cookie = %llx\n",  real_door.di_data);
		(void) printf("\t\t attributes = %x\n",
		    real_door.di_attributes);
		if (real_door.di_attributes & DOOR_UNREF)
			(void) printf("\t\t\t UNREF\n");
		if (real_door.di_attributes & DOOR_PRIVATE)
			(void) printf("\t\t\t PRIVATE\n");
		if (real_door.di_attributes & DOOR_LOCAL)
			(void) printf("\t\t\t LOCAL\n");
		if (real_door.di_attributes & DOOR_REVOKED)
			(void) printf("\t\t\t REVOKED\n");
		if (real_door.di_attributes & DOOR_DESCRIPTOR)
			(void) printf("\t\t\t DESCRIPTOR\n");
		if (real_door.di_attributes & DOOR_RELEASE)
			(void) printf("\t\t\t RELEASE\n");
		if (real_door.di_attributes & DOOR_DELAY)
			(void) printf("\t\t\t DELAY\n");
		(void) printf("\t\t id = %llx\n", real_door.di_uniquifier);
#endif	/* DEBUG */
		if ((real_door.di_attributes & DOOR_REVOKED) ||
		    (real_door.di_data != (door_ptr_t)(uintptr_t)COOKIE)) {
#ifdef	DEBUG
			(void) printf("real door revoked\n");
#endif	/* DEBUG */
			(void) close(doorfd);
			doorfd = -1;
			(void) mutex_unlock(&_door_lock);
			return (NOSERVER);
		}
	} else {
		if ((door_info(doorfd, &my_door) < 0) ||
		    (my_door.di_data != (door_ptr_t)(uintptr_t)COOKIE) ||
		    (my_door.di_uniquifier != real_door.di_uniquifier)) {
			perror("my door door_info");
			/*
			 * don't close it - someone else has clobbered fd
			 */
			doorfd = -1;
			goto try_again;
		}
		if (fstat(doorfd, &st) < 0) {
			perror("my door fstat");
			goto try_again;
		}
#ifdef	DEBUG
		(void) sprintf(door_name, "%s%s", DOOR_PATH, DOOR_NAME);
		(void) printf("\tmy door %s\n", door_name);
		(void) printf("\t\tuid = %d, gid = %d, mode = %o\n", st.st_uid,
		    st.st_gid, st.st_mode);
		(void) printf("\t\toutstanding requests = %d\n", st.st_nlink-1);
		(void) printf("\t\t pid = %d\n", my_door.di_target);
		(void) printf("\t\t procedure = %llx\n", my_door.di_proc);
		(void) printf("\t\t cookie = %llx\n",  my_door.di_data);
		(void) printf("\t\t attributes = %x\n", my_door.di_attributes);
		if (my_door.di_attributes & DOOR_UNREF)
			(void) printf("\t\t\t UNREF\n");
		if (my_door.di_attributes & DOOR_PRIVATE)
			(void) printf("\t\t\t PRIVATE\n");
		if (my_door.di_attributes & DOOR_LOCAL)
			(void) printf("\t\t\t LOCAL\n");
		if (my_door.di_attributes & DOOR_REVOKED)
			(void) printf("\t\t\t REVOKED\n");
		if (my_door.di_attributes & DOOR_DESCRIPTOR)
			(void) printf("\t\t\t DESCRIPTOR\n");
		if (my_door.di_attributes & DOOR_RELEASE)
			(void) printf("\t\t\t RELEASE\n");
		if (my_door.di_attributes & DOOR_DELAY)
			(void) printf("\t\t\t DELAY\n");
		(void) printf("\t\t id = %llx\n", my_door.di_uniquifier);
#endif	/* DEBUG */
		if (my_door.di_attributes & DOOR_REVOKED) {
#ifdef	DEBUG
			(void) printf("my door revoked\n");
#endif	/* DEBUG */
			(void) close(doorfd);	/* labeld exited .... */
			doorfd = -1;	/* try and restart connection */
			goto try_again;
		}
	}
	(void) mutex_unlock(&_door_lock);

	param.data_ptr = (char *)*dptr;
	param.data_size = *adata;
	param.desc_ptr = NULL;
	param.desc_num = 0;
	param.rbuf = (char *)*dptr;
	param.rsize = *ndata;

	if (door_call(doorfd, &param) < 0) {
		if (errno == EAGAIN && busy++ < 10) {
			/* adjust backoff */
			if ((ts.tv_nsec *= 10) >= NANOSEC) {
				ts.tv_sec++;
				ts.tv_nsec = 100;
			}
			(void) nanosleep(&ts, NULL);
#ifdef	DEBUG
			(void) printf("door_call failed EAGAIN # %d\n", busy);
#endif	/* DEBUG */
			(void) mutex_lock(&_door_lock);
			goto try_again;
		}
		perror("door call");
		return (NOSERVER);
	}

	*adata = (int)param.data_size;
	*ndata = (int)param.rsize;
	/*LINTED*/
	*dptr = (labeld_data_t *)param.data_ptr;

	if (*adata == 0 || *dptr == NULL) {
#ifdef	DEBUG
		(void) printf("\tNo data returned, size = %lu, dptr = %p\n",
		    (unsigned long)*adata, (void *)*dptr);
#endif	/* DEBUG */
		return (NOSERVER);
	}
#ifdef	DEBUG
	(void) printf("call buf = %x, buf size  = %d, call size = %d\n",
	    callptr, buf_size, return_size);
	(void) printf("retn buf = %x, buf size  = %d, retn size = %d\n",
	    *dptr, *ndata, *adata);
	(void) printf("\treply status = %d\n", (*dptr)->param.aret.ret);
#endif	/* DEBUG */
	return ((*dptr)->param.aret.ret);

}  /* __call_labeld */
