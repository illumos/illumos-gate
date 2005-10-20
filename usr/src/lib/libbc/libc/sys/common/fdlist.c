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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>

#define NUM_FD	16

struct fd_lst {
        int     fd[NUM_FD];                 /* list of 16 descriptors */
	int 	fds[NUM_FD];
        struct fd_lst *next;     
};
 

static struct fd_lst *fdlist = NULL;
static struct fd_lst *fdtail = NULL;

void
fd_init(struct fd_lst *lst)
{
	int i;
	
	for (i=0; i<NUM_FD; i++) {
		lst->fd[i] = -1;
		lst->fds[i] = -1;
	}
	lst->next = NULL;
}


	
int
fd_add(int fd, int fds)
{
	int i;
	struct fd_lst *fdc, *fdnew;

	fdc = fdlist;

	while (fdc != NULL) {
		for (i=0; i<NUM_FD; i++) {
			if (fdc->fd[i] == -1) {
				fdc->fd[i] = fd;
				fdc->fds[i] = fds;
				return(0);
			}	
		}
		fdc = fdc->next;
	}

	if ((fdnew = (struct fd_lst *)malloc(sizeof(struct fd_lst))) == NULL) {
		fprintf(stderr,"fd_add: malloc failed\n");
		exit(1);
	}

	fd_init(fdnew);

	if (fdlist == NULL) 
		fdlist = fdnew;
	else 
		fdtail->next = fdnew;

	fdtail = fdnew;
	fdtail->fd[0] = fd;
	fdtail->fds[0] = fds;
	return (0);
}


int
fd_rem(int fd)
{
	int i;
	struct fd_lst *fdc = fdlist;

	while (fdc != NULL) {
		for (i=0; i<NUM_FD; i++) {
			if (fdc->fd[i] == fd) {
				fdc->fd[i] = -1;
				fdc->fds[i] = -1;
				return (0);
			}
		}
		fdc = fdc->next;
	}
	return (0);
}


int
fd_get(int fd)
{
	int i;
	struct fd_lst *fdc = fdlist;

	while (fdc != NULL) {
		for (i=0; i<NUM_FD; i++) {
			if (fdc->fd[i] == fd) {
				return (fdc->fds[i]);
			}
		}
		fdc = fdc->next;
	}
	return (-1);
}
