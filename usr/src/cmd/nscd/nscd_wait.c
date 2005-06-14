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
 * Copyright (c) 1994 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * routines to wait and wake up a client waiting on a list for a
 * name service request
 */
#include <thread.h>
#include <synch.h>
#include "getxby_door.h"

int
nscd_wait(waiter_t * wchan,  mutex_t * lock, char ** key)
{
	waiter_t mywait;
	cond_init(&(mywait.w_waitcv), USYNC_THREAD, 0);
	mywait.w_key = key;
	mywait.w_next = wchan->w_next;
	mywait.w_prev = wchan;
	if(mywait.w_next)
		mywait.w_next->w_prev = &mywait;
	wchan->w_next = &mywait;
	
	while( *key == (char *) -1)
		cond_wait(&(mywait.w_waitcv), lock);
	if(mywait.w_prev)
		mywait.w_prev->w_next = mywait.w_next;
	if(mywait.w_next)
		mywait.w_next->w_prev = mywait.w_prev;
	return(0);
}

int
nscd_signal(waiter_t * wchan, char ** key)
{
	int c = 0;
	waiter_t * tmp = wchan->w_next;

	while(tmp) {
		if(tmp->w_key == key) {
			cond_signal(&(tmp->w_waitcv));
			c++;
		}
		tmp = tmp->w_next;
	}

	return(c);
}

#ifdef TESTPROG

static waiter_t w;
static mutex_t  l;
static char ** blocks;

static int num_threads;

main(int argc, char * argv[])
{
	int i;
	void * go();
	if(argc != 2) {
		printf("usage: %s numthreads\n", argv[0]);
		exit(1);
		}

	num_threads = atoi(argv[1]);

	blocks = (char **) malloc(sizeof(char **) * num_threads);

	memset(blocks, -1, sizeof(char**) * num_threads);

	mutex_lock(&l);

	for(i=0;i<num_threads;i++)
		if(thr_create(NULL, NULL, go, (void*)i, THR_NEW_LWP, NULL) != 0) {
			printf("thread_create failed\n");
			exit(2);
		}

		

	mutex_unlock(&l);

	sleep(5);

	printf("going\n");
	mutex_lock(&l);

	memset(blocks, 0, sizeof(char**) * num_threads);

	for(i=0;i<num_threads;i++) 
		nscd_signal(&w, blocks+i);

	mutex_unlock(&l);

	while(num_threads--) {
		if(thr_join(NULL, NULL, NULL) < 0) {
			printf("error in join\n");
			exit(2);
		}
	}

	printf("all done\n");
	exit(0);
}

void * go(int index)
{
	printf("thread %d locking\n", index);

	mutex_lock(&l);

	printf("thread %d waiting\n", index);

	nscd_wait(&w,&l, blocks+index);

	printf("thread %d unlocking\n", index);

	mutex_unlock(&l);

	thr_exit(NULL);
}

		
#endif TESTPROG
	
