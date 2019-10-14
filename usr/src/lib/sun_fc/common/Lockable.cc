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
 *
 * Copyright 2019 RackTop Systems.
 */


#include "Lockable.h"
#include <iostream>
#include <cstdio>
#include <cerrno>
#include <unistd.h>
#include <cstring>

using namespace std;

#define	    DEADLOCK_WARNING 10
#define	    LOCK_SLEEP 1

/**
 * @memo	    Create a lockable instance and initialize internal locks
 */
Lockable::Lockable() {
	if (pthread_mutex_init(&mutex, NULL)) {
	}
}

/**
 * @memo	    Free up a lockable instance
 */
Lockable::~Lockable() {
	if (pthread_mutex_destroy(&mutex)) {
	}
}

/**
 * @memo	    Unlock the instance
 * @precondition    This thread must have locked the instance
 * @postcondition   The instance will be unlocked
 */
void Lockable::unlock() {
	unlock(&mutex);
}

/**
 * @memo	    Unlock a given mutex lock
 * @precondition    The lock must be held by this thread
 * @postcondition   The lock will be released
 * @param	    myMutex The lock to unlock
 */
void Lockable::unlock(pthread_mutex_t *myMutex) {
	pthread_mutex_unlock(myMutex);
}

/**
 * @memo	    Lock the instance
 * @postcondition   The lock will be held by this thread.
 */
void Lockable::lock() {
	lock(&mutex);
}

/**
 * @memo	    Lock the given mutex lock
 * @postcondition   The lock will be held by this thread
 * @param	    myMutex The mutex lock to take
 */
void Lockable::lock(pthread_mutex_t *myMutex) {
	int status;
	int loop = 0;
	do {
	    loop++;
	    status = pthread_mutex_trylock(myMutex);
	    if (status) { 
		switch (pthread_mutex_trylock(myMutex)) {
		case EFAULT:
		    cerr << "Lock failed: Fault" << endl;
		    break;
		case EINVAL:
		    cerr << "Lock failed: Invalid" << endl;
		    break;
		case EBUSY:
		    if (loop > DEADLOCK_WARNING) {
			cerr << "Lock failed: Deadlock" << endl;
		    }
		    break;
		case EOWNERDEAD:
		    cerr << "Lock failed: Owner died" << endl;
		    break;
		case ELOCKUNMAPPED:
		    cerr << "Lock failed: Unmapped" << endl;
		    break;
		case ENOTRECOVERABLE:
		    cerr << "Lock failed: not recoverable" << endl;
		    /* FALLTHROUGH */
		default:
		    if (loop > DEADLOCK_WARNING) {
			cerr << "Lock failed: " <<strerror(status) << endl;
			break;
		    }
		}
	    } else {
		break; // Lock taken succesfully
	    }
	    sleep(LOCK_SLEEP);
	} while (status);
}
