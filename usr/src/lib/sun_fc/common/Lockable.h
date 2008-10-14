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

#ifndef	_LOCKABLE_H
#define	_LOCKABLE_H



#include <pthread.h>

/**
 * @memo	    Utility class to abstract away locking primitives
 */
class Lockable {
public:
    static void lock(pthread_mutex_t* mutex);
    static void unlock(pthread_mutex_t* mutex);
protected:
    Lockable();
    ~Lockable();
    void	lock();
    void	unlock();

private:
    pthread_mutex_t mutex;
};

#endif /* _LOCKABLE_H */
