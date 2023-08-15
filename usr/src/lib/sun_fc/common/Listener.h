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

#ifndef	_LISTENER_H
#define	_LISTENER_H



#include "Event.h"
#include <vector>
#include <pthread.h>

/**
 * @memo	    Generic listener super-class for event dispatch
 *
 * @doc		    All listener interfaces sub-class this interface
 */
class Listener {
public:
    Listener(void *userData);
    ~Listener();
    virtual void dispatch(Event &event) = 0;
    static Listener* findListener(void *cbh);
    void* getData() { return (data); }
private:
    static pthread_mutex_t	    staticLock;
    static std::vector<Listener*>   listeners;
    void *data;
};

#endif /* _LISTENER_H */
