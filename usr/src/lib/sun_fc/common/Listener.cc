/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 *  You may not use this file except in compliance with the License.
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



#include "Listener.h"
#include "Exceptions.h"
#include "Lockable.h"

using namespace std;

/**
 * Global lock for list of listeners
 */
pthread_mutex_t Listener::staticLock = PTHREAD_MUTEX_INITIALIZER;

/**
 * Global list of listeners
 */
vector<Listener*> Listener::listeners;

/**
 * Type for listener list iteration
 */
typedef vector<Listener *>::iterator ListenerIterator;

/**
 * @memo	    Create a new generic listener
 * @exception	    ... underlying exceptions will be thrown
 * @param	    userData The opaque user data for event callback
 * 
 */
Listener::Listener(void *userData) {
	data = userData;
	Lockable::lock(&staticLock);
	try {
	    listeners.insert(listeners.begin(), this);
	} catch (...) {
	    Lockable::unlock(&staticLock);
	    throw;
	}
	Lockable::unlock(&staticLock);
}

/**
 * @memo	    Free up a generic listener, keeping global list in sync.
 * @exception	    ... underlying exceptions will be thrown
 */
Listener::~Listener() {
	Lockable::lock(&staticLock);
	try {
	    for (ListenerIterator tmp = listeners.begin();
			tmp != listeners.end(); tmp++) {
		if (*tmp == this) {
		    listeners.erase(tmp);
		    Lockable::unlock(&staticLock);
		    return;
		}
	    }
	} catch (...) {
	    Lockable::unlock(&staticLock);
	    throw;
	}
	Lockable::unlock(&staticLock);
}

/**
 * @memo	    Find a listener based on the callback handle
 * @exception	    InvalidHandleException if the callback handle does not
 *		    match any listeners
 * @return	    The Listener who matches the callback handle
 * @param	    cbh The callback handle
 */
Listener* Listener::findListener(void *cbh) {
	Lockable::lock(&staticLock);
	try {
	    for (ListenerIterator tmp = listeners.begin();
			tmp != listeners.end(); tmp++) {
		if (*tmp == cbh) {
		    Lockable::unlock(&staticLock);
		    return (*tmp);
		}
	    }
	} catch (...) {
	    Lockable::unlock(&staticLock);
	    throw;
	}
	Lockable::unlock(&staticLock);
	throw InvalidHandleException();
}
