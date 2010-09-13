/*******************************************************************************
 * Copyright (C) 2004-2008 Intel Corp. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of Intel Corp. nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL Intel Corp. OR THE CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/

//////////////////////////////////////////////////////////////////////////
// EventLinux.cpp
//
// This file contains the linux implementation of the Event class
//////////////////////////////////////////////////////////////////////////
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "Event.h"
#include "SPtr.h"
#include <pthread.h>
#include <cerrno>
#include <sys/time.h>
#include <iostream>

class OSEvent_s
{
public:
	OSEvent_s()
	{
		pthread_mutex_init(&_mut, NULL);
		pthread_cond_init(&_cond, NULL);
		_set = false;
	}

	~OSEvent_s()
	{
		pthread_cond_destroy(&_cond);
		pthread_mutex_destroy(&_mut);
	}

	pthread_mutex_t _mut;
	pthread_cond_t _cond;
	bool _set;
};

class OSEvent
{
public:
	OSEvent()
	{
		_ose = SPtr<OSEvent_s>(new OSEvent_s);
	}

	~OSEvent()
	{
		_ose = SPtr<OSEvent_s>(NULL);
	}

	SPtr<OSEvent_s> _ose;
};

Event::Event(bool manual)
{
	_osEvent = new OSEvent;

	/*
	_osEvent->ose->_set = false;
	pthread_mutex_init(&_osEvent->ose->_mut, NULL);
	pthread_cond_init(&_osEvent->ose->_cond, NULL);
	*/
}

Event::Event(const Event &rhs)
{
	_osEvent = new OSEvent;
	_osEvent->_ose = rhs._osEvent->_ose;
	/*
	_osEvent->_mut = rhs._osEvent->_mut;
	_osEvent->_cond = rhs._osEvent->_cond;
	*/
}

Event::~Event()
{
	/*
	pthread_cond_destroy(&_osEvent->ose->_cond);
	pthread_mutex_destroy(&_osEvent->ose->_mut);
	*/
	delete _osEvent;
}

bool Event::wait(unsigned long msecs_p)
{
	int retcode = 0;

	if (msecs_p != WAIT_INFINITE) {
		timeval now;
		timespec timeout, time;

		gettimeofday(&now, NULL);
		time.tv_sec = msecs_p / 1000;
		time.tv_nsec = (msecs_p % 1000) * 1000000;
		timeout.tv_sec = now.tv_sec + time.tv_sec;
		timeout.tv_nsec = now.tv_usec + time.tv_nsec;

		pthread_mutex_lock(&_osEvent->_ose->_mut);
		//printf("@@@@ Event (%p) wait (cond %p), set: %d (to %d)\n",
		//	 this, &_osEvent->_ose->_cond, _osEvent->_ose->_set, msecs_p);
		if (!_osEvent->_ose->_set) {
			retcode = pthread_cond_timedwait(&_osEvent->_ose->_cond,
				&_osEvent->_ose->_mut,
				&timeout);
			//printf("@@@@ Event (%p) after wait, set: %d\n", this, _osEvent->_ose->_set);
			_osEvent->_ose->_set = false;
		}
		//printf("@@@@ Event (%p) after wait, set: %d\n", this, _osEvent->_ose->_set);
		pthread_mutex_unlock(&_osEvent->_ose->_mut);

		if (retcode == ETIMEDOUT) {
			return false;
		} else {
			return true;
		}
	} else {
		pthread_mutex_lock(&_osEvent->_ose->_mut);
		//printf("@@@@ Event (%p) wait (cond %p), set: %d\n",
		//	 this, &_osEvent->_ose->_cond, _osEvent->_ose->_set);
		if (!_osEvent->_ose->_set) {
			pthread_cond_wait(&_osEvent->_ose->_cond, &_osEvent->_ose->_mut);
		}
		_osEvent->_ose->_set = false;
		//printf("@@@@ Event (%p) after wait, set: %d\n", this, _osEvent->_ose->_set);
		pthread_mutex_unlock(&_osEvent->_ose->_mut);
		return true;
	}

}

void Event::set()
{
	pthread_mutex_lock(&_osEvent->_ose->_mut);
	pthread_cond_signal(&_osEvent->_ose->_cond);
	//printf("@@@@ Event (%p) set (cond %p)\n", this, &_osEvent->_ose->_cond);
	_osEvent->_ose->_set = true;
	pthread_mutex_unlock(&_osEvent->_ose->_mut);
}

void Event::reset()
{
	pthread_mutex_lock(&_osEvent->_ose->_mut);
	// only way to reset the condition is to destroy it and restart it
	pthread_cond_destroy(&_osEvent->_ose->_cond);
	pthread_cond_init(&_osEvent->_ose->_cond, NULL);
	_osEvent->_ose->_set = false;
	pthread_mutex_unlock(&_osEvent->_ose->_mut);
}
