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
// ThreadLinux.cpp
//
// This file contains the linux implementation of the Thread class
///////////////////////////////////////////////////////////////////////////
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "Thread.h"
#include <pthread.h>
#include <sys/time.h>
#include <cerrno>
#include <cstdio>


class OSThread
{
public:
	pthread_t _handle;
	pthread_cond_t _cond;
	pthread_mutex_t _mut;
	bool _running;
	static void *threadFunc(void * thread_p);
};


void *OSThread::threadFunc(void *thread_p)
{
	if (thread_p) {
		Thread *t = (Thread*)thread_p;
		//printf("@@@@ OSThread::threadFunc (%p)\n", t->_osThread);
		t->run();
		//printf("@@@@ OSThread::threadFunc (%p) after run\n", t->_osThread);
		pthread_mutex_lock(&t->_osThread->_mut);
		t->_osThread->_running = false;
		//printf("@@@@ OSThread::threadFunc setting signal\n");
		pthread_cond_signal(&t->_osThread->_cond);
		pthread_mutex_unlock(&t->_osThread->_mut);
	}
	return (void *)0;
}

Thread::Thread(CallbackFunction func_p, void* param_p)
{
	_osThread = new OSThread;
	_osThread->_handle = 0;
	_osThread->_running = false;
	pthread_mutex_init(&_osThread->_mut, NULL);
	pthread_cond_init(&_osThread->_cond, NULL);
	_func = func_p;
	_param = param_p;
}

Thread::~Thread()
{
	pthread_cond_destroy(&_osThread->_cond);
	pthread_mutex_destroy(&_osThread->_mut);
	delete _osThread;
}

unsigned long Thread::currentThread()
{
	return pthread_self();
}

bool Thread::wait(unsigned long msecs_p) const
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

		pthread_mutex_lock(&_osThread->_mut);
		if (_osThread->_running) {
			retcode = pthread_cond_timedwait(&_osThread->_cond, &_osThread->_mut, &timeout);
		}
		pthread_mutex_unlock(&_osThread->_mut);

		if (retcode == ETIMEDOUT) {
			return false;
		} else {
			return true;
		}
	} else {
		pthread_mutex_lock(&_osThread->_mut);
		//printf("@@@@ Thread wait (%p), running: %d\n", _osThread, _osThread->_running);
		if (_osThread->_running) {
			pthread_cond_wait(&_osThread->_cond, &_osThread->_mut);
			_osThread->_running = false;
		}
		//printf("@@@@ Thread after wait\n");
		pthread_mutex_unlock(&_osThread->_mut);
		return true;
	}
}

bool Thread::start()
{
	if (running() == false) {
		timeval now;
		struct timezone tz;

		gettimeofday(&now, &tz);
		_startTime = now.tv_sec;
		_osThread->_running = true;
		if (pthread_create(&_osThread->_handle, NULL, OSThread::threadFunc, this) != 0) {
			return false;
		}
	}

	return true;
}

bool Thread::running() const
{
	return (_osThread->_running);
}

void Thread::msleep(long msecs_p)
{
	timespec time, rem;
	int counter = 5; // givin it 5 tries

	time.tv_sec = msecs_p / 1000;
	time.tv_nsec = (msecs_p % 1000) * 1000000;
	while (counter > 0) {
		// nanosleep might return due to a signal, in which case
		// rem will include the remaining time
		if (nanosleep(&time, &rem) == -1) {
			time.tv_sec = rem.tv_sec;
			time.tv_nsec = rem.tv_nsec;
			--counter;
		} else {
			break;
		}
	}
}

void Thread::run()
{
	if (_func != NULL) {
		_func(_param);
	}
}

long Thread::elapsedTime() const
{
	struct timezone tz;
	timeval now;

	gettimeofday(&now, &tz);
	return ((now.tv_sec - _startTime)*1000);
}

