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
// Thread.h
//
// This file contains an OS independent interface for thread manipulation
// A Thread class is defined for easy usage.
//
// Usage:
//
// Option 1: Construct an instance of the "Thread" class with an external
// callback function. When calling the "start" method, the thread will be
// started on the callback function
//
// Option 2: Subclass the "Thread" class and reimplement the virtual "run"
// method. When calling the "start" method, the thread will be started
// on the "run" function.
//
// Implementation overview:
// Calling the "start" method will start the new thread, which will call the
// "run" method. The default implementation of the "run" method will call
// the Callback function given in the constructor.
//
//////////////////////////////////////////////////////////////////////////
#ifndef _LAD_THREAD_H
#define _LAD_THREAD_H

#ifndef WAIT_INFINITE
#define WAIT_INFINITE 0xffffffff
#endif
#ifndef NULL
#define NULL 0
#endif

typedef void (*CallbackFunction) (void *);

class OSThread;

class Thread
{
	friend class OSThread;

public:
	Thread(CallbackFunction func = NULL, void *param = NULL);
	Thread(const Thread &rhs);
	virtual ~Thread();

	// wait for the thread to complete; return true if the thread completed,
	// false on timeout
	bool wait(unsigned long msecs = WAIT_INFINITE) const;
	// start the new thread, return true on success
	bool start();
	// true if the thread is in running state
	bool running() const;
	// measure the time (in msecs) from thread start-time
	long elapsedTime() const;

	// return ID for the current thread
	static unsigned long currentThread();
	// put the current thread to sleep
	static void msleep(long msecs);

	Thread &operator=(const Thread &rhs);

protected:
	virtual void run();

private:
	CallbackFunction _func;
	void *_param;
	long _startTime;
	OSThread *_osThread;
};

#endif //_LAD_THREAD_H

