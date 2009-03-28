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
// Lock.h
//
// This file contains the definition and implementation of the Lock class
// and the TryLock class
//////////////////////////////////////////////////////////////////////////
#ifndef _LAD_LOCK_H
#define _LAD_LOCK_H
#include "RWLock.h"

#ifndef NULL
#define NULL 0
#endif

class Lock
{
public:
	Lock(Semaphore &sem) : _sem(&sem), _rw_lock(NULL)
	{
		_sem->acquire();
	}

	Lock(RWLock &rw_lock, RWLock::RWMode mode = RWLock::READ_ONLY) :
	_sem(NULL), _rw_lock(&rw_lock)
	{
		_rw_lock->acquire(mode);
	}

	~Lock()
	{
		if (_sem) {
			_sem->release();
		}
		if (_rw_lock) {
			_rw_lock->release();
		}

	}

private:
	Semaphore *_sem;
	RWLock *_rw_lock;
};

class TryLock
{
public:
	TryLock(Semaphore &sem, bool &is_locked) : _sem(&sem)
	{
		_locked = _sem->acquireTry();
		is_locked = _locked;
	}

	~TryLock()
	{
		if (_locked) {
			_sem->release();
		}
	}

private:
	bool _locked;
	Semaphore *_sem;
};

#endif //_LAD_LOCK_H

