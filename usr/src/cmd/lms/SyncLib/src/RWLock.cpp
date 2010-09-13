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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "RWLock.h"

RWLock::RWLock() : _counter(0) {}

void RWLock::acquire(const RWMode mode_p)
{

	if (mode_p == READ_ONLY) {
		//wait for writer's exit
		_writeSem.acquire();
		//might be blocked only to decrement _counter and _readSem.release() in release()
		_countSem.acquire();
		int tmp = ++_counter;
		_countSem.release();
		if (tmp == 1) {
			//never blocks, no writers, first reader
			_readSem.acquire();
		}
		_writeSem.release();
	} else {
		_writeSem.acquire();
		//wait for reader's exit
		_readSem.acquire();
	}

	return;
}

//will do nothing if no read-write lock was acquired
void RWLock::switch2RO()
{
	_countSem.acquire();
	if (!_counter) {
		_counter = 1;
		_writeSem.release();
	}
	_countSem.release();
}

//will do nothing if no lock was acquired
void RWLock::release()
{

	//might be blocked only to increment _counter in read-only mode
	_countSem.acquire();
	if (_counter) {
		//read-only mode
		_counter--;
		if (!_counter) {
			//the last reader
			_readSem.release();
		}
	} else {
		//read-write mode
		_readSem.release();
		_writeSem.release();
	}
	_countSem.release();

	return;
}

