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
//  SPtr.h
//
//  This is a smart pointer class. It receives an initialized object in
//  the constructor, and maintains a reference count to this object. It
//  deletes the object only when the reference count reaches 0.
//
//////////////////////////////////////////////////////////////////////////

#ifndef _SPTR_H_
#define _SPTR_H_

#include <memory>
#include "Semaphore.h"

template
<class T>
class SPtr
{
public:
	// constructor
	explicit SPtr(T *ptr_p = 0) :
		_ptr(ptr_p),
		_pref_count(new int(1)),
		_psem(new Semaphore(1)) {}

	// copy constructor
	template<class X>
	SPtr(const SPtr<X> &other_sptr_p)
	{
		other_sptr_p.getSem()->acquire();
		_ptr = other_sptr_p.get();
		_pref_count = other_sptr_p.getRefcnt();
		_psem = other_sptr_p.getSem();
		++(*_pref_count);
		_psem->release();
	}

	SPtr(const SPtr &other_sptr_p)
	{
		other_sptr_p.getSem()->acquire();
		_ptr = other_sptr_p.get();
		_pref_count = other_sptr_p.getRefcnt();
		_psem = other_sptr_p.getSem();
		++(*_pref_count);
		_psem->release();
	}

	// destructor
	~SPtr()
	{
		_psem->acquire();
		if (--(*_pref_count) == 0) {
			// delete pointer only on last destruction
			delete _pref_count;
			delete _psem;
			if (_ptr) {
				delete _ptr;
			}
			_ptr = 0;
		} else {
			_psem->release();
		}
	}

	// operator=
	// if 'this' already points to an object, unreference it
	template<class X>
	SPtr &operator= (const SPtr<X> &other_sptr_p)
	{
		if ((void *)&other_sptr_p == this) {
			return *this;
		}
		_psem->acquire();
		if (--(*_pref_count) == 0) {
			delete _pref_count;
			delete _psem;
			if (_ptr) {
				delete _ptr;
			}
		} else {
			_psem->release();
		}
		other_sptr_p.getSem()->acquire();
		_ptr = (T *)other_sptr_p.get();
		_pref_count = other_sptr_p.getRefcnt();
		_psem = other_sptr_p.getSem();
		++(*_pref_count);
		_psem->release();
		return *this;
	}

	SPtr &operator=(const SPtr &other_sptr_p)
	{
		if (&other_sptr_p == this) {
			return *this;
		}
		_psem->acquire();
		if (--(*_pref_count) == 0) {
			delete _pref_count;
			delete _psem;
			if (_ptr) {
				delete _ptr;
			}
		} else {
			_psem->release();
		}
		other_sptr_p.getSem()->acquire();
		_ptr = other_sptr_p.get();
		_pref_count = other_sptr_p.getRefcnt();
		_psem = other_sptr_p.getSem();
		++(*_pref_count);
		_psem->release();
		return *this;
	}

	// operator*
	T &operator*() const
	{
		return *_ptr;
	}

	// operator->
	T *operator->() const
	{
		return _ptr;
	}

	// get - return inner pointer
	T *get() const
	{
		return _ptr;
	}

	int *getRefcnt() const
	{
		return _pref_count;
	}

	Semaphore *getSem() const
	{
		return _psem;
	}

private:
	// the pointer itself
	T *_ptr;
	// a pointer to the reference count
	int *_pref_count;
	Semaphore *_psem;
} ;

template
<class T>
inline bool operator==(const SPtr<T> &x, const SPtr<T> &y) {
	return(x.get() == y.get());
}

template
<class T>
inline bool operator!=(const SPtr<T> &x, const SPtr<T> &y) {
	return(x.get() != y.get());
}

#endif // _SPTR_H_

