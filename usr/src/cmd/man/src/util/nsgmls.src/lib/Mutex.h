// Copyright (c) 1996 James Clark
// See the file copying.txt for copying permission.
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef Mutex_INCLUDED
#define Mutex_INCLUDED 1

#ifdef SP_MUTEX_WIN32
#define SP_MUTEX

#define STRICT 1
#include <windows.h>
// <windows.h> appears to turn these warnings back on
#ifdef _MSC_VER
#pragma warning ( disable : 4237 )
#endif

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

class Mutex {
public:
  class Lock {
  public:
    Lock(Mutex *mp) : mp_(mp) {
      if (mp) ::EnterCriticalSection(&mp->cs_);
    }
    ~Lock() {
      if (mp_) ::LeaveCriticalSection(&mp_->cs_);
    }
  private:
    Mutex *mp_;
  };
  Mutex() {
    ::InitializeCriticalSection(&cs_);
  }
  ~Mutex() {
    ::DeleteCriticalSection(&cs_);
  }
  friend class Lock;
private:
  CRITICAL_SECTION cs_;
};

#ifdef SP_NAMESPACE
}
#endif

#endif /* SP_MUTEX_WIN32 */

#ifdef SP_MUTEX_MACH
#define SP_MUTEX

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

#ifdef SP_NAMESPACE
}
#endif

#endif /* SP_MUTEX_MACH */

#ifndef SP_MUTEX

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

class Mutex {
public:
  class Lock {
  public:
    Lock(Mutex *) { }
  };
  Mutex() { }
};

#ifdef SP_NAMESPACE
}
#endif

#endif /* not SP_MUTEX */

#endif /* not Mutex_INCLUDED */
