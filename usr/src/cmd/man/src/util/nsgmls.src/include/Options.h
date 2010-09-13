// Copyright (c) 1996 James Clark
// See the file COPYING for copying permission.
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef Options_INCLUDED
#define Options_INCLUDED 1

#include "Boolean.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

// This is a mildly C++ified version of getopt().
// It never prints any message.

template<class T>
class Options {
public:
  Options(int argc, T *const *, const T *);
  // Returns false if there are no more options.
  bool get(T &);
  T *arg() const { return arg_; } // optarg
  T opt() const { return opt_; }  // optopt
  int ind() const { return ind_; } // optind
private:
  const T *search(T) const;
  const T *opts_;
  T *const *argv_;
  int argc_;
  int ind_;
  T opt_;
  T *arg_;
  int sp_;
};

#ifdef SP_NAMESPACE
}
#endif

#endif /* not Options_INCLUDED */

#ifdef SP_DEFINE_TEMPLATES
#include "Options.cxx"
#endif
