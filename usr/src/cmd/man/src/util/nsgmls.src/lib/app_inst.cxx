#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif


#ifdef SP_NAMESPACE
}
#endif
// Copyright (c) 1994 James Clark
// See the file COPYING for copying permission.

#include "splib.h"

#ifdef SP_MANUAL_INST

#define SP_DEFINE_TEMPLATES
#include "Vector.h"
#include "Owner.h"
#include "Options.h"
#undef SP_DEFINE_TEMPLATES

#include <stddef.h>
#include "CodingSystem.h"
#include "CmdLineApp.h"
#include "Event.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

#ifdef __DECCXX
#pragma define_template Vector<const CmdLineApp::AppChar *>
#else
#ifdef __xlC__
#pragma define(Vector<const CmdLineApp::AppChar *>)
#else
#ifdef SP_ANSI_CLASS_INST
template class Vector<const CmdLineApp::AppChar *>;
#else
typedef Vector<const CmdLineApp::AppChar *> Dummy_0;
#endif
#endif
#endif
#ifdef __DECCXX
#pragma define_template Owner<Encoder>
#else
#ifdef __xlC__
#pragma define(Owner<Encoder>)
#else
#ifdef SP_ANSI_CLASS_INST
template class Owner<Encoder>;
#else
typedef Owner<Encoder> Dummy_1;
#endif
#endif
#endif
#ifdef __DECCXX
#pragma define_template Options<CmdLineApp::AppChar>
#else
#ifdef __xlC__
#pragma define(Options<CmdLineApp::AppChar>)
#else
#ifdef SP_ANSI_CLASS_INST
template class Options<CmdLineApp::AppChar>;
#else
typedef Options<CmdLineApp::AppChar> Dummy_2;
#endif
#endif
#endif
#ifdef __DECCXX
#pragma define_template Owner<EventHandler>
#else
#ifdef __xlC__
#pragma define(Owner<EventHandler>)
#else
#ifdef SP_ANSI_CLASS_INST
template class Owner<EventHandler>;
#else
typedef Owner<EventHandler> Dummy_3;
#endif
#endif
#endif

#ifdef SP_NAMESPACE
}
#endif

#endif /* SP_MANUAL_INST */
