// Copyright (c) 1994 James Clark
// See the file COPYING for copying permission.
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __GNUG__
#pragma implementation
#endif
#include "splib.h"
#include "ElementType.h"
#include "ContentToken.h"
#include "macros.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

ElementType::ElementType(const StringC &name, size_t index)
: Named(name), index_(index), map_(0), defIndex_(0)
{
}

ElementDefinition::ElementDefinition(const Location &location,
				     size_t index,
				     unsigned char omitFlags,
				     DeclaredContent declaredContent)
: location_(location),
  index_(index),
  omitFlags_(omitFlags),
  declaredContent_(declaredContent)
{
  computeMode();
}

ElementDefinition::ElementDefinition(const Location &location,
				     size_t index,
				     unsigned char omitFlags,
				     DeclaredContent declaredContent,
				     Owner<CompiledModelGroup> &LOCALmodelGroup)
: location_(location),
  index_(index),
  omitFlags_(omitFlags),
  declaredContent_(declaredContent),
  modelGroup_(LOCALmodelGroup.extract())
{
  computeMode();
}

void ElementDefinition::computeMode()
{
  switch (declaredContent_) {
  case modelGroup:
    if (!modelGroup_->containsPcdata()) {
      netMode_ = econnetMode;
      mode_ = econMode;
      break;
    }
    // fall through
  case any:
    netMode_ = mconnetMode;
    mode_ = mconMode;
    break;
  case cdata:
    netMode_ = cconnetMode;
    mode_ = cconMode;
    break;
  case rcdata:
    netMode_ = rcconnetMode;
    mode_ = rcconMode;
    break;
  case empty:
    break;
  default:
    CANNOT_HAPPEN();
  }
}

void ElementType::swap(ElementType &to)
{
  Named::swap(to);
  {
    size_t tem = to.index_;
    to.index_ = index_;
    index_ = tem;
  }
  {
    size_t tem = to.defIndex_;
    to.defIndex_ = defIndex_;
    defIndex_ = tem;
  }
  def_.swap(to.def_);
  {
    const ShortReferenceMap *tem = to.map_;
    to.map_ = map_;
    map_ = tem;
  }
}

RankStem::RankStem(const StringC &name, size_t index)
: Named(name), index_(index)
{
}

void RankStem::addDefinition(const ConstPtr<ElementDefinition> &p)
{
  def_.push_back(p);
}


#ifdef SP_NAMESPACE
}
#endif
