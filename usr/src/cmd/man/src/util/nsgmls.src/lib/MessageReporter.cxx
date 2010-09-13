// Copyright (c) 1994, 1995 James Clark
// See the file COPYING for copying permission.
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __GNUG__
#pragma implementation
#endif

#include "splib.h"
#include "MessageReporter.h"
#include "MessageReporterMessages.h"
#include "ExtendEntityManager.h"
#include "StorageManager.h"
#include "macros.h"

#include <string.h>

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

const OutputCharStream::Newline nl = OutputCharStream::newline;

MessageReporter::MessageReporter(OutputCharStream *os)
: os_(os), options_(0)
{
}

MessageReporter::~MessageReporter()
{
  delete os_;
}

void MessageReporter::setMessageStream(OutputCharStream *os)
{
  if (os != os_) {
    delete os_;
    os_ = os;
  }
}

void MessageReporter::addOption(Option option)
{
  options_ |= option;
}

void MessageReporter::dispatchMessage(const Message &message)
{
  Offset off;
  const ExternalInfo *externalInfo = locationHeader(message.loc, off);
  if (programName_.size())
    os() << programName_ << ':';
  if (externalInfo) {
    printLocation(externalInfo, off);
    os() << ':';
  }
  if (options_ & messageNumbers)
    os() << (unsigned long)message.type->module() << "." 
      << (unsigned long)message.type->number() << ":";
  switch (message.type->severity()) {
  case MessageType::info:
    formatFragment(MessageReporterMessages::infoTag, os());
    break;
  case MessageType::warning:
    formatFragment(MessageReporterMessages::warningTag, os());
    break;
  case MessageType::quantityError:
    formatFragment(MessageReporterMessages::quantityErrorTag, os());
    break;
  case MessageType::idrefError:
    formatFragment(MessageReporterMessages::idrefErrorTag, os());
    break;
  case MessageType::error:
    formatFragment(MessageReporterMessages::errorTag, os());
    break;
  default:
    CANNOT_HAPPEN();
  }
  os() << ": ";
  formatMessage(*message.type, message.args, os());
  os() << nl;
  if (!message.auxLoc.origin().isNull()) {
    Offset off;
    const ExternalInfo *externalInfo = locationHeader(message.auxLoc, off);
    if (programName_.size())
      os() << programName_ << ':';
    if (externalInfo) {
      printLocation(externalInfo, off);
      os() << ": ";
    }
    formatMessage(message.type->auxFragment(), message.args, os());
    os() << nl;
  }
  if ((options_ & openElements) && message.openElementInfo.size() > 0) {
    if (programName_.size())
      os() << programName_ << ':';
    if (externalInfo) {
      printLocation(externalInfo, off);
      os() << ": ";
    }
    formatFragment(MessageReporterMessages::openElements, os());
    os() << ':';
    formatOpenElements(message.openElementInfo, os());
    os() << nl;
  }
  os().flush();
}

// Note this is written so as not to change any reference counts.

const ExternalInfo *MessageReporter::locationHeader(const Location &loc,
						    Offset &off)
{
  return locationHeader(loc.origin().pointer(), loc.index(), off);
}

const ExternalInfo *MessageReporter::locationHeader(const Origin *origin,
						    Index index,
						    Offset &off)
{
   if (!(options_ & openEntities)) {
    while (origin) {
      const ExternalInfo *externalInfo = origin->externalInfo();
      if (externalInfo) {
  	off = origin->startOffset(index);
	return externalInfo;
      }
      const Location &loc = origin->parent();
      if (loc.origin().isNull()) {
	if (!origin->defLocation(origin->startOffset(index), origin, index))
	  break;
      }
      else {
	index = loc.index() + origin->refLength();
	origin = loc.origin().pointer();
      }
    }
  }
  else {
    Boolean doneHeader = 0;
    while (origin) {
      if (origin->entityName() || origin->parent().origin().isNull()) {
	if (!doneHeader) {
	  Offset parentOff;
	  const Location &parentLoc = origin->parent();
	  const ExternalInfo *parentInfo
	    = locationHeader(parentLoc.origin().pointer(),
			     parentLoc.index() + origin->refLength(),
			     parentOff);
	  if (parentInfo) {
	    StringC text;
	    if (getMessageText(origin->entityName()
			       ? MessageReporterMessages::inNamedEntity
			       : MessageReporterMessages::inUnnamedEntity,
				text)) {
	      for (size_t i = 0; i < text.size(); i++) {
		if (text[i] == '%') {
		  if (i + 1 < text.size()) {
		    i++;
		    if (text[i] == '1')
		      os() << *origin->entityName();
		    else if (text[i] == '2')
		      printLocation(parentInfo, parentOff);
		    else if (text[i] >= '3' && text[i] <= '9')
		      ;
		    else
		      os().put(text[i]);
		  }
		}
		else
		  os().put(text[i]);
	      }
	      os() << nl;
	    }
	  }
	  doneHeader = 1;
	}
	off = origin->startOffset(index);
	const ExternalInfo *externalInfo = origin->externalInfo();
	if (externalInfo)
	  return externalInfo;
	if (!origin->defLocation(off, origin, index))
	  break;
      }
      else {
	const Location &loc = origin->parent();
	index = loc.index() + origin->refLength();
	origin = loc.origin().pointer();
      }
    }
  }
  return 0;
}

void MessageReporter::printLocation(const ExternalInfo *externalInfo,
				    Offset off)
{
  if (!externalInfo) {
    formatFragment(MessageReporterMessages::invalidLocation, os());
    return;
  }
  StorageObjectLocation soLoc;
  if (!ExtendEntityManager::externalize(externalInfo, off, soLoc)) {
    formatFragment(MessageReporterMessages::invalidLocation, os());
    return;
  }
  if (strcmp(soLoc.storageObjectSpec->storageManager->type(), "OSFILE") != 0)
    os() << '<' << soLoc.storageObjectSpec->storageManager->type() << '>';
  os() << soLoc.actualStorageId;
  if (soLoc.lineNumber == (unsigned long)-1) {
    os() << ": ";
    formatFragment(MessageReporterMessages::offset, os());
    os() << soLoc.storageObjectOffset;
  }
  else {
    os() << ':' << soLoc.lineNumber;
    if (soLoc.columnNumber != 0 && soLoc.columnNumber != (unsigned long)-1)
      os() << ':' << soLoc.columnNumber - 1;
  }
#if 0
  if (soLoc.byteIndex != (unsigned long)-1)
    os() << ':' << soLoc.byteIndex;
#endif
}

Boolean MessageReporter::getMessageText(const MessageFragment &frag,
					StringC &str)
{
  const char *p = frag.text();
  if (!p)
    return 0;
  str.resize(0);
  for (; *p; p++)
    str += Char((unsigned char)*p);
  return 1;
}

#ifdef SP_NAMESPACE
}
#endif
