// Copyright (c) 1994 James Clark
// See the file COPYING for copying permission.
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef MessageReporter_INCLUDED
#define MessageReporter_INCLUDED 1

#ifdef __GNUG__
#pragma interface
#endif

#include "types.h"
#include "MessageFormatter.h"
#include "Boolean.h"
#include "OutputCharStream.h"
#include "Message.h"
#include "Location.h"
#include "StringC.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

class SP_API MessageReporter : public MessageFormatter, public Messenger {
public:
  enum Option {
    openElements = 01,
    openEntities = 02,
    messageNumbers = 04
    };
  // The OutputCharStream will be deleted by the MessageReporter
  MessageReporter(OutputCharStream *);
  ~MessageReporter();
  void setMessageStream(OutputCharStream *);
  OutputCharStream *releaseMessageStream();
  void dispatchMessage(const Message &);
  void dispatchMessage(Message &tmp_message) {
        dispatchMessage((const Message &)tmp_message);
  };
  virtual Boolean getMessageText(const MessageFragment &, StringC &);
  void addOption(Option);
  void setProgramName(const StringC &);
private:
  MessageReporter(const MessageReporter &); // undefined
  void operator=(const MessageReporter &);  // undefined
  
  const ExternalInfo *locationHeader(const Location &, Offset &off);
  const ExternalInfo *locationHeader(const Origin *, Index, Offset &off);
  void printLocation(const ExternalInfo *info, Offset off);
  OutputCharStream &os();

  OutputCharStream *os_;
  unsigned options_;
  StringC programName_;
};

inline
OutputCharStream &MessageReporter::os()
{
  return *os_;
}

inline
void MessageReporter::setProgramName(const StringC &programName)
{
  programName_ = programName;
}

inline
OutputCharStream *MessageReporter::releaseMessageStream()
{
  OutputCharStream *tem = os_;
  os_ = 0;
  return tem;
}

#ifdef SP_NAMESPACE
}
#endif

#endif /* not MessageReporter_INCLUDED */
