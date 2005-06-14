// This file was automatically generated from lib\ParserAppMessages.msg by msggen.pl.
#include "Message.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

struct ParserAppMessages {
  // 4200
  static const MessageType1 unknownWarning;
  // 4201
  static const MessageType0 badErrorLimit;
  // 4202
  static const MessageType1 errorLimitExceeded;
};
const MessageType1 ParserAppMessages::unknownWarning(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
4200
#ifndef SP_NO_MESSAGE_TEXT
,"unknown warning type %1"
#endif
);
const MessageType0 ParserAppMessages::badErrorLimit(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
4201
#ifndef SP_NO_MESSAGE_TEXT
,"invalid error limit"
#endif
);
const MessageType1 ParserAppMessages::errorLimitExceeded(
MessageType::info,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
4202
#ifndef SP_NO_MESSAGE_TEXT
,"maximum number of errors (%1) reached; change with -E option"
#endif
);
#ifdef SP_NAMESPACE
}
#endif
