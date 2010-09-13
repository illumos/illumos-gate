// This file was automatically generated from lib\StdioStorageMessages.msg by msggen.pl.
#include "Message.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

struct StdioStorageMessages {
  // 2400
  static const MessageType2 openFailed;
  // 2401
  static const MessageType2 readFailed;
  // 2402
  static const MessageType2 seekFailed;
};
const MessageType2 StdioStorageMessages::openFailed(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2400
#ifndef SP_NO_MESSAGE_TEXT
,"cannot open %1 (%2)"
#endif
);
const MessageType2 StdioStorageMessages::readFailed(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2401
#ifndef SP_NO_MESSAGE_TEXT
,"\"error reading %1 (%2)"
#endif
);
const MessageType2 StdioStorageMessages::seekFailed(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2402
#ifndef SP_NO_MESSAGE_TEXT
,"error seeking %1 (%2)"
#endif
);
#ifdef SP_NAMESPACE
}
#endif
