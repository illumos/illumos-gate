// This file was automatically generated from lib\MessageFormatterMessages.msg by msggen.pl.
#include "Message.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

struct MessageFormatterMessages {
  // 5100
  static const MessageFragment ordinal1;
  // 5101
  static const MessageFragment ordinal2;
  // 5102
  static const MessageFragment ordinal3;
  // 5103
  static const MessageFragment ordinaln;
  // 5104
  static const MessageFragment invalidArgumentType;
  // 5105
  static const MessageFragment invalidMessage;
};
const MessageFragment MessageFormatterMessages::ordinal1(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
5100
#ifndef SP_NO_MESSAGE_TEXT
,"st"
#endif
);
const MessageFragment MessageFormatterMessages::ordinal2(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
5101
#ifndef SP_NO_MESSAGE_TEXT
,"nd"
#endif
);
const MessageFragment MessageFormatterMessages::ordinal3(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
5102
#ifndef SP_NO_MESSAGE_TEXT
,"rd"
#endif
);
const MessageFragment MessageFormatterMessages::ordinaln(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
5103
#ifndef SP_NO_MESSAGE_TEXT
,"th"
#endif
);
const MessageFragment MessageFormatterMessages::invalidArgumentType(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
5104
#ifndef SP_NO_MESSAGE_TEXT
,"(invalid argument type)"
#endif
);
const MessageFragment MessageFormatterMessages::invalidMessage(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
5105
#ifndef SP_NO_MESSAGE_TEXT
,"(invalid message)"
#endif
);
#ifdef SP_NAMESPACE
}
#endif
