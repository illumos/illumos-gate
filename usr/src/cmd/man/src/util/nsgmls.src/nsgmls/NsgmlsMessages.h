// This file was automatically generated from nsgmls\NsgmlsMessages.msg by msggen.pl.
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#include "Message.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

struct NsgmlsMessages {
  // 0
  static const MessageType1 unknownOutputOption;
};
const MessageType1 NsgmlsMessages::unknownOutputOption(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
0
#ifndef SP_NO_MESSAGE_TEXT
,"unknown output option %1"
#endif
);
#ifdef SP_NAMESPACE
}
#endif
