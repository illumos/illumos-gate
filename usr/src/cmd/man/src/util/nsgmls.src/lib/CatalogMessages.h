// This file was automatically generated from lib\CatalogMessages.msg by msggen.pl.
#include "Message.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

struct CatalogMessages {
  // 2100
  static const MessageType0 nameExpected;
  // 2101
  static const MessageType0 literalExpected;
  // 2102
  static const MessageType0 nameOrLiteralExpected;
  // 2103
  static const MessageType0 nulChar;
  // 2104
  static const MessageType0 minimumData;
  // 2105
  static const MessageType0 eofInComment;
  // 2106
  static const MessageType0 eofInLiteral;
  // 2107
  static const MessageType0 overrideYesOrNo;
  // 2108
  static const MessageType0 inLoop;
  // 2109
  static const MessageType0 systemShouldQuote;
  // 2110
  static const MessageType1 noDocumentEntry;
  // 2111
  static const MessageType2 noPublicEntry;
  // 2112
  static const MessageType0 dtddeclNotSupported;
};
const MessageType0 CatalogMessages::nameExpected(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2100
#ifndef SP_NO_MESSAGE_TEXT
,"name expected"
#endif
);
const MessageType0 CatalogMessages::literalExpected(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2101
#ifndef SP_NO_MESSAGE_TEXT
,"literal expected"
#endif
);
const MessageType0 CatalogMessages::nameOrLiteralExpected(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2102
#ifndef SP_NO_MESSAGE_TEXT
,"name or literal expected"
#endif
);
const MessageType0 CatalogMessages::nulChar(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2103
#ifndef SP_NO_MESSAGE_TEXT
,"nul character"
#endif
);
const MessageType0 CatalogMessages::minimumData(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2104
#ifndef SP_NO_MESSAGE_TEXT
,"not a minimum data character"
#endif
);
const MessageType0 CatalogMessages::eofInComment(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2105
#ifndef SP_NO_MESSAGE_TEXT
,"end of entity in comment"
#endif
);
const MessageType0 CatalogMessages::eofInLiteral(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2106
#ifndef SP_NO_MESSAGE_TEXT
,"end of entity in literal"
#endif
);
const MessageType0 CatalogMessages::overrideYesOrNo(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2107
#ifndef SP_NO_MESSAGE_TEXT
,"OVERRIDE requires argument of YES or NO"
#endif
);
const MessageType0 CatalogMessages::inLoop(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2108
#ifndef SP_NO_MESSAGE_TEXT
,"CATALOG entries cause loop"
#endif
);
const MessageType0 CatalogMessages::systemShouldQuote(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2109
#ifndef SP_NO_MESSAGE_TEXT
,"second argument for SYSTEM entry should be quoted to avoid ambiguity"
#endif
);
const MessageType1 CatalogMessages::noDocumentEntry(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2110
#ifndef SP_NO_MESSAGE_TEXT
,"no DOCUMENT entry in catalog %1"
#endif
);
const MessageType2 CatalogMessages::noPublicEntry(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2111
#ifndef SP_NO_MESSAGE_TEXT
,"no entry for public identifier %1 in catalog %2"
#endif
);
const MessageType0 CatalogMessages::dtddeclNotSupported(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2112
#ifndef SP_NO_MESSAGE_TEXT
,"DTDDECL catalog entries are not supported"
#endif
);
#ifdef SP_NAMESPACE
}
#endif
