// This file was automatically generated from lib\ArcEngineMessages.msg by msggen.pl.
#include "Message.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

struct ArcEngineMessages {
  // 3000
  static const MessageType1 arcGenerateSystemId;
  // 3001
  static const MessageType1 undefinedElement;
  // 3002
  static const MessageType1 elementExcluded;
  // 3003
  static const MessageType1 invalidElement;
  // 3004
  static const MessageType1 documentElementNotArc;
  // 3005
  static const MessageType1 unfinishedElement;
  // 3006
  static const MessageType0 renameMissingAttName;
  // 3007
  static const MessageType1 renameToInvalid;
  // 3008
  static const MessageType1 renameToDuplicate;
  // 3009
  static const MessageType1 renameFromInvalid;
  // 3010
  static const MessageType1 missingId;
  // 3011
  static const MessageType0 invalidArcContent;
  // 3012
  static const MessageType1 invalidSuppress;
  // 3013
  static const MessageType1 arcDtdNotDeclaredParameter;
  // 3014
  static const MessageType1 arcDtdNotDeclaredGeneral;
  // 3015
  static const MessageType1 arcDtdNotExternal;
  // 3016
  static const MessageType0 noArcDTDAtt;
  // 3017
  static const MessageType1 noArcDataF;
  // 3018
  static const MessageType1 idMismatch;
  // 3019
  static const MessageType1 invalidArcAuto;
  // 3020
  static const MessageType1 noArcNotation;
  // 3021
  static const MessageType0 invalidData;
  // 3022
  static const MessageType1 invalidIgnD;
  // 3023
  static const MessageType1 invalidArcIndr;
  // 3024
  static const MessageType1 invalidQuantity;
  // 3025
  static const MessageType1 missingQuantityValue;
  // 3026
  static const MessageType1 quantityValueTooLong;
  // 3027
  static const MessageType1 invalidDigit;
  // 3028
  static const MessageType0 arcIndrNotSupported;
};
const MessageType1 ArcEngineMessages::arcGenerateSystemId(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3000
#ifndef SP_NO_MESSAGE_TEXT
,"no system identifier could be generated for meta-DTD for architecture %1"
#endif
);
const MessageType1 ArcEngineMessages::undefinedElement(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3001
#ifndef SP_NO_MESSAGE_TEXT
,"element type %1 not defined in meta-DTD"
#endif
);
const MessageType1 ArcEngineMessages::elementExcluded(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3002
#ifndef SP_NO_MESSAGE_TEXT
,"element %1 invalid in meta-DTD because excluded"
#endif
);
const MessageType1 ArcEngineMessages::invalidElement(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3003
#ifndef SP_NO_MESSAGE_TEXT
,"meta-DTD does not allow element %1 at this point"
#endif
);
const MessageType1 ArcEngineMessages::documentElementNotArc(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3004
#ifndef SP_NO_MESSAGE_TEXT
,"document element must be instance of %1 element type form"
#endif
);
const MessageType1 ArcEngineMessages::unfinishedElement(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3005
#ifndef SP_NO_MESSAGE_TEXT
,"element %1 unfinished in meta-DTD"
#endif
);
const MessageType0 ArcEngineMessages::renameMissingAttName(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3006
#ifndef SP_NO_MESSAGE_TEXT
,"missing substitute name"
#endif
);
const MessageType1 ArcEngineMessages::renameToInvalid(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3007
#ifndef SP_NO_MESSAGE_TEXT
,"substitute for non-existent architecture attribute %1"
#endif
);
const MessageType1 ArcEngineMessages::renameToDuplicate(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3008
#ifndef SP_NO_MESSAGE_TEXT
,"substitute name for %1 already defined"
#endif
);
const MessageType1 ArcEngineMessages::renameFromInvalid(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3009
#ifndef SP_NO_MESSAGE_TEXT
,"substitute name %1 is not the name of an attribute"
#endif
);
const MessageType1 ArcEngineMessages::missingId(
MessageType::idrefError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3010
#ifndef SP_NO_MESSAGE_TEXT
,"reference in architecture to non-existent ID %1"
#endif
);
const MessageType0 ArcEngineMessages::invalidArcContent(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3011
#ifndef SP_NO_MESSAGE_TEXT
,"architectural content specified with #ARCCONT not allowed by meta-DTD"
#endif
);
const MessageType1 ArcEngineMessages::invalidSuppress(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3012
#ifndef SP_NO_MESSAGE_TEXT
,"invalid value %1 for ArcSupr attribute"
#endif
);
const MessageType1 ArcEngineMessages::arcDtdNotDeclaredParameter(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3013
#ifndef SP_NO_MESSAGE_TEXT
,"no declaration for meta-DTD parameter entity %1"
#endif
);
const MessageType1 ArcEngineMessages::arcDtdNotDeclaredGeneral(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3014
#ifndef SP_NO_MESSAGE_TEXT
,"no declaration for meta-DTD general entity %1"
#endif
);
const MessageType1 ArcEngineMessages::arcDtdNotExternal(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3015
#ifndef SP_NO_MESSAGE_TEXT
,"meta-DTD entity %1 must be external"
#endif
);
const MessageType0 ArcEngineMessages::noArcDTDAtt(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3016
#ifndef SP_NO_MESSAGE_TEXT
,"no ArcDTD architecture support attribute specified"
#endif
);
const MessageType1 ArcEngineMessages::noArcDataF(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3017
#ifndef SP_NO_MESSAGE_TEXT
,"ArcDataF notation %1 not defined in meta-DTD"
#endif
);
const MessageType1 ArcEngineMessages::idMismatch(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3018
#ifndef SP_NO_MESSAGE_TEXT
,"ID attribute %1 in meta-DTD not declared as ID in DTD"
#endif
);
const MessageType1 ArcEngineMessages::invalidArcAuto(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3019
#ifndef SP_NO_MESSAGE_TEXT
,"invalid value %1 for ArcAuto architectural support attribute"
#endif
);
const MessageType1 ArcEngineMessages::noArcNotation(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3020
#ifndef SP_NO_MESSAGE_TEXT
,"no notation declaration for architecture %1"
#endif
);
const MessageType0 ArcEngineMessages::invalidData(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3021
#ifndef SP_NO_MESSAGE_TEXT
,"meta-DTD does not allow data at this point"
#endif
);
const MessageType1 ArcEngineMessages::invalidIgnD(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3022
#ifndef SP_NO_MESSAGE_TEXT
,"invalid value %1 for ArcIgnD attribute"
#endif
);
const MessageType1 ArcEngineMessages::invalidArcIndr(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3023
#ifndef SP_NO_MESSAGE_TEXT
,"invalid value %1 for ArcIndr architectural support attribute"
#endif
);
const MessageType1 ArcEngineMessages::invalidQuantity(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3024
#ifndef SP_NO_MESSAGE_TEXT
,"unrecognized quantity name %1"
#endif
);
const MessageType1 ArcEngineMessages::missingQuantityValue(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3025
#ifndef SP_NO_MESSAGE_TEXT
,"no value specified for quantity %1"
#endif
);
const MessageType1 ArcEngineMessages::quantityValueTooLong(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3026
#ifndef SP_NO_MESSAGE_TEXT
,"length of value %1 for quantity is too long"
#endif
);
const MessageType1 ArcEngineMessages::invalidDigit(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3027
#ifndef SP_NO_MESSAGE_TEXT
,"invalid digit %1"
#endif
);
const MessageType0 ArcEngineMessages::arcIndrNotSupported(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3028
#ifndef SP_NO_MESSAGE_TEXT
,"only value of nArcIndr for ArcIndr attribute supported"
#endif
);
#ifdef SP_NAMESPACE
}
#endif
