// This file was automatically generated from lib\URLStorageMessages.msg by msggen.pl.
#include "Message.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

struct URLStorageMessages {
  // 2300
  static const MessageType1 emptyHost;
  // 2301
  static const MessageType1 badRelative;
  // 2302
  static const MessageType1 emptyPort;
  // 2303
  static const MessageType1 invalidPort;
  // 2304
  static const MessageType1 hostNotFound;
  // 2305
  static const MessageType1 hostTryAgain;
  // 2306
  static const MessageType1 hostNoRecovery;
  // 2307
  static const MessageType1 hostNoData;
  // 2308
  static const MessageType2 hostOtherError;
  // 2309
  static const MessageType1 hostUnknownError;
  // 2310
  static const MessageType1 cannotCreateSocket;
  // 2311
  static const MessageType2 cannotConnect;
  // 2312
  static const MessageType2 writeError;
  // 2313
  static const MessageType2 readError;
  // 2314
  static const MessageType2 closeError;
  // 2315
  static const MessageType1 invalidHostNumber;
  // 2316
  static const MessageType3 getFailed;
  // 2317
  static const MessageType0 notSupported;
  // 2318
  static const MessageType0 onlyHTTP;
  // 2319
  static const MessageType1 winsockInitialize;
  // 2320
  static const MessageType0 winsockVersion;
  // 2321
  static const MessageFragment winsockErrorNumber;
};
const MessageType1 URLStorageMessages::emptyHost(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2300
#ifndef SP_NO_MESSAGE_TEXT
,"empty host in HTTP URL %1"
#endif
);
const MessageType1 URLStorageMessages::badRelative(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2301
#ifndef SP_NO_MESSAGE_TEXT
,"uncompletable relative HTTP URL %1"
#endif
);
const MessageType1 URLStorageMessages::emptyPort(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2302
#ifndef SP_NO_MESSAGE_TEXT
,"empty port number in HTTP URL %1"
#endif
);
const MessageType1 URLStorageMessages::invalidPort(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2303
#ifndef SP_NO_MESSAGE_TEXT
,"invalid port number in HTTP URL %1"
#endif
);
const MessageType1 URLStorageMessages::hostNotFound(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2304
#ifndef SP_NO_MESSAGE_TEXT
,"host %1 not found"
#endif
);
const MessageType1 URLStorageMessages::hostTryAgain(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2305
#ifndef SP_NO_MESSAGE_TEXT
,"could not resolve host %1 (try again later)"
#endif
);
const MessageType1 URLStorageMessages::hostNoRecovery(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2306
#ifndef SP_NO_MESSAGE_TEXT
,"could not resolve host %1 (unrecoverable error)"
#endif
);
const MessageType1 URLStorageMessages::hostNoData(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2307
#ifndef SP_NO_MESSAGE_TEXT
,"no address record for host name %1"
#endif
);
const MessageType2 URLStorageMessages::hostOtherError(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2308
#ifndef SP_NO_MESSAGE_TEXT
,"could not resolve host %1 (%2)"
#endif
);
const MessageType1 URLStorageMessages::hostUnknownError(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2309
#ifndef SP_NO_MESSAGE_TEXT
,"could not resolve host %1 (unknown error)"
#endif
);
const MessageType1 URLStorageMessages::cannotCreateSocket(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2310
#ifndef SP_NO_MESSAGE_TEXT
,"cannot create socket (%1)"
#endif
);
const MessageType2 URLStorageMessages::cannotConnect(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2311
#ifndef SP_NO_MESSAGE_TEXT
,"error connecting to %1 (%2)"
#endif
);
const MessageType2 URLStorageMessages::writeError(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2312
#ifndef SP_NO_MESSAGE_TEXT
,"error sending request to %1 (%2)"
#endif
);
const MessageType2 URLStorageMessages::readError(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2313
#ifndef SP_NO_MESSAGE_TEXT
,"error receiving from host %1 (%2)"
#endif
);
const MessageType2 URLStorageMessages::closeError(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2314
#ifndef SP_NO_MESSAGE_TEXT
,"error closing connection to host %1 (%2)"
#endif
);
const MessageType1 URLStorageMessages::invalidHostNumber(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2315
#ifndef SP_NO_MESSAGE_TEXT
,"invalid host number %1"
#endif
);
const MessageType3 URLStorageMessages::getFailed(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2316
#ifndef SP_NO_MESSAGE_TEXT
,"could not get %2 from %1 (reason given was %3)"
#endif
);
const MessageType0 URLStorageMessages::notSupported(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2317
#ifndef SP_NO_MESSAGE_TEXT
,"URL not supported by this version"
#endif
);
const MessageType0 URLStorageMessages::onlyHTTP(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2318
#ifndef SP_NO_MESSAGE_TEXT
,"only HTTP scheme supported"
#endif
);
const MessageType1 URLStorageMessages::winsockInitialize(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2319
#ifndef SP_NO_MESSAGE_TEXT
,"could not initialize Windows Sockets (%1)"
#endif
);
const MessageType0 URLStorageMessages::winsockVersion(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2320
#ifndef SP_NO_MESSAGE_TEXT
,"incompatible Windows Sockets version"
#endif
);
const MessageFragment URLStorageMessages::winsockErrorNumber(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2321
#ifndef SP_NO_MESSAGE_TEXT
,"error number "
#endif
);
#ifdef SP_NAMESPACE
}
#endif
