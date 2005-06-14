/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Copyright (C) RSA Data Security, Inc. created 1993, 1996.  This is an
   unpublished work protected as such under copyright law.  This work
   contains proprietary, confidential, and trade secret information of
   RSA Data Security, Inc.  Use, disclosure or reproduction without the
   express written authorization of RSA Data Security, Inc. is
   prohibited.
 */

#ifndef _ALGCHOICE_H_
#define _ALGCHOICE_H_ 1

#define IS_FATAL_BSAFE_ERROR(status) \
  (status == BE_ALLOC || status == BE_HARDWARE || status == BE_CANCEL)

/* Use the THIS_ALGA_CHOICE macro to define the type of object in the
     INIT_ALGA prototype.  It defaults to the AlgaChoice, but
     derived modules may define the macro to a more derived class before
     including this header file.
 */
struct AlgaChoice;
#ifndef THIS_ALGA_CHOICE
#define THIS_ALGA_CHOICE struct AlgaChoice
#endif

/* In C++:
class ResizeContext {
public:
  ResizeContext ();
  ~ResizeContext ();
  int makeNewContext (unsigned int contextSize);
  POINTER context () {return z.context;}

private:
  struct {
    POINTER context;
    unsigned int contextSize;
  } z;
};

class AlgaChoice;
typedef int (*INIT_ALGA)
  (THIS_ALGA_CHOICE *algaChoice, POINTER keyInfo,
   struct B_ALGORITHM_METHOD *algorithmMethod,
   A_SURRENDER_CTX *surrenderContext);

class AlgaChoice {
public:
  AlgaChoice (INIT_ALGA InitAlga) : _InitAlga (InitAlga) {}
  ~AlgaChoice () {}
  int choose
    (int encryptFlag, B_Key *key, B_ALGORITHM_CHOOSER chooser,
     A_SURRENDER_CTX *surrenderContext);
  int makeNewContext (unsigned int contextSize) {
    context.makeNewContext (contextSize); }
  POINTER alga () {return _alga;}
  POINTER algorithmInfo () {return _algorithmInfo;}
  POINTER context () {return context.context ();}
  void setAlgorithmInfoType (B_AlgorithmInfoType *algorithmInfoType) {
    _algorithmInfoType = algorithmInfoType;
  }
  void setAlgorithmInfo (POINTER algorithmInfo) {
    _algorithmInfo = algorithmInfo;
  }

private:
  POINTER _alga;
  B_AlgorithmInfoType *_algorithmInfoType;
  POINTER _algorithmInfo;
  INIT_ALGA _InitAlga;

  ResizeContext context;
};
 */
struct B_AlgorithmInfoType;

typedef struct ResizeContext {
  struct {
    POINTER context;
    unsigned int contextSize;
  } z;                                            /* zeriozed by constructor */
} ResizeContext;

typedef int (*INIT_ALGA) PROTO_LIST
  ((THIS_ALGA_CHOICE *, POINTER, struct B_ALGORITHM_METHOD *,
    A_SURRENDER_CTX *));

typedef struct AlgaChoice {
  POINTER _alga;
  struct B_AlgorithmInfoType *_algorithmInfoType;
  POINTER _algorithmInfo;
  INIT_ALGA _InitAlga;

  ResizeContext context;
} AlgaChoice;

void ResizeContextConstructor PROTO_LIST ((ResizeContext *));
void ResizeContextDestructor PROTO_LIST ((ResizeContext *));
int ResizeContextMakeNewContext PROTO_LIST ((ResizeContext *, unsigned int));

#define ALGA_CHOICE_Constructor(algaChoice, InitAlga)\
  (ResizeContextConstructor (&(algaChoice)->context), \
   (algaChoice)->_InitAlga = (InitAlga))
#define ALGA_CHOICE_Destructor(algaChoice)\
  (ResizeContextDestructor (&(algaChoice)->context))

int AlgaChoiceChoose PROTO_LIST
  ((AlgaChoice *, int, B_Key *, B_ALGORITHM_CHOOSER, A_SURRENDER_CTX *));

int ConvertAlgaeError PROTO_LIST ((int));

#endif
