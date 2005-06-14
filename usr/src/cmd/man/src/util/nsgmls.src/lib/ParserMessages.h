// This file was automatically generated from lib\ParserMessages.msg by msggen.pl.
#ifndef ParserMessages_INCLUDED
#define ParserMessages_INCLUDED 1

#ifdef __GNUG__
#pragma interface
#endif
#include "Message.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

struct ParserMessages {
  // 0
  static const MessageType1 nameLength;
  // 1
  static const MessageType1 parameterEntityNameLength;
  // 2
  static const MessageType1 numberLength;
  // 3
  static const MessageType1 attributeValueLength;
  // 4
  static const MessageType0 peroGrpoProlog;
  // 5
  static const MessageType0 groupLevel;
  // 6
  static const MessageType2 groupCharacter;
  // 7
  static const MessageType0 psRequired;
  // 8
  static const MessageType2 markupDeclarationCharacter;
  // 9
  static const MessageType0 declarationLevel;
  // 10
  static const MessageType0 groupEntityEnd;
  // 11
  static const MessageType1 invalidToken;
  // 12
  static const MessageType0 groupEntityReference;
  // 13
  static const MessageType1 duplicateGroupToken;
  // 14
  static const MessageType1 groupCount;
  // 15
  static const MessageType0 literalLevel;
  // 16
  static const MessageType1 literalMinimumData;
  // 17
  static const MessageType0 dataTagPatternNonSgml;
  // 18
  static const MessageType0 dataTagPatternFunction;
  // 19
  static const MessageType0 eroGrpoStartTag;
  // 20
  static const MessageType0 eroGrpoProlog;
  // 21
  static const MessageType1 functionName;
  // 22
  static const MessageType1 characterNumber;
  // 23
  static const MessageType1 parameterEntityUndefined;
  // 24
  static const MessageType1 entityUndefined;
  // 25
  static const MessageType0 rniNameStart;
  // 26
  static const MessageType0L commentEntityEnd;
  // 28
  static const MessageType0 mixedConnectors;
  // 29
  static const MessageType1 noSuchReservedName;
  // 30
  static const MessageType1 invalidReservedName;
  // 31
  static const MessageType1 minimumLiteralLength;
  // 32
  static const MessageType1 tokenizedAttributeValueLength;
  // 33
  static const MessageType1 systemIdentifierLength;
  // 34
  static const MessageType1 parameterLiteralLength;
  // 35
  static const MessageType1 dataTagPatternLiteralLength;
  // 36
  static const MessageType0 literalClosingDelimiter;
  // 37
  static const MessageType2 paramInvalidToken;
  // 38
  static const MessageType2 groupTokenInvalidToken;
  // 39
  static const MessageType2 connectorInvalidToken;
  // 40
  static const MessageType1 noSuchDeclarationType;
  // 41
  static const MessageType1 dtdSubsetDeclaration;
  // 42
  static const MessageType1 declSubsetCharacter;
  // 43
  static const MessageType0 documentEndDtdSubset;
  // 44
  static const MessageType1 prologCharacter;
  // 45
  static const MessageType0 documentEndProlog;
  // 46
  static const MessageType1 prologDeclaration;
  // 47
  static const MessageType1 rankStemGenericIdentifier;
  // 48
  static const MessageType0 missingTagMinimization;
  // 49
  static const MessageType1 duplicateElementDefinition;
  // 50
  static const MessageType0 entityApplicableDtd;
  // 51
  static const MessageType1L commentDeclInvalidToken;
  // 53
  static const MessageType1 instanceDeclaration;
  // 54
  static const MessageType0 contentNonSgml;
  // 55
  static const MessageType1 noCurrentRank;
  // 56
  static const MessageType1 duplicateAttlistNotation;
  // 57
  static const MessageType1 duplicateAttlistElement;
  // 58
  static const MessageType0 endTagEntityEnd;
  // 59
  static const MessageType1 endTagCharacter;
  // 60
  static const MessageType1 endTagInvalidToken;
  // 61
  static const MessageType0 pcdataNotAllowed;
  // 62
  static const MessageType1 elementNotAllowed;
  // 63
  static const MessageType2 missingElementMultiple;
  // 64
  static const MessageType2 missingElementInferred;
  // 65
  static const MessageType1 startTagEmptyElement;
  // 66
  static const MessageType1L omitEndTagDeclare;
  // 68
  static const MessageType1L omitEndTagOmittag;
  // 70
  static const MessageType1 omitStartTagDeclaredContent;
  // 71
  static const MessageType1 elementEndTagNotFinished;
  // 72
  static const MessageType1 omitStartTagDeclare;
  // 73
  static const MessageType1 taglvlOpenElements;
  // 74
  static const MessageType1 undefinedElement;
  // 75
  static const MessageType0 emptyEndTagNoOpenElements;
  // 76
  static const MessageType1 elementNotFinished;
  // 77
  static const MessageType1 elementNotOpen;
  // 78
  static const MessageType1 internalParameterDataEntity;
  // 79
  static const MessageType1 attributeSpecCharacter;
  // 80
  static const MessageType0 unquotedAttributeValue;
  // 81
  static const MessageType0 attributeSpecEntityEnd;
  // 82
  static const MessageType1 externalParameterDataSubdocEntity;
  // 83
  static const MessageType1 duplicateEntityDeclaration;
  // 84
  static const MessageType1 duplicateParameterEntityDeclaration;
  // 85
  static const MessageType0 piEntityReference;
  // 86
  static const MessageType0 internalDataEntityReference;
  // 87
  static const MessageType0 externalNonTextEntityReference;
  // 88
  static const MessageType0 externalNonTextEntityRcdata;
  // 89
  static const MessageType0 entlvl;
  // 90
  static const MessageType0 piEntityRcdata;
  // 91
  static const MessageType1 recursiveEntityReference;
  // 92
  static const MessageType1 undefinedShortrefMapInstance;
  // 93
  static const MessageType0 usemapAssociatedElementTypeDtd;
  // 94
  static const MessageType0 usemapAssociatedElementTypeInstance;
  // 95
  static const MessageType2 undefinedShortrefMapDtd;
  // 96
  static const MessageType1 unknownShortrefDelim;
  // 97
  static const MessageType1 delimDuplicateMap;
  // 98
  static const MessageType0 noDocumentElement;
  // 99
  static const MessageType0 processingInstructionEntityEnd;
  // 100
  static const MessageType1 processingInstructionLength;
  // 101
  static const MessageType0 processingInstructionClose;
  // 102
  static const MessageType0 attributeSpecNameTokenExpected;
  // 103
  static const MessageType1 noSuchAttributeToken;
  // 104
  static const MessageType0 attributeNameShorttag;
  // 105
  static const MessageType1 noSuchAttribute;
  // 106
  static const MessageType0 attributeValueExpected;
  // 107
  static const MessageType1 nameTokenLength;
  // 108
  static const MessageType0 attributeSpecLiteral;
  // 109
  static const MessageType1 duplicateAttributeSpec;
  // 110
  static const MessageType1 duplicateAttributeDef;
  // 111
  static const MessageType0 emptyDataAttributeSpec;
  // 112
  static const MessageType0 markedSectionEnd;
  // 113
  static const MessageType1 markedSectionLevel;
  // 114
  static const MessageType0L unclosedMarkedSection;
  // 116
  static const MessageType0 specialParseEntityEnd;
  // 117
  static const MessageType2 normalizedAttributeValueLength;
  // 118
  static const MessageType0 attributeValueSyntax;
  // 119
  static const MessageType2 attributeValueChar;
  // 120
  static const MessageType1 attributeValueMultiple;
  // 121
  static const MessageType2 attributeValueNumberToken;
  // 122
  static const MessageType2 attributeValueName;
  // 123
  static const MessageType1 attributeMissing;
  // 124
  static const MessageType1 requiredAttributeMissing;
  // 125
  static const MessageType1 currentAttributeMissing;
  // 126
  static const MessageType1 invalidNotationAttribute;
  // 127
  static const MessageType1 invalidEntityAttribute;
  // 128
  static const MessageType3 attributeValueNotInGroup;
  // 129
  static const MessageType1 notDataOrSubdocEntity;
  // 130
  static const MessageType3 ambiguousModelInitial;
  // 131
  static const MessageType5 ambiguousModel;
  // 132
  static const MessageType5 ambiguousModelSingleAnd;
  // 133
  static const MessageType6 ambiguousModelMultipleAnd;
  // 134
  static const MessageType1L commentDeclarationCharacter;
  // 136
  static const MessageType1 nonSgmlCharacter;
  // 137
  static const MessageType0 dataMarkedSectionDeclSubset;
  // 138
  static const MessageType1L duplicateId;
  // 140
  static const MessageType1 notFixedValue;
  // 141
  static const MessageType1 sdCommentSignificant;
  // 142
  static const MessageType1 standardVersion;
  // 143
  static const MessageType1 namingBeforeLcnmstrt;
  // 144
  static const MessageType1 sdEntityEnd;
  // 145
  static const MessageType2 sdInvalidNameToken;
  // 146
  static const MessageType1 numberTooBig;
  // 147
  static const MessageType1 sdLiteralSignificant;
  // 148
  static const MessageType1 syntaxCharacterNumber;
  // 149
  static const MessageType0 sdParameterEntity;
  // 150
  static const MessageType2 sdParamInvalidToken;
  // 151
  static const MessageType0 giveUp;
  // 152
  static const MessageType1 sdMissingCharacters;
  // 153
  static const MessageType1 missingMinimumChars;
  // 154
  static const MessageType1 duplicateCharNumbers;
  // 155
  static const MessageType1 codeSetHoles;
  // 156
  static const MessageType1 basesetCharsMissing;
  // 157
  static const MessageType1 documentCharMax;
  // 158
  static const MessageType1 fpiMissingField;
  // 159
  static const MessageType1 fpiMissingTextClassSpace;
  // 160
  static const MessageType1 fpiInvalidTextClass;
  // 161
  static const MessageType1 fpiInvalidLanguage;
  // 162
  static const MessageType1 fpiIllegalDisplayVersion;
  // 163
  static const MessageType1 fpiExtraField;
  // 164
  static const MessageType0 notationIdentifierTextClass;
  // 165
  static const MessageType1 unknownBaseset;
  // 166
  static const MessageType2 lexicalAmbiguity;
  // 167
  static const MessageType1 missingSignificant;
  // 168
  static const MessageType1 translateSyntaxCharDoc;
  // 169
  static const MessageType1 translateSyntaxCharInternal;
  // 170
  static const MessageType1 missingSyntaxChar;
  // 171
  static const MessageType1 unknownCapacitySet;
  // 172
  static const MessageType1 duplicateCapacity;
  // 173
  static const MessageType1 capacityExceedsTotalcap;
  // 174
  static const MessageType1 unknownPublicSyntax;
  // 175
  static const MessageType0 nmstrtLength;
  // 176
  static const MessageType0 nmcharLength;
  // 177
  static const MessageType1 subdocLevel;
  // 178
  static const MessageType1 subdocEntity;
  // 179
  static const MessageType0 parameterEntityNotEnded;
  // 180
  static const MessageType1 missingId;
  // 181
  static const MessageType1 dtdUndefinedElement;
  // 182
  static const MessageType1 elementNotFinishedDocumentEnd;
  // 183
  static const MessageType0 subdocGiveUp;
  // 184
  static const MessageType0 noDtd;
  // 185
  static const MessageType0 noDtdSubset;
  // 186
  static const MessageType0 notSgml;
  // 187
  static const MessageType1 taglen;
  // 188
  static const MessageType0 groupParameterEntityNotEnded;
  // 189
  static const MessageType1 invalidSgmlChar;
  // 190
  static const MessageType1 translateDocChar;
  // 191
  static const MessageType1 attributeValueLengthNeg;
  // 192
  static const MessageType1 tokenizedAttributeValueLengthNeg;
  // 193
  static const MessageType1 scopeInstanceQuantity;
  // 194
  static const MessageType1 basesetTextClass;
  // 195
  static const MessageType1 capacityTextClass;
  // 196
  static const MessageType1 syntaxTextClass;
  // 197
  static const MessageType0 msocharRequiresMsichar;
  // 198
  static const MessageType1 switchNotMarkup;
  // 199
  static const MessageType1 switchNotInCharset;
  // 200
  static const MessageType1 ambiguousDocCharacter;
  // 201
  static const MessageType1 oneFunction;
  // 202
  static const MessageType1 duplicateFunctionName;
  // 203
  static const MessageType1 missingSignificant646;
  // 204
  static const MessageType1 generalDelimAllFunction;
  // 205
  static const MessageType1 nmcharLetter;
  // 206
  static const MessageType1 nmcharDigit;
  // 207
  static const MessageType1 nmcharRe;
  // 208
  static const MessageType1 nmcharRs;
  // 209
  static const MessageType1 nmcharSpace;
  // 210
  static const MessageType1 nmcharSepchar;
  // 211
  static const MessageType1 switchLetterDigit;
  // 212
  static const MessageType0 zeroNumberOfCharacters;
  // 213
  static const MessageType1 nameReferenceReservedName;
  // 214
  static const MessageType1 ambiguousReservedName;
  // 215
  static const MessageType1 duplicateReservedName;
  // 216
  static const MessageType1 reservedNameSyntax;
  // 217
  static const MessageType1 multipleBSequence;
  // 218
  static const MessageType1 blankAdjacentBSequence;
  // 219
  static const MessageType2 delimiterLength;
  // 220
  static const MessageType2 reservedNameLength;
  // 221
  static const MessageType1 nmcharNmstrt;
  // 222
  static const MessageType0 scopeInstanceSyntaxCharset;
  // 223
  static const MessageType0 emptyOmitEndTag;
  // 224
  static const MessageType1 conrefOmitEndTag;
  // 225
  static const MessageType1 conrefEmpty;
  // 226
  static const MessageType1 notationEmpty;
  // 227
  static const MessageType0 dataAttributeDeclaredValue;
  // 228
  static const MessageType0 dataAttributeDefaultValue;
  // 229
  static const MessageType2 attcnt;
  // 230
  static const MessageType0 idDeclaredValue;
  // 231
  static const MessageType1 multipleIdAttributes;
  // 232
  static const MessageType1 multipleNotationAttributes;
  // 233
  static const MessageType1 duplicateAttributeToken;
  // 234
  static const MessageType1 notationNoAttributes;
  // 235
  static const MessageType2 entityNotationUndefined;
  // 236
  static const MessageType2 mapEntityUndefined;
  // 237
  static const MessageType1 attlistNotationUndefined;
  // 238
  static const MessageType1 bracketedLitlen;
  // 239
  static const MessageType1 genericIdentifierLength;
  // 240
  static const MessageType0 instanceStartOmittag;
  // 241
  static const MessageType1 grplvl;
  // 242
  static const MessageType1 grpgtcnt;
  // 243
  static const MessageType0 unclosedStartTagShorttag;
  // 244
  static const MessageType0 netEnablingStartTagShorttag;
  // 245
  static const MessageType0 unclosedEndTagShorttag;
  // 246
  static const MessageType0 multipleDtds;
  // 247
  static const MessageType0 afterDocumentElementEntityEnd;
  // 248
  static const MessageType1 declarationAfterDocumentElement;
  // 249
  static const MessageType0 characterReferenceAfterDocumentElement;
  // 250
  static const MessageType0 entityReferenceAfterDocumentElement;
  // 251
  static const MessageType0 markedSectionAfterDocumentElement;
  // 252
  static const MessageType3 requiredElementExcluded;
  // 253
  static const MessageType3 invalidExclusion;
  // 254
  static const MessageType0 attributeValueShorttag;
  // 255
  static const MessageType0 conrefNotation;
  // 256
  static const MessageType1 duplicateNotationDeclaration;
  // 257
  static const MessageType1L duplicateShortrefDeclaration;
  // 259
  static const MessageType1 duplicateDelimGeneral;
  // 260
  static const MessageType1 idrefGrpcnt;
  // 261
  static const MessageType1 entityNameGrpcnt;
  // 262
  static const MessageType2 attsplen;
  // 263
  static const MessageType1 duplicateDelimShortref;
  // 264
  static const MessageType1 duplicateDelimShortrefSet;
  // 265
  static const MessageType1 defaultEntityInAttribute;
  // 266
  static const MessageType1 defaultEntityReference;
  // 267
  static const MessageType2 mapDefaultEntity;
  // 268
  static const MessageType1 noSuchDtd;
  // 269
  static const MessageType1 noLpdSubset;
  // 270
  static const MessageType0 assocElementDifferentAtts;
  // 271
  static const MessageType1 duplicateLinkSet;
  // 272
  static const MessageType0 emptyResultAttributeSpec;
  // 273
  static const MessageType1 noSuchSourceElement;
  // 274
  static const MessageType1 noSuchResultElement;
  // 275
  static const MessageType0 documentEndLpdSubset;
  // 276
  static const MessageType1 lpdSubsetDeclaration;
  // 277
  static const MessageType0 idlinkDeclSimple;
  // 278
  static const MessageType0 linkDeclSimple;
  // 279
  static const MessageType1 simpleLinkAttlistElement;
  // 280
  static const MessageType0 shortrefOnlyInBaseDtd;
  // 281
  static const MessageType0 usemapOnlyInBaseDtd;
  // 282
  static const MessageType0 linkAttributeDefaultValue;
  // 283
  static const MessageType0 linkAttributeDeclaredValue;
  // 284
  static const MessageType0 simpleLinkFixedAttribute;
  // 285
  static const MessageType0 duplicateIdLinkSet;
  // 286
  static const MessageType1 noInitialLinkSet;
  // 287
  static const MessageType1 notationUndefinedSourceDtd;
  // 288
  static const MessageType0 simpleLinkResultNotImplied;
  // 289
  static const MessageType0 simpleLinkFeature;
  // 290
  static const MessageType0 implicitLinkFeature;
  // 291
  static const MessageType0 explicitLinkFeature;
  // 292
  static const MessageType0 lpdBeforeBaseDtd;
  // 293
  static const MessageType0 dtdAfterLpd;
  // 294
  static const MessageType1 unstableLpdGeneralEntity;
  // 295
  static const MessageType1 unstableLpdParameterEntity;
  // 296
  static const MessageType1 multipleIdLinkRuleAttribute;
  // 297
  static const MessageType1 multipleLinkRuleAttribute;
  // 298
  static const MessageType2 uselinkBadLinkSet;
  // 299
  static const MessageType1 uselinkSimpleLpd;
  // 300
  static const MessageType1 uselinkBadLinkType;
  // 301
  static const MessageType1 duplicateDtdLpd;
  // 302
  static const MessageType1 duplicateLpd;
  // 303
  static const MessageType1 duplicateDtd;
  // 304
  static const MessageType1 undefinedLinkSet;
  // 305
  static const MessageType1 duplicateImpliedResult;
  // 306
  static const MessageType1 simpleLinkCount;
  // 307
  static const MessageType0 duplicateExplicitChain;
  // 308
  static const MessageType1 explicit1RequiresSourceTypeBase;
  // 309
  static const MessageType0 oneImplicitLink;
  // 310
  static const MessageType1 sorryLink;
  // 311
  static const MessageType0 entityReferenceMissingName;
  // 312
  static const MessageType1 explicitNoRequiresSourceTypeBase;
  // 313
  static const MessageType0 linkActivateTooLate;
  // 314
  static const MessageType0 pass2Ee;
  // 315
  static const MessageType2 idlinkElementType;
  // 316
  static const MessageType0 datatagNotImplemented;
  // 317
  static const MessageType0 startTagMissingName;
  // 318
  static const MessageType0 endTagMissingName;
  // 319
  static const MessageType0 startTagGroupNet;
  // 320
  static const MessageType0 documentElementUndefined;
  // 321
  static const MessageType0 badDefaultSgmlDecl;
  // 322
  static const MessageType1L nonExistentEntityRef;
  // 324
  static const MessageType0 pcdataUnreachable;
  // 325
  static const MessageType0 sdRangeNotSingleChar;
  // 326
  static const MessageType0 sdInvalidRange;
  // 327
  static const MessageType0 sdEmptyDelimiter;
  // 328
  static const MessageType0 tooManyCharsMinimumLiteral;
  // 329
  static const MessageType1 defaultedEntityDefined;
  // 330
  static const MessageType0 emptyStartTag;
  // 331
  static const MessageType0 emptyEndTag;
  // 332
  static const MessageType1 unusedMap;
  // 333
  static const MessageType1 unusedParamEntity;
  // 334
  static const MessageType1 cannotGenerateSystemIdPublic;
  // 335
  static const MessageType1 cannotGenerateSystemIdGeneral;
  // 336
  static const MessageType1 cannotGenerateSystemIdParameter;
  // 337
  static const MessageType1 cannotGenerateSystemIdDoctype;
  // 338
  static const MessageType1 cannotGenerateSystemIdLinktype;
  // 339
  static const MessageType1 cannotGenerateSystemIdNotation;
  // 340
  static const MessageType1 excludeIncludeSame;
  // 341
  static const MessageType1 implyingDtd;
  // 342
  static const MessageType1 afdrVersion;
  // 343
  static const MessageType0 missingAfdrDecl;
  // 344
  static const MessageType0 enrRequired;
  // 345
  static const MessageType1 numericCharRefLiteralNonSgml;
  // 346
  static const MessageType2 numericCharRefUnknownDesc;
  // 347
  static const MessageType3 numericCharRefUnknownBase;
  // 348
  static const MessageType1 numericCharRefBadInternal;
  // 349
  static const MessageType1 numericCharRefNoInternal;
  // 350
  static const MessageType0 wwwRequired;
  // 351
  static const MessageType1 attributeTokenNotUnique;
  // 352
  static const MessageType1 hexNumberLength;
  // 353
  static const MessageType1 entityNameSyntax;
  // 354
  static const MessageType0 cdataContent;
  // 355
  static const MessageType0 rcdataContent;
  // 356
  static const MessageType0 inclusion;
  // 357
  static const MessageType0 exclusion;
  // 358
  static const MessageType0 numberDeclaredValue;
  // 359
  static const MessageType0 nameDeclaredValue;
  // 360
  static const MessageType0 nutokenDeclaredValue;
  // 361
  static const MessageType0 conrefAttribute;
  // 362
  static const MessageType0 currentAttribute;
  // 363
  static const MessageType0 tempMarkedSection;
  // 364
  static const MessageType0 instanceIncludeMarkedSection;
  // 365
  static const MessageType0 instanceIgnoreMarkedSection;
  // 366
  static const MessageType0 rcdataMarkedSection;
  // 367
  static const MessageType0 piEntity;
  // 368
  static const MessageType0 bracketEntity;
  // 369
  static const MessageType0 internalCdataEntity;
  // 370
  static const MessageType0 internalSdataEntity;
  // 371
  static const MessageType0 externalCdataEntity;
  // 372
  static const MessageType0 externalSdataEntity;
  // 373
  static const MessageType0 dataAttributes;
  // 374
  static const MessageType0 rank;
  // 375
  static const MessageType0 missingSystemId;
  // 376
  static const MessageType0 psComment;
  // 377
  static const MessageType0 namedCharRef;
  // 378
  static const MessageType0 andGroup;
  // 379
  static const MessageType0 attributeValueNotLiteral;
  // 380
  static const MessageType0 missingAttributeName;
  // 381
  static const MessageType0 elementGroupDecl;
  // 382
  static const MessageType0 attlistGroupDecl;
  // 383
  static const MessageType0 emptyCommentDecl;
  // 384
  static const MessageType0 commentDeclS;
  // 385
  static const MessageType0 commentDeclMultiple;
  // 386
  static const MessageType0 missingStatusKeyword;
  // 387
  static const MessageType0 multipleStatusKeyword;
  // 388
  static const MessageType0 instanceParamEntityRef;
  // 389
  static const MessageType0 current;
  // 390
  static const MessageType0 minimizationParam;
  // 391
  static const MessageType0 refc;
  // 392
  static const MessageType0 pcdataNotFirstInGroup;
  // 393
  static const MessageType0 pcdataInSeqGroup;
  // 394
  static const MessageType0 pcdataInNestedModelGroup;
  // 395
  static const MessageType0 pcdataGroupNotRep;
  // 396
  static const MessageType0 nameGroupNotOr;
  // 397
  static const MessageType0 piMissingName;
  // 398
  static const MessageType0 instanceStatusKeywordSpecS;
  // 399
  static const MessageType0 externalDataEntityRef;
  // 400
  static const MessageType0 attributeValueExternalEntityRef;
  // 401
  static const MessageType1 dataCharDelim;
  // 402
  static const MessageType0 explicitSgmlDecl;
  // 403
  static const MessageType0 internalSubsetMarkedSection;
  // 404
  static const MessageType0 nestcWithoutNet;
  // 405
  static const MessageType0 contentAsyncEntityRef;
  // 406
  static const MessageType0 immednetRequiresEmptynrm;
  // 407
  static const MessageType0 nonSgmlCharRef;
  // 408
  static const MessageType0 defaultEntityDecl;
  // 409
  static const MessageType0 internalSubsetPsParamEntityRef;
  // 410
  static const MessageType0 internalSubsetTsParamEntityRef;
  // 411
  static const MessageType0 internalSubsetLiteralParamEntityRef;
  // 412
  static const MessageType0 cannotGenerateSystemIdSgml;
  // 413
  static const MessageType1 sdTextClass;
  // 414
  static const MessageType0 sgmlDeclRefRequiresWww;
  // 415
  static const MessageType0 pcdataGroupMemberOccurrenceIndicator;
  // 416
  static const MessageType0 pcdataGroupMemberModelGroup;
  // 1000
  static const MessageFragment delimStart;
  // 1001
  static const MessageFragment delimEnd;
  // 1002
  static const MessageFragment digit;
  // 1003
  static const MessageFragment nameStartCharacter;
  // 1004
  static const MessageFragment sepchar;
  // 1005
  static const MessageFragment separator;
  // 1006
  static const MessageFragment nameCharacter;
  // 1007
  static const MessageFragment dataCharacter;
  // 1008
  static const MessageFragment minimumDataCharacter;
  // 1009
  static const MessageFragment significantCharacter;
  // 1010
  static const MessageFragment recordEnd;
  // 1011
  static const MessageFragment recordStart;
  // 1012
  static const MessageFragment space;
  // 1013
  static const MessageFragment listSep;
  // 1014
  static const MessageFragment rangeSep;
  // 1015
  static const MessageFragment parameterLiteral;
  // 1016
  static const MessageFragment dataTagGroup;
  // 1017
  static const MessageFragment modelGroup;
  // 1018
  static const MessageFragment dataTagTemplateGroup;
  // 1019
  static const MessageFragment name;
  // 1020
  static const MessageFragment nameToken;
  // 1021
  static const MessageFragment elementToken;
  // 1022
  static const MessageFragment inclusions;
  // 1023
  static const MessageFragment exclusions;
  // 1024
  static const MessageFragment minimumLiteral;
  // 1025
  static const MessageFragment attributeValueLiteral;
  // 1026
  static const MessageFragment systemIdentifier;
  // 1027
  static const MessageFragment number;
  // 1028
  static const MessageFragment attributeValue;
  // 1029
  static const MessageFragment capacityName;
  // 1030
  static const MessageFragment generalDelimiteRoleName;
  // 1031
  static const MessageFragment referenceReservedName;
  // 1032
  static const MessageFragment quantityName;
  // 1033
  static const MessageFragment entityEnd;
  // 1034
  static const MessageFragment shortrefDelim;
};

#ifdef SP_NAMESPACE
}
#endif

#endif /* not ParserMessages_INCLUDED */
