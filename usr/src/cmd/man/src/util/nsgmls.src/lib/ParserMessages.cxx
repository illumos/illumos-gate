// This file was automatically generated from lib\ParserMessages.msg by msggen.pl.

#ifdef __GNUG__
#pragma implementation
#endif

#include "splib.h"
#include "ParserMessages.h"

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

const MessageType1 ParserMessages::nameLength(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
0
#ifndef SP_NO_MESSAGE_TEXT
,"length of name must not exceed NAMELEN (%1)"
#endif
);
const MessageType1 ParserMessages::parameterEntityNameLength(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1
#ifndef SP_NO_MESSAGE_TEXT
,"length of parameter entity name must not exceed NAMELEN less the length of the PERO delimiter (%1)"
#endif
);
const MessageType1 ParserMessages::numberLength(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
2
#ifndef SP_NO_MESSAGE_TEXT
,"length of number must not exceed NAMELEN (%1)"
#endif
);
const MessageType1 ParserMessages::attributeValueLength(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
3
#ifndef SP_NO_MESSAGE_TEXT
,"length of attribute value must not exceed LITLEN less NORMSEP (%1)"
#endif
);
const MessageType0 ParserMessages::peroGrpoProlog(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
4
#ifndef SP_NO_MESSAGE_TEXT
,"a name group is not allowed in a parameter entity reference in the prolog"
#endif
);
const MessageType0 ParserMessages::groupLevel(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
5
#ifndef SP_NO_MESSAGE_TEXT
,"an entity end in a token separator must terminate an entity referenced in the same group"
#endif
);
const MessageType2 ParserMessages::groupCharacter(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
6
#ifndef SP_NO_MESSAGE_TEXT
,"character %1 invalid: only %2 and token separators allowed"
#endif
);
const MessageType0 ParserMessages::psRequired(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
7
#ifndef SP_NO_MESSAGE_TEXT
,"a parameter separator is required after a number that is followed by a name start character"
#endif
);
const MessageType2 ParserMessages::markupDeclarationCharacter(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
8
#ifndef SP_NO_MESSAGE_TEXT
,"character %1 invalid: only %2 and parameter separators allowed"
#endif
);
const MessageType0 ParserMessages::declarationLevel(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
9
#ifndef SP_NO_MESSAGE_TEXT
,"an entity end in a parameter separator must terminate an entity referenced in the same declaration"
#endif
);
const MessageType0 ParserMessages::groupEntityEnd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
10
#ifndef SP_NO_MESSAGE_TEXT
,"an entity end is not allowed in a token separator that does not follow a token"
#endif
);
const MessageType1 ParserMessages::invalidToken(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
11
#ifndef SP_NO_MESSAGE_TEXT
,"%1 is not a valid token here"
#endif
);
const MessageType0 ParserMessages::groupEntityReference(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
12
#ifndef SP_NO_MESSAGE_TEXT
,"a parameter entity reference can only occur in a group where a token could occur"
#endif
);
const MessageType1 ParserMessages::duplicateGroupToken(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
13
#ifndef SP_NO_MESSAGE_TEXT
,"token %1 has already occurred in this group"
#endif
);
const MessageType1 ParserMessages::groupCount(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
14
#ifndef SP_NO_MESSAGE_TEXT
,"the number of tokens in a group must not exceed GRPCNT (%1)"
#endif
);
const MessageType0 ParserMessages::literalLevel(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
15
#ifndef SP_NO_MESSAGE_TEXT
,"an entity end in a literal must terminate an entity referenced in the same literal"
#endif
);
const MessageType1 ParserMessages::literalMinimumData(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
16
#ifndef SP_NO_MESSAGE_TEXT
,"character %1 invalid: only minimum data characters allowed"
#endif
);
const MessageType0 ParserMessages::dataTagPatternNonSgml(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
17
#ifndef SP_NO_MESSAGE_TEXT
,"a parameter literal in a data tag pattern must not contain a numeric character reference to a non-SGML character"
#endif
);
const MessageType0 ParserMessages::dataTagPatternFunction(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
18
#ifndef SP_NO_MESSAGE_TEXT
,"a parameter literal in a data tag pattern must not contain a numeric character reference to a function character"
#endif
);
const MessageType0 ParserMessages::eroGrpoStartTag(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
19
#ifndef SP_NO_MESSAGE_TEXT
,"a name group is not allowed in a general entity reference in a start tag"
#endif
);
const MessageType0 ParserMessages::eroGrpoProlog(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
20
#ifndef SP_NO_MESSAGE_TEXT
,"a name group is not allowed in a general entity reference in the prolog"
#endif
);
const MessageType1 ParserMessages::functionName(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
21
#ifndef SP_NO_MESSAGE_TEXT
,"%1 is not a function name"
#endif
);
const MessageType1 ParserMessages::characterNumber(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
22
#ifndef SP_NO_MESSAGE_TEXT
,"%1 is not a character number in the document character set"
#endif
);
const MessageType1 ParserMessages::parameterEntityUndefined(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
23
#ifndef SP_NO_MESSAGE_TEXT
,"parameter entity %1 not defined"
#endif
);
const MessageType1 ParserMessages::entityUndefined(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
24
#ifndef SP_NO_MESSAGE_TEXT
,"general entity %1 not defined and no default entity"
#endif
);
const MessageType0 ParserMessages::rniNameStart(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
25
#ifndef SP_NO_MESSAGE_TEXT
,"RNI delimiter must be followed by name start character"
#endif
);
const MessageType0L ParserMessages::commentEntityEnd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
26
#ifndef SP_NO_MESSAGE_TEXT
,"unterminated comment: found end of entity inside comment"
,"comment started here"
#endif
);
const MessageType0 ParserMessages::mixedConnectors(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
28
#ifndef SP_NO_MESSAGE_TEXT
,"only one type of connector should be used in a single group"
#endif
);
const MessageType1 ParserMessages::noSuchReservedName(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
29
#ifndef SP_NO_MESSAGE_TEXT
,"%1 is not a reserved name"
#endif
);
const MessageType1 ParserMessages::invalidReservedName(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
30
#ifndef SP_NO_MESSAGE_TEXT
,"%1 is not allowed as a reserved name here"
#endif
);
const MessageType1 ParserMessages::minimumLiteralLength(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
31
#ifndef SP_NO_MESSAGE_TEXT
,"length of interpreted minimum literal must not exceed reference LITLEN (%1)"
#endif
);
const MessageType1 ParserMessages::tokenizedAttributeValueLength(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
32
#ifndef SP_NO_MESSAGE_TEXT
,"length of tokenized attribute value must not exceed LITLEN less NORMSEP (%1)"
#endif
);
const MessageType1 ParserMessages::systemIdentifierLength(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
33
#ifndef SP_NO_MESSAGE_TEXT
,"length of system identifier must not exceed LITLEN (%1)"
#endif
);
const MessageType1 ParserMessages::parameterLiteralLength(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
34
#ifndef SP_NO_MESSAGE_TEXT
,"length of interpreted parameter literal must not exceed LITLEN (%1)"
#endif
);
const MessageType1 ParserMessages::dataTagPatternLiteralLength(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
35
#ifndef SP_NO_MESSAGE_TEXT
,"length of interpreted parameter literal in data tag pattern must not exceed DTEMPLEN"
#endif
);
const MessageType0 ParserMessages::literalClosingDelimiter(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
36
#ifndef SP_NO_MESSAGE_TEXT
,"literal is missing closing delimiter"
#endif
);
const MessageType2 ParserMessages::paramInvalidToken(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
37
#ifndef SP_NO_MESSAGE_TEXT
,"%1 invalid: only %2 and parameter separators are allowed"
#endif
);
const MessageType2 ParserMessages::groupTokenInvalidToken(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
38
#ifndef SP_NO_MESSAGE_TEXT
,"%1 invalid: only %2 and token separators are allowed"
#endif
);
const MessageType2 ParserMessages::connectorInvalidToken(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
39
#ifndef SP_NO_MESSAGE_TEXT
,"%1 invalid: only %2 and token separators are allowed"
#endif
);
const MessageType1 ParserMessages::noSuchDeclarationType(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
40
#ifndef SP_NO_MESSAGE_TEXT
,"unknown declaration type %1"
#endif
);
const MessageType1 ParserMessages::dtdSubsetDeclaration(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
41
#ifndef SP_NO_MESSAGE_TEXT
,"%1 declaration not allowed in DTD subset"
#endif
);
const MessageType1 ParserMessages::declSubsetCharacter(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
42
#ifndef SP_NO_MESSAGE_TEXT
,"character %1 not allowed in declaration subset"
#endif
);
const MessageType0 ParserMessages::documentEndDtdSubset(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
43
#ifndef SP_NO_MESSAGE_TEXT
,"end of document in DTD subset"
#endif
);
const MessageType1 ParserMessages::prologCharacter(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
44
#ifndef SP_NO_MESSAGE_TEXT
,"character %1 not allowed in prolog"
#endif
);
const MessageType0 ParserMessages::documentEndProlog(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
45
#ifndef SP_NO_MESSAGE_TEXT
,"end of document in prolog"
#endif
);
const MessageType1 ParserMessages::prologDeclaration(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
46
#ifndef SP_NO_MESSAGE_TEXT
,"%1 declaration not allowed in prolog"
#endif
);
const MessageType1 ParserMessages::rankStemGenericIdentifier(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
47
#ifndef SP_NO_MESSAGE_TEXT
,"%1 used both a rank stem and generic identifier"
#endif
);
const MessageType0 ParserMessages::missingTagMinimization(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
48
#ifndef SP_NO_MESSAGE_TEXT
,"omitted tag minimization parameter can be omitted only if \"OMITTAG NO\" is specified on the SGML declaration"
#endif
);
const MessageType1 ParserMessages::duplicateElementDefinition(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
49
#ifndef SP_NO_MESSAGE_TEXT
,"element type %1 already defined"
#endif
);
const MessageType0 ParserMessages::entityApplicableDtd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
50
#ifndef SP_NO_MESSAGE_TEXT
,"entity reference with no applicable DTD"
#endif
);
const MessageType1L ParserMessages::commentDeclInvalidToken(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
51
#ifndef SP_NO_MESSAGE_TEXT
,"invalid comment declaration: found %1 outside comment but inside comment declaration"
,"comment declaration started here"
#endif
);
const MessageType1 ParserMessages::instanceDeclaration(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
53
#ifndef SP_NO_MESSAGE_TEXT
,"%1 declaration not allowed in instance"
#endif
);
const MessageType0 ParserMessages::contentNonSgml(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
54
#ifndef SP_NO_MESSAGE_TEXT
,"non-SGML character not allowed in content"
#endif
);
const MessageType1 ParserMessages::noCurrentRank(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
55
#ifndef SP_NO_MESSAGE_TEXT
,"no current rank for rank stem %1"
#endif
);
const MessageType1 ParserMessages::duplicateAttlistNotation(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
56
#ifndef SP_NO_MESSAGE_TEXT
,"duplicate attribute definition list for notation %1"
#endif
);
const MessageType1 ParserMessages::duplicateAttlistElement(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
57
#ifndef SP_NO_MESSAGE_TEXT
,"duplicate attribute definition list for element %1"
#endif
);
const MessageType0 ParserMessages::endTagEntityEnd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
58
#ifndef SP_NO_MESSAGE_TEXT
,"entity end not allowed in end tag"
#endif
);
const MessageType1 ParserMessages::endTagCharacter(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
59
#ifndef SP_NO_MESSAGE_TEXT
,"character %1 not allowed in end tag"
#endif
);
const MessageType1 ParserMessages::endTagInvalidToken(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
60
#ifndef SP_NO_MESSAGE_TEXT
,"%1 invalid: only s and tagc allowed here"
#endif
);
const MessageType0 ParserMessages::pcdataNotAllowed(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
61
#ifndef SP_NO_MESSAGE_TEXT
,"character data is not allowed here"
#endif
);
const MessageType1 ParserMessages::elementNotAllowed(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
62
#ifndef SP_NO_MESSAGE_TEXT
,"document type does not allow element %1 here"
#endif
);
const MessageType2 ParserMessages::missingElementMultiple(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
63
#ifndef SP_NO_MESSAGE_TEXT
,"document type does not allow element %1 here; missing one of %2 start-tag"
#endif
);
const MessageType2 ParserMessages::missingElementInferred(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
64
#ifndef SP_NO_MESSAGE_TEXT
,"document type does not allow element %1 here; assuming missing %2 start-tag"
#endif
);
const MessageType1 ParserMessages::startTagEmptyElement(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
65
#ifndef SP_NO_MESSAGE_TEXT
,"no start tag specified for implied empty element %1"
#endif
);
const MessageType1L ParserMessages::omitEndTagDeclare(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
66
#ifndef SP_NO_MESSAGE_TEXT
,"end tag for %1 omitted, but its declaration does not permit this"
,"start tag was here"
#endif
);
const MessageType1L ParserMessages::omitEndTagOmittag(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
68
#ifndef SP_NO_MESSAGE_TEXT
,"end tag for %1 omitted, but OMITTAG NO was specified"
,"start tag was here"
#endif
);
const MessageType1 ParserMessages::omitStartTagDeclaredContent(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
70
#ifndef SP_NO_MESSAGE_TEXT
,"start tag omitted for element %1 with declared content"
#endif
);
const MessageType1 ParserMessages::elementEndTagNotFinished(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
71
#ifndef SP_NO_MESSAGE_TEXT
,"end tag for %1 which is not finished"
#endif
);
const MessageType1 ParserMessages::omitStartTagDeclare(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
72
#ifndef SP_NO_MESSAGE_TEXT
,"start tag for %1 omitted, but its declaration does not permit this"
#endif
);
const MessageType1 ParserMessages::taglvlOpenElements(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
73
#ifndef SP_NO_MESSAGE_TEXT
,"number of open elements exceeds TAGLVL (%1)"
#endif
);
const MessageType1 ParserMessages::undefinedElement(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
74
#ifndef SP_NO_MESSAGE_TEXT
,"element %1 undefined"
#endif
);
const MessageType0 ParserMessages::emptyEndTagNoOpenElements(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
75
#ifndef SP_NO_MESSAGE_TEXT
,"empty end tag but no open elements"
#endif
);
const MessageType1 ParserMessages::elementNotFinished(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
76
#ifndef SP_NO_MESSAGE_TEXT
,"%1 not finished but containing element ended"
#endif
);
const MessageType1 ParserMessages::elementNotOpen(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
77
#ifndef SP_NO_MESSAGE_TEXT
,"end tag for element %1 which is not open"
#endif
);
const MessageType1 ParserMessages::internalParameterDataEntity(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
78
#ifndef SP_NO_MESSAGE_TEXT
,"internal parameter entity %1 cannot be CDATA or SDATA"
#endif
);
const MessageType1 ParserMessages::attributeSpecCharacter(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
79
#ifndef SP_NO_MESSAGE_TEXT
,"character %1 not allowed in attribute specification list"
#endif
);
const MessageType0 ParserMessages::unquotedAttributeValue(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
80
#ifndef SP_NO_MESSAGE_TEXT
,"an attribute value must be a literal unless it contains only name characters"
#endif
);
const MessageType0 ParserMessages::attributeSpecEntityEnd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
81
#ifndef SP_NO_MESSAGE_TEXT
,"entity end not allowed in attribute specification list except in attribute value literal"
#endif
);
const MessageType1 ParserMessages::externalParameterDataSubdocEntity(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
82
#ifndef SP_NO_MESSAGE_TEXT
,"external parameter entity %1 cannot be CDATA, SDATA, NDATA or SUBDOC"
#endif
);
const MessageType1 ParserMessages::duplicateEntityDeclaration(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
83
#ifndef SP_NO_MESSAGE_TEXT
,"duplicate declaration of entity %1"
#endif
);
const MessageType1 ParserMessages::duplicateParameterEntityDeclaration(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
84
#ifndef SP_NO_MESSAGE_TEXT
,"duplicate declaration of parameter entity %1"
#endif
);
const MessageType0 ParserMessages::piEntityReference(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
85
#ifndef SP_NO_MESSAGE_TEXT
,"a reference to a PI entity is allowed only in a context where a processing instruction could occur"
#endif
);
const MessageType0 ParserMessages::internalDataEntityReference(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
86
#ifndef SP_NO_MESSAGE_TEXT
,"a reference to a CDATA or SDATA entity is allowed only in a context where a data character could occur"
#endif
);
const MessageType0 ParserMessages::externalNonTextEntityReference(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
87
#ifndef SP_NO_MESSAGE_TEXT
,"a reference to a subdocument entity or external data entity is allowed only in a context where a data character could occur"
#endif
);
const MessageType0 ParserMessages::externalNonTextEntityRcdata(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
88
#ifndef SP_NO_MESSAGE_TEXT
,"a reference to a subdocument entity or external data entity is not allowed in replaceable character data"
#endif
);
const MessageType0 ParserMessages::entlvl(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
89
#ifndef SP_NO_MESSAGE_TEXT
,"the number of open entities cannot exceed ENTLVL"
#endif
);
const MessageType0 ParserMessages::piEntityRcdata(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
90
#ifndef SP_NO_MESSAGE_TEXT
,"a reference to a PI entity is not allowed in replaceable character data"
#endif
);
const MessageType1 ParserMessages::recursiveEntityReference(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
91
#ifndef SP_NO_MESSAGE_TEXT
,"entity %1 is already open"
#endif
);
const MessageType1 ParserMessages::undefinedShortrefMapInstance(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
92
#ifndef SP_NO_MESSAGE_TEXT
,"short reference map %1 not defined"
#endif
);
const MessageType0 ParserMessages::usemapAssociatedElementTypeDtd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
93
#ifndef SP_NO_MESSAGE_TEXT
,"short reference map in DTD must specify associated element type"
#endif
);
const MessageType0 ParserMessages::usemapAssociatedElementTypeInstance(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
94
#ifndef SP_NO_MESSAGE_TEXT
,"short reference map in document instance cannot specify associated element type"
#endif
);
const MessageType2 ParserMessages::undefinedShortrefMapDtd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
95
#ifndef SP_NO_MESSAGE_TEXT
,"short reference map %1 for element %2 not defined in DTD"
#endif
);
const MessageType1 ParserMessages::unknownShortrefDelim(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
96
#ifndef SP_NO_MESSAGE_TEXT
,"%1 is not a short reference delimiter"
#endif
);
const MessageType1 ParserMessages::delimDuplicateMap(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
97
#ifndef SP_NO_MESSAGE_TEXT
,"short reference delimiter %1 already mapped in this declaration"
#endif
);
const MessageType0 ParserMessages::noDocumentElement(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
98
#ifndef SP_NO_MESSAGE_TEXT
,"no document element"
#endif
);
const MessageType0 ParserMessages::processingInstructionEntityEnd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
99
#ifndef SP_NO_MESSAGE_TEXT
,"entity end not allowed in processing instruction"
#endif
);
const MessageType1 ParserMessages::processingInstructionLength(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
100
#ifndef SP_NO_MESSAGE_TEXT
,"length of processing instruction must not exceed PILEN (%1)"
#endif
);
const MessageType0 ParserMessages::processingInstructionClose(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
101
#ifndef SP_NO_MESSAGE_TEXT
,"missing pic delimiter"
#endif
);
const MessageType0 ParserMessages::attributeSpecNameTokenExpected(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
102
#ifndef SP_NO_MESSAGE_TEXT
,"an attribute specification must start with a name or name token"
#endif
);
const MessageType1 ParserMessages::noSuchAttributeToken(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
103
#ifndef SP_NO_MESSAGE_TEXT
,"%1 is not a member of a group specified for any attribute"
#endif
);
const MessageType0 ParserMessages::attributeNameShorttag(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
104
#ifndef SP_NO_MESSAGE_TEXT
,"the name and vi delimiter can be omitted from an attribute specification only if SHORTTAG YES is specified"
#endif
);
const MessageType1 ParserMessages::noSuchAttribute(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
105
#ifndef SP_NO_MESSAGE_TEXT
,"there is no attribute %1"
#endif
);
const MessageType0 ParserMessages::attributeValueExpected(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
106
#ifndef SP_NO_MESSAGE_TEXT
,"an attribute value specification must start with a literal or a name character"
#endif
);
const MessageType1 ParserMessages::nameTokenLength(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
107
#ifndef SP_NO_MESSAGE_TEXT
,"length of name token must not exceed NAMELEN (%1)"
#endif
);
const MessageType0 ParserMessages::attributeSpecLiteral(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
108
#ifndef SP_NO_MESSAGE_TEXT
,"an attribute value literal can occur in an attribute specification list only after a vi delimiter"
#endif
);
const MessageType1 ParserMessages::duplicateAttributeSpec(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
109
#ifndef SP_NO_MESSAGE_TEXT
,"duplicate specification of attribute %1"
#endif
);
const MessageType1 ParserMessages::duplicateAttributeDef(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
110
#ifndef SP_NO_MESSAGE_TEXT
,"duplicate definition of attribute %1"
#endif
);
const MessageType0 ParserMessages::emptyDataAttributeSpec(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
111
#ifndef SP_NO_MESSAGE_TEXT
,"data attribute specification must be omitted if attribute specification list is empty"
#endif
);
const MessageType0 ParserMessages::markedSectionEnd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
112
#ifndef SP_NO_MESSAGE_TEXT
,"marked section end not in marked section declaration"
#endif
);
const MessageType1 ParserMessages::markedSectionLevel(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
113
#ifndef SP_NO_MESSAGE_TEXT
,"number of open marked sections must not exceed TAGLVL (%1)"
#endif
);
const MessageType0L ParserMessages::unclosedMarkedSection(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
114
#ifndef SP_NO_MESSAGE_TEXT
,"missing marked section end"
,"marked section started here"
#endif
);
const MessageType0 ParserMessages::specialParseEntityEnd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
116
#ifndef SP_NO_MESSAGE_TEXT
,"entity end in character data, replaceable character data or ignored marked section"
#endif
);
const MessageType2 ParserMessages::normalizedAttributeValueLength(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
117
#ifndef SP_NO_MESSAGE_TEXT
,"normalized length of attribute value literal must not exceed LITLEN (%1); length was %2"
#endif
);
const MessageType0 ParserMessages::attributeValueSyntax(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
118
#ifndef SP_NO_MESSAGE_TEXT
,"syntax of attribute value does not conform to declared value"
#endif
);
const MessageType2 ParserMessages::attributeValueChar(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
119
#ifndef SP_NO_MESSAGE_TEXT
,"character %1 is not allowed in the value of attribute %2"
#endif
);
const MessageType1 ParserMessages::attributeValueMultiple(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
120
#ifndef SP_NO_MESSAGE_TEXT
,"value of attribute %1 must be a single token"
#endif
);
const MessageType2 ParserMessages::attributeValueNumberToken(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
121
#ifndef SP_NO_MESSAGE_TEXT
,"value of attribute %2 invalid: %1 cannot start a number token"
#endif
);
const MessageType2 ParserMessages::attributeValueName(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
122
#ifndef SP_NO_MESSAGE_TEXT
,"value of attribute %2 invalid: %1 cannot start a name"
#endif
);
const MessageType1 ParserMessages::attributeMissing(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
123
#ifndef SP_NO_MESSAGE_TEXT
,"non-impliable attribute %1 not specified but OMITTAG NO and SHORTTAG NO"
#endif
);
const MessageType1 ParserMessages::requiredAttributeMissing(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
124
#ifndef SP_NO_MESSAGE_TEXT
,"required attribute %1 not specified"
#endif
);
const MessageType1 ParserMessages::currentAttributeMissing(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
125
#ifndef SP_NO_MESSAGE_TEXT
,"first occurrence of current attribute %1 not specified"
#endif
);
const MessageType1 ParserMessages::invalidNotationAttribute(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
126
#ifndef SP_NO_MESSAGE_TEXT
,"%1 is not a notation name"
#endif
);
const MessageType1 ParserMessages::invalidEntityAttribute(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
127
#ifndef SP_NO_MESSAGE_TEXT
,"%1 is not a general entity name"
#endif
);
const MessageType3 ParserMessages::attributeValueNotInGroup(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
128
#ifndef SP_NO_MESSAGE_TEXT
,"value of attribute %2 cannot be %1; must be one of %3"
#endif
);
const MessageType1 ParserMessages::notDataOrSubdocEntity(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
129
#ifndef SP_NO_MESSAGE_TEXT
,"%1 is not a data or subdocument entity"
#endif
);
const MessageType3 ParserMessages::ambiguousModelInitial(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
130
#ifndef SP_NO_MESSAGE_TEXT
,"content model is ambiguous: when no tokens have been matched, both the %2 and %3 occurrences of %1 are possible"
#endif
);
const MessageType5 ParserMessages::ambiguousModel(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
131
#ifndef SP_NO_MESSAGE_TEXT
,"content model is ambiguous: when the current token is the %2 occurrence of %1, both the %4 and %5 occurrences of %3 are possible"
#endif
);
const MessageType5 ParserMessages::ambiguousModelSingleAnd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
132
#ifndef SP_NO_MESSAGE_TEXT
,"content model is ambiguous: when the current token is the %2 occurrence of %1 and the innermost containing and group has been matched, both the %4 and %5 occurrences of %3 are possible"
#endif
);
const MessageType6 ParserMessages::ambiguousModelMultipleAnd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
133
#ifndef SP_NO_MESSAGE_TEXT
,"content model is ambiguous: when the current token is the %2 occurrence of %1 and the innermost %3 containing and groups have been matched, both the %5 and %6 occurrences of %4 are possible"
#endif
);
const MessageType1L ParserMessages::commentDeclarationCharacter(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
134
#ifndef SP_NO_MESSAGE_TEXT
,"invalid comment declaration: found character %1 outside comment but inside comment declaration"
,"comment declaration started here"
#endif
);
const MessageType1 ParserMessages::nonSgmlCharacter(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
136
#ifndef SP_NO_MESSAGE_TEXT
,"non SGML character number %1"
#endif
);
const MessageType0 ParserMessages::dataMarkedSectionDeclSubset(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
137
#ifndef SP_NO_MESSAGE_TEXT
,"data or replaceable character data in declaration subset"
#endif
);
const MessageType1L ParserMessages::duplicateId(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
138
#ifndef SP_NO_MESSAGE_TEXT
,"ID %1 already defined"
,"ID %1 first defined here"
#endif
);
const MessageType1 ParserMessages::notFixedValue(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
140
#ifndef SP_NO_MESSAGE_TEXT
,"value of fixed attribute %1 not equal to default"
#endif
);
const MessageType1 ParserMessages::sdCommentSignificant(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
141
#ifndef SP_NO_MESSAGE_TEXT
,"character %1 is not significant in the reference concrete syntax and so cannot occur in a comment in the SGML declaration"
#endif
);
const MessageType1 ParserMessages::standardVersion(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
142
#ifndef SP_NO_MESSAGE_TEXT
,"minimum data of first minimum literal in SGML declaration must be \"ISO 8879:1986\" or \"ISO 8879:1986 (ENR)\" or \"ISO 8879:1986 (WWW)\" not %1"
#endif
);
const MessageType1 ParserMessages::namingBeforeLcnmstrt(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
143
#ifndef SP_NO_MESSAGE_TEXT
,"parameter before \"LCNMSTRT\" must be \"NAMING\" not %1"
#endif
);
const MessageType1 ParserMessages::sdEntityEnd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
144
#ifndef SP_NO_MESSAGE_TEXT
,"unexpected entity end in SGML declaration: only %1, S separators and comments allowed"
#endif
);
const MessageType2 ParserMessages::sdInvalidNameToken(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
145
#ifndef SP_NO_MESSAGE_TEXT
,"%1 invalid: only %2 and parameter separators allowed"
#endif
);
const MessageType1 ParserMessages::numberTooBig(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
146
#ifndef SP_NO_MESSAGE_TEXT
,"magnitude of %1 too big (length exceeds NAMELEN)"
#endif
);
const MessageType1 ParserMessages::sdLiteralSignificant(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
147
#ifndef SP_NO_MESSAGE_TEXT
,"character %1 is not significant in the reference concrete syntax and so cannot occur in a literal in the SGML declaration except as the replacement of a character reference"
#endif
);
const MessageType1 ParserMessages::syntaxCharacterNumber(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
148
#ifndef SP_NO_MESSAGE_TEXT
,"%1 is not a valid syntax reference character number"
#endif
);
const MessageType0 ParserMessages::sdParameterEntity(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
149
#ifndef SP_NO_MESSAGE_TEXT
,"a parameter entity reference cannot occur in an SGML declaration"
#endif
);
const MessageType2 ParserMessages::sdParamInvalidToken(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
150
#ifndef SP_NO_MESSAGE_TEXT
,"%1 invalid: only %2 and parameter separators are allowed"
#endif
);
const MessageType0 ParserMessages::giveUp(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
151
#ifndef SP_NO_MESSAGE_TEXT
,"cannot continue because of previous errors"
#endif
);
const MessageType1 ParserMessages::sdMissingCharacters(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
152
#ifndef SP_NO_MESSAGE_TEXT
,"SGML declaration cannot be parsed because the character set does not contain characters having the following numbers in ISO 646: %1"
#endif
);
const MessageType1 ParserMessages::missingMinimumChars(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
153
#ifndef SP_NO_MESSAGE_TEXT
,"the specified character set is invalid because it does not contain the minimum data characters having the following numbers in ISO 646: %1"
#endif
);
const MessageType1 ParserMessages::duplicateCharNumbers(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
154
#ifndef SP_NO_MESSAGE_TEXT
,"character numbers declared more than once: %1"
#endif
);
const MessageType1 ParserMessages::codeSetHoles(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
155
#ifndef SP_NO_MESSAGE_TEXT
,"character numbers should have been declared UNUSED: %1"
#endif
);
const MessageType1 ParserMessages::basesetCharsMissing(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
156
#ifndef SP_NO_MESSAGE_TEXT
,"character numbers missing in base set: %1"
#endif
);
const MessageType1 ParserMessages::documentCharMax(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
157
#ifndef SP_NO_MESSAGE_TEXT
,"characters in the document character set with numbers exceeding %1 not supported"
#endif
);
const MessageType1 ParserMessages::fpiMissingField(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
158
#ifndef SP_NO_MESSAGE_TEXT
,"invalid formal public identifier %1: missing //"
#endif
);
const MessageType1 ParserMessages::fpiMissingTextClassSpace(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
159
#ifndef SP_NO_MESSAGE_TEXT
,"invalid formal public identifier %1: no SPACE after public text class"
#endif
);
const MessageType1 ParserMessages::fpiInvalidTextClass(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
160
#ifndef SP_NO_MESSAGE_TEXT
,"invalid formal public identifier %1: invalid public text class"
#endif
);
const MessageType1 ParserMessages::fpiInvalidLanguage(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
161
#ifndef SP_NO_MESSAGE_TEXT
,"invalid formal public identifier %1: public text language must be a name containing only upper case letters"
#endif
);
const MessageType1 ParserMessages::fpiIllegalDisplayVersion(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
162
#ifndef SP_NO_MESSAGE_TEXT
,"invalid formal public identifer %1: public text display version not permitted with this text class"
#endif
);
const MessageType1 ParserMessages::fpiExtraField(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
163
#ifndef SP_NO_MESSAGE_TEXT
,"invalid formal public identifier %1: extra field"
#endif
);
const MessageType0 ParserMessages::notationIdentifierTextClass(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
164
#ifndef SP_NO_MESSAGE_TEXT
,"public text class of public identifier in notation identifier must be NOTATION"
#endif
);
const MessageType1 ParserMessages::unknownBaseset(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
165
#ifndef SP_NO_MESSAGE_TEXT
,"base character set %1 is unknown"
#endif
);
const MessageType2 ParserMessages::lexicalAmbiguity(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
166
#ifndef SP_NO_MESSAGE_TEXT
,"delimiter set is ambiguous: %1 and %2 can be recognized in the same mode"
#endif
);
const MessageType1 ParserMessages::missingSignificant(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
167
#ifndef SP_NO_MESSAGE_TEXT
,"characters with the following numbers in the syntax reference character set are significant in the concrete syntax but are not in the document character set: %1"
#endif
);
const MessageType1 ParserMessages::translateSyntaxCharDoc(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
168
#ifndef SP_NO_MESSAGE_TEXT
,"there is no unique character in the document character set corresponding to character number %1 in the syntax reference character set"
#endif
);
const MessageType1 ParserMessages::translateSyntaxCharInternal(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
169
#ifndef SP_NO_MESSAGE_TEXT
,"there is no unique character in the internal character set corresponding to character number %1 in the syntax reference character set"
#endif
);
const MessageType1 ParserMessages::missingSyntaxChar(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
170
#ifndef SP_NO_MESSAGE_TEXT
,"the character with number %1 in ISO 646 is significant but has no representation in the syntax reference character set"
#endif
);
const MessageType1 ParserMessages::unknownCapacitySet(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
171
#ifndef SP_NO_MESSAGE_TEXT
,"capacity set %1 is unknown"
#endif
);
const MessageType1 ParserMessages::duplicateCapacity(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
172
#ifndef SP_NO_MESSAGE_TEXT
,"capacity %1 already specified"
#endif
);
const MessageType1 ParserMessages::capacityExceedsTotalcap(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
173
#ifndef SP_NO_MESSAGE_TEXT
,"value of capacity %1 exceeds value of TOTALCAP"
#endif
);
const MessageType1 ParserMessages::unknownPublicSyntax(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
174
#ifndef SP_NO_MESSAGE_TEXT
,"syntax %1 is unknown"
#endif
);
const MessageType0 ParserMessages::nmstrtLength(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
175
#ifndef SP_NO_MESSAGE_TEXT
,"UCNMSTRT must have the same number of characters as LCNMSTRT"
#endif
);
const MessageType0 ParserMessages::nmcharLength(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
176
#ifndef SP_NO_MESSAGE_TEXT
,"UCNMCHAR must have the same number of characters as LCNMCHAR"
#endif
);
const MessageType1 ParserMessages::subdocLevel(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
177
#ifndef SP_NO_MESSAGE_TEXT
,"number of open subdocuments exceeds quantity specified for SUBDOC parameter in SGML declaration (%1)"
#endif
);
const MessageType1 ParserMessages::subdocEntity(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
178
#ifndef SP_NO_MESSAGE_TEXT
,"entity %1 declared SUBDOC, but SUBDOC NO specified in SGML declaration"
#endif
);
const MessageType0 ParserMessages::parameterEntityNotEnded(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
179
#ifndef SP_NO_MESSAGE_TEXT
,"a parameter entity referenced in a parameter separator must end in the same declaration"
#endif
);
const MessageType1 ParserMessages::missingId(
MessageType::idrefError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
180
#ifndef SP_NO_MESSAGE_TEXT
,"reference to non-existent ID %1"
#endif
);
const MessageType1 ParserMessages::dtdUndefinedElement(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
181
#ifndef SP_NO_MESSAGE_TEXT
,"generic identifier %1 used in DTD but not defined"
#endif
);
const MessageType1 ParserMessages::elementNotFinishedDocumentEnd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
182
#ifndef SP_NO_MESSAGE_TEXT
,"%1 not finished but document ended"
#endif
);
const MessageType0 ParserMessages::subdocGiveUp(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
183
#ifndef SP_NO_MESSAGE_TEXT
,"cannot continue with subdocument because of previous errors"
#endif
);
const MessageType0 ParserMessages::noDtd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
184
#ifndef SP_NO_MESSAGE_TEXT
,"no document type declaration; will parse without validation"
#endif
);
const MessageType0 ParserMessages::noDtdSubset(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
185
#ifndef SP_NO_MESSAGE_TEXT
,"no internal or external document type declaration subset; will parse without validation"
#endif
);
const MessageType0 ParserMessages::notSgml(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
186
#ifndef SP_NO_MESSAGE_TEXT
,"this is not an SGML document"
#endif
);
const MessageType1 ParserMessages::taglen(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
187
#ifndef SP_NO_MESSAGE_TEXT
,"length of start-tag before interpretation of literals must not exceed TAGLEN (%1)"
#endif
);
const MessageType0 ParserMessages::groupParameterEntityNotEnded(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
188
#ifndef SP_NO_MESSAGE_TEXT
,"a parameter entity referenced in a token separator must end in the same group"
#endif
);
const MessageType1 ParserMessages::invalidSgmlChar(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
189
#ifndef SP_NO_MESSAGE_TEXT
,"the following character numbers are shunned characters that are not significant and so should have been declared UNUSED: %1"
#endif
);
const MessageType1 ParserMessages::translateDocChar(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
190
#ifndef SP_NO_MESSAGE_TEXT
,"there is no unique character in the specified document character set corresponding to character number %1 in ISO 646"
#endif
);
const MessageType1 ParserMessages::attributeValueLengthNeg(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
191
#ifndef SP_NO_MESSAGE_TEXT
,"length of attribute value must not exceed LITLEN less NORMSEP (-%1)"
#endif
);
const MessageType1 ParserMessages::tokenizedAttributeValueLengthNeg(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
192
#ifndef SP_NO_MESSAGE_TEXT
,"length of tokenized attribute value must not exceed LITLEN less NORMSEP (-%1)"
#endif
);
const MessageType1 ParserMessages::scopeInstanceQuantity(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
193
#ifndef SP_NO_MESSAGE_TEXT
,"concrete syntax scope is INSTANCE but value of %1 quantity is less than value in reference quantity set"
#endif
);
const MessageType1 ParserMessages::basesetTextClass(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
194
#ifndef SP_NO_MESSAGE_TEXT
,"public text class of formal public identifier of base character set must be CHARSET"
#endif
);
const MessageType1 ParserMessages::capacityTextClass(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
195
#ifndef SP_NO_MESSAGE_TEXT
,"public text class of formal public identifier of capacity set must be CAPACITY"
#endif
);
const MessageType1 ParserMessages::syntaxTextClass(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
196
#ifndef SP_NO_MESSAGE_TEXT
,"public text class of formal public identifier of concrete syntax must be SYNTAX"
#endif
);
const MessageType0 ParserMessages::msocharRequiresMsichar(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
197
#ifndef SP_NO_MESSAGE_TEXT
,"when there is an MSOCHAR there must also be an MSICHAR"
#endif
);
const MessageType1 ParserMessages::switchNotMarkup(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
198
#ifndef SP_NO_MESSAGE_TEXT
,"character number %1 in the syntax reference character set was specified as a character to be switched but is not a markup character"
#endif
);
const MessageType1 ParserMessages::switchNotInCharset(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
199
#ifndef SP_NO_MESSAGE_TEXT
,"character number %1 was specified as a character to be switched but is not in the syntax reference character set"
#endif
);
const MessageType1 ParserMessages::ambiguousDocCharacter(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
200
#ifndef SP_NO_MESSAGE_TEXT
,"character numbers %1 in the document character set have been assigned the same meaning, but this is the meaning of a significant character"
#endif
);
const MessageType1 ParserMessages::oneFunction(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
201
#ifndef SP_NO_MESSAGE_TEXT
,"character number %1 assigned to more than one function"
#endif
);
const MessageType1 ParserMessages::duplicateFunctionName(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
202
#ifndef SP_NO_MESSAGE_TEXT
,"%1 is already a function name"
#endif
);
const MessageType1 ParserMessages::missingSignificant646(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
203
#ifndef SP_NO_MESSAGE_TEXT
,"characters with the following numbers in ISO 646 are significant in the concrete syntax but are not in the document character set: %1"
#endif
);
const MessageType1 ParserMessages::generalDelimAllFunction(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
204
#ifndef SP_NO_MESSAGE_TEXT
,"general delimiter %1 consists solely of function characters"
#endif
);
const MessageType1 ParserMessages::nmcharLetter(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
205
#ifndef SP_NO_MESSAGE_TEXT
,"letters assigned to LCNMCHAR, UCNMCHAR, LCNMSTRT or UCNMSTRT: %1"
#endif
);
const MessageType1 ParserMessages::nmcharDigit(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
206
#ifndef SP_NO_MESSAGE_TEXT
,"digits assigned to LCNMCHAR, UCNMCHAR, LCNMSTRT or UCNMSTRT: %1"
#endif
);
const MessageType1 ParserMessages::nmcharRe(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
207
#ifndef SP_NO_MESSAGE_TEXT
,"character number %1 cannot be assigned to LCNMCHAR, UCNMCHAR, LCNMSTRT or UCNMSTRT because it is RE"
#endif
);
const MessageType1 ParserMessages::nmcharRs(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
208
#ifndef SP_NO_MESSAGE_TEXT
,"character number %1 cannot be assigned to LCNMCHAR, UCNMCHAR, LCNMSTRT or UCNMSTRT because it is RS"
#endif
);
const MessageType1 ParserMessages::nmcharSpace(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
209
#ifndef SP_NO_MESSAGE_TEXT
,"character number %1 cannot be assigned to LCNMCHAR, UCNMCHAR, LCNMSTRT or UCNMSTRT because it is SPACE"
#endif
);
const MessageType1 ParserMessages::nmcharSepchar(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
210
#ifndef SP_NO_MESSAGE_TEXT
,"separator characters assigned to LCNMCHAR, UCNMCHAR, LCNMSTRT or UCNMSTRT: %1"
#endif
);
const MessageType1 ParserMessages::switchLetterDigit(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
211
#ifndef SP_NO_MESSAGE_TEXT
,"character number %1 cannot be switched because it is a Digit, LC Letter or UC Letter"
#endif
);
const MessageType0 ParserMessages::zeroNumberOfCharacters(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
212
#ifndef SP_NO_MESSAGE_TEXT
,"pointless for number of characters to be 0"
#endif
);
const MessageType1 ParserMessages::nameReferenceReservedName(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
213
#ifndef SP_NO_MESSAGE_TEXT
,"%1 cannot be the replacement for a reference reserved name because it is another reference reserved name"
#endif
);
const MessageType1 ParserMessages::ambiguousReservedName(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
214
#ifndef SP_NO_MESSAGE_TEXT
,"%1 cannot be the replacement for a reference reserved name because it is the replacement of another reference reserved name"
#endif
);
const MessageType1 ParserMessages::duplicateReservedName(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
215
#ifndef SP_NO_MESSAGE_TEXT
,"replacement for reserved name %1 already specified"
#endif
);
const MessageType1 ParserMessages::reservedNameSyntax(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
216
#ifndef SP_NO_MESSAGE_TEXT
,"%1 is not a valid name in the declared concrete syntax"
#endif
);
const MessageType1 ParserMessages::multipleBSequence(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
217
#ifndef SP_NO_MESSAGE_TEXT
,"%1 is not a valid short reference delimiter because it has more than one B sequence"
#endif
);
const MessageType1 ParserMessages::blankAdjacentBSequence(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
218
#ifndef SP_NO_MESSAGE_TEXT
,"%1 is not a valid short reference delimiter because it is adjacent to a character that can occur in a blank sequence"
#endif
);
const MessageType2 ParserMessages::delimiterLength(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
219
#ifndef SP_NO_MESSAGE_TEXT
,"length of delimiter %1 exceeds NAMELEN (%2)"
#endif
);
const MessageType2 ParserMessages::reservedNameLength(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
220
#ifndef SP_NO_MESSAGE_TEXT
,"length of reserved name %1 exceeds NAMELEN (%2)"
#endif
);
const MessageType1 ParserMessages::nmcharNmstrt(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
221
#ifndef SP_NO_MESSAGE_TEXT
,"character numbers assigned to both LCNMCHAR or UCNMCHAR and LCNMSTRT or UCNMSTRT: %1"
#endif
);
const MessageType0 ParserMessages::scopeInstanceSyntaxCharset(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
222
#ifndef SP_NO_MESSAGE_TEXT
,"when the concrete syntax scope is INSTANCE the syntax reference character set of the declared syntax must be the same as that of the reference concrete syntax"
#endif
);
const MessageType0 ParserMessages::emptyOmitEndTag(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
223
#ifndef SP_NO_MESSAGE_TEXT
,"end-tag minimization should be \"O\" for element with declared content of EMPTY"
#endif
);
const MessageType1 ParserMessages::conrefOmitEndTag(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
224
#ifndef SP_NO_MESSAGE_TEXT
,"end-tag minimization should be \"O\" for element %1 because it has CONREF attribute"
#endif
);
const MessageType1 ParserMessages::conrefEmpty(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
225
#ifndef SP_NO_MESSAGE_TEXT
,"element %1 has a declared content of EMPTY and a CONREF attribute"
#endif
);
const MessageType1 ParserMessages::notationEmpty(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
226
#ifndef SP_NO_MESSAGE_TEXT
,"element %1 has a declared content of EMPTY and a NOTATION attribute"
#endif
);
const MessageType0 ParserMessages::dataAttributeDeclaredValue(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
227
#ifndef SP_NO_MESSAGE_TEXT
,"declared value of data attribute cannot be ENTITY, ENTITIES, ID, IDREF, IDREFS or NOTATION"
#endif
);
const MessageType0 ParserMessages::dataAttributeDefaultValue(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
228
#ifndef SP_NO_MESSAGE_TEXT
,"default value of data attribute cannot be CONREF or CURRENT"
#endif
);
const MessageType2 ParserMessages::attcnt(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
229
#ifndef SP_NO_MESSAGE_TEXT
,"number of attribute names and name tokens (%1) exceeds ATTCNT (%2)"
#endif
);
const MessageType0 ParserMessages::idDeclaredValue(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
230
#ifndef SP_NO_MESSAGE_TEXT
,"if the declared value is ID the default value must be IMPLIED or REQUIRED"
#endif
);
const MessageType1 ParserMessages::multipleIdAttributes(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
231
#ifndef SP_NO_MESSAGE_TEXT
,"the attribute definition list already declared attribute %1 as the ID attribute"
#endif
);
const MessageType1 ParserMessages::multipleNotationAttributes(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
232
#ifndef SP_NO_MESSAGE_TEXT
,"the attribute definition list already declared attribute %1 as the NOTATION attribute"
#endif
);
const MessageType1 ParserMessages::duplicateAttributeToken(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
233
#ifndef SP_NO_MESSAGE_TEXT
,"token %1 occurs more than once in attribute definition list"
#endif
);
const MessageType1 ParserMessages::notationNoAttributes(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
234
#ifndef SP_NO_MESSAGE_TEXT
,"no attributes defined for notation %1"
#endif
);
const MessageType2 ParserMessages::entityNotationUndefined(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
235
#ifndef SP_NO_MESSAGE_TEXT
,"notation %1 for entity %2 undefined"
#endif
);
const MessageType2 ParserMessages::mapEntityUndefined(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
236
#ifndef SP_NO_MESSAGE_TEXT
,"entity %1 undefined in short reference map %2"
#endif
);
const MessageType1 ParserMessages::attlistNotationUndefined(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
237
#ifndef SP_NO_MESSAGE_TEXT
,"notation %1 is undefined but had attribute definition"
#endif
);
const MessageType1 ParserMessages::bracketedLitlen(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
238
#ifndef SP_NO_MESSAGE_TEXT
,"length of interpreted parameter literal in bracketed text plus the length of the bracketing delimiters must not exceed LITLEN (%1)"
#endif
);
const MessageType1 ParserMessages::genericIdentifierLength(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
239
#ifndef SP_NO_MESSAGE_TEXT
,"length of rank stem plus length of rank suffix must not exceed NAMELEN (%1)"
#endif
);
const MessageType0 ParserMessages::instanceStartOmittag(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
240
#ifndef SP_NO_MESSAGE_TEXT
,"document instance must start with document element"
#endif
);
const MessageType1 ParserMessages::grplvl(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
241
#ifndef SP_NO_MESSAGE_TEXT
,"content model nesting level exceeds GRPLVL (%1)"
#endif
);
const MessageType1 ParserMessages::grpgtcnt(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
242
#ifndef SP_NO_MESSAGE_TEXT
,"grand total of content tokens exceeds GRPGTCNT (%1)"
#endif
);
const MessageType0 ParserMessages::unclosedStartTagShorttag(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
243
#ifndef SP_NO_MESSAGE_TEXT
,"unclosed start-tag requires SHORTTAG YES"
#endif
);
const MessageType0 ParserMessages::netEnablingStartTagShorttag(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
244
#ifndef SP_NO_MESSAGE_TEXT
,"net-enabling start-tag requires SHORTTAG YES"
#endif
);
const MessageType0 ParserMessages::unclosedEndTagShorttag(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
245
#ifndef SP_NO_MESSAGE_TEXT
,"unclosed end-tag requires SHORTTAG YES"
#endif
);
const MessageType0 ParserMessages::multipleDtds(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
246
#ifndef SP_NO_MESSAGE_TEXT
,"DTDs other than base allowed only if CONCUR YES or EXPLICIT YES"
#endif
);
const MessageType0 ParserMessages::afterDocumentElementEntityEnd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
247
#ifndef SP_NO_MESSAGE_TEXT
,"end of entity other than document entity after document element"
#endif
);
const MessageType1 ParserMessages::declarationAfterDocumentElement(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
248
#ifndef SP_NO_MESSAGE_TEXT
,"%1 declaration illegal after document element"
#endif
);
const MessageType0 ParserMessages::characterReferenceAfterDocumentElement(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
249
#ifndef SP_NO_MESSAGE_TEXT
,"character reference illegal after document element"
#endif
);
const MessageType0 ParserMessages::entityReferenceAfterDocumentElement(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
250
#ifndef SP_NO_MESSAGE_TEXT
,"entity reference illegal after document element"
#endif
);
const MessageType0 ParserMessages::markedSectionAfterDocumentElement(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
251
#ifndef SP_NO_MESSAGE_TEXT
,"marked section illegal after document element"
#endif
);
const MessageType3 ParserMessages::requiredElementExcluded(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
252
#ifndef SP_NO_MESSAGE_TEXT
,"the %1 occurrence of %2 in the content model for %3 cannot be excluded at this point because it is contextually required"
#endif
);
const MessageType3 ParserMessages::invalidExclusion(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
253
#ifndef SP_NO_MESSAGE_TEXT
,"the %1 occurrence of %2 in the content model for %3 cannot be excluded because it is neither inherently optional nor a member of an or group"
#endif
);
const MessageType0 ParserMessages::attributeValueShorttag(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
254
#ifndef SP_NO_MESSAGE_TEXT
,"an attribute value specification must be an attribute value literal unless SHORTTAG YES is specified"
#endif
);
const MessageType0 ParserMessages::conrefNotation(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
255
#ifndef SP_NO_MESSAGE_TEXT
,"value cannot be specified both for notation attribute and content reference attribute"
#endif
);
const MessageType1 ParserMessages::duplicateNotationDeclaration(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
256
#ifndef SP_NO_MESSAGE_TEXT
,"notation %1 already defined"
#endif
);
const MessageType1L ParserMessages::duplicateShortrefDeclaration(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
257
#ifndef SP_NO_MESSAGE_TEXT
,"short reference map %1 already defined"
,"first defined here"
#endif
);
const MessageType1 ParserMessages::duplicateDelimGeneral(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
259
#ifndef SP_NO_MESSAGE_TEXT
,"general delimiter role %1 already defined"
#endif
);
const MessageType1 ParserMessages::idrefGrpcnt(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
260
#ifndef SP_NO_MESSAGE_TEXT
,"number of id references in start-tag must not exceed GRPCNT (%1)"
#endif
);
const MessageType1 ParserMessages::entityNameGrpcnt(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
261
#ifndef SP_NO_MESSAGE_TEXT
,"number of entity names in attribute specification list must not exceed GRPCNT (%1)"
#endif
);
const MessageType2 ParserMessages::attsplen(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
262
#ifndef SP_NO_MESSAGE_TEXT
,"normalized length of attribute specification list must not exceed ATTSPLEN (%1); length was %2"
#endif
);
const MessageType1 ParserMessages::duplicateDelimShortref(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
263
#ifndef SP_NO_MESSAGE_TEXT
,"short reference delimiter %1 already specified"
#endif
);
const MessageType1 ParserMessages::duplicateDelimShortrefSet(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
264
#ifndef SP_NO_MESSAGE_TEXT
,"single character short references were already specified for character numbers: %1"
#endif
);
const MessageType1 ParserMessages::defaultEntityInAttribute(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
265
#ifndef SP_NO_MESSAGE_TEXT
,"default entity used in entity attribute %1"
#endif
);
const MessageType1 ParserMessages::defaultEntityReference(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
266
#ifndef SP_NO_MESSAGE_TEXT
,"reference to entity %1 uses default entity "
#endif
);
const MessageType2 ParserMessages::mapDefaultEntity(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
267
#ifndef SP_NO_MESSAGE_TEXT
,"entity %1 in short reference map %2 uses default entity"
#endif
);
const MessageType1 ParserMessages::noSuchDtd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
268
#ifndef SP_NO_MESSAGE_TEXT
,"no DTD %1 declared"
#endif
);
const MessageType1 ParserMessages::noLpdSubset(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
269
#ifndef SP_NO_MESSAGE_TEXT
,"LPD %1 has neither internal nor external subset"
#endif
);
const MessageType0 ParserMessages::assocElementDifferentAtts(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
270
#ifndef SP_NO_MESSAGE_TEXT
,"element types have different link attribute definitions"
#endif
);
const MessageType1 ParserMessages::duplicateLinkSet(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
271
#ifndef SP_NO_MESSAGE_TEXT
,"link set %1 already defined"
#endif
);
const MessageType0 ParserMessages::emptyResultAttributeSpec(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
272
#ifndef SP_NO_MESSAGE_TEXT
,"empty result attribute specification"
#endif
);
const MessageType1 ParserMessages::noSuchSourceElement(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
273
#ifndef SP_NO_MESSAGE_TEXT
,"no source element type %1"
#endif
);
const MessageType1 ParserMessages::noSuchResultElement(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
274
#ifndef SP_NO_MESSAGE_TEXT
,"no result element type %1"
#endif
);
const MessageType0 ParserMessages::documentEndLpdSubset(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
275
#ifndef SP_NO_MESSAGE_TEXT
,"end of document in LPD subset"
#endif
);
const MessageType1 ParserMessages::lpdSubsetDeclaration(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
276
#ifndef SP_NO_MESSAGE_TEXT
,"%1 declaration not allowed in LPD subset"
#endif
);
const MessageType0 ParserMessages::idlinkDeclSimple(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
277
#ifndef SP_NO_MESSAGE_TEXT
,"ID link set declaration not allowed in simple link declaration subset"
#endif
);
const MessageType0 ParserMessages::linkDeclSimple(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
278
#ifndef SP_NO_MESSAGE_TEXT
,"link set declaration not allowed in simple link declaration subset"
#endif
);
const MessageType1 ParserMessages::simpleLinkAttlistElement(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
279
#ifndef SP_NO_MESSAGE_TEXT
,"attributes can only be defined for base document element (not %1) in simple link declaration subset"
#endif
);
const MessageType0 ParserMessages::shortrefOnlyInBaseDtd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
280
#ifndef SP_NO_MESSAGE_TEXT
,"a short reference mapping declaration is allowed only in the base DTD"
#endif
);
const MessageType0 ParserMessages::usemapOnlyInBaseDtd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
281
#ifndef SP_NO_MESSAGE_TEXT
,"a short reference use declaration is allowed only in the base DTD"
#endif
);
const MessageType0 ParserMessages::linkAttributeDefaultValue(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
282
#ifndef SP_NO_MESSAGE_TEXT
,"default value of link attribute cannot be CURRENT or CONREF"
#endif
);
const MessageType0 ParserMessages::linkAttributeDeclaredValue(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
283
#ifndef SP_NO_MESSAGE_TEXT
,"declared value of link attribute cannot be ID, IDREF, IDREFS or NOTATION"
#endif
);
const MessageType0 ParserMessages::simpleLinkFixedAttribute(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
284
#ifndef SP_NO_MESSAGE_TEXT
,"only fixed attributes can be defined in simple LPD"
#endif
);
const MessageType0 ParserMessages::duplicateIdLinkSet(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
285
#ifndef SP_NO_MESSAGE_TEXT
,"only one ID link set declaration allowed in an LPD subset"
#endif
);
const MessageType1 ParserMessages::noInitialLinkSet(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
286
#ifndef SP_NO_MESSAGE_TEXT
,"no initial link set defined for LPD %1"
#endif
);
const MessageType1 ParserMessages::notationUndefinedSourceDtd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
287
#ifndef SP_NO_MESSAGE_TEXT
,"notation %1 not defined in source DTD"
#endif
);
const MessageType0 ParserMessages::simpleLinkResultNotImplied(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
288
#ifndef SP_NO_MESSAGE_TEXT
,"result document type in simple link specification must be implied"
#endif
);
const MessageType0 ParserMessages::simpleLinkFeature(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
289
#ifndef SP_NO_MESSAGE_TEXT
,"simple link requires SIMPLE YES"
#endif
);
const MessageType0 ParserMessages::implicitLinkFeature(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
290
#ifndef SP_NO_MESSAGE_TEXT
,"implicit link requires IMPLICIT YES"
#endif
);
const MessageType0 ParserMessages::explicitLinkFeature(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
291
#ifndef SP_NO_MESSAGE_TEXT
,"explicit link requires EXPLICIT YES"
#endif
);
const MessageType0 ParserMessages::lpdBeforeBaseDtd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
292
#ifndef SP_NO_MESSAGE_TEXT
,"LPD not allowed before first DTD"
#endif
);
const MessageType0 ParserMessages::dtdAfterLpd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
293
#ifndef SP_NO_MESSAGE_TEXT
,"DTD not allowed after an LPD"
#endif
);
const MessageType1 ParserMessages::unstableLpdGeneralEntity(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
294
#ifndef SP_NO_MESSAGE_TEXT
,"definition of general entity %1 is unstable"
#endif
);
const MessageType1 ParserMessages::unstableLpdParameterEntity(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
295
#ifndef SP_NO_MESSAGE_TEXT
,"definition of parameter entity %1 is unstable"
#endif
);
const MessageType1 ParserMessages::multipleIdLinkRuleAttribute(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
296
#ifndef SP_NO_MESSAGE_TEXT
,"multiple link rules for ID %1 but not all have link attribute specifications"
#endif
);
const MessageType1 ParserMessages::multipleLinkRuleAttribute(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
297
#ifndef SP_NO_MESSAGE_TEXT
,"multiple link rules for element type %1 but not all have link attribute specifications"
#endif
);
const MessageType2 ParserMessages::uselinkBadLinkSet(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
298
#ifndef SP_NO_MESSAGE_TEXT
,"link type %1 does not have a link set %2"
#endif
);
const MessageType1 ParserMessages::uselinkSimpleLpd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
299
#ifndef SP_NO_MESSAGE_TEXT
,"link set use declaration for simple link process"
#endif
);
const MessageType1 ParserMessages::uselinkBadLinkType(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
300
#ifndef SP_NO_MESSAGE_TEXT
,"no link type %1"
#endif
);
const MessageType1 ParserMessages::duplicateDtdLpd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
301
#ifndef SP_NO_MESSAGE_TEXT
,"both document type and link type %1"
#endif
);
const MessageType1 ParserMessages::duplicateLpd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
302
#ifndef SP_NO_MESSAGE_TEXT
,"link type %1 already defined"
#endif
);
const MessageType1 ParserMessages::duplicateDtd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
303
#ifndef SP_NO_MESSAGE_TEXT
,"document type %1 already defined"
#endif
);
const MessageType1 ParserMessages::undefinedLinkSet(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
304
#ifndef SP_NO_MESSAGE_TEXT
,"link set %1 used in LPD but not defined"
#endif
);
const MessageType1 ParserMessages::duplicateImpliedResult(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
305
#ifndef SP_NO_MESSAGE_TEXT
,"#IMPLIED already linked to result element type %1"
#endif
);
const MessageType1 ParserMessages::simpleLinkCount(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
306
#ifndef SP_NO_MESSAGE_TEXT
,"number of active simple link processes exceeds quantity specified for SIMPLE parameter in SGML declaration (%1)"
#endif
);
const MessageType0 ParserMessages::duplicateExplicitChain(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
307
#ifndef SP_NO_MESSAGE_TEXT
,"only one chain of explicit link processes can be active"
#endif
);
const MessageType1 ParserMessages::explicit1RequiresSourceTypeBase(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
308
#ifndef SP_NO_MESSAGE_TEXT
,"source document type name for link type %1 must be base document type since EXPLICIT YES 1"
#endif
);
const MessageType0 ParserMessages::oneImplicitLink(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
309
#ifndef SP_NO_MESSAGE_TEXT
,"one one implicit link process can be active"
#endif
);
const MessageType1 ParserMessages::sorryLink(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
310
#ifndef SP_NO_MESSAGE_TEXT
,"sorry, link type %1 not activated: only one implicit or explicit link process can be active (with base document type as source document type)"
#endif
);
const MessageType0 ParserMessages::entityReferenceMissingName(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
311
#ifndef SP_NO_MESSAGE_TEXT
,"name missing after name group in entity reference"
#endif
);
const MessageType1 ParserMessages::explicitNoRequiresSourceTypeBase(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
312
#ifndef SP_NO_MESSAGE_TEXT
,"source document type name for link type %1 must be base document type since EXPLICIT NO"
#endif
);
const MessageType0 ParserMessages::linkActivateTooLate(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
313
#ifndef SP_NO_MESSAGE_TEXT
,"link process must be activated before base DTD"
#endif
);
const MessageType0 ParserMessages::pass2Ee(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
314
#ifndef SP_NO_MESSAGE_TEXT
,"unexpected entity end while starting second pass"
#endif
);
const MessageType2 ParserMessages::idlinkElementType(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
315
#ifndef SP_NO_MESSAGE_TEXT
,"type %1 of element with ID %2 not associated element type for applicable link rule in ID link set"
#endif
);
const MessageType0 ParserMessages::datatagNotImplemented(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
316
#ifndef SP_NO_MESSAGE_TEXT
,"DATATAG feature not implemented"
#endif
);
const MessageType0 ParserMessages::startTagMissingName(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
317
#ifndef SP_NO_MESSAGE_TEXT
,"generic identifier specification missing after document type specification in start-tag"
#endif
);
const MessageType0 ParserMessages::endTagMissingName(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
318
#ifndef SP_NO_MESSAGE_TEXT
,"generic identifier specification missing after document type specification in end-tag"
#endif
);
const MessageType0 ParserMessages::startTagGroupNet(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
319
#ifndef SP_NO_MESSAGE_TEXT
,"a net-enabling start-tag cannot include a document type specification"
#endif
);
const MessageType0 ParserMessages::documentElementUndefined(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
320
#ifndef SP_NO_MESSAGE_TEXT
,"DTD did not contain element declaration for document type name"
#endif
);
const MessageType0 ParserMessages::badDefaultSgmlDecl(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
321
#ifndef SP_NO_MESSAGE_TEXT
,"invalid default SGML declaration"
#endif
);
const MessageType1L ParserMessages::nonExistentEntityRef(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
322
#ifndef SP_NO_MESSAGE_TEXT
,"reference to entity %1 for which no system identifier could be generated"
,"entity was defined here"
#endif
);
const MessageType0 ParserMessages::pcdataUnreachable(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
324
#ifndef SP_NO_MESSAGE_TEXT
,"content model is mixed but does not allow #PCDATA everywhere"
#endif
);
const MessageType0 ParserMessages::sdRangeNotSingleChar(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
325
#ifndef SP_NO_MESSAGE_TEXT
,"start or end of range must specify a single character"
#endif
);
const MessageType0 ParserMessages::sdInvalidRange(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
326
#ifndef SP_NO_MESSAGE_TEXT
,"number of first character in range must not exceed number of second character in range"
#endif
);
const MessageType0 ParserMessages::sdEmptyDelimiter(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
327
#ifndef SP_NO_MESSAGE_TEXT
,"delimiter cannot be an empty string"
#endif
);
const MessageType0 ParserMessages::tooManyCharsMinimumLiteral(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
328
#ifndef SP_NO_MESSAGE_TEXT
,"too many characters assigned same meaning with minimum literal"
#endif
);
const MessageType1 ParserMessages::defaultedEntityDefined(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
329
#ifndef SP_NO_MESSAGE_TEXT
,"earlier reference to entity %1 used default entity"
#endif
);
const MessageType0 ParserMessages::emptyStartTag(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
330
#ifndef SP_NO_MESSAGE_TEXT
,"empty start-tag"
#endif
);
const MessageType0 ParserMessages::emptyEndTag(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
331
#ifndef SP_NO_MESSAGE_TEXT
,"empty end-tag"
#endif
);
const MessageType1 ParserMessages::unusedMap(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
332
#ifndef SP_NO_MESSAGE_TEXT
,"unused short reference map %1"
#endif
);
const MessageType1 ParserMessages::unusedParamEntity(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
333
#ifndef SP_NO_MESSAGE_TEXT
,"unused parameter entity %1"
#endif
);
const MessageType1 ParserMessages::cannotGenerateSystemIdPublic(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
334
#ifndef SP_NO_MESSAGE_TEXT
,"cannot generate system identifier for public text %1"
#endif
);
const MessageType1 ParserMessages::cannotGenerateSystemIdGeneral(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
335
#ifndef SP_NO_MESSAGE_TEXT
,"cannot generate system identifier for general entity %1"
#endif
);
const MessageType1 ParserMessages::cannotGenerateSystemIdParameter(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
336
#ifndef SP_NO_MESSAGE_TEXT
,"cannot generate system identifier for parameter entity %1"
#endif
);
const MessageType1 ParserMessages::cannotGenerateSystemIdDoctype(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
337
#ifndef SP_NO_MESSAGE_TEXT
,"cannot generate system identifier for document type %1"
#endif
);
const MessageType1 ParserMessages::cannotGenerateSystemIdLinktype(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
338
#ifndef SP_NO_MESSAGE_TEXT
,"cannot generate system identifier for link type %1"
#endif
);
const MessageType1 ParserMessages::cannotGenerateSystemIdNotation(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
339
#ifndef SP_NO_MESSAGE_TEXT
,"cannot generate system identifier for notation %1"
#endif
);
const MessageType1 ParserMessages::excludeIncludeSame(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
340
#ifndef SP_NO_MESSAGE_TEXT
,"element type %1 both included and excluded"
#endif
);
const MessageType1 ParserMessages::implyingDtd(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
341
#ifndef SP_NO_MESSAGE_TEXT
,"no document type declaration; implying %1"
#endif
);
const MessageType1 ParserMessages::afdrVersion(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
342
#ifndef SP_NO_MESSAGE_TEXT
,"minimum data of AFDR declaration must be \"ISO/IEC 10744:1997\" not %1"
#endif
);
const MessageType0 ParserMessages::missingAfdrDecl(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
343
#ifndef SP_NO_MESSAGE_TEXT
,"AFDR declaration required before use of AFDR extensions"
#endif
);
const MessageType0 ParserMessages::enrRequired(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
344
#ifndef SP_NO_MESSAGE_TEXT
,"ENR extensions were used but minimum literal was not \"ISO 8879:1986 (ENR)\" or \"ISO 8879:1986 (WWW)\""
#endif
);
const MessageType1 ParserMessages::numericCharRefLiteralNonSgml(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
345
#ifndef SP_NO_MESSAGE_TEXT
,"illegal numeric character reference to non-SGML character %1 in literal"
#endif
);
const MessageType2 ParserMessages::numericCharRefUnknownDesc(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
346
#ifndef SP_NO_MESSAGE_TEXT
,"cannot convert character reference to number %1 because description %2 unrecognized"
#endif
);
const MessageType3 ParserMessages::numericCharRefUnknownBase(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
347
#ifndef SP_NO_MESSAGE_TEXT
,"cannot convert character reference to number %1 because character %2 from baseset %3 unknown"
#endif
);
const MessageType1 ParserMessages::numericCharRefBadInternal(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
348
#ifndef SP_NO_MESSAGE_TEXT
,"character reference to number %1 cannot be converted because of problem with internal character set"
#endif
);
const MessageType1 ParserMessages::numericCharRefNoInternal(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
349
#ifndef SP_NO_MESSAGE_TEXT
,"cannot convert character reference to number %1 because character not in internal character set"
#endif
);
const MessageType0 ParserMessages::wwwRequired(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
350
#ifndef SP_NO_MESSAGE_TEXT
,"Web SGML adaptations were used but minimum literal was not \"ISO 8879:1986 (WWW)\""
#endif
);
const MessageType1 ParserMessages::attributeTokenNotUnique(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
351
#ifndef SP_NO_MESSAGE_TEXT
,"token %1 can be value for more multiple attributes so attribute name required"
#endif
);
const MessageType1 ParserMessages::hexNumberLength(
MessageType::quantityError,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
352
#ifndef SP_NO_MESSAGE_TEXT
,"length of hex number must not exceed NAMELEN (%1)"
#endif
);
const MessageType1 ParserMessages::entityNameSyntax(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
353
#ifndef SP_NO_MESSAGE_TEXT
,"%1 is not a valid name in the declared concrete syntax"
#endif
);
const MessageType0 ParserMessages::cdataContent(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
354
#ifndef SP_NO_MESSAGE_TEXT
,"CDATA declared content"
#endif
);
const MessageType0 ParserMessages::rcdataContent(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
355
#ifndef SP_NO_MESSAGE_TEXT
,"RCDATA declared content"
#endif
);
const MessageType0 ParserMessages::inclusion(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
356
#ifndef SP_NO_MESSAGE_TEXT
,"inclusion"
#endif
);
const MessageType0 ParserMessages::exclusion(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
357
#ifndef SP_NO_MESSAGE_TEXT
,"exclusion"
#endif
);
const MessageType0 ParserMessages::numberDeclaredValue(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
358
#ifndef SP_NO_MESSAGE_TEXT
,"NUMBER or NUMBERS declared value"
#endif
);
const MessageType0 ParserMessages::nameDeclaredValue(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
359
#ifndef SP_NO_MESSAGE_TEXT
,"NAME or NAMES declared value"
#endif
);
const MessageType0 ParserMessages::nutokenDeclaredValue(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
360
#ifndef SP_NO_MESSAGE_TEXT
,"NUTOKEN or NUTOKENS declared value"
#endif
);
const MessageType0 ParserMessages::conrefAttribute(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
361
#ifndef SP_NO_MESSAGE_TEXT
,"conref attribute"
#endif
);
const MessageType0 ParserMessages::currentAttribute(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
362
#ifndef SP_NO_MESSAGE_TEXT
,"current attribute"
#endif
);
const MessageType0 ParserMessages::tempMarkedSection(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
363
#ifndef SP_NO_MESSAGE_TEXT
,"TEMP marked section"
#endif
);
const MessageType0 ParserMessages::instanceIncludeMarkedSection(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
364
#ifndef SP_NO_MESSAGE_TEXT
,"included marked section in the instance"
#endif
);
const MessageType0 ParserMessages::instanceIgnoreMarkedSection(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
365
#ifndef SP_NO_MESSAGE_TEXT
,"ignored marked section in the instance"
#endif
);
const MessageType0 ParserMessages::rcdataMarkedSection(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
366
#ifndef SP_NO_MESSAGE_TEXT
,"RCDATA marked section"
#endif
);
const MessageType0 ParserMessages::piEntity(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
367
#ifndef SP_NO_MESSAGE_TEXT
,"processing instruction entity"
#endif
);
const MessageType0 ParserMessages::bracketEntity(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
368
#ifndef SP_NO_MESSAGE_TEXT
,"bracketed text entity"
#endif
);
const MessageType0 ParserMessages::internalCdataEntity(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
369
#ifndef SP_NO_MESSAGE_TEXT
,"internal CDATA entity"
#endif
);
const MessageType0 ParserMessages::internalSdataEntity(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
370
#ifndef SP_NO_MESSAGE_TEXT
,"internal SDATA entity"
#endif
);
const MessageType0 ParserMessages::externalCdataEntity(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
371
#ifndef SP_NO_MESSAGE_TEXT
,"external CDATA entity"
#endif
);
const MessageType0 ParserMessages::externalSdataEntity(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
372
#ifndef SP_NO_MESSAGE_TEXT
,"external SDATA entity"
#endif
);
const MessageType0 ParserMessages::dataAttributes(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
373
#ifndef SP_NO_MESSAGE_TEXT
,"attribute definition list declaration for notation"
#endif
);
const MessageType0 ParserMessages::rank(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
374
#ifndef SP_NO_MESSAGE_TEXT
,"rank stem"
#endif
);
const MessageType0 ParserMessages::missingSystemId(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
375
#ifndef SP_NO_MESSAGE_TEXT
,"no system id specified"
#endif
);
const MessageType0 ParserMessages::psComment(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
376
#ifndef SP_NO_MESSAGE_TEXT
,"comment in parameter separator"
#endif
);
const MessageType0 ParserMessages::namedCharRef(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
377
#ifndef SP_NO_MESSAGE_TEXT
,"named character reference"
#endif
);
const MessageType0 ParserMessages::andGroup(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
378
#ifndef SP_NO_MESSAGE_TEXT
,"and group"
#endif
);
const MessageType0 ParserMessages::attributeValueNotLiteral(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
379
#ifndef SP_NO_MESSAGE_TEXT
,"attribute value not a literal"
#endif
);
const MessageType0 ParserMessages::missingAttributeName(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
380
#ifndef SP_NO_MESSAGE_TEXT
,"attribute name missing"
#endif
);
const MessageType0 ParserMessages::elementGroupDecl(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
381
#ifndef SP_NO_MESSAGE_TEXT
,"element declaration for group of element types"
#endif
);
const MessageType0 ParserMessages::attlistGroupDecl(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
382
#ifndef SP_NO_MESSAGE_TEXT
,"attribute definition list declaration for group of element types"
#endif
);
const MessageType0 ParserMessages::emptyCommentDecl(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
383
#ifndef SP_NO_MESSAGE_TEXT
,"empty comment declaration"
#endif
);
const MessageType0 ParserMessages::commentDeclS(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
384
#ifndef SP_NO_MESSAGE_TEXT
,"s separator in comment declaration"
#endif
);
const MessageType0 ParserMessages::commentDeclMultiple(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
385
#ifndef SP_NO_MESSAGE_TEXT
,"multiple comments in comment declaration"
#endif
);
const MessageType0 ParserMessages::missingStatusKeyword(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
386
#ifndef SP_NO_MESSAGE_TEXT
,"no status keyword"
#endif
);
const MessageType0 ParserMessages::multipleStatusKeyword(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
387
#ifndef SP_NO_MESSAGE_TEXT
,"multiple status keywords"
#endif
);
const MessageType0 ParserMessages::instanceParamEntityRef(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
388
#ifndef SP_NO_MESSAGE_TEXT
,"parameter entity reference in document instance"
#endif
);
const MessageType0 ParserMessages::current(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
389
#ifndef SP_NO_MESSAGE_TEXT
,"current attribute"
#endif
);
const MessageType0 ParserMessages::minimizationParam(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
390
#ifndef SP_NO_MESSAGE_TEXT
,"element type minimization parameter"
#endif
);
const MessageType0 ParserMessages::refc(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
391
#ifndef SP_NO_MESSAGE_TEXT
,"reference not terminated by refc delimiter"
#endif
);
const MessageType0 ParserMessages::pcdataNotFirstInGroup(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
392
#ifndef SP_NO_MESSAGE_TEXT
,"#PCDATA not first in model group"
#endif
);
const MessageType0 ParserMessages::pcdataInSeqGroup(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
393
#ifndef SP_NO_MESSAGE_TEXT
,"#PCDATA in seq group"
#endif
);
const MessageType0 ParserMessages::pcdataInNestedModelGroup(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
394
#ifndef SP_NO_MESSAGE_TEXT
,"#PCDATA in nested model group"
#endif
);
const MessageType0 ParserMessages::pcdataGroupNotRep(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
395
#ifndef SP_NO_MESSAGE_TEXT
,"#PCDATA in model group that does not have rep occurrence indicator"
#endif
);
const MessageType0 ParserMessages::nameGroupNotOr(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
396
#ifndef SP_NO_MESSAGE_TEXT
,"name group or name token group used connector other than OR"
#endif
);
const MessageType0 ParserMessages::piMissingName(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
397
#ifndef SP_NO_MESSAGE_TEXT
,"processing instruction does not start with name"
#endif
);
const MessageType0 ParserMessages::instanceStatusKeywordSpecS(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
398
#ifndef SP_NO_MESSAGE_TEXT
,"s separator in status keyword specification in document instance"
#endif
);
const MessageType0 ParserMessages::externalDataEntityRef(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
399
#ifndef SP_NO_MESSAGE_TEXT
,"reference to external data entity"
#endif
);
const MessageType0 ParserMessages::attributeValueExternalEntityRef(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
400
#ifndef SP_NO_MESSAGE_TEXT
,"reference to external entity in attribute value"
#endif
);
const MessageType1 ParserMessages::dataCharDelim(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
401
#ifndef SP_NO_MESSAGE_TEXT
,"character %1 is the first character of a delimiter but occurred as data"
#endif
);
const MessageType0 ParserMessages::explicitSgmlDecl(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
402
#ifndef SP_NO_MESSAGE_TEXT
,"SGML declaration was not implied"
#endif
);
const MessageType0 ParserMessages::internalSubsetMarkedSection(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
403
#ifndef SP_NO_MESSAGE_TEXT
,"marked section in internal DTD subset"
#endif
);
const MessageType0 ParserMessages::nestcWithoutNet(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
404
#ifndef SP_NO_MESSAGE_TEXT
,"net-enabling start-tag not immediately followed by null end-tag"
#endif
);
const MessageType0 ParserMessages::contentAsyncEntityRef(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
405
#ifndef SP_NO_MESSAGE_TEXT
,"entity end in different element from entity reference"
#endif
);
const MessageType0 ParserMessages::immednetRequiresEmptynrm(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
406
#ifndef SP_NO_MESSAGE_TEXT
,"NETENABL IMMEDNET requires EMPTYNRM YES"
#endif
);
const MessageType0 ParserMessages::nonSgmlCharRef(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
407
#ifndef SP_NO_MESSAGE_TEXT
,"reference to non-SGML character"
#endif
);
const MessageType0 ParserMessages::defaultEntityDecl(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
408
#ifndef SP_NO_MESSAGE_TEXT
,"declaration of default entity"
#endif
);
const MessageType0 ParserMessages::internalSubsetPsParamEntityRef(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
409
#ifndef SP_NO_MESSAGE_TEXT
,"reference to parameter entity in parameter separator in internal subset"
#endif
);
const MessageType0 ParserMessages::internalSubsetTsParamEntityRef(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
410
#ifndef SP_NO_MESSAGE_TEXT
,"reference to parameter entity in token separator in internal subset"
#endif
);
const MessageType0 ParserMessages::internalSubsetLiteralParamEntityRef(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
411
#ifndef SP_NO_MESSAGE_TEXT
,"reference to parameter entity in parameter literal in internal subset"
#endif
);
const MessageType0 ParserMessages::cannotGenerateSystemIdSgml(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
412
#ifndef SP_NO_MESSAGE_TEXT
,"cannot generate system identifier for SGML declaration reference"
#endif
);
const MessageType1 ParserMessages::sdTextClass(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
413
#ifndef SP_NO_MESSAGE_TEXT
,"public text class of formal public identifier of SGML declaration must be SD"
#endif
);
const MessageType0 ParserMessages::sgmlDeclRefRequiresWww(
MessageType::error,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
414
#ifndef SP_NO_MESSAGE_TEXT
,"SGML declaration reference was used but minimum literal was not \"ISO 8879:1986 (WWW)\""
#endif
);
const MessageType0 ParserMessages::pcdataGroupMemberOccurrenceIndicator(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
415
#ifndef SP_NO_MESSAGE_TEXT
,"member of model group containing #PCDATA has occurrence indicator"
#endif
);
const MessageType0 ParserMessages::pcdataGroupMemberModelGroup(
MessageType::warning,
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
416
#ifndef SP_NO_MESSAGE_TEXT
,"member of model group containing #PCDATA is a model group"
#endif
);
const MessageFragment ParserMessages::delimStart(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1000
#ifndef SP_NO_MESSAGE_TEXT
,"delimiter "
#endif
);
const MessageFragment ParserMessages::delimEnd(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1001
#ifndef SP_NO_MESSAGE_TEXT
,""
#endif
);
const MessageFragment ParserMessages::digit(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1002
#ifndef SP_NO_MESSAGE_TEXT
,"digit"
#endif
);
const MessageFragment ParserMessages::nameStartCharacter(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1003
#ifndef SP_NO_MESSAGE_TEXT
,"name start character"
#endif
);
const MessageFragment ParserMessages::sepchar(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1004
#ifndef SP_NO_MESSAGE_TEXT
,"sepchar"
#endif
);
const MessageFragment ParserMessages::separator(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1005
#ifndef SP_NO_MESSAGE_TEXT
,"separator"
#endif
);
const MessageFragment ParserMessages::nameCharacter(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1006
#ifndef SP_NO_MESSAGE_TEXT
,"name character"
#endif
);
const MessageFragment ParserMessages::dataCharacter(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1007
#ifndef SP_NO_MESSAGE_TEXT
,"data character"
#endif
);
const MessageFragment ParserMessages::minimumDataCharacter(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1008
#ifndef SP_NO_MESSAGE_TEXT
,"minimum data character"
#endif
);
const MessageFragment ParserMessages::significantCharacter(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1009
#ifndef SP_NO_MESSAGE_TEXT
,"significant character"
#endif
);
const MessageFragment ParserMessages::recordEnd(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1010
#ifndef SP_NO_MESSAGE_TEXT
,"record end character"
#endif
);
const MessageFragment ParserMessages::recordStart(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1011
#ifndef SP_NO_MESSAGE_TEXT
,"record start character"
#endif
);
const MessageFragment ParserMessages::space(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1012
#ifndef SP_NO_MESSAGE_TEXT
,"space character"
#endif
);
const MessageFragment ParserMessages::listSep(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1013
#ifndef SP_NO_MESSAGE_TEXT
,", "
#endif
);
const MessageFragment ParserMessages::rangeSep(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1014
#ifndef SP_NO_MESSAGE_TEXT
,"-"
#endif
);
const MessageFragment ParserMessages::parameterLiteral(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1015
#ifndef SP_NO_MESSAGE_TEXT
,"parameter literal"
#endif
);
const MessageFragment ParserMessages::dataTagGroup(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1016
#ifndef SP_NO_MESSAGE_TEXT
,"data tag group"
#endif
);
const MessageFragment ParserMessages::modelGroup(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1017
#ifndef SP_NO_MESSAGE_TEXT
,"model group"
#endif
);
const MessageFragment ParserMessages::dataTagTemplateGroup(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1018
#ifndef SP_NO_MESSAGE_TEXT
,"data tag template group"
#endif
);
const MessageFragment ParserMessages::name(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1019
#ifndef SP_NO_MESSAGE_TEXT
,"name"
#endif
);
const MessageFragment ParserMessages::nameToken(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1020
#ifndef SP_NO_MESSAGE_TEXT
,"name token"
#endif
);
const MessageFragment ParserMessages::elementToken(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1021
#ifndef SP_NO_MESSAGE_TEXT
,"element token"
#endif
);
const MessageFragment ParserMessages::inclusions(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1022
#ifndef SP_NO_MESSAGE_TEXT
,"inclusions"
#endif
);
const MessageFragment ParserMessages::exclusions(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1023
#ifndef SP_NO_MESSAGE_TEXT
,"exclusions"
#endif
);
const MessageFragment ParserMessages::minimumLiteral(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1024
#ifndef SP_NO_MESSAGE_TEXT
,"minimum literal"
#endif
);
const MessageFragment ParserMessages::attributeValueLiteral(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1025
#ifndef SP_NO_MESSAGE_TEXT
,"attribute value literal"
#endif
);
const MessageFragment ParserMessages::systemIdentifier(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1026
#ifndef SP_NO_MESSAGE_TEXT
,"system identifier"
#endif
);
const MessageFragment ParserMessages::number(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1027
#ifndef SP_NO_MESSAGE_TEXT
,"number"
#endif
);
const MessageFragment ParserMessages::attributeValue(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1028
#ifndef SP_NO_MESSAGE_TEXT
,"attribute value"
#endif
);
const MessageFragment ParserMessages::capacityName(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1029
#ifndef SP_NO_MESSAGE_TEXT
,"name of capacity"
#endif
);
const MessageFragment ParserMessages::generalDelimiteRoleName(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1030
#ifndef SP_NO_MESSAGE_TEXT
,"name of general delimiter role"
#endif
);
const MessageFragment ParserMessages::referenceReservedName(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1031
#ifndef SP_NO_MESSAGE_TEXT
,"reference reserved name"
#endif
);
const MessageFragment ParserMessages::quantityName(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1032
#ifndef SP_NO_MESSAGE_TEXT
,"name of quantity"
#endif
);
const MessageFragment ParserMessages::entityEnd(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1033
#ifndef SP_NO_MESSAGE_TEXT
,"entity end"
#endif
);
const MessageFragment ParserMessages::shortrefDelim(
#ifdef BUILD_LIBSP
MessageFragment::libModule,
#else
MessageFragment::appModule,
#endif
1034
#ifndef SP_NO_MESSAGE_TEXT
,"short reference delimiter"
#endif
);
#ifdef SP_NAMESPACE
}
#endif
