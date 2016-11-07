FICL_TOKEN(ficlInstructionInvalid, "** invalid **")
FICL_TOKEN(ficlInstruction1, "1")
FICL_TOKEN(ficlInstruction2, "2")
FICL_TOKEN(ficlInstruction3, "3")
FICL_TOKEN(ficlInstruction4, "4")
FICL_TOKEN(ficlInstruction5, "5")
FICL_TOKEN(ficlInstruction6, "6")
FICL_TOKEN(ficlInstruction7, "7")
FICL_TOKEN(ficlInstruction8, "8")
FICL_TOKEN(ficlInstruction9, "9")
FICL_TOKEN(ficlInstruction10, "10")
FICL_TOKEN(ficlInstruction11, "11")
FICL_TOKEN(ficlInstruction12, "12")
FICL_TOKEN(ficlInstruction13, "13")
FICL_TOKEN(ficlInstruction14, "14")
FICL_TOKEN(ficlInstruction15, "15")
FICL_TOKEN(ficlInstruction16, "16")
FICL_TOKEN(ficlInstruction0, "0")
FICL_TOKEN(ficlInstructionNeg1, "-1")
FICL_TOKEN(ficlInstructionNeg2, "-2")
FICL_TOKEN(ficlInstructionNeg3, "-3")
FICL_TOKEN(ficlInstructionNeg4, "-4")
FICL_TOKEN(ficlInstructionNeg5, "-5")
FICL_TOKEN(ficlInstructionNeg6, "-6")
FICL_TOKEN(ficlInstructionNeg7, "-7")
FICL_TOKEN(ficlInstructionNeg8, "-8")
FICL_TOKEN(ficlInstructionNeg9, "-9")
FICL_TOKEN(ficlInstructionNeg10, "-10")
FICL_TOKEN(ficlInstructionNeg11, "-11")
FICL_TOKEN(ficlInstructionNeg12, "-12")
FICL_TOKEN(ficlInstructionNeg13, "-13")
FICL_TOKEN(ficlInstructionNeg14, "-14")
FICL_TOKEN(ficlInstructionNeg15, "-15")
FICL_TOKEN(ficlInstructionNeg16, "-16")
#if FICL_WANT_FLOAT
FICL_TOKEN(ficlInstructionF0, "0.0e")
FICL_TOKEN(ficlInstructionF1, "1.0e")
FICL_TOKEN(ficlInstructionFNeg1, "-1.0e")
#endif /* FICL_WANT_FLOAT */
FICL_INSTRUCTION_TOKEN(ficlInstructionPlus, "+", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionMinus, "-", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstruction1Plus, "1+", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstruction1Minus, "1-", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstruction2Plus, "2+", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstruction2Minus, "2-", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionSemiParen, "(;)", FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionExitParen, "(exit)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionDup, "dup", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionSwap, "swap", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionGreaterThan, ">", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionBranchParenWithCheck, "(branch)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionBranchParen, "(branch-final)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionBranch0ParenWithCheck, "(branch0)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionBranch0Paren, "(branch0-final)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionLiteralParen, "(literal)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionLoopParen, "(loop)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionOfParen, "(of)", FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionPlusLoopParen, "(+loop)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionFetch, "@", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionStore, "!", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionComma, ",", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionCComma, "c,", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionCells, "cells", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionCellPlus, "cell+", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionNegate, "negate", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionStar, "*", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionSlash, "/", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionStarSlash, "*/", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionSlashMod, "/mod", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionStarSlashMod, "*/mod", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstruction2Star, "2*", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstruction2Slash, "2/", FICL_WORD_DEFAULT)

FICL_INSTRUCTION_TOKEN(ficlInstructionColonParen, "** (colon) **",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionVariableParen, "(variable)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionConstantParen, "(constant)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstruction2ConstantParen, "(2constant)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstruction2LiteralParen, "(2literal)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionDoDoes, "** do-does **",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionDoParen, "(do)", FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionDoesParen, "(does)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionQDoParen, "(?do)", FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionCreateParen, "(create)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionStringLiteralParen, "(.\")",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionCStringLiteralParen, "(c\")",
    FICL_WORD_COMPILE_ONLY)

FICL_INSTRUCTION_TOKEN(ficlInstructionPlusStore, "+!", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstruction0Less, "0<", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstruction0Greater, "0>", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstruction0Equals, "0=", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstruction2Store, "2!", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstruction2Fetch, "2@", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionOver, "over", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionRot, "rot", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstruction2Drop, "2drop", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstruction2Dup, "2dup", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstruction2Over, "2over", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstruction2Swap, "2swap", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFromRStack, "r>", FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionFetchRStack, "r@", FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstruction2ToR, "2>r", FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstruction2RFrom, "2r>", FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstruction2RFetch, "2r@", FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionLess, "<", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionEquals, "=", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionToRStack, ">r", FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionQuestionDup, "?dup", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionAnd, "and", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionCStore, "c!", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionCFetch, "c@", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionDrop, "drop", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionPick, "pick", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionRoll, "roll", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionMinusRoll, "-roll", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionMinusRot, "-rot", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFill, "fill", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionSToD, "s>d", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionULess, "u<", FICL_WORD_DEFAULT)

FICL_INSTRUCTION_TOKEN(ficlInstructionQuadFetch, "q@", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionQuadStore, "q!", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionWFetch, "w@", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionWStore, "w!", FICL_WORD_DEFAULT)

FICL_INSTRUCTION_TOKEN(ficlInstructionInvert, "invert", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionLShift, "lshift", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionMax, "max", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionMin, "min", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionMove, "move", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionOr, "or", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionRShift, "rshift", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionXor, "xor", FICL_WORD_DEFAULT)

FICL_INSTRUCTION_TOKEN(ficlInstructionI, "i", FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionJ, "j", FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionK, "k", FICL_WORD_COMPILE_ONLY)

FICL_INSTRUCTION_TOKEN(ficlInstructionCompare, "compare", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionCompareInsensitive, "compare-insensitive",
    FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionRandom, "random", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionSeedRandom, "seed-random",
    FICL_WORD_DEFAULT)

FICL_INSTRUCTION_TOKEN(ficlInstructionLeave, "leave", FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionUnloop, "unloop", FICL_WORD_COMPILE_ONLY)

#if FICL_WANT_USER
FICL_INSTRUCTION_TOKEN(ficlInstructionUserParen, "(user)", FICL_WORD_DEFAULT)
#endif /* FICL_WANT_USER */

#if FICL_WANT_LOCALS
FICL_INSTRUCTION_TOKEN(ficlInstructionLinkParen, "(link)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionUnlinkParen, "(unlink)",
    FICL_WORD_COMPILE_ONLY)

FICL_INSTRUCTION_TOKEN(ficlInstructionGetLocalParen, "(@local)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionGet2LocalParen, "(@2Local)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionToLocalParen, "(toLocal)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionTo2LocalParen, "(to2Local)",
    FICL_WORD_COMPILE_ONLY)

FICL_INSTRUCTION_TOKEN(ficlInstructionGetLocal0, "(@local0)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionGet2Local0, "(@2Local0)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionToLocal0, "(toLocal0)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionTo2Local0, "(To2Local0)",
    FICL_WORD_COMPILE_ONLY)

FICL_INSTRUCTION_TOKEN(ficlInstructionGetLocal1, "(@local1)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionToLocal1, "(toLocal1)",
    FICL_WORD_COMPILE_ONLY)

#if FICL_WANT_FLOAT
FICL_INSTRUCTION_TOKEN(ficlInstructionGetFLocalParen, "(@fLocal)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionGetF2LocalParen, "(@f2Local)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionToFLocalParen, "(toFLocal)",
    FICL_WORD_COMPILE_ONLY)
FICL_INSTRUCTION_TOKEN(ficlInstructionToF2LocalParen, "(toF2Local)",
    FICL_WORD_COMPILE_ONLY)
#endif /* FICL_WANT_FLOAT */

#endif /* FICL_WANT_LOCALS */

#if FICL_WANT_FLOAT
FICL_INSTRUCTION_TOKEN(ficlInstructionFLiteralParen, "(fliteral)",
    FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFConstantParen, "(fconstant)",
    FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionF2ConstantParen, "(f2constant)",
    FICL_WORD_DEFAULT)

FICL_INSTRUCTION_TOKEN(ficlInstructionFPlus, "f+", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFMinus, "f-", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFStar, "f*", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFSlash, "f/", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFNegate, "fnegate", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFPlusI, "f+i", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFMinusI, "f-i", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFStarI, "f*i", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFSlashI, "f/i", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionIMinusF, "i-f", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionISlashF, "i/f", FICL_WORD_DEFAULT)

FICL_INSTRUCTION_TOKEN(ficlInstructionFFrom, "float>", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionToF, ">float", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionIntToFloat, "int>float",
    FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFloatToInt, "float>int",
    FICL_WORD_DEFAULT)

FICL_INSTRUCTION_TOKEN(ficlInstructionFFetch, "f@", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFStore, "f!", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionF2Fetch, "f2@", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionF2Store, "f2!", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFPlusStore, "f+!", FICL_WORD_DEFAULT)

FICL_INSTRUCTION_TOKEN(ficlInstructionFDrop, "fdrop", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionF2Drop, "f2drop", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFDup, "fdup", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionF2Dup, "f2dup", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFMinusRoll, "f-roll", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFMinusRot, "f-rot", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFQuestionDup, "f?dup", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFOver, "fover", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionF2Over, "f2over", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFPick, "fpick", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFRoll, "froll", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFRot, "frot", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFSwap, "fswap", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionF2Swap, "f2swap", FICL_WORD_DEFAULT)

FICL_INSTRUCTION_TOKEN(ficlInstructionF0Less, "f0<", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFLess, "f<", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionF0Equals, "f0=", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFEquals, "f=", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionF0Greater, "f0>", FICL_WORD_DEFAULT)
FICL_INSTRUCTION_TOKEN(ficlInstructionFGreater, "f>", FICL_WORD_DEFAULT)

#endif  /* FICL_WANT_FLOAT */

FICL_TOKEN(ficlInstructionExitInnerLoop, "** exit inner loop **")
