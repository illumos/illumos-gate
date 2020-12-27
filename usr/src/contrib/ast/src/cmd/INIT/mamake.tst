# : : generated from mamake.rt by mktest : : #

# regression tests for the mamake command

UNIT mamake

TEST 01 macros

	EXEC	-n
		INPUT -n -
		INPUT Mamfile $'info mam static 00000 1994-07-17 make (AT&T Research) 5.3 2009-05-05
setv DEFINED defined
setv EMPTY
make all

exec - echo DEFINED ${DEFINED}
exec - echo DEFINED:VALUE ${DEFINED:VALUE}
exec - echo DEFINED:-VALUE ${DEFINED:-VALUE}
exec - echo DEFINED=VALUE ${DEFINED=VALUE}
exec - echo DEFINED[VALUE] ${DEFINED[VALUE]}
exec - echo DEFINED.COMPONENT ${DEFINED.COMPONENT}
exec - echo DEFINED.COMPONENT[VALUE] ${DEFINED.COMPONENT[VALUE]}

exec - echo EMPTY ${EMPTY}
exec - echo EMPTY:VALUE ${EMPTY:VALUE}
exec - echo EMPTY:-VALUE ${EMPTY:-VALUE}
exec - echo EMPTY=VALUE ${EMPTY=VALUE}
exec - echo EMPTY[VALUE] ${EMPTY[VALUE]}
exec - echo EMPTY.COMPONENT ${EMPTY.COMPONENT}
exec - echo EMPTY.COMPONENT[VALUE] ${EMPTY.COMPONENT[VALUE]}

exec - echo __NoT_DeFiNeD__ ${__NoT_DeFiNeD__}
exec - echo __NoT_DeFiNeD__:VALUE ${__NoT_DeFiNeD__:VALUE}
exec - echo __NoT_DeFiNeD__:-VALUE ${__NoT_DeFiNeD__:-VALUE}
exec - echo __NoT_DeFiNeD__=VALUE ${__NoT_DeFiNeD__=VALUE}
exec - echo __NoT_DeFiNeD__[VALUE] ${__NoT_DeFiNeD__[VALUE]}
exec - echo __NoT_DeFiNeD__.COMPONENT ${__NoT_DeFiNeD__.COMPONENT}
exec - echo __NoT_DeFiNeD__.COMPONENT[VALUE] ${__NoT_DeFiNeD__.COMPONENT[VAL'\
$'UE]}

done all generated virtual'
		OUTPUT - $'echo DEFINED defined
echo DEFINED:VALUE 
echo DEFINED:-VALUE 
echo DEFINED=VALUE defined
echo DEFINED[VALUE] ${DEFINED[VALUE]}
echo DEFINED.COMPONENT 
echo DEFINED.COMPONENT[VALUE] ${DEFINED.COMPONENT[VALUE]}
echo EMPTY 
echo EMPTY:VALUE ${EMPTY:VALUE}
echo EMPTY:-VALUE ${EMPTY:-VALUE}
echo EMPTY=VALUE 
echo EMPTY[VALUE] ${EMPTY[VALUE]}
echo EMPTY.COMPONENT 
echo EMPTY.COMPONENT[VALUE] ${EMPTY.COMPONENT[VALUE]}
echo __NoT_DeFiNeD__ ${__NoT_DeFiNeD__}
echo __NoT_DeFiNeD__:VALUE ${__NoT_DeFiNeD__:VALUE}
echo __NoT_DeFiNeD__:-VALUE ${__NoT_DeFiNeD__:-VALUE}
echo __NoT_DeFiNeD__=VALUE ${__NoT_DeFiNeD__=VALUE}
echo __NoT_DeFiNeD__[VALUE] ${__NoT_DeFiNeD__[VALUE]}
echo __NoT_DeFiNeD__.COMPONENT 
echo __NoT_DeFiNeD__.COMPONENT[VALUE] ${__NoT_DeFiNeD__.COMPONENT[VALUE]}'
		ERROR -n -
