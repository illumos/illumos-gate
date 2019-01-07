#!/bin/bash -e

TMP_DIR=/tmp

help()
{
    echo "Usage: $0 [--no-compile|--ammend] <filename>"
    echo "You must be at the base of the kernel tree to run this."
    exit 1
}

continue_yn()
{
    echo -n "Do you want to fix these issues now? "
    read ans
    if ! echo $ans | grep -iq ^n ; then
	exit 1;
    fi
}

qc()
{
    local msg=$1
    local ans

    echo -n "$msg:  "
    read ans
    if ! echo $ans | grep -qi ^y ; then
	exit 1
    fi
}

NO_COMPILE=false
AMEND=""

while true ; do
    if [[ "$1" == "--no-compile" ]] ; then
        NO_COMPILE=true
        shift
    elif [[ "$1" == "--ammend" ]] ; then
        AMEND="--amend"
        shift
    else
        break
    fi
done

if [ ! -f $1 ] ; then
    help
fi

fullname=$1
filename=$(basename $fullname)
oname=$(echo ${fullname/.c/.o})

MAIL_FILE=$TMP_DIR/${filename}.msg

echo "QC checklist"
qc "Have you handled all the errors properly?"
if git diff $fullname | grep ^+ | grep -qi alloc ; then
    qc "Have you freed all your mallocs?"
fi
if git diff $fullname | grep ^+ | grep -qi alloc ; then
    qc "Have you check all your mallocs for NULL returns?"
fi

if [ "$NO_COMPILE" != "true" ] ; then
    kchecker --spammy $fullname
    kchecker --sparse --endian $fullname
#    rm $oname
#    make C=1 CHECK="scripts/coccicheck" $oname
fi

grepmail $fullname ~/var/mail/sent* | grep -i ^subject || echo -n ""
qc "Looks OK?"

git log --oneline $fullname | head -n 10
echo "Copy and paste one of these subjects?"
read unused

git add $fullname
git commit --signoff $AMEND

to_addr=$(./scripts/get_maintainer.pl -f --noroles --norolestats $fullname | head -n 1)
cc_addr=$(./scripts/get_maintainer.pl -f --noroles --norolestats $fullname | tail -n +2 | \
    perl -ne 's/\n$/, /; print')
cc_addr="$cc_addr, kernel-janitors@vger.kernel.org"

echo -n "To:  "  > $MAIL_FILE
echo "$to_addr" >> $MAIL_FILE
echo -n "CC:  " >> $MAIL_FILE
echo "$cc_addr" >> $MAIL_FILE
echo "X-Mailer: git-send-email haha only kidding" >> $MAIL_FILE

git format-patch HEAD^ --stdout >> $MAIL_FILE

./scripts/checkpatch.pl $MAIL_FILE || continue_yn

echo "Press ENTER to continue"
read unused

mutt -H $MAIL_FILE
