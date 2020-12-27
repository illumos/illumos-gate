#
# DIRECTORY MANIPULATION FUNCTIONS PUSHD, POPD AND DIRS
#
# Uses global parameters _push_max _push_top _push_stack
integer _push_max=100 _push_top=100
# Display directory stack -- $HOME displayed as ~
function dirs
{
    typeset dir="${PWD#$HOME/}"
    case $dir in
    $HOME)
        dir=\~
        ;;
    /*) ;;
    *)  dir=\~/$dir
    esac
    print -r - "$dir ${_push_stack[@]}"
}

# Change directory and put directory on front of stack
function pushd
{
    typeset dir= type=0
    integer i
    case $1 in
    "") # pushd
        if    ((_push_top >= _push_max))
        then  print pushd: No other directory.
              return 1
        fi
        type=1 dir=${_push_stack[_push_top]}
        ;;
    +[1-9]|+[1-9][0-9]) # pushd +n
        integer i=_push_top$1-1
        if    ((i >= _push_max))
        then  print pushd: Directory stack not that deep.
              return 1
        fi
        type=2 dir=${_push_stack[i]}
        ;;
    *)  if    ((_push_top <= 0))
        then  print pushd: Directory stack overflow.
              return 1
        fi
    esac
    case $dir in
    \~*)   dir=$HOME${dir#\~}
    esac
    cd "${dir:-$1}" > /dev/null || return 1
    dir=${OLDPWD#$HOME/}
    case $dir in
    $HOME)
        dir=\~
        ;;
    /*) ;;
    *)  dir=\~/$dir
    esac
    case $type in
    0)  # pushd name
        _push_stack[_push_top=_push_top-1]=$dir
        ;;
    1)  # pushd
        _push_stack[_push_top]=$dir
        ;;
    2)  # push +n
        type=${1#+} i=_push_top-1
        set -- "${_push_stack[@]}" "$dir" "${_push_stack[@]}"
        shift $type
        for dir
        do  (((i=i+1) < _push_max)) || break
            _push_stack[i]=$dir
        done
    esac
    dirs
}

# Pops the top directory
function popd
{
    typeset dir
    if    ((_push_top >= _push_max))
    then  print popd: Nothing to pop.
          return 1
    fi
    case $1 in  
    "")
        dir=${_push_stack[_push_top]}
        case $dir in
        \~*)   dir=$HOME${dir#\~}
        esac
        cd "$dir" || return 1
        ;;
    +[1-9]|+[1-9][0-9])
        typeset savedir
        integer i=_push_top$1-1
        if    ((i >= _push_max))
        then  print pushd: Directory stack not that deep.
              return 1
        fi
        while ((i > _push_top))
        do _push_stack[i]=${_push_stack[i-1]}
              i=i-1
        done
        ;;
    *)  print pushd: Bad directory.
        return 1
    esac
    unset '_push_stack[_push_top]'
    _push_top=_push_top+1
    dirs
}
