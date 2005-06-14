// Derived from comp.sources.unix/volume3/att_getopt.
// See

#ifndef Options_DEF_INCLUDED
#define Options_DEF_INCLUDED 1

#ifndef OPTION_CHAR
#define OPTION_CHAR T('-')
#endif

#ifdef SP_NAMESPACE
namespace SP_NAMESPACE {
#endif

template<class T>
Options<T>::Options(int argc, T *const *argv, const T *opts)
: argc_(argc), argv_(argv), opts_(opts), ind_(1), sp_(1)
{
}

template<class T>
const T *Options<T>::search(T c) const
{
  for (const T *s = opts_; *s; s++)
    if (*s == c)
      return s;
  return 0;
}

template<class T>
bool Options<T>::get(T &c)
{
  const T *cp;
  if (sp_ == 1) {
    if (ind_ >= argc_)
      return false;
    if ((
#ifdef OTHER_OPTION_CHAR
	 argv_[ind_][0] != OTHER_OPTION_CHAR &&
#endif
	 argv_[ind_][0] != OPTION_CHAR) || argv_[ind_][1] == 0) {
#ifdef REORDER_ARGS
      int i;
      for (i = ind_; i < argc_; i++)
	if ((
#ifdef OTHER_OPTION_CHAR
	     argv_[i][0] == OTHER_OPTION_CHAR ||
#endif
	     argv_[i][0] == OPTION_CHAR) && argv_[i][1] != 0)
	  break;
      if (i < argc_) {
	c = argv_[i][1];
	if (c != T(':') && c != OPTION_CHAR
	    && (cp = search(c)) != 0
	    && cp[1] == T(':') && argv_[i][2] == 0 && i < argc_ - 1) {
	  int j;
	  T *temp1 = argv_[i];
	  T *temp2 = argv_[i + 1];
	  for (j = i - 1; j >= ind_; j--)
	    argv_[j+2] = argv_[j];
	  argv_[ind_] = temp1;
	  argv_[ind_ + 1] = temp2;
	}
	else {
	  int j;
	  T *temp = argv_[i];
	  for (j = i - 1; j >= ind_; j--)
	    argv_[j+1] = argv_[j];
	  argv_[ind_] = temp;
	}
      }
      else
#endif
	return false;
    }
    if ((argv_[ind_][0] == OPTION_CHAR && argv_[ind_][1] == OPTION_CHAR
	 && argv_[ind_][2] == 0)
#ifdef OTHER_OPTION_CHAR
	|| (argv_[ind_][0] == OTHER_OPTION_CHAR
	    && argv_[ind_][1] == OTHER_OPTION_CHAR
	    && argv_[ind_][2] == 0)
#endif
	) {
      ind_++;
      return false;
    }
  }
  opt_ = c = argv_[ind_][sp_];
  if (c == T(':') || (cp = search(c)) == 0) {
    if (argv_[ind_][++sp_] == 0) {
      ind_++;
      sp_ = 1;
    }
    c = T('?');
    return true;
  }
  if (*++cp == T(':')) {
    if (argv_[ind_][sp_ + 1] != 0)
      arg_ = &argv_[ind_++][sp_ + 1];
    else if (++ind_ >= argc_) {
      sp_ = 1;
      c = (*opts_ == T(':') ? T(':') : T('?'));
      return true;
    }
    else
      arg_ = argv_[ind_++];
    sp_ = 1;
  } 
  else {
    if (argv_[ind_][++sp_] == 0) {
      sp_ = 1;
      ind_++;
    }
    arg_ = 0;
  }
  return true;
}

#ifdef SP_NAMESPACE
}
#endif

#endif /* not Options_DEF_INCLUDED */
