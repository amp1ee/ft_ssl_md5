#include "libft.h"

#define EOF			(-1)
#define END			""
#define BADCH		(int)'?'

typedef struct	s_getopt
{
	int		ind;		// index into parent argv param
	int		err;		// if error should be printed
	int		opt;		// character checked for validity
	char	*arg;		// argument associated with option
	char	*oli;		// option letter list index
}				t_getopt;

int				ft_getopt(int argc, char **argv, const char *optstr, int *ind)
{
	static t_getopt	opt = {1, 1, 0, NULL, NULL};
	static char		*place = END;
	char			*p;

	if (!*place)
	{
		if (opt.ind >= argc || *(place = argv[opt.ind]) != '-')
		{
			place = END;
			return (EOF);
		}
		if (place[1] && *++place == '-')
		{
			++optind;
			place = END;
			return (EOF);
		}
	}
	if ((opt.opt = (int)*place++) == (int)':' ||
		!(opt.oli = ft_strchr(optstr, opt.opt)))
	{
		if (opt.opt == (int)'-')
			return (EOF);
		if (!*place)
			++(opt.ind);
		if (opt.err)
		{
			if (!(p = ft_strrchr(*argv, '/')))
				p = *argv;
			else
				++p;
			ft_putchar(opt.opt);
			ft_putendl(" -- illegal option");
		}
		return (BADCH);
	}
	if (*++(opt.oli) != ':')
	{
		opt.arg = NULL;
		if (!*place)
			++(opt.ind);
	}
	else
	{
		if (*place)
			opt.arg = place;
		else if (argc <= ++(opt.ind))
		{
			place = END;
			if (!(p = ft_strrchr(*argv, '/')))
				p = *argv;
			else
				++p;
			if (opt.err)
			{
				ft_putchar(opt.opt);
				ft_putendl(" -- option requires an argument");
			}
			return (BADCH);
		}
		else
			opt.arg = argv[opt.ind];
		place = END;
		++(opt.ind);
	}
	*ind = opt.ind;
	return (opt.opt);
}