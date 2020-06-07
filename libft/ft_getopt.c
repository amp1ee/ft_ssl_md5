#include "libft.h"

#define EOF			(-1)
#define END			""
#define BADCH		(int)'?'

typedef struct	s_getopt
{
	int		ind;		// index into parent argv param
	int		opt;		// character checked for validity
	char	*arg;		// argument associated with option
	char	*oli;		// option letter list index
	char	*place;
}				t_getopt;

static int			ft_getopt_error(int opt, char *mesg)
{
	ft_putchar(opt);
	ft_putstr(" -- ");
	ft_putendl(mesg);
	return (BADCH);
}

static int			ft_getopt_resume(t_getopt *opt, int argc, char **argv,
									int *ind)
{
	if (*++(opt->oli) != ':') // if the option doesn't need a value
	{
		opt->arg = NULL;
		if (!*opt->place)
			++(opt->ind);
	}
	else
	{
		if (*opt->place) // no whitespace
			opt->arg = opt->place;
		else if (argc <= ++(opt->ind)) // no arg given
		{
			opt->place = END;
			return (ft_getopt_error(opt->opt, "option requires an argument"));
		}
		else
			opt->arg = argv[opt->ind];
		opt->place = END;
		++(opt->ind);
	}
	*ind = opt->ind;
	return (opt->opt);
}

int					ft_getopt(int argc, char **argv, const char *optstr,
								int *ind)
{
	static t_getopt	opt = {1, 0, NULL, NULL, END};

	if (!*opt.place) // we're either at the end or the start of arg string
	{
		if (opt.ind >= argc || *(opt.place = argv[opt.ind]) != '-' ||			// end of args || cur arg isn't an option (place := cur arg)
			(opt.place[1] && *++opt.place == '-'))								// stumbled upon an arg that starts with '--'
		{
			opt.place = END;
			return (EOF);
		}
	}
	if ((opt.opt = (int)*opt.place++) == ':' ||
		!(opt.oli = ft_strchr(optstr, opt.opt))) // (if we're given '-:' as arg) || No such letter in optstring
	{
		if (opt.opt == (int)'-')
			return (EOF);
		if (!*opt.place) // reached end of option arg
			++(opt.ind);
		return (ft_getopt_error(opt.opt, "illegal option"));
	}
	return (ft_getopt_resume(&opt, argc, argv, ind));
}