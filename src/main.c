#include "ft_ssl_md5.h"

void				exit_nomem(t_global *g)
{
	ft_putstr((g) ? g->name : "ft_ssl");
	ft_putstr(": ");
	ft_putendl("Memory allocation error");
	exit(2);
}

static void			set_self_name(t_global *g, char *argv0)
{
	char			*slash_pos;

	if ((slash_pos = ft_strrchr(argv0, '/')) != NULL)
		g->self_name = slash_pos + 1;
	else
		g->self_name = argv0;
}

static void			args_cleanup(void *arg, size_t argsize)
{
	t_input			*in;

	in = (t_input *)arg;
	if (in->digest != NULL)
		ft_strdel(&(in->digest));
	ft_bzero(arg, argsize);
}

static void			global_cleanup(t_global *g)
{
	ft_lstdel(&(g->inputs), args_cleanup);
	ft_strdel(&(g->name));
}

int					main(int argc, char *argv[])
{
	t_global		g;

	set_self_name(&g, argv[0]);
	if (argc == 1)
		print_usage(); 
	else
	{
		g.argc = argc;
		g.argv = argv;
		identify_type(&g);
		if (g.algo.type == NO_TYPE)
			return (1);
		parse_options(&g);
		proceed_digest(&g);
	}
	global_cleanup(&g);
	return (0);
}
