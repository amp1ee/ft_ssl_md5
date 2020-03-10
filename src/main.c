#include "ft_ssl_md5.h"
#include <stdio.h>

void				print_usage(void)
{
	ft_putendl("usage: ft_ssl command [command opts] [command args]");
}

void			digest_stdin(t_global *g)
{
	(void)g;
	return ;
}

void			identify_type(t_global *g)
{
	size_t		i;

	i = 0;
	while (i < NUM_ALGOS)
	{
		if (ft_strequ(g->argv[1], g_algorithms[i].name))
		{
			g->algo = g_algorithms[i];
			break ;
		}
		i++;
	}
	if (i == NUM_ALGOS)
	{
		g->algo.type = NO_TYPE;
		ft_putendl("Invalid command"); // TODO: echo the command
		print_usage();
	}
}

void			save_option(t_global *g, t_list **list, int optind)
{
	t_list		*new;

	if (!(new = ft_lstnew(g->argv[optind], ft_strlen(g->argv[optind]))))
		return ;			// TODO: malloc error handling
	ft_lstadd(list, new);	// TODO: append instead of prepend to list
}

void			parse_options(t_global *g)
{
	const char			*opts = "pqrs:";
	int					opt;
	int					optind;

	g->flags = 0;
	g->str_opts = NULL;
	g->files = NULL;
	while ((opt = ft_getopt(g->argc - 1, &(g->argv)[1], opts, &optind)) != -1)
	{
		if (opt == 'p')
			g->flags |= PRINT_STDINOUT;
		else if (opt == 'q')
			g->flags |= QUIET_MODE;
		else if (opt == 'r')
			g->flags |= REVERSE_FMT;
		else if (opt == 's')
		{
			g->flags |= GIVEN_STRING;
			save_option(g, &(g->str_opts), optind);
		}
		else if (opt == '?')
			save_option(g, &(g->files), optind);
		else
			print_usage();
	}
}

void				proceed_digest(t_global *g)
{
	t_algo			algo;
	char			*digested;
	t_list			*arg;

	algo = g->algo;
	arg = g->str_opts;
	while (arg != NULL)
	{
		algo.init_ctx(&(algo.ctx));
		digested = algo.hashfunc((char *)(arg->content), (uint64_t)(arg->content_size));
		printf("%s\n", digested);
		ft_strdel(&digested);
		arg = arg->next;
	}
}

int				main(int argc, char *argv[])
{
	t_global	g;

	if (argc == 1)
		digest_stdin(&g);
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
	return (0);
}