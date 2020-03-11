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
		ft_putendl("Invalid command");											// TODO: echo the command
		print_usage();
	}
}

void			save_input(t_global *g, int optind, t_argtype atype)
{
	t_list		*new;
	t_input		arg;

	arg.type = atype;
	arg.str = (optind) ? g->argv[optind] : "";
	arg.str_len = (optind) ? ft_strlen(g->argv[optind]) : 0;
	if (!(new = ft_lstnew((void *)&arg, sizeof(t_input))))
		return ;																// TODO: malloc error handling
	ft_lstadd(&(g->inputs), new);												// TODO: append instead of prepend to list
}

void			parse_options(t_global *g)
{
	const char			*opts = "pqrs:";
	int					opt;
	int					optind;

	g->flags = 0;
	g->inputs = NULL;
	while ((opt = ft_getopt(g->argc - 1, &(g->argv)[1], opts, &optind)) != -1)
	{
		if (opt == 'p')
		{
			save_input(g, 0, P_STDIN);
			g->flags |= PRINT_STDINOUT;
		}
		else if (opt == 'q')
			g->flags |= QUIET_MODE;
		else if (opt == 'r')
			g->flags |= REVERSE_FMT;
		else if (opt == 's')
		{
			g->flags |= GIVEN_STRING;
			save_input(g, optind, S_STRING);
		}
		else if (opt == '?')
			save_input(g, optind, F_FILE);
		else
			print_usage();
	}
}

void				proceed_digest(t_global *g)
{
	t_algo			algo;
	char			*digested;
	t_list			*arg;
	t_input			*i;

	algo = g->algo;
	arg = g->inputs;
	while (arg != NULL)
	{
		i = (t_input *)(arg->content);
		if (i->type == P_STDIN)													//TODO: OR == EMPTY
			digest_stdin(g);
		else if (i->type == S_STRING)
		{
			algo.init_ctx(&(algo.ctx));
			digested = algo.hashfunc((char *)(i->str), (uint64_t)(i->str_len));
			printf("%s\n", digested);
			ft_strdel(&digested);
		}
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