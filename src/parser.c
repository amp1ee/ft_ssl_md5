#include "ft_ssl_md5.h"

void				identify_type(t_global *g)
{
	size_t			i;

	i = 0;
	while (i < NUM_ALGOS)
	{
		if (ft_strequ(g->argv[1], g_algorithms[i].name))
		{
			g->algo = g_algorithms[i];
			g->name = ft_upperstr(g_algorithms[i].name);
			if (g->name == NULL)
				exit_nomem(g);
			break ;
		}
		i++;
	}
	if (i == NUM_ALGOS)
	{
		g->algo.type = NO_TYPE;
		ft_putstr("Invalid command: '");
		ft_putstr(g->argv[1]);
		ft_putendl("'");
		print_usage();
	}
}

void				save_input(t_global *g, int optind, t_argtype atype)
{
	t_list			*new;
	t_input			arg;

	arg.type = atype;
	if (atype != F_FILE && optind > 1 && (ft_strchr(g->argv[optind], 's'))
									&& g->argv[optind][0] == '-')
		g->argv[optind] = (ft_strchr(g->argv[optind], 's') + 1);
	arg.str = (optind > 0) ? g->argv[optind] : "";
	arg.str_len = (optind > 0) ? ft_strlen(g->argv[optind]) : 0;
	if (!(new = ft_lstnew((void *)&arg, sizeof(t_input))))
		exit_nomem(g);
	ft_lstadd(&(g->inputs), new);
}

void				parse_options(t_global *g)
{
	const char		*opts = "pqrs:";
	int				opt;
	int				optind;

	g->flags = 0;
	g->inputs = NULL;
	optind = 0;
	while ((opt = ft_getopt(g->argc - 1, &(g->argv)[1], opts, &optind)) != -1)
	{
		if (opt == 'p')
			save_input(g, 0, P_STDIN);
		else if (opt == 'q')
			g->flags |= QUIET_MODE;
		else if (opt == 'r')
			g->flags |= REVERSE_FMT;
		else if (opt == 's')
			save_input(g, optind, S_STRING);
		else
			print_usage();
	}
	if ((optind < g->argc - 1 && optind != 0) || optind++ == 0)
	{
		while (++optind < g->argc)
			save_input(g, optind, F_FILE);
	}
	if (!g->inputs)
		save_input(g, 0, EMPTY);
	ft_lstreverse(&(g->inputs));
}