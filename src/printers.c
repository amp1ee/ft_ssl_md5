#include "ft_ssl_md5.h"

void				print_usage(void)
{
	ft_putendl("usage: ft_ssl command [command opts] [command args]");
	exit(1);
}

void				print_hash_stdin(t_input *arg)
{
	ft_putstr(arg->str);
	ft_putendl(arg->digest);
}

void				print_hash_revfmt(t_input *arg)
{
	ft_putstr(arg->digest);
	ft_putchar(' ');
	(arg->type == S_STRING) ? ft_putchar('"') : 0;
	ft_putstr(arg->str);
	(arg->type == S_STRING) ? ft_putchar('"') : 0;
	ft_putchar('\n');
}

void				print_hash_default(char *algo_name, t_input *arg)
{
	ft_putstr(algo_name);
	ft_putstr(" (");
	(arg->type == S_STRING) ? ft_putchar('"') : 0;
	ft_putstr(arg->str);
	(arg->type == S_STRING) ? ft_putchar('"') : 0;
	ft_putstr(") = ");
	ft_putendl(arg->digest);
}

void				print_digest(t_global *g, t_input *arg)
{
	if (arg->type == ERR)
		return ;
	if (arg->type == P_STDIN)
		print_hash_stdin(arg);
	else if (arg->type == S_STRING || arg->type == F_FILE)
	{
		if (g->flags & QUIET_MODE)
			ft_putendl(arg->digest);
		else if (g->flags & REVERSE_FMT)
			print_hash_revfmt(arg);
		else
			print_hash_default(g->name, arg);
	}
	else if (arg->type == EMPTY)
		ft_putendl(arg->digest);
}

void				print_file_err(t_global *g, t_input *i)
{
	int				add_quotes;

	ft_putstr(g->self_name);
	ft_putstr(": ");
	ft_putstr(g->algo.name);
	ft_putstr(": ");
	add_quotes = (i->str_len == 0 || ft_strchr(i->str, ' '));
	add_quotes ? ft_putchar('\'') : 0;
	ft_putstr(i->str);
	add_quotes ? ft_putchar('\'') : 0;
	ft_putstr(": ");
	ft_putendl(strerror(errno));
	i->digest = NULL;
	i->type = ERR;
}
