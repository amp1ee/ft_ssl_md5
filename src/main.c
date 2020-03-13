#include "ft_ssl_md5.h"
#include <stdio.h>

void				print_usage(void)
{
	ft_putendl("usage: ft_ssl command [command opts] [command args]");
}

// TODO !!
void			print_digest(t_global *g, t_input *arg)
{
	if (arg->type == P_STDIN)
		printf("%s%s\n", arg->str, arg->digest);
	else if (arg->type == S_STRING || arg->type == F_FILE)
	{
		if (g->flags & QUIET_MODE)
			printf("%s\n", arg->digest);
		else if (g->flags & REVERSE_FMT)
			printf(((arg->type == S_STRING) ? "%s \"%s\"\n" : "%s %s\n"),
				arg->digest, arg->str);
		else
			printf(((arg->type == S_STRING) ? "%s (\"%s\") = %s\n"
				: "%s (%s) = %s\n"), g->algo.name, arg->str, arg->digest);
	}
	/*else if (arg->atype == empty)
		printf("%s\n", arg->hash);
	else if (arg->atype == error)
		(arg->hash) ?
		printf("ft_ssl: %s: %s: %s\n", ssl->algo.str, arg->str, arg->digest)
		: printf("ft_ssl: %s: %s\n", ssl->algo.str, arg->str);*/
}

uint32_t			swap_uint32(uint32_t val)
{
	val = ((val << 8) & 0xFF00FF00)
		| ((val >> 8) & 0xFF00FF);
	return (val << 16) | (val >> 16);
}

// TODO: what's going on?
uint64_t			swap_uint64(uint64_t val)
{
	val = ((val << 8) & 0xFF00FF00FF00FF00ULL)
		| ((val >> 8) & 0x00FF00FF00FF00FFULL);
	val = ((val << 16) & 0xFFFF0000FFFF0000ULL)
		| ((val >> 16) & 0x0000FFFF0000FFFFULL);
	return (val << 32) | (val >> 32);
}

void			swap_words(uint64_t *words, int wsize, int n)
{
	int i;

	i = -1;
	while (++i < n)
		(wsize == sizeof(uint64_t)) ? words[i] = swap_uint64(words[i])
		: (((uint32_t *)words)[i] = swap_uint32(((uint32_t *)words)[i]));
}

void					digest_stdin(t_global *g)
{
	(void)g;
	return ;
}

char				*bytes_to_ascii(uint64_t bytes, size_t size)
{
	const char		*hexbase = "0123456789abcdef";
	char			*ascii;
	size_t			i;
	size_t			j;

	if (!(ascii = ft_strnew(size << 1)))
		return (NULL);
	i = 0;
	j = 0;
	while (j < size)
	{
		ascii[i++] = hexbase[((unsigned char *)&bytes)[j] / 16];
		ascii[i++] = hexbase[((unsigned char *)&bytes)[j] % 16];
		j++;
	}
	return (ascii);
}

void				build_digest_message(t_global *g, t_input *arg)
{
	char			*tmp;
	uint32_t		*ctx_buf;
	size_t			j;
	size_t			out_len;

	ctx_buf = (g->algo.type == MD5) ? g->algo.ctx.md5 : g->algo.ctx.sha2;
	arg->digest = ft_strnew(g->algo.digest_len);
	out_len = (g->algo.digest_len << 3) / g->algo.chunk_len;
	j = 0;
	while (j < out_len)
	{
		tmp = bytes_to_ascii(ctx_buf[j], sizeof(uint32_t));
		ft_strncpy(arg->digest + (j << 3), tmp, sizeof(uint32_t) << 1);
		ft_strdel(&tmp);
		j++;
	}
}

void				digest_final_chunk(t_global *g, char *buf, size_t read_len,
										uint64_t append_len)
{
	const uint64_t	aligned_len = LEN_ALIGN(read_len);
	t_algo			alg;
	unsigned		i;

	alg = g->algo;
	buf = alg.append_padding(buf, read_len);
	if (alg.type == MD5)
		buf = alg.add_64bit_len(buf, (append_len << 3), aligned_len);
	else
		buf = alg.add_64bit_len(buf, swap_uint64(append_len << 3), aligned_len);
	i = 0;
	while (i < ((unsigned)aligned_len / alg.chunk_len))
	{
		alg.hashfunc(&(g->algo.ctx), buf + alg.chunk_len * i);
		i++;
	}
	ft_strdel(&buf);
}

void				digest_fd(t_global *g, int fd, t_input *arg)
{
	const unsigned	chunk_len = g->algo.chunk_len;
	char			chunk[chunk_len];
	uint64_t		length;
	int				ret;

	ft_bzero(chunk, sizeof(chunk));
	length = 0;
	g->algo.init_ctx(&(g->algo.ctx));
	while ((ret = read(fd, chunk, chunk_len)) > 0 && ret == (int)chunk_len)
	{
		g->algo.hashfunc(&(g->algo.ctx), chunk);
		length += chunk_len;
		ft_bzero(chunk, sizeof(chunk));
	}
	if (ret < 0)
		return ; // TODO: Handle error
	digest_final_chunk(g, chunk, ret, length + ret);
	build_digest_message(g, arg);
}

void				digest_files(t_global *g)
{
	t_list			*arg;
	t_input			*i;
	int				fd;

	arg = g->inputs;
	while (arg != NULL)
	{
		i = (t_input *)(arg->content);
		if (i->type == F_FILE)
		{
			if ((fd = open((i->str), O_RDONLY)) <= 0)
			{
				printf("No such FILE: %s\n", i->str);
				arg = arg->next;
				continue ;	// TODO: handle error;
			}
			digest_fd(g, fd, i);
			close(fd);
			print_digest(g, i);
		}
		arg = arg->next;
	}
}

void				identify_type(t_global *g)
{
	size_t			i;

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

void				save_input(t_global *g, int optind, t_argtype atype)
{
	t_list			*new;
	t_input			arg;

	arg.type = atype;
	arg.str = (optind) ? g->argv[optind] : "";
	arg.str_len = (optind) ? ft_strlen(g->argv[optind]) : 0;
	if (!(new = ft_lstnew((void *)&arg, sizeof(t_input))))
		return ;																// TODO: malloc error handling
	ft_lstadd(&(g->inputs), new);												// TODO: append instead of prepend to list
}

void					parse_options(t_global *g)
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
			save_input(g, optind, S_STRING);
		else
			print_usage();
	}
	if (optind != g->argc - 1)
	{
		while (++optind < g->argc)
			save_input(g, optind, F_FILE);
	}
}

void				proceed_digest(t_global *g)
{
	t_algo			algo;
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
			algo.init_ctx(&(g->algo.ctx));
			digest_final_chunk(g, i->str, i->str_len, i->str_len);
			build_digest_message(g, i);
		}
		if (i->type != F_FILE)
			print_digest(g, i);
		arg = arg->next;
	}
	digest_files(g);
}

int				main(int argc, char *argv[])
{
	t_global	g;

	// TODO: (g->inputs = NULL) here?
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