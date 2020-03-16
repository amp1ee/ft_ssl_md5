#include "ft_ssl_md5.h"
#include <stdio.h>

void				print_usage(void)
{
	ft_putendl("usage: ft_ssl command [command opts] [command args]");
}

// TODO !!
void				print_digest(t_global *g, t_input *arg)
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
	else if (arg->type == EMPTY)
		printf("%s\n", arg->digest);
	/*else if (arg->atype == error)
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

void				swap_words(uint64_t *words, int wsize, int n)
{
	int i;

	i = -1;
	while (++i < n)
		(wsize == sizeof(uint64_t)) ? words[i] = swap_uint64(words[i])
		: (((uint32_t *)words)[i] = swap_uint32(((uint32_t *)words)[i]));
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

void				read_stdin(t_input *i, size_t rd, char *chunk, uint64_t *l)
{
	char			*tmp;

	tmp = NULL;
	if (i->type == P_STDIN)
	{
		tmp = ft_strjoin(i->str, chunk);
		//ft_strdel(&(i->str));
		i->str = tmp;
	}
	*l += rd;
}

void				digest_stdin(t_global *g, t_input *arg)
{
	const size_t	chunk_len = (size_t)g->algo.chunk_len;
	char			chunk[chunk_len + 1];
	ssize_t			ret;
	size_t			rd;
	uint64_t		length;

	length = 0;
	ft_bzero(chunk, sizeof(chunk));
	rd = 0;
	g->algo.init_ctx(&(g->algo.ctx));
	while ((ret = read(STDIN_FILENO, &(chunk[rd]), chunk_len - rd)) > 0)
	{
		rd += ret;
		if (rd == chunk_len)
		{
			g->algo.hashfunc(&(g->algo.ctx), chunk);
			read_stdin(arg, rd, chunk, &length);
			rd = 0;
			ft_bzero(chunk, chunk_len);
		}
	}
	if (ret < 0 ) // TODO: Handle error
		return ;
	if (rd)
		read_stdin(arg, rd, chunk, &length);
	digest_final_chunk(g, chunk, rd, length);
	g->algo.build_digest_msg(arg, g->algo.ctx, g->algo.digest_len, chunk_len);
}

void				digest_fd(t_global *g, int fd, t_input *arg)
{
	const size_t	chunk_len = (size_t)g->algo.chunk_len;
	char			chunk[chunk_len + 1];
	uint64_t		length;
	ssize_t			ret;

	ft_bzero(chunk, sizeof(chunk));
	length = 0;
	g->algo.init_ctx(&(g->algo.ctx));
	while ((ret = read(fd, chunk, chunk_len)) > 0
		&& (ret == (ssize_t)chunk_len))
	{
		g->algo.hashfunc(&(g->algo.ctx), chunk);
		length += chunk_len;
		ft_bzero(chunk, chunk_len);
	}
	if (ret < 0)
		return ; // TODO: Handle error
	digest_final_chunk(g, chunk, ret, length + ret);
	g->algo.build_digest_msg(arg, g->algo.ctx, g->algo.digest_len, chunk_len);
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
			g->name = g_algorithms[i].name; // TODO: Capitalize command name
			break ;
		}
		i++;
	}
	if (i == NUM_ALGOS)
	{
		g->algo.type = NO_TYPE;
		ft_putendl("Invalid command");		// TODO: echo the command
		print_usage();
	}
}

void				save_input(t_global *g, int optind, t_argtype atype)
{
	t_list			*new;
	t_input			arg;

	arg.type = atype;
	arg.str = (optind > 0) ? g->argv[optind] : "";
	arg.str_len = (optind > 0) ? ft_strlen(g->argv[optind]) : 0;
	if (!(new = ft_lstnew((void *)&arg, sizeof(t_input))))
		return ;					// TODO: malloc error handling
	ft_lstadd(&(g->inputs), new);	// TODO: append instead of prepend to list
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
//	printf("OPTIND:%d\n", optind);
	if (optind < g->argc - 1)
	{
		while (++optind < g->argc)
			save_input(g, optind, F_FILE);
	}
	if (!g->inputs)
		save_input(g, 0, EMPTY);
}

void				proceed_digest(t_global *g)
{
	t_algo			alg;
	t_list			*arg;
	t_input			*i;

	alg = g->algo;
	arg = g->inputs;
	while (arg != NULL)
	{
		i = (t_input *)(arg->content);
		if (i->type == P_STDIN || i->type == EMPTY)			//TODO: OR == EMPTY
			digest_stdin(g, i);
		else if (i->type == S_STRING)
		{
			alg.init_ctx(&(g->algo.ctx));
			digest_final_chunk(g, i->str, i->str_len, i->str_len);
			alg.build_digest_msg(i, g->algo.ctx, alg.digest_len, alg.chunk_len);
		}
		if (i->type != F_FILE)
			print_digest(g, i);
		arg = arg->next;
	}
	digest_files(g);
}

int					main(int argc, char *argv[])
{
	t_global	g;

	// TODO: (g->inputs = NULL) here?
	if (argc == 1) //	./ft_ssl w/o command
		digest_stdin(&g, NULL); //TODO
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
