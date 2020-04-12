#include "ft_ssl_md5.h"
#include <stdio.h>

void				exit_nomem(t_global *g)
{
	ft_putstr((g) ? g->name : "ft_ssl");
	ft_putstr(": ");
	ft_putendl("Memory allocation error");
	exit(2);
}

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
	/*else if (arg->atype == error)
		(arg->digest) ?
		printf("ft_ssl: %s: %s: %s\n", ssl->algo.str, arg->str, arg->digest)
		: printf("ft_ssl: %s: %s\n", ssl->algo.str, arg->str);*/
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

uint128_t			swap_uint128(uint128_t val)
{
	val = ((val << 8) & (uint128_t)0xFF00FF00FF00FF00)
		| ((val >> 8) & (uint128_t)0x00FF00FF00FF00FF);
	val = ((val << 16) & (uint128_t)0xFFFF0000FFFF0000)
		| ((val >> 16) & (uint128_t)0x0000FFFF0000FFFF);
	val = ((val << 32) & (uint128_t)0xFFFFFFFF00000000)
		| ((val >> 32) & (uint128_t)0x00000000FFFFFFFF);
	return (val << 64) | (val >> 64);
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
										uint128_t append_len)
{
	uint128_t		aligned_len;
	t_algo			alg;
	unsigned		i;

	alg = g->algo;
	aligned_len = (alg.type < SHA512) ? LEN_ALIGN(read_len) :
										LEN_ALIGN_128(read_len);
	buf = alg.append_padding(buf, read_len);
	if (!buf)
		exit_nomem(g);
	if (alg.type == MD5)
		buf = alg.append_length(buf, (append_len << 3), aligned_len);
	else if (alg.type < SHA512)
		buf = alg.append_length(buf, swap_uint64(append_len << 3), aligned_len);
	else
		buf = alg.append_length(buf, swap_uint128(append_len << 3), aligned_len);
	i = 0;
	while (i < ((unsigned)aligned_len / alg.chunk_len))
	{
		alg.hashfunc(&(g->algo.ctx), buf + alg.chunk_len * i);
		i++;
	}
	ft_strdel(&buf);
}

void				read_stdin(t_input *i, size_t rd, char *chunk, uint128_t *l)
{
	char			*tmp;

	tmp = NULL;
	if (i->type == P_STDIN)
	{
		tmp = ft_strjoin(i->str, chunk);
		if (!tmp)
			exit_nomem(NULL);
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
	uint128_t		length;

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
	uint128_t		length;
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
	{
		print_file_err(g, arg);
		return ;
	}
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
				print_file_err(g, i);
				arg = arg->next;
				continue ;
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
		if (i->type == P_STDIN || i->type == EMPTY)
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

void				set_self_name(t_global *g, char *argv0)
{
	char			*slash_pos;

	if ((slash_pos = ft_strrchr(argv0, '/')) != NULL)
		g->self_name = slash_pos + 1;
	else
		g->self_name = argv0;
}

void				args_cleanup(void *arg, size_t argsize)
{
	t_input			*in;

	in = (t_input *)arg;
	if (in->digest != NULL)
		ft_strdel(&(in->digest));
	ft_bzero(arg, argsize);
}

void				global_cleanup(t_global *g)
{
	ft_lstdel(&(g->inputs), args_cleanup);
	ft_strdel(&(g->name));
}

int					main(int argc, char *argv[])
{
	t_global		g;

	set_self_name(&g, argv[0]);
	if (argc == 1) //	./ft_ssl w/o command
		digest_stdin(&g, NULL); //TODO OpenSSL behavior
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
