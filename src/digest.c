#include "ft_ssl_md5.h"

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
