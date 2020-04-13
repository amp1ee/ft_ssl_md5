#include "ft_ssl_md5.h"
#include "ft_sha2.h"
// delete these:
#include <stdio.h>

void				init_sha256_context(t_context *ctx)
{
	ctx->sha2[A] = 0x6A09E667;
	ctx->sha2[B] = 0xBB67AE85;
	ctx->sha2[C] = 0x3C6EF372;
	ctx->sha2[D] = 0xA54FF53A;
	ctx->sha2[E] = 0x510E527F;
	ctx->sha2[F] = 0x9B05688C;
	ctx->sha2[G] = 0x1F83D9AB;
	ctx->sha2[H] = 0x5BE0CD19;
}

/*
** TODO
*/
static void			extend_words(uint32_t *sched)
{
	uint32_t		s0;
	uint32_t		s1;
	uint32_t		i;

	i = 16;
	while (i < 64)
	{
		s0 = RIGHT_ROTATE(sched[i - 15], 7) ^ RIGHT_ROTATE(sched[i - 15], 18)
			^ (sched[i - 15] >> 3);
		s1 = RIGHT_ROTATE(sched[i - 2], 17) ^ RIGHT_ROTATE(sched[i - 2], 19)
			^ (sched[i - 2] >> 10);
		sched[i] = sched[i - 16] + s0 + sched[i - 7] + s1;
		i++;
	}
}

/*
** TODO
*/
static void		compress_loop(uint32_t *h, uint32_t *sched, int j)
{
	uint32_t	tmp[6];

	tmp[A] = RIGHT_ROTATE(h[A], 2) ^ RIGHT_ROTATE(h[A], 13)
				^ RIGHT_ROTATE(h[A], 22);
	tmp[B] = (h[A] & h[B]) ^ (h[A] & h[C]) ^ (h[B] & h[C]);
	tmp[C] = RIGHT_ROTATE(h[E], 6) ^ RIGHT_ROTATE(h[E], 11)
				^ RIGHT_ROTATE(h[E], 25);
	tmp[D] = (h[E] & h[F]) ^ ((~h[E]) & h[G]);
	tmp[E] = h[H] + tmp[C] + tmp[D] + g_sha2_k[j] + sched[j];
	tmp[F] = tmp[A] + tmp[B];
	h[H] = h[G];
	h[G] = h[F];
	h[F] = h[E];
	h[E] = h[D] + tmp[E];
	h[D] = h[C];
	h[C] = h[B];
	h[B] = h[A];
	h[A] = tmp[E] + tmp[F];
}

void				build_digest_msg_sha2(t_input *arg, t_context ctx,
										unsigned digest_len, unsigned chunk_len)
{
	char			*tmp;
	uint32_t		*ctx_buf;
	size_t			j;
	size_t			out_len;

	ctx_buf = ctx.sha2;
	if (!(arg->digest = ft_strnew(digest_len)))
		exit_nomem(NULL);
	out_len = (digest_len << 3) / chunk_len;
	j = 0;
	while (j < out_len)
	{
		tmp = bytes_to_ascii(swap_uint32(ctx_buf[j]), sizeof(uint32_t));
		if (!tmp)
			exit_nomem(NULL);
		ft_strncpy(arg->digest + (j << 3), tmp, sizeof(uint32_t) << 1);
		ft_strdel(&tmp);
		j++;
	}
}

void				hash_sha2(t_context *ctx, char *chunk)
{
	uint32_t		h[8];
	uint32_t		tmp[64];
	int				j;

	j = -1;
	while (++j < 8)
		h[j] = ctx->sha2[j];
	ft_memcpy((void *)tmp, (void *)chunk, 64);
	swap_words((uint64_t *)tmp, sizeof(uint32_t), 16);
	extend_words((uint32_t *)tmp);
	j = -1;
	while (++j < 64)
		compress_loop(h, (uint32_t *)tmp, j);
	j = -1;
	while (++j < 8)
		ctx->sha2[j] += h[j];
}
