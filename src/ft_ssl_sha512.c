#include "ft_ssl_md5.h"
#include "ft_sha512.h"

void				init_sha512_context(t_context *ctx)
{
	ctx->sha5[0] = 0x6a09e667f3bcc908;
	ctx->sha5[1] = 0xbb67ae8584caa73b;
	ctx->sha5[2] = 0x3c6ef372fe94f82b;
	ctx->sha5[3] = 0xa54ff53a5f1d36f1;
	ctx->sha5[4] = 0x510e527fade682d1;
	ctx->sha5[5] = 0x9b05688c2b3e6c1f;
	ctx->sha5[6] = 0x1f83d9abfb41bd6b;
	ctx->sha5[7] = 0x5be0cd19137e2179;
}

char				*append_padding_sha5(char *input, uint128_t input_len)
{
	const uint128_t	padded_len = LEN_ALIGN_128(input_len);
	char			*padded;

	if (!(padded = ft_memalloc(padded_len)))
		return (NULL);
	ft_memcpy(padded, input, input_len);
	if (++input_len <= (padded_len - 16))	//TODO: get rid of this 'if'
		padded[input_len - 1] = 0x80;
	while (++input_len <= (padded_len - 16))
		padded[input_len - 1] = 0x0;
	return (padded);
}

char				*add_128bit_len_sha5(char *input, uint128_t append_len,
											uint128_t padded_len)
{
	uint128_t		pos;

	pos = padded_len - 16;
	while (pos < padded_len) {
		input[pos++] = (char)(append_len & 0xff);
		input[pos++] = (char)((append_len >> 8) & 0xff);
		input[pos++] = (char)((append_len >> 16) & 0xff);
		input[pos++] = (char)((append_len >> 24) & 0xff);
		input[pos++] = (char)((append_len >> 32) & 0xff);
		input[pos++] = (char)((append_len >> 40) & 0xff);
		input[pos++] = (char)((append_len >> 48) & 0xff);
		input[pos++] = (char)((append_len >> 56) & 0xff);
		append_len >>= 64;
	}
	return (input);
}

/* TODO */
static void			compress_loop(uint64_t *h, uint64_t *sched, int j)
{
	uint64_t	tmp[6];

	// S0
	tmp[0] = RIGHT_ROT_64(h[0], 28) ^ RIGHT_ROT_64(h[0], 34)
				^ RIGHT_ROT_64(h[0], 39);
	tmp[1] = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);
	// S1
	tmp[2] = RIGHT_ROT_64(h[4], 14) ^ RIGHT_ROT_64(h[4], 18)
				^ RIGHT_ROT_64(h[4], 41);
	tmp[3] = (h[4] & h[5]) ^ ((~h[4]) & h[6]);
	tmp[4] = h[7] + tmp[2] + tmp[3] + g_sha5_k[j] + sched[j];
	tmp[5] = tmp[0] + tmp[1];
	h[7] = h[6];
	h[6] = h[5];
	h[5] = h[4];
	h[4] = h[3] + tmp[4];
	h[3] = h[2];
	h[2] = h[1];
	h[1] = h[0];
	h[0] = tmp[4] + tmp[5];
}

/* TODO */
static void			extend_words(uint64_t *sched)
{
	uint64_t		s0;
	uint64_t		s1;
	uint64_t		i;

	i = 16;
	while (i < 80)
	{
		s0 = RIGHT_ROT_64(sched[i - 15], 1) ^ RIGHT_ROT_64(sched[i - 15], 8)
			^ (sched[i - 15] >> 7);
		s1 = RIGHT_ROT_64(sched[i - 2], 19) ^ RIGHT_ROT_64(sched[i - 2], 61)
			^ (sched[i - 2] >> 6);
		sched[i] = sched[i - 16] + s0 + sched[i - 7] + s1;
		i++;
	}
}

void				build_digest_msg_sha5(t_input *arg, t_context ctx,
										unsigned digest_len, unsigned chunk_len)
{
	char			*tmp;
	uint64_t		*ctx_buf;
	size_t			j;
	size_t			out_len;

	ctx_buf = ctx.sha5;
	arg->digest = ft_strnew(digest_len);
	out_len = (digest_len << 3) / chunk_len;
	j = 0;
	while (j < out_len)
	{
		tmp = bytes_to_ascii(swap_uint64(ctx_buf[j]), sizeof(uint64_t));
		ft_strncpy(arg->digest + (j << 4), tmp, sizeof(uint64_t) << 1);
		ft_strdel(&tmp);
		j++;
	}
}

void				hash_sha5(t_context *ctx, char *chunk)
{
	uint64_t		h[8];
	uint64_t		tmp[80];
	int				j;

	j = -1;
	while (++j < 8)
		h[j] = ctx->sha5[j];
	ft_memcpy((void *)tmp, (void *)chunk, 128);
	swap_words(tmp, sizeof(uint64_t), 16);
	extend_words(tmp);
	j = -1;
	while (++j < 80)
		compress_loop(h, tmp, j);
	j = -1;
	while (++j < 8)
		ctx->sha5[j] += h[j];
}