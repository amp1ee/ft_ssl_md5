#include "ft_ssl_md5.h"
#include "ft_md5.h"
#include <stdio.h>

void				build_digest_msg_md5(t_input *arg, t_context ctx,
										unsigned digest_len, unsigned chunk_len)
{
	char			*tmp;
	uint32_t		*ctx_buf;
	size_t			j;
	size_t			out_len;

	ctx_buf = ctx.md5;
	if (!(arg->digest = ft_strnew(digest_len)))
		exit_nomem(NULL);
	out_len = (digest_len << 3) / chunk_len;
	j = 0;
	while (j < out_len)
	{
		tmp = bytes_to_ascii(ctx_buf[j], sizeof(uint32_t));
		if (!tmp)
			exit_nomem(NULL);
		ft_strncpy(arg->digest + (j << 3), tmp, sizeof(uint32_t) << 1);
		ft_strdel(&tmp);
		j++;
	}
}

char				*append_padding_md5sha2(char *input, uint128_t input_len)
{
	const uint128_t	padded_len = LEN_ALIGN(input_len); // TODO: get rid of this
	char			*padded;

	if (!(padded = ft_memalloc(padded_len)))
		return (NULL);
	ft_memcpy(padded, input, input_len);
	padded[++input_len - 1] = 0x80;
	while (++input_len <= (padded_len - 8))
		padded[input_len - 1] = 0x0;
	return (padded);
}

char				*add_64bit_len_md5sha2(char *input, uint128_t append_len,
											uint128_t padded_len)
{
	uint128_t		pos;

	pos = padded_len - 8;
	while (pos < padded_len) {
		input[pos++] = (char)(append_len & 0xff);
		input[pos++] = (char)((append_len >> 8) & 0xff);
		input[pos++] = (char)((append_len >> 16) & 0xff);
		input[pos++] = (char)((append_len >> 24) & 0xff);
		append_len >>= 32;
	}
	return (input);
}

void				init_md5_context(t_context *ctx)
{
	ctx->md5[A] = 0x67452301;
	ctx->md5[B] = 0xefcdab89;
	ctx->md5[C] = 0x98badcfe;
	ctx->md5[D] = 0x10325476;
}

static void			do_hash_md5_round(uint32_t *ctx, size_t j,
									uint32_t *f, uint32_t *g)
{
	if (j < 16)
	{
		*f = (ctx[B] & ctx[C]) | (~ctx[B] & ctx[D]);
		*g = j;
	}
	else if (j < 32)
	{
		*f = (ctx[B] & ctx[D]) | (ctx[C] & ~ctx[D]);
		*g = (5 * j + 1) % 16;
	}
	else if (j < 48)
	{
		*f = ctx[B] ^ ctx[C] ^ ctx[D];
		*g = (3 * j + 5) % 16;
	}
	else
	{
		*f = ctx[C] ^ (ctx[B] | ~ctx[D]);
		*g = (7 * j) % 16;
	}
}

void				hash_md5(t_context *ctx, char *chunk)
{
	uint32_t		ctx_b[4];
	uint32_t		f;
	uint32_t		g;
	size_t			j;

	ctx_b[A] = ctx->md5[A];
	ctx_b[B] = ctx->md5[B];
	ctx_b[C] = ctx->md5[C];
	ctx_b[D] = ctx->md5[D];
	j = 0;
	while (j < 64)
	{
		do_hash_md5_round(ctx_b, j, &f, &g);
		f = f + ctx_b[A] + g_md5_k[j] + ((uint32_t *)chunk)[g];
		ctx_b[A] = ctx_b[D];
		ctx_b[D] = ctx_b[C];
		ctx_b[C] = ctx_b[B];
		ctx_b[B] = ctx_b[B] + LEFT_ROTATE(f, g_s[j]);
		j++;
	}
	ctx->md5[A] += ctx_b[A];
	ctx->md5[B] += ctx_b[B];
	ctx->md5[C] += ctx_b[C];
	ctx->md5[D] += ctx_b[D];
}
