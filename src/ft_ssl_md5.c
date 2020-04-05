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
	arg->digest = ft_strnew(digest_len);
	out_len = (digest_len << 3) / chunk_len;
	j = 0;
	while (j < out_len)
	{
		tmp = bytes_to_ascii(ctx_buf[j], sizeof(uint32_t));
		ft_strncpy(arg->digest + (j << 3), tmp, sizeof(uint32_t) << 1);
		ft_strdel(&tmp);
		j++;
	}
}

char				*append_padding_md5sha2(char *input, uint64_t input_len)
{
	const uint64_t	padded_len = LEN_ALIGN(input_len); // TODO: get rid of this
	char			*padded;

	if (!(padded = ft_memalloc(padded_len)))
		return (NULL);
	ft_memcpy(padded, input, input_len);
	if (++input_len <= (padded_len - 8))	//TODO: get rid of this 'if'
		padded[input_len - 1] = 0x80;
	while (++input_len <= (padded_len - 8))
		padded[input_len - 1] = 0x0;
	return (padded);
}

char				*add_64bit_len_md5sha2(char *input, uint64_t append_len,
											uint64_t padded_len)
{
	uint64_t		pos;

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
	const uint32_t	a0 = 0x67452301;
	const uint32_t	b0 = 0xefcdab89;
	const uint32_t	c0 = 0x98badcfe;
	const uint32_t	d0 = 0x10325476;
	ctx->md5[0] = a0;
	ctx->md5[1] = b0;
	ctx->md5[2] = c0;
	ctx->md5[3] = d0;
}

//	TODO: define A = 0, B = 1, C = 2, D = 3 for ctx_b[A]/[B]/[C]/[D]
void				hash_md5(t_context *ctx, char *chunk)
{
	uint32_t		ctx_b[4];
	uint32_t		F, g;	//TODO
	size_t			j;

	ctx_b[0] = ctx->md5[0];
	ctx_b[1] = ctx->md5[1];
	ctx_b[2] = ctx->md5[2];
	ctx_b[3] = ctx->md5[3];
	j = 0;
	while (j < 64)
	{
		if (j < 16)
		{
			F = (ctx_b[1] & ctx_b[2]) | (~ctx_b[1] & ctx_b[3]);
			g = j;
		}
		else if (j < 32)
		{
			F = (ctx_b[1] & ctx_b[3]) | (ctx_b[2] & ~ctx_b[3]);
			g = (5*j + 1) % 16;
		}
		else if (j < 48)
		{
			F = ctx_b[1] ^ ctx_b[2] ^ ctx_b[3];
			g = (3*j + 5) % 16;
		}
		else
		{
			F = ctx_b[2] ^ (ctx_b[1] | ~ctx_b[3]);
			g = (7*j) % 16;
		}
		F = F + ctx_b[0] + g_md5_k[j] + ((uint32_t *)chunk)[g];
		ctx_b[0] = ctx_b[3];
		ctx_b[3] = ctx_b[2];
		ctx_b[2] = ctx_b[1];
		ctx_b[1] = ctx_b[1] + LEFT_ROTATE(F, g_s[j]);
		j++;
	}
	ctx->md5[0] += ctx_b[0];
	ctx->md5[1] += ctx_b[1];
	ctx->md5[2] += ctx_b[2];
	ctx->md5[3] += ctx_b[3];
}
