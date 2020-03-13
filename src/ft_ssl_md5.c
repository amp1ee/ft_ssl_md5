#include "ft_ssl_md5.h"
#include <stdio.h>

unsigned char	g_s[64] = {
	7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

uint32_t		g_md5_k[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 
};

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
/*	printf("%x\n", ctx->md5[0]);
	printf("%x\n", ctx->md5[1]);
	printf("%x\n", ctx->md5[2]);
	printf("%x\n", ctx->md5[3]);*/
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
/*	printf("%x\n", ctx->md5[0]);
	printf("%x\n", ctx->md5[1]);
	printf("%x\n", ctx->md5[2]);
	printf("%x\n", ctx->md5[3]);*/
}

/*
static void			process_blocks(char *padded, size_t input_len,
									t_context *ctx)
{
	const size_t	padded_len = LEN_ALIGN(input_len);
	size_t			i;
	char			chunk[64];
	uint32_t		A, B, C, D, j;
	uint32_t		F, g;

	i = 0;
	while (i < padded_len)
	{
		ft_memcpy(chunk, &padded[i], 64);
		A = ctx->md5[0];
		B = ctx->md5[1];
		C = ctx->md5[2];
		D = ctx->md5[3];
		j = 0;
		while (j < 64)
		{
			if (j < 16)
			{
				F = (B & C) | (~B & D);
				g = j;
			}
			else if (j < 32)
			{
				F = (B & D) | (C & ~D);
				g = (5*j + 1) % 16;
			}
			else if (j < 48)
			{
				F = B ^ C ^ D;
				g = (3*j + 5) % 16;
			}
			else
			{
				F = C ^ (B | ~D);
				g = (7*j) % 16;
			}
			F = F + A + MD5_K[j] + ((uint32_t *)chunk)[g];
			A = D;
			D = C;
			C = B;
			B = B + LEFT_ROTATE(F, s[j]);
			j++;
		}
		ctx->md5[0] += A;
		ctx->md5[1] += B;
		ctx->md5[2] += C;
		ctx->md5[3] += D;
		i += 64;
	}
}
*/

/*
char				*hash_md5(char *input, uint64_t input_len)
{
	char			*digested;
	char			*tmp;
	t_context		ctx;
	size_t			j;

	init_md5_context(&ctx);
	input = append_padding(input, input_len);
	input = add_64bit_rep(input, input_len << 3, LEN_ALIGN(input_len));

	process_blocks(input, input_len, &ctx);
	ft_strdel(&input);

	j = 0;
	digested = ft_strnew(32);
	while (j < 4)
	{
		tmp = bytes_to_ascii(ctx.md5[j], sizeof(uint32_t));
		ft_strncpy(digested + (j << 3), tmp, sizeof(uint32_t) << 1);
		ft_strdel(&tmp);
		++j;
	}
	return (digested);
}
*/