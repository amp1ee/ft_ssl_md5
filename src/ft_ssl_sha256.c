#include "ft_ssl_md5.h"
// delete these:
#include <stdio.h>
#include <byteswap.h>

uint32_t			g_sha2_k[64] = {
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
	0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
	0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
	0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
	0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
	0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
	0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
	0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
	0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

void				init_sha2_context(t_sha2ctx *ctx)
{
	ctx->state[0] = 0x6A09E667;
	ctx->state[1] = 0xBB67AE85;
	ctx->state[2] = 0x3C6EF372;
	ctx->state[3] = 0xA54FF53A;
	ctx->state[4] = 0x510E527F;
	ctx->state[5] = 0x9B05688C;
	ctx->state[6] = 0x1F83D9AB;
	ctx->state[7] = 0x5BE0CD19;
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

	tmp[0] = RIGHT_ROTATE(h[0], 2) ^ RIGHT_ROTATE(h[0], 13)
				^ RIGHT_ROTATE(h[0], 22);
	tmp[1] = (h[0] & h[1]) ^ (h[0] & h[2]) ^ (h[1] & h[2]);
	tmp[2] = RIGHT_ROTATE(h[4], 6) ^ RIGHT_ROTATE(h[4], 11)
				^ RIGHT_ROTATE(h[4], 25);
	tmp[3] = (h[4] & h[5]) ^ ((~h[4]) & h[6]);
	tmp[4] = h[7] + tmp[2] + tmp[3] + g_sha2_k[j] + sched[j];
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

static void			process_blocks(char *padded, size_t input_len,
									t_sha2ctx *ctx)
{
	const size_t	padded_len = LEN_ALIGN(input_len);
	size_t			i;
	uint32_t		chunk[64];
	uint32_t		h[8];
	int 			j;

	i = 0;
	while (i < padded_len)
	{
		j = -1;
		while (++j < 8)
			h[j] = ctx->state[j];
		ft_memcpy((void *)chunk, (void *)&padded[i], 64);
		swap_words((uint64_t *)chunk, sizeof(uint32_t), 16);
		extend_words(chunk);
		j = -1;
		while (++j < 64)
			compress_loop(h, chunk, j);
		j = -1;
		while (++j < 8)
			ctx->state[j] += h[j];
		i += 64;
	}
}

char				*hash_sha256(char *input, uint64_t input_len)
{
	char			*digested;
	char			*tmp;
	t_sha2ctx		ctx;
	size_t			j;

	init_sha2_context(&ctx);
	input = append_padding(input, input_len);
	input = add_64bit_rep(input, swap_uint64(input_len << 3),
										LEN_ALIGN(input_len));
	process_blocks(input, input_len, &ctx);
	ft_strdel(&input);
	j = 0;
	digested = ft_strnew(64);
	while (j < 8)
	{
		tmp = bytes_to_ascii(swap_uint32(ctx.state[j]), sizeof(uint32_t));
		ft_strncpy(digested + (j << 3), tmp, sizeof(uint32_t) << 1);
		ft_strdel(&tmp);
		j++;
	}
	return (digested);
}