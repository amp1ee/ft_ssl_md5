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

void				init_sha2_context(t_context *ctx)
{
	ctx->sha2[0] = 0x6A09E667;
	ctx->sha2[1] = 0xBB67AE85;
	ctx->sha2[2] = 0x3C6EF372;
	ctx->sha2[3] = 0xA54FF53A;
	ctx->sha2[4] = 0x510E527F;
	ctx->sha2[5] = 0x9B05688C;
	ctx->sha2[6] = 0x1F83D9AB;
	ctx->sha2[7] = 0x5BE0CD19;
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

void				build_digest_msg_sha2(t_input *arg, t_context ctx,
										unsigned digest_len, unsigned chunk_len)
{
	char			*tmp;
	uint32_t		*ctx_buf;
	size_t			j;
	size_t			out_len;

	ctx_buf = ctx.sha2;
	arg->digest = ft_strnew(digest_len);
	out_len = (digest_len << 3) / chunk_len;
	j = 0;
	while (j < out_len)
	{
		tmp = bytes_to_ascii(swap_uint32(ctx_buf[j]), sizeof(uint32_t));
		ft_strncpy(arg->digest + (j << 3), tmp, sizeof(uint32_t) << 1);
		ft_strdel(&tmp);
		j++;
	}
}

void				hash_sha256(t_context *ctx, char *chunk)
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
