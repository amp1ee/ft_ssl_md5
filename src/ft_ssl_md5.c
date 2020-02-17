#include "ft_ssl_md5.h"
#include <stdio.h>
#include <errno.h>

#define TMPFILE "/tmp/fprintf.tmp"

unsigned char	s[64] = {
	7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
	5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
	4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
	6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

uint32_t		K[64] = {
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


void				print_usage(void)
{
	ft_putendl("usage: ft_ssl command [command opts] [command args]");
}

char		*hash_sha256(char *input, uint64_t input_len)
{
	(void)input_len;
	return (input);
}

char				*append_padding(char *input, size_t input_len)
{
	const size_t	padded_len = MD5_ALIGN(input_len);
	char			*padded;

	if (!(padded = ft_memalloc(padded_len)))
		return (NULL);
	ft_memcpy(padded, input, input_len);
	if (++input_len <= (padded_len - 8))
		padded[input_len - 1] = 0x80;
	while (++input_len <= (padded_len - 8))
		padded[input_len - 1] = 0x0;
	return (padded);
}

char				*add_64bit_rep(char *input, uint64_t input_len)
{
	const size_t	padded_len = MD5_ALIGN(input_len);
	size_t			pos;

	fprintf(fopen(TMPFILE, "a"), "%zu\n", padded_len);

	input_len <<= 3;
	pos = padded_len - 8;
	while (pos < padded_len) {
		input[pos++] = (char)(input_len & 0xff);
		input[pos++] = (char)((input_len >> 8) & 0xff);
		input[pos++] = (char)((input_len >> 16) & 0xff);
		input[pos++] = (char)((input_len >> 24) & 0xff);
		input_len >>= 32;
	}
	return (input);
}

void				initialize_context(t_md5ctx *ctx)
{
	const uint32_t	a0 = 0x67452301;
	const uint32_t	b0 = 0xefcdab89;
	const uint32_t	c0 = 0x98badcfe;
	const uint32_t	d0 = 0x10325476;
	ctx->state[0] = a0;
	ctx->state[1] = b0;
	ctx->state[2] = c0;
	ctx->state[3] = d0;
	ctx->count[0] = 0;
	ctx->count[1] = 0;
}

void				process_blocks(char *padded, size_t input_len,
									t_md5ctx *ctx)
{
	const size_t	padded_len = MD5_ALIGN(input_len);
	size_t			i;
	char			chunk[64];
	uint32_t		A, B, C, D, j;
	uint32_t		F, g;

	i = 0;
	while (i < padded_len)
	{
		ft_memcpy(chunk, &padded[i], 64);
		A = ctx->state[0];
		B = ctx->state[1];
		C = ctx->state[2];
		D = ctx->state[3];
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
			F = F + A + K[j] + ((uint32_t *)chunk)[g];
			A = D;
			D = C;
			C = B;
			B = B + LEFT_ROTATE(F, s[j]);
			j++;
		}
		ctx->state[0] += A;
		ctx->state[1] += B;
		ctx->state[2] += C;
		ctx->state[3] += D;
		i += 64;
	}
}

char			*bytes_to_ascii(uint64_t bytes, size_t size)
{
	const char	*hexbase = "0123456789abcdef";
	char		*ascii;
	size_t		i;
	size_t		j;

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

char		*hash_md5(char *input, uint64_t input_len)
{
	char			*digested;
	t_md5ctx		ctx;
	size_t			j;

	initialize_context(&ctx);
	input = append_padding(input, input_len);
	input = add_64bit_rep(input, input_len);

	process_blocks(input, input_len, &ctx);
	ft_strdel(&input);

	j = 0;
	char	*tmp;
	digested = ft_strnew(32);
	while (j < 4)
	{
		tmp = bytes_to_ascii(ctx.state[j], sizeof(uint32_t));
		ft_strncpy(digested + (j << 3), tmp, sizeof(uint32_t) << 1);
		ft_strdel(&tmp);
		++j;
	}
	return (digested);
}

int					main(int argc, char **argv)
{
	const t_hashfuncs	hashfuncs[] = {
		{"md5",		MD5,	hash_md5	},
		{"sha256",	SHA256,	hash_sha256	}
	};
	const char			*opts = "pqrs:";
	int					opt;
	int					flags;
	char				*msg = NULL;
	int					optind;

	if (argc < 3)
	{
		print_usage();
		return (0);
	}
	int i = 0;
	while (i < 2 && !ft_strequ(argv[1], hashfuncs[i].name))
		i++;
	if (i >= 2)
		return (1);
	flags = 0;
	while ((opt = ft_getopt(argc - 1, &argv[1], opts, &optind)) != -1)
	{
		if (opt == 'p')
			flags |= PRINT_STDINOUT;
		else if (opt == 'q')
			flags |= QUIET_MODE;
		else if (opt == 'r')
			flags |= REVERSE_FMT;
		else if (opt == 's')
		{
			flags |= GIVEN_STRING;
			msg = argv[optind];
		}
		else
			print_usage();
	}
	char	*digested;
	if (flags & GIVEN_STRING && msg)
	{
		digested = hashfuncs[i].hashfunc(msg, (uint64_t)ft_strlen(msg));
		printf("%s\n", digested);
		ft_strdel(&digested);
	}
	return (0);
}
