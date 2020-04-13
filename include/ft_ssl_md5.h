#ifndef _FT_SSL_MD5_H_
# define _FT_SSL_MD5_H_

# include <stdlib.h>
# include <unistd.h>
# include <fcntl.h>
# include <stdio.h>
# include <errno.h>
# include <stdint.h>
# include "libft.h"

# define LEN_ALIGN(x)		((((((((x) +  9) << 3) +  511) &  ~511)) >> 3))
# define LEN_ALIGN_128(x)	((((((((x) + 17) << 3) + 1023) & ~1023)) >> 3))
# define LEFT_ROTATE(x, c)	(((x) << (c)) | ((x) >> (32-(c))))
# define RIGHT_ROTATE(x, c)	(((x) >> (c)) | ((x) << (32-(c))))
# define RIGHT_ROT_64(x, c)	(((x) >> (c)) | ((x) << (64-(c))))

# define A		0
# define B		1
# define C		2
# define D		3
# define E		4
# define F		5
# define G		6
# define H		7

typedef unsigned __int128			uint128_t;

typedef enum			e_options
{
	PRINT_STDINOUT = 1,
	QUIET_MODE = 2,
	REVERSE_FMT = 4
}						t_option;

typedef enum			e_hash_types
{
	NO_TYPE = 0,
	MD5,
	SHA256,
	SHA224,
	SHA512,
	SHA384
}						t_hash_type;

typedef struct			s_context
{
	uint64_t			sha5[8];
	uint32_t			sha2[8];
	uint32_t			md5[4];
}						t_context;

typedef enum			e_argtypes
{
	EMPTY = 0,
	P_STDIN,
	S_STRING,
	F_FILE,
	ERR
}						t_argtype;

typedef struct			s_input_arg
{
	t_argtype			type;
	char				*str;
	char				*digest;
	size_t				str_len;
}						t_input;

typedef struct			s_algorithm
{
	char				*name;
	t_hash_type			type;
	void				(*hashfunc)(t_context *ctx, char *chunk);
	void				(*init_ctx)(t_context *ctx);
	char				*(*append_padding)(char *input, uint128_t input_len);
	char				*(*append_length)(char *input, uint128_t input_len,
										uint128_t padded_len);
	void				(*build_digest_msg)(t_input *arg, t_context ctx,
								unsigned digest_len, unsigned chunk_len);
	unsigned			digest_len;
	unsigned			chunk_len;
	t_context			ctx;
}						t_algo;

// TODO: rename?
typedef struct			s_global
{
	t_algo				algo;
	char				*self_name;
	char				*name;
	int					argc;
	char				**argv;
	unsigned			flags;
	t_list				*inputs;
}						t_global;

void					exit_nomem(t_global *g);

char					*append_padding_md5sha2(char *buf, uint128_t buf_len);
char					*append_padding_sha5(char *buf, uint128_t buf_len);

char					*add_64bit_len_md5sha2(char *input, uint128_t append_len,
												uint128_t padded_len);
char					*add_128bit_len_sha5(char *input, uint128_t append_len,
											uint128_t padded_len);

char					*bytes_to_ascii(uint64_t bytes, size_t size);

void					hash_md5(t_context *ctx, char *chunk);
void					hash_sha2(t_context *ctx, char *chunk);
void					hash_sha5(t_context *ctx, char *chunk);

void					init_md5_context(t_context *ctx);
void					init_sha256_context(t_context *ctx);
void					init_sha224_context(t_context *ctx);
void					init_sha512_context(t_context *ctx);
void					init_sha384_context(t_context *ctx);

void					build_digest_msg_md5(t_input *arg, t_context ctx,
								unsigned digest_len, unsigned chunk_len);
void					build_digest_msg_sha2(t_input *arg, t_context ctx,
								unsigned digest_len, unsigned chunk_len);
void					build_digest_msg_sha5(t_input *arg, t_context ctx,
								unsigned digest_len, unsigned chunk_len);

uint32_t				swap_uint32(uint32_t val);
uint64_t				swap_uint64(uint64_t val);
void					swap_words(uint64_t *words, int wsize, int n);

static const t_algo			g_algorithms[] = {
	{"md5", MD5, hash_md5, init_md5_context, append_padding_md5sha2,
	add_64bit_len_md5sha2, build_digest_msg_md5,
	.digest_len = 32, .chunk_len = 64 },
	{"sha256", SHA256, hash_sha2, init_sha256_context, append_padding_md5sha2,
	add_64bit_len_md5sha2, build_digest_msg_sha2,
	.digest_len = 64, .chunk_len = 64 },
	{"sha224", SHA224, hash_sha2, init_sha224_context, append_padding_md5sha2,
	add_64bit_len_md5sha2, build_digest_msg_sha2,
	.digest_len = 56, .chunk_len = 64 },
	{"sha512", SHA512, hash_sha5, init_sha512_context, append_padding_sha5,
	add_128bit_len_sha5, build_digest_msg_sha5,
	.digest_len = 128, .chunk_len = 128 },
	{"sha384", SHA384, hash_sha5, init_sha384_context, append_padding_sha5,
	add_128bit_len_sha5, build_digest_msg_sha5,
	.digest_len = 96, .chunk_len = 128 }
};

# define NUM_ALGOS (sizeof(g_algorithms) / sizeof(t_algo))

#endif
