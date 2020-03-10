#ifndef _FT_SSL_MD5_H_
# define _FT_SSL_MD5_H_

# include <stdlib.h>
# include <unistd.h>
# include <fcntl.h>
# include <stdint.h>
# include "libft.h"

# define LEN_ALIGN(x)		(((((((x + 9) << 3) + 511) & ~511)) >> 3))
/*# define ENDIAN_SWP(x) \
		 ((((x) & 0xff00000000000000ull) >> 56)					\
		| (((x) & 0x00ff000000000000ull) >> 40)					\
		| (((x) & 0x0000ff0000000000ull) >> 24)					\
		| (((x) & 0x000000ff00000000ull) >> 8)					\
		| (((x) & 0x00000000ff000000ull) << 8)					\
		| (((x) & 0x0000000000ff0000ull) << 24)					\
		| (((x) & 0x000000000000ff00ull) << 40)					\
		| (((x) & 0x00000000000000ffull) << 56))*/
# define LEFT_ROTATE(x, c)	(((x) << (c)) | ((x) >> (32-(c))))
# define RIGHT_ROTATE(x, c)	(((x) >> (c)) | ((x) << (32-(c))))

#define TMPFILE "/tmp/fprintf.tmp"

typedef enum			e_opt_type
{
	PRINT_STDINOUT = 1,
	QUIET_MODE = 2,
	REVERSE_FMT = 4,
	GIVEN_STRING = 8
}						t_opt_type;

typedef enum			e_hash_type
{
	NO_TYPE = 0,
	MD5,
	SHA256
}						t_hash_type;

char					*hash_md5(char *input, uint64_t input_len);
char					*hash_sha256(char *input, uint64_t input_len);

typedef struct			s_context
{
	uint32_t			sha2[8];
	uint32_t			md5[4];
}						t_context;

void				init_sha2_context(t_context *ctx);
void				init_md5_context(t_context *ctx);

typedef struct			s_algorithm
{
	char				*name;
	t_hash_type			type;
	char				*(*hashfunc)(char *input, uint64_t input_len);
	void				(*init_ctx)(t_context *ctx);
	unsigned			digest_len;
	unsigned			chunk_len;
	t_context			ctx;
}						t_algo;

static const t_algo			g_algorithms[] = {
		{"md5", 	MD5,	hash_md5,	init_md5_context,
		.digest_len = 32, .chunk_len = 64 },
		{"sha256",	SHA256,	hash_sha256,init_sha2_context,
		.digest_len = 64, .chunk_len = 64 }
};

// TODO: rename
typedef struct			s_global
{
	t_algo				algo;
	char				*name;
	int					argc;
	char				**argv;
	unsigned			flags;
	t_list				*str_opts;
	t_list				*files;
}						t_global;

# define NUM_ALGOS (sizeof(g_algorithms) / sizeof(t_algo))

char					*append_padding(char *input, uint64_t input_len);
char					*add_64bit_rep(char *input, uint64_t input_len,
												uint64_t padded_len);
char					*bytes_to_ascii(uint64_t bytes, size_t size);

#endif