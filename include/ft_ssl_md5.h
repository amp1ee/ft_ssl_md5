#ifndef _FT_SSL_MD5_H_
# define _FT_SSL_MD5_H_

# include <stdlib.h>
# include <unistd.h>
# include <fcntl.h>
# include <stdint.h>
# include "libft.h"

# define LEN_ALIGN(x)		(((((((x + 9) << 3) + 511) & ~511)) >> 3))
# define ENDIAN_SWP(x) \
		 ((((x) & 0xff00000000000000ull) >> 56)					\
		| (((x) & 0x00ff000000000000ull) >> 40)					\
		| (((x) & 0x0000ff0000000000ull) >> 24)					\
		| (((x) & 0x000000ff00000000ull) >> 8)					\
		| (((x) & 0x00000000ff000000ull) << 8)					\
		| (((x) & 0x0000000000ff0000ull) << 24)					\
		| (((x) & 0x000000000000ff00ull) << 40)					\
		| (((x) & 0x00000000000000ffull) << 56))
# define LEFT_ROTATE(x, c)	(((x) << (c)) | ((x) >> (32-(c))))
# define RIGHT_ROTATE(x, c)	(((x) >> (c)) | ((x) << (32-(c))))

#define TMPFILE "/tmp/fprintf.tmp"

typedef enum		e_options
{
	PRINT_STDINOUT = 1,
	QUIET_MODE = 2,
	REVERSE_FMT = 4,
	GIVEN_STRING = 8
}					t_options;

typedef enum		e_hashtypes
{
	MD5 = 32,
	SHA256 = 64
}					t_hashtypes;

char				*hash_md5(char *input, uint64_t input_len);
char				*hash_sha256(char *input, uint64_t input_len);

typedef struct		s_hashfuncs
{
	char			*name;
	t_hashtypes		type;
	char			*(*hashfunc)(char *input, uint64_t input_len);
}					t_hashfuncs;

typedef struct		s_md5ctx
{
	uint32_t		state[4];
	uint32_t		count[2];
}					t_md5ctx;

typedef struct		s_sha2ctx
{
	uint32_t		state[8];
	uint32_t		count[2];
}					t_sha2ctx;

char				*append_padding(char *input, uint64_t input_len);
char				*add_64bit_rep(char *input, uint64_t input_len,
												uint64_t padded_len);
char				*bytes_to_ascii(uint64_t bytes, size_t size);


#endif