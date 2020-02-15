#ifndef _FT_SSL_MD5_H_
# define _FT_SSL_MD5_H_

# include <stdlib.h>
# include <unistd.h>
# include <fcntl.h>
# include "libft.h"

# define MD5_ALIGN(x)	(((((((x + 8) << 3) + 0x1FF) & ~0x1FF)) >> 3) - 8)

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

char				*hash_md5(char *input, size_t input_len);
char				*hash_sha256(char *input, size_t input_len);

typedef struct		s_hashfuncs
{
	char			*name;
	t_hashtypes		type;
	char			*(*hashfunc)(char *input, size_t input_len);
}					t_hashfuncs;

#endif