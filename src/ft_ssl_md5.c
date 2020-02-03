#include "ft_ssl_md5.h"
#include <stdio.h>

# define MD5_ALIGN(x)	((((x + 64) + 511) & ~511) - 64)

void				print_usage(void)
{
	ft_putendl("usage: ft_ssl command [command opts] [command args]");
}

char				*hash_sha256(char *input)
{
	return (input);
}

char				*append_padding(char *input)
{
	size_t			input_len;
	size_t			padded_len;
	char			*padded;

	input_len = ft_strlen(input);
	padded_len = input_len;
	padded_len = MD5_ALIGN(input_len);
	if (!(padded = ft_memalloc(padded_len)))
		return (NULL);
	ft_strncpy(padded, input, input_len);
	if (++input_len <= padded_len)
		padded[input_len - 1] = '1';
	while (++input_len <= padded_len)
		padded[input_len - 1] = '0';
	return (padded);
}

char				*hash_md5(char *input)
{
//	char			*outbuf;
//	char			md5bufs[64][4];

	input = append_padding(input);
	return (input);
	//input = add_64bit_rep(input);
	//initialize_buffers(&md5bufs);
//outbuf = process_blocks(input, md5bufs);
//	return (outbuf);
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
		digested = hashfuncs[i].hashfunc(msg);
		ft_putstr(digested);
		ft_strdel(&digested);
	}
	return (0);
}