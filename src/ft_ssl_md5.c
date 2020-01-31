#include "ft_ssl_md5.h"
#include <stdio.h>

void				print_usage(void)
{
	ft_putendl("usage: ft_ssl command [command opts] [command args]");
}

char				*hash_md5(char *input)
{
	char			*outbuf;
	char			*cmdbuf;
	char			*cmd = "md5sum - ";
	FILE			*hash;

	if (!(outbuf = ft_memalloc(MD5 + 1)))
		return (NULL);
	if (!(cmdbuf = ft_memalloc(ft_strlen(input) + ft_strlen(cmd) + 
			ft_strlen("echo \'\' | "))))
		return (NULL);
	sprintf(cmdbuf, "echo \'%s\' | %s", input, cmd);
	hash = popen(cmdbuf, "r");
	if (fgets(outbuf, MD5 + 1, hash))
		return (outbuf);
	return (NULL);
}

char				*hash_sha256(char *input)
{
	char			*outbuf;
	char			*cmdbuf;
	char			*cmd = "sha256sum - ";
	FILE			*hash;

	if (!(outbuf = ft_memalloc(SHA256 + 1)))
		return (NULL);
	if (!(cmdbuf = ft_memalloc(ft_strlen(input) + ft_strlen(cmd) + 
			ft_strlen("echo \'\' | "))))
		return (NULL);
	sprintf(cmdbuf, "echo \'%s\' | %s", input, cmd);
	hash = popen(cmdbuf, "r");
	if (fgets(outbuf, SHA256 + 1, hash))
		return (outbuf);
	return (NULL);
}

int					main(int argc, char **argv)
{
	const t_hashfuncs	hashfuncs[] = {
		{"md5",		MD5,	hash_md5	},
		{"sha256",	SHA256,	hash_sha256	}
	};

	if (argc < 2)
	{
		print_usage();
		return (0);
	}
	int i = 0;
	while (i < 2 && !ft_strequ(argv[1], hashfuncs[i].name))
		i++;
	if (i >= 2)
		return (1);
	ft_putendl(hashfuncs[i].hashfunc(argv[2]));
	return (0);
}