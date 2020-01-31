#include "ft_ssl_md5.h"

void			print_usage(void)
{
	ft_putendl("usage: ft_ssl command [command opts] [command args]");
}

int				main(int argc, char **argv)
{
	if (argc < 2)
		print_usage();
	(void)argv;
	return (0);
}