#include "libft.h"

char		*ft_upperstr(char *str)
{
	char	*new;
	ssize_t	i;

	if (str == NULL)
		return (NULL);
	if (!(new = ft_strnew(ft_strlen(str))))
		return (NULL);
	i = -1;
	while (str[++i])
		new[i] = (char)ft_toupper(str[i]);
	return (new);
}
