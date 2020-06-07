/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strmapi.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/02 21:09:37 by oahieiev          #+#    #+#             */
/*   Updated: 2017/11/02 21:09:39 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strmapi(char const *s, char (*f)(unsigned int, char))
{
	char			*new;
	size_t			s_len;
	unsigned int	i;

	if (!s)
		return (0);
	s_len = ft_strlen(s);
	new = (char *)malloc(sizeof(char) * (s_len + 1));
	if (!new)
		return (0);
	i = 0;
	while (*s)
		*new++ = f(i++, *s++);
	*new = '\0';
	return (new - s_len);
}
