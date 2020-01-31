/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strmap.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/02 21:10:15 by oahieiev          #+#    #+#             */
/*   Updated: 2017/11/02 21:10:16 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strmap(char const *s, char (*f)(char))
{
	char	*new;
	size_t	s_len;

	if (!s)
		return (0);
	s_len = ft_strlen(s);
	new = (char *)malloc(sizeof(char) * (s_len + 1));
	if (!new)
		return (0);
	while (*s)
		*new++ = f(*s++);
	*new = '\0';
	return (new - s_len);
}
