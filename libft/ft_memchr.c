/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/31 18:47:17 by oahieiev          #+#    #+#             */
/*   Updated: 2017/10/31 18:47:36 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memchr(const void *s, int c, size_t n)
{
	size_t			i;
	unsigned char	*s1;

	s1 = (unsigned char *)s;
	if (n == 0)
		return (0);
	i = 0;
	while (i < n)
	{
		if (*s1 == (unsigned char)c)
			return (s1);
		i++;
		s1++;
	}
	return (0);
}
