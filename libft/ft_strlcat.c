/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlcat.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/31 18:27:57 by oahieiev          #+#    #+#             */
/*   Updated: 2017/10/31 18:27:59 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

size_t	ft_strlcat(char *dst, const char *src, size_t size)
{
	size_t	len;
	size_t	dst_len;
	char	*s;

	s = (char *)src;
	dst_len = ft_strlen(dst);
	dst_len = (size < dst_len) ? size : dst_len;
	if (!(len = size - dst_len))
		return (dst_len + ft_strlen(s));
	while (*s)
	{
		if (len != 1)
		{
			*(dst++ + dst_len) = *s;
			len--;
		}
		s++;
	}
	*(dst + dst_len) = '\0';
	return (dst_len + ft_strlen(src));
}
