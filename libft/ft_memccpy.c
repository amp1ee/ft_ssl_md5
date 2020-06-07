/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memccpy.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/31 18:48:09 by oahieiev          #+#    #+#             */
/*   Updated: 2017/10/31 18:48:32 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memccpy(void *dst, const void *src, int c, size_t n)
{
	size_t			i;
	unsigned char	*p_dst;
	unsigned char	*p_src;

	if (n == 0)
		return (0);
	p_dst = (unsigned char *)dst;
	p_src = (unsigned char *)src;
	i = 0;
	while (i < n)
	{
		if (*p_src != (unsigned char)c)
			*(p_dst++) = *(p_src++);
		else
		{
			*(p_dst++) = *(p_src++);
			return (p_dst);
		}
		i++;
	}
	return (0);
}
