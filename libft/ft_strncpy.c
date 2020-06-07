/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strncpy.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/31 18:20:29 by oahieiev          #+#    #+#             */
/*   Updated: 2017/10/31 18:20:30 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strncpy(char *dst, const char *src, size_t len)
{
	size_t	i;
	char	*p;

	i = 0;
	p = dst;
	while (*src && i < len)
	{
		*(dst++) = *(src++);
		i++;
	}
	while (i < len)
	{
		*(dst++) = '\0';
		i++;
	}
	return (p);
}
