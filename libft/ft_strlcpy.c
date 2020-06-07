/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlcpy.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/04 17:36:35 by oahieiev          #+#    #+#             */
/*   Updated: 2017/11/04 17:36:36 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

size_t		ft_strlcpy(char *dst, const char *src, size_t size)
{
	const char	*src_o;

	src_o = src;
	if (!src)
		return (0);
	while ((size-- - 1) && *src)
		*(dst++) = *(src++);
	*dst = '\0';
	while (*src)
		src++;
	return (src - src_o);
}
