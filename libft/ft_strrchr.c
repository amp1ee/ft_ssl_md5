/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strrchr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/31 18:17:30 by oahieiev          #+#    #+#             */
/*   Updated: 2017/10/31 18:17:44 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strrchr(const char *s, int c)
{
	size_t	s_len;

	s_len = ft_strlen(s);
	if (c == 0)
		return ((char *)s + s_len);
	else
		while (s_len--)
			if (*(s + s_len) == (char)c)
				return ((char *)(s + s_len));
	return (0);
}
