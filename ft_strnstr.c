/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strnstr.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/31 18:18:40 by oahieiev          #+#    #+#             */
/*   Updated: 2017/10/31 18:18:42 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strnstr(const char *big, const char *little, size_t len)
{
	size_t		i;
	size_t		j;
	size_t		l_len;

	i = 0;
	if (ft_strlen(big) == 0)
		return (NULL);
	if (!little[i] || !big[i])
		return ((char *)big);
	if (len < (l_len = ft_strlen(little)))
		return (0);
	while (big[i] && i <= len - l_len)
	{
		j = 0;
		while (little[j])
		{
			if (little[j] != big[i + j])
				break ;
			j++;
		}
		if (j == l_len)
			return ((char *)big + i);
		i++;
	}
	return (NULL);
}
