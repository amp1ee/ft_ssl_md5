/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strstr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/31 18:17:03 by oahieiev          #+#    #+#             */
/*   Updated: 2017/10/31 18:17:04 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strstr(const char *big, const char *little)
{
	size_t		i;
	size_t		j;

	i = 0;
	if (!little[i])
		return ((char *)big);
	else
		while (big[i])
		{
			j = 0;
			while (little[j])
			{
				if (little[j] != big[i + j])
					break ;
				j++;
			}
			if (j == ft_strlen(little))
				return ((char *)big + i);
			i++;
		}
	return (NULL);
}
