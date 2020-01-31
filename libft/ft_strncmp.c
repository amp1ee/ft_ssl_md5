/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strncmp.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/31 18:27:02 by oahieiev          #+#    #+#             */
/*   Updated: 2017/10/31 18:27:21 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int		ft_strncmp(const char *s1, const char *s2, size_t n)
{
	unsigned char	*us1;
	unsigned char	*us2;
	size_t			i;

	i = 0;
	us1 = (unsigned char *)s1;
	us2 = (unsigned char *)s2;
	if (!(*s1) && !(*s2))
		return (0);
	else if (!(*s1))
		return (-1);
	else
		while (i < n && (*us1 || *us2))
		{
			if (*us1 != *us2)
				return (*us1 - *us2);
			us1++;
			us2++;
			i++;
		}
	return (0);
}
