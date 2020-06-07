/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strdup.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/31 18:28:17 by oahieiev          #+#    #+#             */
/*   Updated: 2017/10/31 18:28:19 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_strdup(const char *s1)
{
	char	*new;
	char	*b;

	new = (char *)malloc(sizeof(char) * (ft_strlen(s1) + 1));
	b = new;
	if (new)
	{
		while (*s1)
			*new++ = *s1++;
		*new = '\0';
	}
	return (b);
}
