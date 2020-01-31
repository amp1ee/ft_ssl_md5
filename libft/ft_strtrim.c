/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtrim.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/02 21:08:04 by oahieiev          #+#    #+#             */
/*   Updated: 2017/11/02 21:08:06 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int		is_whitespace(char c)
{
	return (c == ' ' || c == '\n' || c == '\t');
}

char			*ft_strtrim(char const *s)
{
	int		start;
	int		end;
	char	*trim;
	int		len;

	if (!s)
		return (0);
	start = 0;
	while (is_whitespace(s[start]))
		start++;
	end = ft_strlen(s);
	while (is_whitespace(s[end - 1]))
		end--;
	if ((len = (end - start)) <= 0)
		return (ft_strnew(0));
	if (!(trim = (char *)malloc((len + 1) * sizeof(char))))
		return (0);
	while (start < end)
		*trim++ = s[start++];
	*trim = '\0';
	return (trim - len);
}
