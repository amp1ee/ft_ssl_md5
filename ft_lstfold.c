/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstfold.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/04 16:54:44 by oahieiev          #+#    #+#             */
/*   Updated: 2017/11/04 16:54:46 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_lstfold(t_list *elem, void *(*f)(void *, void *, size_t))
{
	void	*result;

	if (!elem || !f)
		return (NULL);
	result = elem->content;
	while (elem->next)
	{
		if (elem->content && elem->next->content)
		{
			result = f(result, elem->next->content,
				elem->next->content_size);
		}
		elem = elem->next;
	}
	return (result);
}
