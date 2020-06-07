/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstnew.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/02 21:07:02 by oahieiev          #+#    #+#             */
/*   Updated: 2017/11/02 21:07:04 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

t_list	*ft_lstnew(void const *content, size_t content_size)
{
	t_list	*new;

	if (!(new = (t_list *)malloc(sizeof(t_list))))
		return (NULL);
	new->content = (content) ? malloc(content_size) : NULL;
	new->content = (content) ?
		ft_memcpy(new->content, content, content_size) : NULL;
	new->content_size = (content) ? content_size : 0;
	new->next = NULL;
	return (new);
}
