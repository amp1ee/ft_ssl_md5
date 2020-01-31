/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_next_line.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/02/04 16:53:56 by oahieiev          #+#    #+#             */
/*   Updated: 2018/02/04 16:53:59 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "get_next_line.h"

char	*strjoin(char **s1, char const *s2)
{
	char	*join;
	char	*s1_bak;
	int		i;

	if (!s1 && !s2)
		return (0);
	else if (!s1)
		return ((char *)s2);
	else if (!s2)
		return (*s1);
	s1_bak = *s1;
	if (!(join = ft_strnew(ft_strlen(s1_bak) + ft_strlen(s2))))
		return (0);
	i = 0;
	while (*s1_bak)
		join[i++] = *s1_bak++;
	ft_strdel(s1);
	while (*s2)
		join[i++] = *s2++;
	join[i] = '\0';
	return (join);
}

int		line_length(char *buf, int count)
{
	int		len;

	len = 0;
	while (buf[len] != '\n' && len < count)
		len++;
	return (len);
}

t_list	*handle_fdesc(int fd, t_list **head)
{
	t_list	*lst;

	lst = *head;
	while (lst)
	{
		if ((int)lst->content_size == fd)
			return (lst);
		lst = lst->next;
	}
	if (!(lst = (t_list *)malloc(sizeof(t_list))))
		return (NULL);
	lst->content = NULL;
	lst->content_size = fd;
	ft_lstadd(head, lst);
	return (lst);
}

int		read_fd(const int fd, char **line, char **prev)
{
	char		buf[BUFF_SIZE + 1];
	char		*str;
	int			rv;
	int			l;
	int			len;

	while ((rv = read(fd, buf, BUFF_SIZE)))
	{
		buf[rv] = '\0';
		l = line_length(buf, rv);
		if (l < rv)
		{
			len = ft_strlen(*line);
			*line = strjoin(line, buf);
			str = *line;
			*line = ft_strsub(*line, 0, l + len);
			ft_strdel(&str);
			*prev = (*prev) ? strjoin(prev, ft_strsub(buf, l + 1, rv - l))
				: ft_strsub(buf, l + 1, rv - l);
			return (1);
		}
		else
			*line = strjoin(line, buf);
	}
	return (0);
}

int		get_next_line(const int fd, char **line)
{
	static t_list	*head;
	t_list			*cur;
	char			*str;
	int				l;
	int				len;

	if (fd < 0 || !line || !(*line = ft_strnew(0)) || read(fd, NULL, 0) < 0
		|| !(cur = handle_fdesc(fd, &head)))
		return (-1);
	if (cur->content)
	{
		ft_strdel(line);
		len = ft_strlen(cur->content);
		l = line_length(cur->content, len);
		(l < len) ? str = cur->content : 0;
		*line = ft_strndup(cur->content, l);
		(l < len) ? cur->content = ft_strsub(cur->content, l + 1, len - l) : 0;
		(l < len) ? ft_strdel(&str) : ft_strdel((char **)&cur->content);
		if (l < len)
			return ((*line && cur->content) ? 1 : -1);
	}
	if (read_fd(fd, line, (char **)&cur->content) || ft_strlen(*line))
		return (1);
	ft_strdel(line);
	return (0);
}
