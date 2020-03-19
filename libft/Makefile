NAME	= libft.a
SRC		= ft_memcpy.c	ft_putstr.c		\
		ft_striteri.c	ft_strnstr.c	\
		ft_atoi.c		ft_lstadd.c		\
		ft_memdel.c		ft_putstr_fd.c	\
		ft_strjoin.c	ft_strrchr.c	\
		ft_bzero.c		ft_lstdel.c		\
		ft_memmove.c	ft_strcat.c		\
		ft_strlcat.c	ft_strsplit.c	\
		ft_isalnum.c	ft_lstdelone.c	\
		ft_memset.c		ft_strchr.c		\
		ft_strlen.c		ft_strstr.c		\
		ft_isalpha.c	ft_lstiter.c	\
		ft_pow.c		ft_strclr.c		\
		ft_strmap.c		ft_strsub.c		\
		ft_isascii.c	ft_lstmap.c		\
		ft_putchar.c	ft_strcmp.c		\
		ft_strmapi.c	ft_strtrim.c	\
		ft_isblank.c	ft_lstnew.c		\
		ft_putchar_fd.c	ft_strcpy.c		\
		ft_strncat.c	ft_tolower.c	\
		ft_isdelim.c	ft_memalloc.c	\
		ft_putendl.c	ft_strdel.c		\
		ft_strncmp.c	ft_toupper.c	\
		ft_isdigit.c	ft_memccpy.c	\
		ft_putendl_fd.c	ft_strlcpy.c	\
		ft_strdup.c		ft_strncpy.c	\
		ft_isprint.c	ft_memchr.c		\
		ft_putnbr.c		ft_putunbr.c	\
		ft_strequ.c		ft_strndup.c	\
		ft_strnequ.c	ft_itoa.c		\
		ft_memcmp.c		ft_putnbr_fd.c	\
		ft_striter.c	ft_strnew.c		\
		ft_lstfold.c	ft_itoa_base.c	\
		get_next_line.c	ft_atoi_base.c	\
		ft_lstreverse.c	ft_strpos.c		\
		ft_atof.c		ft_getopt.c		\
		ft_upperstr.c

.PHONY: all clean fclean re

CC = gcc
CFLAGS = -fPIC -Wall -Wextra -Werror
ifdef DEBUG
	CFLAGS += -g
endif

OBJ=$(SRC:%.c=%.o)

$(NAME): $(OBJ)
	@ar rc $@ $^
	@ranlib $@
	@printf '\t\t$@ is ready              \n'

%.o: %.c
	@printf '\t\tCompiling $(NAME) sources\r'
	@$(CC) $(CFLAGS) -o $@ -c $^

all: $(NAME)

clean:
	@rm -f $(OBJ)
	@printf '\t$(NAME) object files deleted\n'

fclean: clean
	@rm -f $(NAME)
	@printf '\t$(NAME) deleted\n'
re: fclean all
