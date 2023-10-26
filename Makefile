NAME = ft_nmap

SRCS_DIR = ./srcs/

SRCS =	ft_nmap.c		\
		parser.c		\
		ft_strsplit.c	\
		ft_strsub.c		\
		loop.c			\
		configure.c		\
		scan.c \
		ip.c

OBJS_DIR = objs/

OBJ = $(SRCS:.c=.o)

OBJS = $(addprefix $(OBJS_DIR), $(OBJ))

FLAGS = -Wall -Wextra -Werror

INC_DIR = ./incs
INC = ft_nmap.h
HEAD = $(INC_DIR)/$(INC)

$(OBJS_DIR)%.o : $(SRCS_DIR)%.c
	@mkdir -p $(OBJS_DIR)
	@echo "Compiling" $<
	@gcc $(FLAGS) -I $(INC_DIR) -pthread -c $< -o $@ -lpcap

#$(OBJS): $(HEAD)

$(NAME): $(OBJS)
	@gcc $(FLAGS) -I $(INC_DIR) -pthread -o $(NAME) $(OBJS) -lpcap
	@echo "Exec ft_nmap created !"
	@echo "usage: ./ft_nmap [equation]"

all: $(NAME)

clean:
	@echo "Removing objs"
	@rm -rf $(OBJS_DIR)

fclean: clean
	@echo "Removing exec"
	@rm -f $(NAME)

re: fclean all

.PHONY:	all clean fclean re
