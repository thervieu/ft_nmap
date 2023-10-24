NAME = ft_nmap

SRCS_DIR = ./srcs/

SRCS =	ft_nmap.c parser.c

OBJS_DIR = objs/

OBJ = $(SRCS:.c=.o)

OBJS = $(addprefix $(OBJS_DIR), $(OBJ))

FLAGS = -Wall #-Wextra -Werror

$(OBJS_DIR)%.o : $(SRCS_DIR)%.c
	@mkdir -p $(OBJS_DIR)
	@echo "Compiling" $<
	@gcc $(FLAGS) -lpthread -c $< -o $@ #-lpcap 
$(NAME): $(OBJS)
	@gcc $(FLAGS) -lpthread -o $(NAME) $(OBJS) #-lpcap 
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
