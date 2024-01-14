NAME	:= ft_nmap
CFLAGS	:= -Wall -Wextra -Wunreachable-code
# CFLAGS	+= -Werror

HEADERS	:= -I ./include -I ./scripts
LIBS	:= -lpcap -lpthread
SRCS	:= $(shell find src -type f -name "*.c")
OBJS	:= $(SRCS:src/%.c=obj/%.o)

all: $(NAME)

obj/%.o: src/%.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ -c $< $(HEADERS) && echo "Compiled: $(notdir $<)"

$(NAME): $(OBJS)
	$(CC) $(OBJS) $(LIBS) $(HEADERS) -o $(NAME) && echo "Linked: $(NAME)"

clean:
	rm -rf $(OBJS) && echo "Removed: $(OBJS)"

fclean: clean
	rm -rf $(NAME) && echo "Removed: $(NAME)"

re: clean all

docker:
	docker build -t ft_nmap .
	docker run --privileged -itv $(CURDIR):/app ft_nmap

.PHONY: all, clean, fclean, re, docker
.SILENT:
