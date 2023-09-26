NAME	:= ft_nmap
CFLAGS	:= -Wall -Wextra
CFLAGS	+= -Werror
# CFLAGS	:= -Ofast

HEADERS	:= -I ./include
LIBS	:= -lpcap -lpthread
SRCDIR	:= ./src
OBJDIR	:= ./obj
SRCS	:= $(shell find $(SRCDIR) -type f -name "*.c")
OBJS	:= $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

all: $(NAME)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ -c $< $(HEADERS) && echo "Compiled: $(notdir $@)"

$(NAME): $(OBJS)
	$(CC) $(OBJS) $(LIBS) $(HEADERS) -o $(NAME) && echo "Linked: $(NAME)"

clean:
	rm -rf $(OBJDIR) && echo "Removed: $(OBJDIR)"

fclean: clean
	rm -f $(NAME) && echo "Removed: $(NAME)"

re: clean all

docker:
	docker build -t ft_nmap .
	docker run -itv $(CURDIR):/app ft_nmap

.PHONY: all, clean, fclean, re, docker
.SILENT:
