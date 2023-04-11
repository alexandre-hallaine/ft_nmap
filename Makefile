NAME	:= ft_nmap
CFLAGS	:= -Wall -Wextra
# CFLAGS	+= -Werror
# CFLAGS	:= -Ofast

HEADERS	:= -I ./include
LIBS	:= -lpcap -lpthread
SRCDIR	:= ./src
OBJDIR	:= ./obj
SRCS	:=	utils.c \
			loading/adress.c \
			loading/parser.c \
			send/packet.c \
			send/checksum.c \
			send/send.c \
			main.c
OBJS	:= $(SRCS:%.c=$(OBJDIR)/%.o)

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

.PHONY: all, clean, fclean, re
.SILENT:
