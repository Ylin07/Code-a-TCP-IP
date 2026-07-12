CC = gcc
CFLAGS = -Iinclude -Wall

SRCDIR = src
BUILDDIR = build
TARGET = $(BUILDDIR)/app

SRC = $(wildcard $(SRCDIR)/*.c)
OBJ = $(patsubst $(SRCDIR)/%.c, $(BUILDDIR)/%.o, $(SRC))

$(TARGET): $(OBJ)
	$(CC) -o $@ $^

$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -rf $(BUILDDIR)