.PHONY: all emulator

all: emulator

# tested with macOS on Apple Silicon and x86, prob needs modification to run on Linux
# requires Unicorn Engine installation
emulator: main.c
	$(CC) -o emulator $< -lunicorn -L/usr/local/lib -rpath /usr/local/lib

clean:
	rm -f emulator
