.PHONY: all

emulator: main.c
	$(CC) -o emulator $< -lunicorn -L/usr/local/lib

clean:
	rm -f emulator