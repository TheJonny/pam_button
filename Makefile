pam_button.so: pam_button.c
	gcc -Wall -Wextra -fPIC -shared -Wconversion -o $@ $<

install: pam_button.so
	sudo install -g root -o root -m 755 -d             /lib/security/
	sudo install -g root -o root -m 0755 pam_button.so /lib/security/
clean:
	rm -f pam_button.so
.PHONY: clean
