pam_button.so: pam_button.c
	gcc -Wall -Wextra -fPIC -shared -Wconversion -o $@ $<

install: pam_button.so
	sudo install -g root -o root -m 0755 pam_button.so /usr/lib/security/
