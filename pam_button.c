#define PAM_SM_AUTH
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <linux/input.h>

#include <syslog.h>

#include <sys/file.h>
#include <sys/fcntl.h>

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define TRACE(format, x) fprintf(stderr, "%s = "format"\n", #x, (x));

static int err(pam_handle_t *pamh, int errcode, const char *msg){
	char errbuf[100];
	strerror_r(errno, errbuf, sizeof(errbuf));
	
	pam_syslog(pamh, LOG_ERR, "%s: %s", msg, errbuf);
	return errcode;
}

struct argv_options{
	const char *event_device;
	const char *lockfile;
	unsigned short keycode;
	int timeout;
};

bool parse_options(pam_handle_t *pamh, struct argv_options *options, int argc, const char **argv){
	memset(options, 0, sizeof(*options));
	for(int i=0; i<argc; i++){
		if(strstr(argv[i], "event_device=") == argv[i]) options->event_device = strchr(argv[i], '=')+1;
		if(strstr(argv[i], "lockfile=") == argv[i]) options->lockfile = strchr(argv[i], '=')+1;
		if(strstr(argv[i], "keycode=") == argv[i]) options->keycode = (unsigned short)atoi(strchr(argv[i], '=')+1);
		if(strstr(argv[i], "timeout=") == argv[i]) options->timeout = (unsigned short)atoi(strchr(argv[i], '=')+1);
	}

	pam_syslog(pamh, LOG_INFO, "event_device=%s", options->event_device);
	pam_syslog(pamh, LOG_INFO, "lockfile=%s", options->lockfile);
	pam_syslog(pamh, LOG_INFO, "keycode=%hu", options->keycode);

	return options->event_device && options->lockfile && options->keycode;
}
	
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char ** argv){
	struct argv_options options;
	if(!parse_options(pamh, &options, argc, argv)) return PAM_SERVICE_ERR;
	//if(flags & PAM_SILENT) return PAM_IGNORE;
	

	int lockfd = open(options.lockfile, O_RDWR|O_CREAT|O_CLOEXEC, 0600);
	if(lockfd == -1) return err(pamh, PAM_SYSTEM_ERR, "cannot open logfile");
	
	char *response = NULL;
	pam_prompt(pamh, PAM_TEXT_INFO, &response, "Queueing for button");
	free(response);
	if(flock(lockfd, LOCK_EX) == -1) return err(pamh, PAM_SYSTEM_ERR, "lock lockfile");

	FILE *f = fopen(options.event_device, "rb");
	if(f == NULL) return err(pamh, PAM_SYSTEM_ERR, "open input device");

	response = NULL;
	pam_prompt(pamh, PAM_TEXT_INFO, &response, "Please press the configured button");
	free(response);

	struct input_event ev = {};
	for(;;){
		if(fread(&ev, sizeof(ev), 1, f) != 1) return err(pamh, PAM_SYSTEM_ERR, "read from input device");
		if(ev.type == EV_KEY && ev.code == options.keycode && ev.value == 1) break;
	}

	close(lockfd);
	return PAM_SUCCESS;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv){
	(void) pamh, (void) flags, (void) argc, (void) argv;
	return PAM_IGNORE;
}
