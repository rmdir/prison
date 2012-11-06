/* 
 * Copyright (c)u2012 Joris Dedieu <joris.dedieu@gmail.com>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met: 
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer. 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution. 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "mod_prison.h"

#if defined(__FreeBSD__)
#include <osreldate.h>
#else 
#error "Only for FreeBSD"
#endif /* __FreeBSD__ */

#if defined(__FreeBSD_version) && (__FreeBSD_version >= 720000)

#include <sys/cpuset.h>
#ifdef _HAVE_RCTL_
#include <sys/rctl.h>
#endif /*_HAVE_RCTL_ */
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/jail.h>


#include <jail.h>
#include <pwd.h>

#include <sys/event.h>
#include <sys/time.h>


/*******************
 * Various helpers *
 *******************/
static void
jail_set_non_persistant(void) {
	struct jailparam params[2];

	jailparam_init(&params[0], "name");
	jailparam_import(&params[0], cj->name);
	jailparam_init(&params[1], "nopersist");
	jailparam_import(&params[1], NULL);

	if (jailparam_set(params, 2, JAIL_UPDATE) == -1) {
	       ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
	   	"Unexpected error while setting nopersist");
	}	       
	jailparam_free(params, 2);
}

static void 
jail_do_daemon(pid_t parent) 
{
	int kq,i;
	sigset_t set;
	struct kevent ke;
	openlog("mod_prison", LOG_PID | LOG_NDELAY, LOG_DAEMON);
	syslog(LOG_INFO, "launching control daemon for jailed httpd : %s",
	    cj->name);
	syslog(LOG_DEBUG, "change proc title to : %s (control daemon)", 
	    cj->name);
	setproctitle("%s (control daemon)", cj->name);

	syslog(LOG_DEBUG, "Handling signals");
	if (sigfillset(&set) == -1) {
		syslog(LOG_ERR, "sigfillset : %m");
		goto emergency;
	}

	if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
		syslog(LOG_ERR, "sigprocmask : %m");
		goto emergency;
	}

       	syslog(LOG_DEBUG, "start to deal with kqueue");
	kq = kqueue();
	if (kq == -1) {
		syslog(LOG_ERR, "kqueue : %m");
		goto emergency;
	}
	EV_SET(&ke, parent,  EVFILT_PROC, EV_ADD, 
	    NOTE_EXIT, 0, NULL);
	i = kevent(kq, &ke, 1, NULL, 0, NULL);
	if (i == -1) {
		syslog(LOG_ERR, "kevent %m");
		goto emergency;
	}
	syslog(LOG_DEBUG, "ok for kqueue stuff, let's become a daemon");
	if (chdir("/var/empty") == -1) {
		syslog(LOG_ERR, "chdir : %m");
		goto emergency;
	}
	if (chroot("/var/empty") == -1) {
		syslog(LOG_ERR, "chroot : %m");
		goto emergency;
	}
	syslog(LOG_DEBUG, "starting main loop");
	memset(&ke, 0, sizeof(struct kevent));
	i = kevent(kq, NULL, 0, &ke, 1, NULL);
	if (i == -1) {
		syslog(LOG_ERR, "kevent : %m");
		goto emergency;
	}
	if (ke.fflags & NOTE_EXIT) {
		syslog(LOG_INFO, "pid %d exit (signal %d)",
		(int) ke.ident , (int) WTERMSIG(ke.data)); 
	} 
	/* NOTREACHED */
	else {
		 syslog(LOG_ERR, "unexpected event (flag : %d)", (int) ke.fflags);
	}

end:
	syslog(LOG_INFO, "control daemon is terminating");
	jail_set_non_persistant();
	syslog(LOG_DEBUG, "the jail was set unpersistant");
	closelog();
	exit(0);

emergency:
	syslog(LOG_ERR, "Emergency exiting I will kill my father");
	kill(parent, SIGTERM);
	goto end;
}
			
/*
 * Gives a chance to the jail to have some processes attached and not to die
 * when setting nopersist.
 * XXX: should be a better way with ipc
 */
int
ps_start_control_daemon(int error, int reuse)
{
	pid_t pid, parent;

	if (error != 0) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
		    "There was an error setting prison properties");
		if (reuse != 0) {
			ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
			    "So we kill the prison");
		}
		jail_set_non_persistant();
		return -1;
	}
	if (reuse != 0) {
		return OK;
	}

	parent = getpid();
	switch (pid = rfork(RFPROC|RFNOWAIT|RFCFDG)) {
	case -1:
		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
		    "Can't fork control daemon");
		jail_set_non_persistant();
		return -1;
	case 0:
		jail_do_daemon(parent);
	default :
		return OK;
	}
	/* NOTREACHED */
	return OK;
}

/* create the jail and setup security */
int
ps_create(apr_pool_t *pconf, apr_pool_t *ptemp, server_rec *s) {
	int rv, i = 0;
	struct jailparam params[5];

	jailparam_init(&params[i], "name");
	jailparam_import(&params[i], cj->name);
	i++;
	jailparam_init(&params[i], "host.hostname");
	jailparam_import(&params[i],s->server_hostname);
	i++;
	jailparam_init(&params[i], "path");
	jailparam_import(&params[i], ap_prison_config.path);
	i++;
	jailparam_init(&params[i], "persist");
	jailparam_import(&params[i], NULL);
	if (ap_prison_config.ipversion == AF_INET) {
		i++;
		jailparam_init(&params[i], "ip4.addr");
		jailparam_import(&params[i], ap_prison_config.ip);
	}
	if (ap_prison_config.ipversion == AF_INET6) {
		i++;
		jailparam_init(&params[i], "ip6.addr");
		jailparam_import(&params[i], ap_prison_config.ip);
	}

	i++;	
	cj->jid = jailparam_set(params, i, JAIL_CREATE);
	rv = errno;
	jailparam_free(params, i);
	if (cj->jid == -1) {
		errno = rv;
		return -1;
	}
	return 0;
}

int
ps_set_security(apr_pool_t *pconf, apr_pool_t *ptemp, server_rec *s) {
	int rv, i = 0;
	struct jailparam params[10];

	if(ap_prison_config.security > NONE) {
		jailparam_init(&params[i], "name");
		jailparam_import(&params[i], cj->name);
		i++;
		jailparam_init(&params[i], "securelevel");
		jailparam_import(&params[i], "3");
		i++;
		jailparam_init(&params[i], "enforce_statfs");
		jailparam_import(&params[i], "2");
		i++;
		jailparam_init(&params[i], "allow.set_hostname");
		jailparam_import(&params[i], "0");
		i++;
		jailparam_init(&params[i], "allow.raw_sockets");
		jailparam_import(&params[i], "0");
		i++;
		jailparam_init(&params[i], "allow.chflags");
		jailparam_import(&params[i], "0");
		i++;
		jailparam_init(&params[i], "allow.mount");
		jailparam_import(&params[i], "0");
		i++;
		jailparam_init(&params[i], "allow.quotas");
		jailparam_import(&params[i], "0");
		i++;
		jailparam_init(&params[i], "allow.socket_af");
		jailparam_import(&params[i], "0");
		i++;
		jailparam_init(&params[i], "allow.sysvipc");
		switch (ap_prison_config.security) {
		case IPC:
			jailparam_import(&params[i], "1");
			break;
		case SECURE:
			jailparam_import(&params[i], "0");
			break;
		/* NOTREACHED */
		case NONE:
			break;
		}
		i++;	
		cj->jid = jailparam_set(params, i, JAIL_UPDATE);
		rv = errno;
		jailparam_free(params, i);
		if (cj->jid == -1) {
			errno = rv;
			return -1;
		}
	}
	return 0;
}

int
ps_set_cpu_restrictions(apr_pool_t *pconf, apr_pool_t *ptemp, server_rec *s) 
{
	cpuset_t *mask;
	int i;
	if (ap_prison_config.cpuset != ALL) {
		mask = apr_palloc(ptemp, sizeof(cpuset_t));
		if (mask == NULL) {
			return -1;
		}
		CPU_ZERO(mask);
		for (i = 0; ap_prison_config.cpumask[i] != -1; i++) {
			CPU_SET(ap_prison_config.cpumask[i], mask);
		}
		if (cpuset_setaffinity( CPU_LEVEL_WHICH, CPU_WHICH_JAIL, cj->jid,
			sizeof(mask), mask) != 0) {
			return -1;
		}
	}
	return 0;
}

/* Set the memory limit */
int 
ps_set_memory_limits(apr_pool_t *pconf, apr_pool_t *ptemp, server_rec *s)
{
#ifdef _HAVE_RCTL_
	int i = 0;
	size_t len;
	char *rctlrule;
	if (ap_prison_config.memdeny == 0 && ap_prison_config.memreport == 0) {
	      return 0;
	}
	len = sizeof(i);
	if (sysctlbyname("vm.overcommit", &i, &len, NULL, 0) != 0) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL, 
		    "Sysctl vm.overcommit fail");
		return -1;
	}
	if (i != 1) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
		    "You have to set vm.overcommit to use memory limit");
		return -1;
	}
	/* remove old rules */
	rctlrule = apr_pstrcat(ptemp, "jail:",cj->name, NULL);
	if (rctl_remove_rule(rctlrule, strlen(rctlrule) + 1, NULL, 0) != 0 
	    && errno != ESRCH) {
		return -1;
	}

	if (ap_prison_config.memdeny != 0) {
		rctlrule = apr_pstrcat(ptemp, "jail:", cj->name,
		    ":memoryuse:deny=",
		    apr_ltoa(ptemp, (long) ap_prison_config.memdeny),
		    NULL);

		if(rctl_add_rule(rctlrule, strlen(rctlrule) +1, NULL, 0) != 0) {
			return -1;
		} 
	}
	if (ap_prison_config.memreport != 0) {
		rctlrule = apr_pstrcat(ptemp, "jail:", cj->name,
		    ":memoryuse:devctl=",
		    apr_ltoa(ptemp, (long) ap_prison_config.memreport), 
		    NULL);

		if(rctl_add_rule(rctlrule, strlen(rctlrule) +1, NULL, 0) != 0) {
			return -1;
		} 
	}
#endif /* _HAVE_RCTL_ */
	return 0;
}

int
ps_attach(void)
{
	if (cj->jid <= 0) {
		errno = EINVAL;
		return -1;
	}
	if (jail_attach(cj->jid) == -1) {
		return -1;
	}
	return 0;
}

int
ps_exists(void)
{
	if ((cj->jid = jail_getid(cj->name)) > 0) {
		return 0;
	}
	return -1;
}



#else 
#error "Only for FreeBSD > 7.2"

#endif /* __FreeBSD_version */
