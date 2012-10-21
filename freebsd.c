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

#include "apr_strings.h"
#include "apr_portable.h"

#if defined(__FreeBSD__)
#include <osreldate.h>
#else 
#error "Only for FreeBSD"
#endif /* __FreeBSD__ */

#if defined(__FreeBSD_version) && (__FreeBSD_version >= 720000)

#include <sys/param.h>
#include <sys/cpuset.h>
#include <sys/rctl.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/jail.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <ctype.h>
#include <jail.h>
#include <libutil.h>
#include <unistd.h>
#include <pwd.h>


/*******************
 * Various helpers *
 *******************/
static int
jail_set_non_persistant(void) {
	struct jailparam params[2];
	int rv = OK;

	jailparam_init(&params[0], "name");
	jailparam_import(&params[0], cj->name);
	jailparam_init(&params[1], "nopersist");
	jailparam_import(&params[1], NULL);

	if (jailparam_set(params, 2, JAIL_UPDATE) == -1) {
	       ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
	   	"Unexpected error while setting nopersist");
	       rv = -1;
	}	       
	jailparam_free(params, 2);
	return rv;
}

static int
jail_set_persistant(void) {
	struct jailparam params[2];
	int rv = OK;

	jailparam_init(&params[0], "name");
	jailparam_import(&params[0], cj->name);
	jailparam_init(&params[1], "persist");
	jailparam_import(&params[1], NULL);

	if (jailparam_set(params, 2, JAIL_UPDATE) == -1) {
	       ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
	   	"Unexpected error while setting nopersist");
	       rv = -1;
	}	       
	jailparam_free(params, 2);
	return rv;
}

/*
 * Gives a chance to the jail to have some processes attached and not to die
 * when setting nopersist.
 * XXX: should be a better way with ipc
 */
int
ps_last_stuff(int rv)
{
	pid_t pid;
	if (rv == 0) {
		return jail_set_non_persistant();
	}
	switch (pid = fork()) {
	case -1:
		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
		    "Can't fork child waiter");
		break;
	case 0:
		apr_sleep(WAIT_CHILD_TIMEOUT);	
		(void) jail_set_non_persistant();
		exit(0);
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
	}
	i++;	
	cj->jid = jailparam_set(params, i, JAIL_UPDATE);
	rv = errno;
	jailparam_free(params, i);
	if (cj->jid == -1) {
		errno = rv;
		return -1;
	}
	return 0;
}

int
ps_set_cpu_restrictions(apr_pool_t *pconf, apr_pool_t *ptemp, server_rec *s) 
{
	cpuset_t mask;
	int i;
	if (ap_prison_config.cpuset != ALL) {
		CPU_ZERO(&mask);
		for (i = 0; ap_prison_config.cpumask[i] != -1; i++) {
			CPU_SET(ap_prison_config.cpumask[i], &mask);
		}
		if (cpuset_setaffinity( CPU_LEVEL_WHICH, CPU_WHICH_JAIL, cj->jid,
			sizeof(mask), &mask) != 0) {
			return -1;
		}
	}
	return 0;
}

/* Set the memory limit */
int 
ps_set_memory_limits(apr_pool_t *pconf, apr_pool_t *ptemp, server_rec *s)
{
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
		errno = EEXIST;
		return -1;
	}
	return 0;
}



#else 
#error "Only for FreeBSD > 7.2"

#endif /* __FreeBSD_version */
