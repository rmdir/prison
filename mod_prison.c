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

#include "ap_config.h"
#include "httpd.h"
#include "http_log.h"
#include "http_core.h"
#include "mpm_common.h"

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

#else 
#error "Only for FreeBSD > 7.2"

#endif /* __FreeBSD_version */


typedef enum { ALL, SET } cs_type;
typedef enum { NONE, SECURE, IPC } sec_type;

typedef struct {
	char *path;
	int ipversion;
	char *ip;
	sec_type security;
	cs_type cpuset;
	cpuset_t *cpumask;
	uint64_t memreport;
	uint64_t memdeny;
} prison_config;

typedef struct {
	int jid;
	char *name;
} current_jail;

#define WAIT_CHILD_TIMEOUT 10000

prison_config ap_prison_config; 
current_jail *cj;

/* 
 * mod_prison functions :
 * httpd start and create, if JailDir is set, a persistant jail. 
 * It stores the jail id and name in cj global variable. 
 * Jail's name and hosname cames from ServerName, jail's IP is 
 * set or not in config. Security and ressources limits are also set in config.
 * The main problem is to make our persistant jail become not persistant as it
 * will die when httpd stop but persist on graceful restart.
 */


/***********
 * HELPERS *
 ***********/

static void
_prison_launch_child_waiter(void)
{
	pid_t pid;
	struct jailparam params[2];
	switch (pid = fork()) {
	case -1:
		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
		    "Can't fork child waiter");
		break;
	case 0:
		apr_sleep(WAIT_CHILD_TIMEOUT);	

		jailparam_init(&params[0], "name");
		jailparam_import(&params[0], cj->name);
		jailparam_init(&params[1], "nopersist");
		jailparam_import(&params[1], NULL);

		jailparam_set(params, 2, JAIL_UPDATE); 
		jailparam_free(params, 2);
		exit(0);
	}
}

static const char *
_prison_set_cpu(cmd_parms *cmd, void *dummy, const char *arg)
{
	char *end;
	enum { OTHER, RANGE };
        int next = OTHER, cpu, previous, num = 0;  

	const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
	if (err != NULL) {
		return err;
	}
	CPU_ZERO(ap_prison_config.cpumask);
	while(*arg != '\0' && isdigit(*arg)) {
		cpu = (int) strtol(arg, &end, 10);

		if (cpu < 0) {
			ap_prison_config.cpuset = ALL;
			return "CPU id can't be negative";
		}
		if (cpu > CPU_SETSIZE) {
			ap_prison_config.cpuset = ALL;
			return "CPU id too hight";
		}

		switch (next) {
		case OTHER:
			CPU_SET(cpu, ap_prison_config.cpumask);
			ap_prison_config.cpuset = SET;
			previous = cpu;
			previous++; num++;
			break;

		case RANGE:
			if (previous > cpu) {
				return "Invalid CPU range";
			}
			while (previous <= cpu) {
				CPU_SET(cpu, ap_prison_config.cpumask);
				ap_prison_config.cpuset = SET;
				previous++; num++;
			}
		}

		arg = end;
		switch (*arg) {
		case ',':
			next = OTHER;
			arg++;
			break;

		case '-':
			next = RANGE;
			arg++;
			break;

		case '\0':
			break;

		default :
			ap_prison_config.cpuset = ALL;
			return "Invalid character in cpu list";

		}
	}
	if (num == 0) {
		ap_prison_config.cpuset = ALL;
		return "No CPU found in JailCPU";
	}
	return NULL;
}

static const char *
_prison_set_mem(cmd_parms *cmd, void *dummy, const char *report, 
    const char *deny)
{
	char *usage;
	const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
	if (err != NULL) {
		return err;
	}
	usage = "JailMemory takes two arguments : report  deny" ;

	if (expand_number(report, &ap_prison_config.memreport) == -1) {
		return usage;
	}	
	if (expand_number(deny, &ap_prison_config.memdeny) == -1) {
		return usage;
	}	
	return NULL;
}


static const char * 
_prison_set_path(cmd_parms *cmd, void *dummy, const char *arg)
{
#ifdef JAIL_PARANOID
	struct stat st;
#endif /* JAIL_PARANOID */

	const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
	if (err != NULL) {
    		return err;
	}

#ifdef JAIL_PARANOID
	if (stat(arg, &st) == -1 || 
	    (S_ISDIR(st.st_mode) == 0))
    		return "JailDir must be a valid directory";
	if (st.st_uid != 0 || (st.st_mode & (S_IWGRP|S_IWOTH)) != 0)
		return "JailDir must be owned by root and not group "
		    "or world writable";
#else 
	if (!ap_is_directory(cmd->pool, arg)) {
    		return "JailDir must be a valid directory";
	}
#endif /* JAIL_PARANOID */

	ap_prison_config.path = (char *) arg;
	return NULL;
}

static const char *
_prison_set_ip(cmd_parms *cmd, void *dummy, const char *arg)
{
	struct sockaddr_in sa;
	struct sockaddr_in6 sa6;
	const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
	if (err != NULL) {
		return err;
	}
	if (inet_pton(AF_INET, arg,  &(sa.sin_addr)) == 1) {
		ap_prison_config.ipversion = AF_INET;
		ap_prison_config.ip = (char *) arg;
	}
	else if (inet_pton(AF_INET6, arg,  &(sa6.sin6_addr)) == 1) {
		ap_prison_config.ipversion = AF_INET6;
		ap_prison_config.ip = (char *) arg;
	}
	else {
		return "could not make sense of jail ip address";
	}

#ifdef JAIL_PARANOID
	if (sa.sin_addr.s_addr == INADDR_ANY || sa6.sin6_addr.s6_addr == INADDR_ANY) {
		return "Can't use INADDR_ANY for jail ip";
	}
#endif /* JAIL_PARANOID */
	return NULL;
}

static const char *
_prison_set_security(cmd_parms *cmd, void *dummy, const char *arg)
{
	const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
	if (err != NULL) {
		return err;
	}
	if (apr_strnatcasecmp("None", arg) == 0) {
		ap_prison_config.security = NONE;
	}
	else if (apr_strnatcasecmp("All", arg) == 0) {
		ap_prison_config.security = SECURE;
	}
	else if (apr_strnatcasecmp("IPC", arg) == 0) {
		ap_prison_config.security = IPC;
	}
	else {
		return "JailSecurity should be one of All, None or IPC";
	}
	return NULL;
}


/*********
 * HOOKS *
 *********/


/* Sanitize config vars before child start */ 
static int
prison_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                 apr_pool_t *ptemp)
{
	ap_prison_config.path = NULL;
	ap_prison_config.ipversion = AF_UNSPEC;
	ap_prison_config.security = SECURE;
	ap_prison_config.cpumask = apr_pcalloc(pconf, sizeof(cpuset_t));
	ap_prison_config.cpuset = ALL;
	ap_prison_config.memdeny = 0;
	ap_prison_config.memreport = 0;
	return OK;
}


/* Create a jail if needed or update it */
static int 
prison_post_config(apr_pool_t *pconf, apr_pool_t *plog,
    apr_pool_t *ptemp, server_rec *s)
{
	int i, rv;
	size_t len;
	struct jailparam params[14];
	char *rctlrule;

	if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG)
			return OK;

	/* JailDir is not set. Nothing to do */
	if (ap_prison_config.path == NULL) 
		return OK;

	/* Is jailing possible ? */
	if (geteuid()) {
    		rv = errno;
        	ap_log_error(APLOG_MARK, APLOG_ALERT, rv, NULL, 
		    "Cannot jail when not started as root");
        	return rv;
	}
	if (chdir(ap_prison_config.path) != 0) {
    		rv = errno;
    		ap_log_error(APLOG_MARK, APLOG_ALERT, rv, NULL, 
		    "Can't chdir to %s", ap_prison_config.path);
        	return rv;
    	}

	cj = apr_pcalloc(pconf, sizeof(current_jail));
	rv = errno;
	if (cj == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, rv, NULL, 
		    "Error in cj structure allocation.");
		return rv;
	}


	len = strlen(s->server_hostname) + 1;
	cj->name = apr_pcalloc(pconf, len); 
	rv = errno;
	if (cj->name == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, rv, NULL,
			     "Error in cj name allocation.");
		return rv;
	}

	/* jail name does not support dots */
	for (i = 0; i < len ; i++) {
		switch (s->server_hostname[i]) {
		case '.': 
				cj->name[i] = '_';
				break;
		default:
				cj->name[i] = s->server_hostname[i];
		}
	}
	cj->name[len] = '\0';

	/* 
	 * Is there a jail having the same name . This can happen
	 * on graceful restart or if there is a preexisting jail
	 */
	if ((cj->jid = jail_getid(cj->name)) > 0) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, 0, NULL, 
		    "There is already a jail named %s.", cj->name);
		return EEXIST;
	}

	
	/* Let's create a new jail */
	i = 0;	
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

	/* Set security */
	if(ap_prison_config.security > NONE) {
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
		/* XXX: suppress compiler warning */
		case NONE:
			break;
		}
	}
	i++;	
	cj->jid = jailparam_set(params, i, JAIL_CREATE);
	rv = errno;
	jailparam_free(params, i);
	if (cj->jid == -1) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, rv, NULL,
				 "Unable to create the jail %s",
				 s->server_hostname);
		return rv;
	}

	/* cpuset */
	if (ap_prison_config.cpuset != ALL && cpuset_setaffinity(
	    		CPU_LEVEL_WHICH, CPU_WHICH_JAIL, cj->jid,
			sizeof(ap_prison_config.cpumask),
			ap_prison_config.cpumask) != 0) {
		rv = errno;
		ap_log_error(APLOG_MARK, APLOG_ALERT, rv, NULL, "cpuset faild");
	}

	/* set memory limit */
	if (ap_prison_config.memdeny == 0 || ap_prison_config.memreport == 0) {
	       goto end;	
	}
	i = 0;
	len = sizeof(i);
	if (sysctlbyname("vm.overcommit", &i, &len, NULL, 0) != 0) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL, 
		    "Sysctl vm.overcommit fail");
		goto end;
	}
	if (i != 1) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
		    "You have to set vm.overcommit to use memory limit");
		goto end;
	}
	/* remove old rules */
	rctlrule = apr_pstrcat(ptemp, "jail:",cj->name, NULL);
	if (rctl_remove_rule(rctlrule, strlen(rctlrule) + 1, NULL, 0) != 0 &&
	    errno != ESRCH) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
		    "Error removing old rctl rules");
		goto end;
	}
	if (ap_prison_config.memdeny != 0) {
		rctlrule = apr_pstrcat(ptemp, "jail:",cj->name,
		    ":memoryuse:deny=",
		    apr_ltoa(ptemp, (long) ap_prison_config.memdeny), NULL);

		if(rctl_add_rule(rctlrule, strlen(rctlrule) +1, NULL, 0) != 0) {
			ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
			    "Setting memory limit : rctl_add_rule(%s) failed",
			    rctlrule);
			goto end;
		} 
	}
	if (ap_prison_config.memreport != 0) {
		rctlrule = apr_pstrcat(ptemp, "jail:",cj->name,
		    ":memoryuse:devctl=",
		    apr_ltoa(ptemp, (long) ap_prison_config.memreport), NULL);

		if(rctl_add_rule(rctlrule, strlen(rctlrule) +1, NULL, 0) != 0) {
			ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
			    "Setting memory limit : rctl_add_rule(%s) failed",
			    rctlrule);
			goto end;
		} 
	}

end:
	_prison_launch_child_waiter();
	return OK;
}

static int        
prison_drop_privileges(apr_pool_t *pool, server_rec *s)
{

	int rv;
	if (ap_prison_config.path == NULL)
		return OK;

	if (cj->jid <= 0) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, EINVAL, NULL,
		    "Unexpected error ! invalid jid %ld", (long) cj->jid);
		return EINVAL;
	}	
	if (jail_attach(cj->jid) == -1) {
		rv = errno;
		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL, 
		    "Can't attach to jail %ld", (long) cj->jid);
		return rv;
	}
    	return OK;
}


/*****************
 * Apache Magics *
 *****************/

static void 
prison_hooks(apr_pool_t *pool)
{
    ap_hook_pre_config(prison_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_drop_privileges(prison_drop_privileges, NULL, NULL, APR_HOOK_FIRST); 
    ap_hook_post_config(prison_post_config, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec prison_cmds[] = {
    AP_INIT_TAKE1("JailDir", _prison_set_path, NULL, RSRC_CONF, 
                  "The directory to jail(2) into"),
    AP_INIT_TAKE1("JailIP", _prison_set_ip, NULL, RSRC_CONF, 
                  "The ip within the jail"),
    AP_INIT_TAKE1("JailSecurity", _prison_set_security, NULL, RSRC_CONF, 
                  "System security within the jail (None, All, IPC)"),
    AP_INIT_TAKE1("JailCPU", _prison_set_cpu, NULL, RSRC_CONF, 
                  "List of CPU the jail will be restrict on"),
    AP_INIT_TAKE2("JailMemory", _prison_set_mem, NULL, RSRC_CONF, 
                  "Maximum memory usage within the jail"),
    {NULL}
};

AP_DECLARE_MODULE(prison) = {
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    prison_cmds,
    prison_hooks
};

