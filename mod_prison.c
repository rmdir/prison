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

/* 
 * As FreeBSD's jailname doess  not support dots,
 * name is set to ServerName replacing dots with underscores
 */
static int
setup_prison_name(apr_pool_t *pconf, server_rec *s) {
	size_t len;
	int i;
	len = strlen(s->server_hostname) + 1;
	cj->name = apr_palloc(pconf, len); 
	if (cj->name == NULL) {
		return errno;
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
	return 0;
}

/* Construct cpumask from PrisonCPU directive */
static const char *
prison_set_cpu(cmd_parms *cmd, void *dummy, const char *arg)
{
	char *end;
	enum { OTHER, RANGE };
        int next = OTHER, cpu, previous, num = 0;  

	const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
	if (err != NULL) {
		return err;
	}
	while(*arg != '\0' && isdigit(*arg)) {
		cpu = (int) strtol(arg, &end, 10);

		if (cpu < 0) {
			ap_prison_config.cpuset = ALL;
			return "CPU id can't be negative";
		}
		if (cpu > MAXCPU) {
			ap_prison_config.cpuset = ALL;
			return "CPU id too hight";
		}

		switch (next) {
		case OTHER:
			if (num < MAXCPU) {
				ap_prison_config.cpumask[num] = cpu;
				ap_prison_config.cpuset = SET;
				previous = cpu;
				previous++; num++;
			}
			break;

		case RANGE:
			if (previous > cpu) {
				return "Invalid CPU range";
			}
			while (previous <= cpu) {
				if (num < MAXCPU) {
					ap_prison_config.cpumask[num] = cpu;
					ap_prison_config.cpuset = SET;
					previous++; num++;
				}
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
		return "PrisonCPU empty ?";
	}
	ap_prison_config.cpumask[num] = -1;
	return NULL;
}

static const char *
prison_set_options(cmd_parms *cmd, void *dummy, const char *option)
{
	const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
	if (err != NULL) {
		return err;
	}
	if (apr_strnatcasecmp("OneSite", option) == 0) {
		ap_prison_config.onesite = ENABLE;
	}
	else if (apr_strnatcasecmp("OneListen", option) == 0) {
		ap_prison_config.onelisten = ENABLE;
	}
	else {
		return "Invalid PrisonOptions";
	}
	return NULL;
}



/* Parsing values for memorylimit */
static const char *
prison_set_mem(cmd_parms *cmd, void *dummy, const char *report, 
    const char *deny)
{
	char *usage;
	uint64_t r = 0 , d = 0;
	const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
	if (err != NULL) {
		return err;
	}
	usage = "PrisonMemory takes two arguments : report  deny";

	if (expand_number(report, &r) == -1) {
		return usage;
	}	
	if (expand_number(deny, &d) == -1) {
		return usage;
	}	
	if (r != 0 && d != 0 && r > d) {
	   return "PrisonMemory : report can't be higher than deny";
	}
       	ap_prison_config.memdeny = d;
	ap_prison_config.memreport = r;	
	return NULL;
}

/* Check if PrisonDir is a valid directory */
static const char * 
prison_set_path(cmd_parms *cmd, void *dummy, const char *arg)
{
#ifdef PARANOID
	struct stat st;
#endif /* PARANOID */

	const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
	if (err != NULL) {
    		return err;
	}

#ifdef PARANOID
	if (stat(arg, &st) == -1 || 
	    (S_ISDIR(st.st_mode) == 0))
    		return "PrisonDir must be a valid directory";
	if (st.st_uid != 0 || (st.st_mode & (S_IWGRP|S_IWOTH)) != 0)
		return "PrisonDir must be owned by root and not group "
		    "or world writable";
#else 
	if (!ap_is_directory(cmd->pool, arg)) {
    		return "PrisonDir must be a valid directory";
	}
#endif /* PARANOID */

	ap_prison_config.path = (char *) arg;
	return NULL;
}

/* Check PrisonIP */
static const char *
prison_set_ip(cmd_parms *cmd, void *dummy, const char *arg)
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
		return "Could not make sense of prison ip address";
	}

#ifdef PARANOID
	if (sa.sin_addr.s_addr == INADDR_ANY || sa6.sin6_addr.s6_addr == INADDR_ANY) {
		return "Can't use INADDR_ANY for prison ip";
	}
#endif /* PARANOID */
	return NULL;
}

/* set security params */
static const char *
prison_set_security(cmd_parms *cmd, void *dummy, const char *arg)
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
		return "PrisonSecurity should be one of All, None or IPC";
	}
	return NULL;
}

/****************
 * Apache hooks *
 ****************/

/* Setup default values */ 
static int
prison_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                 apr_pool_t *ptemp)
{
	int rv;
	ap_prison_config.path = NULL;
	ap_prison_config.ipversion = AF_UNSPEC;
#ifdef PARANOID
	ap_prison_config.security = SECURE;
#else
	ap_prison_config.security = NONE;
#endif
	memset(&ap_prison_config.cpumask, 0, (size_t) MAXCPU);
	rv = errno;
	if (ap_prison_config.cpumask == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, rv, NULL,
		    "Error in cpumask allocation");
		return rv;
	}

	ap_prison_config.cpuset = ALL;
	ap_prison_config.memdeny = 0;
	ap_prison_config.memreport = 0;
	ap_prison_config.onesite = DISABLE;
	ap_prison_config.onelisten = DISABLE;
	return OK;
}

/* Create the prison */
static int 
prison_post_config(apr_pool_t *pconf, apr_pool_t *plog,
    apr_pool_t *ptemp, server_rec *s)
{
	int rv;

	/* Check the concordence of server_rec with options */
	if (ap_prison_config.onesite == ENABLE && 
	    s->next != NULL) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, rv, NULL, 
		    "Vhost detect while OneSite is set");
		return EPERM;
	}

	if (ap_prison_config.onelisten == ENABLE && 
	    s->addrs->host_addr->next != NULL) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, rv, NULL, 
		    "Multiple Listen detect while OneListen is set");
		return EPERM;
	}



	/* This function is called twice. Do nothing the first time */
	if (ap_state_query(AP_SQ_MAIN_STATE) == AP_SQ_MS_CREATE_PRE_CONFIG)
			return OK;

	/* PrisonDir is not set. Nothing to do */
	if (ap_prison_config.path == NULL) 
		return OK;

	/* Some system calls need us to be root */
	if (geteuid()) {
    		rv = errno;
        	ap_log_error(APLOG_MARK, APLOG_ALERT, rv, NULL, 
		    "Cannot set the prison when not started as root");
        	return rv;
	}
	/* Let's go jailing */
	if (chdir(ap_prison_config.path) != 0) {
    		rv = errno;
    		ap_log_error(APLOG_MARK, APLOG_ALERT, rv, NULL, 
		    "Can't chdir to %s", ap_prison_config.path);
        	return rv;
    	}

	cj = apr_palloc(pconf, sizeof(current_jail));
	rv = errno;
	if (cj == NULL) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, rv, NULL, 
		    "Error in prison structure allocation.");
		return rv;
	}

	/* set cj->name */
	rv = setup_prison_name(pconf, s);
	if (rv != 0) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, rv, NULL,
			     "Error in prison name construction.");
		return rv;
	}

	/* 
	 * Is there a prison having the same name . This can happen
	 * on graceful restart. 
	 */
	if (ps_exists() == -1) {
		rv = errno;
		ap_log_error(APLOG_MARK, APLOG_ALERT, rv, NULL, 
		    "There is already a prison named %s.", cj->name);
		if (ps_reuse_if_is_the_same() != 0) {
			rv = errno;
			ap_log_error(APLOG_MARK, APLOG_ALERT, rv, NULL, 
		    		"Unable to reuse this prison");
			return rv;
		}
	} 
	
	else if (ps_create(pconf, ptemp, s) != 0) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
				 "Unable to create the prison %s",
				 s->server_hostname);
		return rv;
	}

	/* 
	 * At this point the prison is create and persistant so 
	 * we need to run last_stuff if we don't want zombies 
	 * prisons in our system.
	 */ 
	rv = 0;
	if(ps_set_security(pconf, ptemp, s) != 0) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL, 
		    "set security failed");
		rv = -1;
	}

	/* cpuset */
	if (ps_set_cpu_restrictions(pconf, ptemp, s) != 0) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL, "cpuset faild");
		rv = -1;
	}

	/* set memory limit */
	if (ps_set_memory_limits(pconf, ptemp, s) != 0) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL, 
		    		"Problem while setting memorylimit");
		rv = -1;
	}
	return ps_last_stuff(rv);
}

static int        
prison_drop_privileges(apr_pool_t *pool, server_rec *s)
{

	int rv;
	if (ap_prison_config.path == NULL)
		return OK;

	if (ps_attach() == -1) {
		rv = errno;
		if (rv == EINVAL) {
			ap_log_error(APLOG_MARK, APLOG_ALERT, rv, NULL,
		    		"Unexpected error ! invalid id %ld", (long) cj->jid);
			return EINVAL;
		}
		ap_log_error(APLOG_MARK, APLOG_ALERT, rv, NULL, 
		    "Can't attach to prison %ld", (long) cj->jid);
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
	AP_INIT_TAKE1("PrisonDir", prison_set_path, NULL, RSRC_CONF, 
                  "The root directory of the prison"),
	AP_INIT_TAKE1("PrisonIP", prison_set_ip, NULL, RSRC_CONF, 
                  "The ip within the prison"),
	AP_INIT_TAKE1("PrisonSecurity", prison_set_security, NULL, RSRC_CONF, 
                  "System security within the prison (None, All, IPC)"),
	AP_INIT_TAKE1("PrisonCPU", prison_set_cpu, NULL, RSRC_CONF, 
                  "List of CPU the prison will be restrict on"),
	AP_INIT_TAKE2("PrisonMemory", prison_set_mem, NULL, RSRC_CONF, 
                  "Maximum memory usage within the prison"),
	AP_INIT_ITERATE("PrisonOptions", prison_set_options, NULL, RSRC_CONF,
	    	  "Various Prison Options : OneSite, OneListen"),
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
