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

#ifndef _MOD_PRISON_H_
#define _MOD_PRISON_H_

#include "ap_config.h"
#include "httpd.h"
#include "http_log.h"
#include "http_core.h"
#include "mpm_common.h"

#include "apr_strings.h"
#include "apr_portable.h"

/* MAXCPU */
#include <sys/param.h>

/* isdigit */
#include <ctype.h>

/* geteuid, chdir */
#include <unistd.h>
#include <sys/types.h>

/* inet_pton */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* expand_number */
#ifdef _HAVE_LIBUTIL_H_
#include <libutil.h>
#else
extern int expand_number(const char *buf, uint64_t *num);
#endif

/* stat */
#include <sys/stat.h>


typedef enum { ALL, SET } cs_type;
typedef enum { NONE, SECURE, IPC } sec_type;
typedef enum { DISABLE, ENABLE } opt_type;

typedef struct {
	char *path;
	int ipversion;
	char *ip;
	sec_type security;
	cs_type cpuset;
	int cpumask[MAXCPU];
	uint64_t memreport;
	uint64_t memdeny;
	opt_type onesite;
	opt_type onelisten;
} prison_config;

typedef struct {
	int jid;
	char *name;
} current_jail;

#define WAIT_CHILD_TIMEOUT 10000

prison_config ap_prison_config; 
current_jail *cj;


/* 
 * Specific functions for building the prison and setting its
 * properties
 */
int ps_create(apr_pool_t *pconf, apr_pool_t *ptemp, server_rec *s);
int ps_set_security(apr_pool_t *pconf, apr_pool_t *ptemp, server_rec *s);
int ps_set_cpu_restrictions(apr_pool_t *pconf, apr_pool_t *ptemp, server_rec *s); 
int ps_set_memory_limits(apr_pool_t *pconf, apr_pool_t *ptemp, server_rec *s);
int ps_last_stuff(int rv);
int ps_attach(void);
int ps_exists(void);
int ps_reuse_if_is_the_same(void);

#endif /*_MOD_PRISON_H_*/
