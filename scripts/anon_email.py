#!/usr/bin/env python3

"""A message modification plugin to anonymize email address.
    
   Based on rsyslog sample anon_cc_nbrs
   https://github.com/rsyslog/rsyslog/tree/master/plugins/external/messagemod/anon_cc_nbrs

   Copyright (C) 2021 by Sergio del Rio

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
         http://www.apache.org/licenses/LICENSE-2.0
         -or-
         see COPYING.ASL20 in the source distribution
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

import sys
import re
import json

import os

import sys
import logging

# App logic global variables

def onInit():
    """ Initialize processing
    """
    global rc
    global pattern
    global email_prefix
    global email_suffix
    global domain_prefix
    global domain_suffix
    ANON_EMAIL_PREFIX = 1
    ANON_EMAIL_SUFFIX = 2
    ANON_DOMAIN_PREFIX = 3
    ANON_DOMAIN_SUFFIX = 4

    pattern = '([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)' # email regexp
    rc = re.compile("("+")|(" + pattern + ")")

    def get_env(var_index, default=1):
        var = default
        #if os.environ.get(env_var):
        try:
            defined = int(sys.argv[var_index])
            var = defined if defined >= 0 else default
        except Exception as e:
            pass
        return var

    email_prefix = get_env(ANON_EMAIL_PREFIX)
    email_suffix = get_env(ANON_EMAIL_SUFFIX)

    domain_prefix = get_env(ANON_DOMAIN_PREFIX)
    domain_suffix = get_env(ANON_DOMAIN_SUFFIX, default=4)


def onReceive(msg):
    """Entry point where actual work needs to be done. It receives
       the messge from rsyslog and now needs to examine it, do any processing
       necessary. The to-be-modified properties (one or many) need to be pushed
       back to stdout, in JSON format, with no interim line breaks and a line
       break at the end of the JSON. If no field is to be modified, empty
       json ("{}") needs to be emitted.
       Note that no batching takes place (contrary to the output module skeleton)
       and so each message needs to be fully processed (rsyslog will wait for the
       reply before the next message is pushed to this module).
    """
    global rc
    global pattern
    global email_prefix
    global email_suffix
    global domain_prefix
    global domain_suffix

    def anonymize_word(word, prefix=1, suffix=1):
        anonymized_word = ''

        # if word is too short just anonymyze everything
        if ((len(word)-prefix-suffix)<2):
            return '*'

        for idx, val in enumerate(word):
            anonymized_word += val if (idx < prefix or idx >= (len(word)-suffix)) else '*'
        return anonymized_word

    def lookup(match):
        res = re.match(pattern, match.group(0))
        if res:
            mail_user = str(res.group(1))
            mail_domain = str(res.group(2))
            return \
                anonymize_word(mail_user, prefix=email_prefix, suffix=email_suffix) \
                + '@' + \
                anonymize_word(mail_domain, prefix=domain_prefix, suffix=domain_suffix)

    res_msg = rc.sub(lambda m: lookup(m), msg)
    if res_msg == msg:
        print(json.dumps({}))
    else:
        print(json.dumps({'msg': res_msg}))

def onExit():
    """ Nothing to do here
    """
    pass


"""
-------------------------------------------------------
This is plumbing that DOES NOT need to be CHANGED
-------------------------------------------------------
Implementor's note: Python seems to very agressively
buffer stdouot. The end result was that rsyslog does not
receive the script's messages in a timely manner (sometimes
even never, probably due to races). To prevent this, we
flush stdout after we have done processing. This is especially
important once we get to the point where the plugin does
two-way conversations with rsyslog. Do NOT change this!
See also: https://github.com/rsyslog/rsyslog/issues/22
"""
onInit()
keepRunning = 1
while keepRunning == 1:
    msg = sys.stdin.readline()
    if msg:
        msg = msg[:-1] # remove LF
        onReceive(msg)
        sys.stdout.flush() # very important, Python buffers far too much!
    else: # an empty line means stdin has been closed
        keepRunning = 0
onExit()
sys.stdout.flush() # very important, Python buffers far too much!
