#!/usr/bin/env python3

#  Wonderbolt
#  Copyright (C) 2016 Michael Herold <quabla@hemio.de>
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

# PROG_NAME
PROG_NAME = 'wonderbolt'

# LOG_LEVEL
# Possible values: ERROR, WARNING, INFO, DEBUG
LOG_LEVEL = 'DEBUG'

try:
    from systemd.journal import JournalHandler
    LOG_HANDLER = JournalHandler(SYSLOG_IDENTIFIER=PROG_NAME)
except ImportError:
    from logging.handlers import SysLogHandler
    LOG_HANDLER = SysLogHandler('/dev/log')
    LOG_HANDLER.ident = PROG_NAME + ': '

import logging

LOG = logging.getLogger(__name__)
LOG.addHandler(LOG_HANDLER)
LOG.setLevel(LOG_LEVEL)
LOG.debug("Logger initialized: %s", type(LOG_HANDLER))

# get rid of any output immediatley after logging is in place
import io
import sys

POSTFIX_PIPE_ERR = sys.stderr
sys.stdout = io.StringIO()
sys.stderr = io.StringIO()

try:
    import argparse
    import collections
    import email
    import email.utils
    import json
    import smtplib

    class AuthenticationError(Exception):
        pass

    def err(msg):
        global LOG
        LOG.error('Error on executing %s:\n%s', sys.argv, msg)
        raise Exception()

    def infomsg(msg):
        global LOG
        LOG.info('On executing %s:\n%s', sys.argv, msg)

    def config_err(filename, msg):
        err("violation in config file '{}': {}".format(filename, msg))

    def valid_address(to):
        if not isinstance(to, str):
            return False
        addresses = email.utils.getaddresses([to])
        if len(addresses) == 1:
            return addresses[0] != ('', '')
        else:
            return False

    def get_address(to):
        return email.utils.parseaddr(to)[1]

    def get_address_without_delimiter(to, delim):
        addr = get_address(to)
        split = addr.rsplit('@', 1)
        localpart = split[0]
        if len(delim) == 0:
            delim_pos = None
        else:
            positive = [ i for i in map(lambda d: localpart.find(d), delim) if i > 0 ]
            if positive:
                delim_pos = min(positive)
            else:
                delim_pos = None

        new_localpart = localpart[:delim_pos]
        if len(split) == 1:
            return new_localpart
        else:
            return "{}@{}".format(new_localpart, split[1])

    def load_config(filename, defaults):

        config = defaults.copy()

        with open(filename, encoding='utf-8') as f:
            config.update(json.load(f))

        # check for unknown config values

        known_keys = [
            'envelope_mail_from',
            'envelope_rcpt_to',
            'header_add',
            'header_replace',
            'require_from',
            'require_sasl_username',
            'sasl_recipient_delimiter',
            'smtp_server',
            'msg_bounced_requirements'
        ]

        for k in config:
            if k not in known_keys:
                config_err(filename, "unknown parameter '{}'".format(k))

        # validate 'envelope_mail_from

        if config['envelope_mail_from'] is not None:
            if not valid_address(config['envelope_mail_from']):
                config_err(
                    filename,
                    "'envelope_mail_from' must be a valid address")

        # validate 'envelope_rcpt_to'

        if config['envelope_rcpt_to'] is not None:
            if not isinstance(config['envelope_rcpt_to'], list):
                config_err(filename, "'envelope_rcpt_to' must be a list")

            if not all([valid_address(s) for s in config['envelope_rcpt_to']]):
                config_err(
                    filename,
                    "'envelope_rcpt_to' must be a list of valid addresses")

        # validate 'header_add'

        if not isinstance(config['header_add'], dict):
            config_err(filename, "'header_add' must be a dict")

        # validate 'header_replace'

        if not isinstance(config['header_replace'], dict):
            config_err(filename, "'header_replace' must be a dict")

        # validate 'require_from'

        if (config['require_from'] != False and
            config['require_from'] != 'envelope_rcpt_to'):

            if not isinstance(config['require_from'], list):
                config_err(
                    filename,
                    "'require_from' must be a list, `false` or `\"envelope_rcpt_to\"`")

            if not all([valid_address(s) for s in config['require_from']]):
                config_err(
                    filename,
                    "'require_from' lists must only contain valid addresses")

        # validate 'require_sasl_username'

        if (config['require_sasl_username'] != False and
            config['require_sasl_username'] != 'envelope_rcpt_to'):

            if not isinstance(config['require_sasl_username'], list):
                config_err(
                    filename,
                    "'require_sasl_username' must be a list, `false` or `\"envelope_rcpt_to\"`")

            if not all([valid_address(s) for s in config['require_sasl_username']]):
                config_err(
                    filename,
                    "'require_sasl_username' lists must only contain valid addresses")

        if not isinstance(config['sasl_recipient_delimiter'], str):
            config_err("'sasl_recipient_delimiter' must be a string or `false`")

        return config

    argparser = argparse.ArgumentParser(prog=PROG_NAME, description=PROG_NAME)
    argparser.add_argument('--config', nargs='+', required=True)
    argparser.add_argument('--sasl-username', default=None)

    ARGS = argparser.parse_args()

    config = collections.OrderedDict([
        ('envelope_mail_from', None),
        ('envelope_rcpt_to', None),
        ('header_add', {}),
        ('header_replace', {}),
        ('require_from', False),
        ('require_sasl_username', False),
        ('sasl_recipient_delimiter', ""),
        ('smtp_server', 'localhost:25'),
        ('msg_bounced_requirements',
         "You are not fulfilling all requirements for writing to this address.")
    ])

    # load configs

    LOG.debug("Loading config files %s", ARGS.config)
    for filename in ARGS.config:
        config = load_config(filename, config)

    LOG.debug("Using the following config:\n%s", config)

    # check SASL username

    if config['require_sasl_username'] != False:
        LOG.debug("[require_sasl_username] Activated")

        if ARGS.sasl_username == '':
            infomsg("[require_sasl_username] Rejected: Empty username (probably not authenticated)")
            raise AuthenticationError(config['msg_bounced_requirements'])

        if not valid_address(ARGS.sasl_username):
            err("Passed `--sasl-username {}` is not a valid username"
                .format(ARGS.sasl_username))

        if config['require_sasl_username'] == 'envelope_rcpt_to':
            if config['envelope_rcpt_to'] is None:
                config_err(
                    ARGS.config[-1],
                    "'envelope_rcpt_to' must be set if 'require_sasl_username' is used")
            allowed_usernames = config['envelope_rcpt_to']
        else:
            allowed_usernames = config['require_sasl_username']

        filterf = lambda x: get_address_without_delimiter(x, config['sasl_recipient_delimiter'])

        if get_address(ARGS.sasl_username) not in map(filterf, allowed_usernames):
            infomsg("[require_sasl_username] Rejected: Username is not in authorized list")
            raise AuthenticationError(config['msg_bounced_requirements'])
        
        LOG.debug("[require_sasl_username] Passed")
    else:
        LOG.debug("[require_sasl_username] Not activated")

    # parse email

    LOG.debug("Parsing email")
    STDIO = io.TextIOWrapper(sys.stdin.detach(), encoding='us-ascii', errors='surrogateescape')
    msg = email.message_from_file(STDIO)

    # check From Header

    if config['require_from'] != False:
        LOG.debug("[require_from] Activated")

        if not valid_address(msg['From']):
            infomsg("[require_from] Rejected: 'From' is not a valid address")
            raise AuthenticationError(config['msg_bounced_requirements'])

        if config['require_from'] == 'envelope_rcpt_to':
            if config['envelope_rcpt_to'] is None:
                config_err(
                    ARGS.config[-1],
                    "'envelope_rcpt_to' must be set if 'require_from' is used")
            allowed_froms = config['envelope_rcpt_to']
        else:
            allowed_froms = config['require_from']

        if get_address(msg['From']) not in map(get_address, allowed_froms):
            infomsg("[require_from] Rejected: 'From' is not in authorized list")
            raise AuthenticationError(config['msg_bounced_requirements'])

        LOG.debug("[require_from] Passed")
    else:
        LOG.debug("[require_from] Not activated")

    # update headers

    for k in config['header_replace']:
        if k in msg:
            del msg[k]

    for key, value in config['header_replace'].items():
        msg[key] = str(value)

    for key, value in config['header_add'].items():
        msg[key] = str(value)

    # send email

    LOG.debug("Connecting to SMTP server at {}".format(config['smtp_server']))
    smtp_conn = smtplib.SMTP(config['smtp_server'])

    LOG.debug("Sending email via SMTP")
    smtp_conn.send_message(
        msg,
        config['envelope_mail_from'],
        config['envelope_rcpt_to'])

except AuthenticationError as e:
    LOG.debug("Rejecting message with 5.3.0")
    print(
        "5.3.0 {.args[0]}".format(e),
        file=POSTFIX_PIPE_ERR)

    sys.exit(1)

except:
    LOG.exception(
        "Exception on executing %s:\n\nstdout:\n%s\nstderr:\n%s\n",
        sys.argv, sys.stdout.getvalue(), sys.stderr.getvalue())

    print(
        "4.5.1 Requested action aborted - Local error in email list processing",
        file=POSTFIX_PIPE_ERR)

    sys.exit(1)

LOG.debug("Shutting down normally")

