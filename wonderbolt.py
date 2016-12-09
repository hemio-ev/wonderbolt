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
LOG_LEVEL = 'INFO'

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
POSTFIX_PIPE_OUT = sys.stdout
sys.stdout = io.StringIO()
sys.stderr = io.StringIO()

BOUNCE_TEMPLATE = """This is the mail system at host {hostname}.

I'm sorry to have to inform you that a message could not be
delivered to one or more recipients. It's attached below.

The message has probably reached all other recipients if no
additional notifications are received.

For further assistance, please send mail to postmaster.

If you do so, please include this problem report. You can
delete the text from the attached returned message.

                   The mail system (Wonderbolt)

{smtp_err}"""

try:
    import argparse
    import collections
    import email
    import email.utils
    import json
    import smtplib
    import socket
    import textwrap
    from email.mime.message import MIMEMessage
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    class AuthenticationError(Exception):
        pass

    def _reset_stdout() -> None:
        sys.stdout = POSTFIX_PIPE_OUT
        sys.stderr = POSTFIX_PIPE_ERR

    def err(msg: str) -> None:
        global LOG
        LOG.error('Error on executing %s:\n%s', sys.argv, msg)
        raise Exception()

    def infomsg(msg: str) -> None:
        global LOG
        LOG.info('On executing %s:\n%s', sys.argv, msg)

    def config_err(filename: str, msg: str) -> None:
        err("violation in config file '{}': {}".format(filename, msg))

    def valid_address(to) -> bool:
        if not isinstance(to, str):
            return False
        addresses = email.utils.getaddresses([to])
        if len(addresses) == 1:
            return addresses[0] != ('', '')
        else:
            return False

    def get_address(to: str) -> str:
        return email.utils.parseaddr(to)[1]

    def get_address_without_delimiter(to: str, delim: str) -> str:
        addr = get_address(to)
        split = addr.rsplit('@', 1)
        localpart = split[0]
        if len(delim) == 0:
            delim_pos = None
        else:
            positive = [i for i in [localpart.find(d) for d in delim] if i > 0]
            if positive:
                delim_pos = min(positive)
            else:
                delim_pos = None

        new_localpart = localpart[:delim_pos]
        if len(split) == 1:
            return new_localpart
        else:
            return "{}@{}".format(new_localpart, split[1])

    def load_config(filename: str, defaults: collections.OrderedDict) -> collections.OrderedDict:

        config = defaults.copy()

        with open(filename, encoding='utf-8') as f:
            config.update(json.load(f))

        check_config(filename, config)

        return config

    def check_config(filename: str, config: collections.OrderedDict) -> None:

        # check for unknown config values

        known_keys = [
            'envelope_mail_from',
            'envelope_rcpt_to',
            'header_add',
            'header_add_if_missing',
            'header_replace',
            'require_from',
            'require_sasl_username',
            'sasl_recipient_delimiter',
            'smtp_server',
            'bounce_from',
            'reject_msg_requirements',
            'hostname'
        ]

        for k in config:
            if k not in known_keys:
                config_err(filename, "unknown parameter '{}'".format(k))

        # validate 'envelope_mail_from'

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

        # validate 'header_add_if_missing'

        if not isinstance(config['header_add_if_missing'], dict):
            config_err(filename, "'header_add_if_missing' must be a dict")

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

        # validate 'sasl_recipient_delimiter'

        if not isinstance(config['sasl_recipient_delimiter'], str):
            config_err(filename, "'sasl_recipient_delimiter' must be a string or `false`")

        # validate 'envelope_mail_from'

        if config['bounce_from'] is not None:
            if not valid_address(config['bounce_from']):
                config_err(
                    filename,
                    "'bounce_from' must be a valid address")

        # validate 'reject_msg_requirements'

        if not isinstance(config['reject_msg_requirements'], str):
            config_err(filename, "'reject_msg_requirements' must be a string")

        # validate 'hostname'

        if not isinstance(config['hostname'], str):
            config_err(filename, "'hostname' must be a string")

    def main(LOG: logging.Logger, PROG_NAME: str) -> None:
        argparser = argparse.ArgumentParser(prog=PROG_NAME, description=PROG_NAME)
        argparser.add_argument('--config', nargs='+', required=True)
        argparser.add_argument('--sasl-username', default=None)

        ARGS = argparser.parse_args()

        config = collections.OrderedDict([
            ('envelope_mail_from', None),
            ('envelope_rcpt_to', None),
            ('header_add', {}),
            ('header_add_if_missing', {}),
            ('header_replace', {}),
            ('require_from', False),
            ('require_sasl_username', False),
            ('sasl_recipient_delimiter', ""),
            ('smtp_server', 'localhost:25'),
            ('bounce_from', None),
            ('reject_msg_requirements',
             "You are not fulfilling all requirements for writing to this address."),
            ('hostname', socket.getfqdn())
        ])

        # load configs

        LOG.debug("Loading config files %s", ARGS.config)
        for filename in ARGS.config:
            config = load_config(filename, config)

        # generate default 'bounce_from' if missing
        if config['bounce_from'] is None:
            config['bounce_from'] = \
                "Mail Delivery System <MAILER-DAEMON@{hostname}>".format(**config)
            check_config('--not traceable--', config)

        LOG.debug("Using the following config:\n%s", config)

        # check SASL username

        if config['require_sasl_username'] != False:
            LOG.debug("[require_sasl_username] Activated")

            if ARGS.sasl_username == '':
                infomsg("[require_sasl_username] Rejected: Empty username (probably not authenticated)")
                raise AuthenticationError(config['reject_msg_requirements'])

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
                raise AuthenticationError(config['reject_msg_requirements'])

            LOG.debug("[require_sasl_username] Passed")
        else:
            LOG.debug("[require_sasl_username] Not activated")

        # parse email

        LOG.debug("Parsing email")
        msg = email.message_from_binary_file(sys.stdin.detach())

        # check From Header

        if config['require_from'] != False:
            LOG.debug("[require_from] Activated")

            if not valid_address(msg['From']):
                infomsg("[require_from] Rejected: 'From' is not a valid address")
                raise AuthenticationError(config['reject_msg_requirements'])

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
                raise AuthenticationError(config['reject_msg_requirements'])

            LOG.debug("[require_from] Passed")
        else:
            LOG.debug("[require_from] Not activated")

        # update headers

        for k in config['header_replace']:
            if k in msg:
                del msg[k]

        for key, value in config['header_replace'].items():
            msg[key] = str(value)

        for key, value in config['header_add_if_missing'].items():
            if key in msg:
                continue
            msg[key] = str(value)

        for key, value in config['header_add'].items():
            msg[key] = str(value)

        # send email

        LOG.debug("Connecting to SMTP server at {}".format(config['smtp_server']))
        smtp_conn = smtplib.SMTP(config['smtp_server'])

        LOG.debug("Sending email via SMTP")
        smtp_err = smtp_conn.send_message(
            msg,
            config['envelope_mail_from'],
            config['envelope_rcpt_to'])

        # handle partially failed delivery

        if smtp_err:
            smtp_err_printable = [
                {'address': errm[0],
                 'code': errm[1][0],
                 'error': errm[1][1].decode('ascii', 'surrogateescape')}
                for errm in smtp_err.items()]

            for errm in smtp_err_printable:
                LOG.info(
                    "SMTP server '{host}' error for RCPT {address}: {code} {error}"
                    .format(host=config['smtp_server'], **errm))

            # format SMTP error messages
            smtp_msg_text = "\n\n".join([
                s['address'] + "\n" +
                textwrap.indent(prefix=" "*4, text=textwrap.fill(
                    "{code} {error}".format(**s)
                )) for s in smtp_err_printable
                ])
            # create message part that explains bounce
            bounce_text = MIMEText(
                BOUNCE_TEMPLATE.format(smtp_err=smtp_msg_text, **config))
            bounce_text['Content-Description'] = "Notification"

            # create message part with original mail
            original_msg = MIMEMessage(msg)
            original_msg['Content-Description'] = "Undelivered Message"

            # create complete bounce message
            bounce_msg = MIMEMultipart("report; report-type=delivery-status")
            bounce_msg.attach(bounce_text)
            bounce_msg.attach(original_msg)
            bounce_msg['From'] = config['bounce_from']
            bounce_msg['To'] = config['envelope_mail_from']
            bounce_msg['Subject'] = "Mail delivery failed"
            bounce_msg['Date'] = email.utils.formatdate(localtime=True)
            bounce_msg.preamble = "This is a MIME-encapsulated message."

            smtp_err_2 = smtp_conn.send_message(bounce_msg, "<>")

            if smtp_err_2:
                err("Sending bounce message failed partially: {}".format(smtp_err_2))

    if __name__ == "__main__":
        main(LOG, PROG_NAME)
    else:
        _reset_stdout()

except AuthenticationError as auth_err:
    LOG.debug("Rejecting message with 5.3.0")
    print(
        "5.3.0 {.args[0]}".format(auth_err),
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

