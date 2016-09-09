Wonderbolt LDA
==============

Wonderbolt is a config based email modifier, acting as local delivery
agent and resubmitting emails via SMTP after modification.

Wonderbolt's main purpose is to enable simple email lists with external
management of subscribers.

-  Depends: python >= 3.4
-  Recommends: python3-systemd

Command-Line Options
--------------------

``--config``
~~~~~~~~~~~~

Required. Can be given multiple times. Later config files overwrite
values from earlier ones.

``--sasl-username``
~~~~~~~~~~~~~~~~~~~

Optional. See config option ``require_sasl_username``.

Configuration Options
---------------------

``msg_bounced_requirements``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

*string*

Message contained in bounce email delivered if ``require_``
configurations are violated.

``header_add``
~~~~~~~~~~~~~~

*mapping*

Adds header values without removing/changing existing header lines.
Performed after ``header_replace``. Therefore, ``header_add`` adds a
header a second time if key overlaps with ``header_replace`` are
present.

``header_replace``
~~~~~~~~~~~~~~~~~~

*mapping*

Removes all existing headers with the given keys and adds the new
values.

``envelope_mail_from``
~~~~~~~~~~~~~~~~~~~~~~

*string* or *``null``*

Bounce address for the new delivery of the email. If this setting is
``null``, it will be derived from the ``From`` email header.

``envelope_rcpt_to``
~~~~~~~~~~~~~~~~~~~~

*list of strings* or *``null``*

Recipients for new delivery of the email. If this setting is ``null``,
it will be derived from the ``To`` email header.

``require_from``
~~~~~~~~~~~~~~~~

*list of strings* or *``"envelope_rcpt_to"``* or *``false``*

Enables to reject mails if the ``From:`` email header does not fulfill a
condition.

-  *list of strings*: ``From`` must be contained in this list.
-  *``"envelope_rcpt_to"``*: ``From`` must be contained in the
   ``envelope_rcpt_to`` list. If this option is set,
   ``envelope_rcpt_to`` must be set and not ``null``.
-  *``false``*: Disables checks (default).

``require_sasl_username``
~~~~~~~~~~~~~~~~~~~~~~~~~

*list of strings* or *``"envelope_rcpt_to"``* or *``false``*

Enables to reject mails if the SASL username does not fulfill a
condition. Same parameters as for ``require_from``.

For this feature to work, ``--sasl-username ${sasl_username}`` has to be
passed.

``sasl_recipient_delimiter``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

*string*

Recipient delimiters only affect the interpretation of
``envelope_rcpt_to`` if ``require_sasl_username`` is set to this value.
The localpart of all recipients is stripped from all characters occuring
after a first delimiter for comparing with the sasl username.

This option should be set to the same value as the
*recipient\_delimiter* option of the postfix server. Every character in
the string is treated as a delimiter. An empty string (default)
corresponds to no delimiters.

``smtp_server``
~~~~~~~~~~~~~~~

*string*

SMTP server via which the email is submitted. Default is "localhost:25".

Example Configuration
---------------------

.. code:: json

    {
        "msg_bounced_requirements": "Bounced due to unprivileged SASL user",
        "header_add": {
            "X-Header-1": 1,
            "X-Header-3": "Value 3"
        },
        "header_replace": {
            "X-Header-1": "Value 1",
            "X-Header-2": "Value 2"
        },
        "envelope_mail_from": "Bounce To <bounce_to@example.com>",
        "envelope_rcpt_to": [
            "User Name <user@example.org>",
            "user2@example.org"
        ],
        "require_from": false,
        "require_sasl_username": "envelope_rcpt_to",
        "smtp_server": "mail.example.com:25"
    }

Complete Mailinglist under Postfix
----------------------------------

*master.cfg*

``wonderbolt   unix  -       n       n       -       -       pipe   flags=Ohu   user=ldaml   argv=/usr/local/bin/wonderbolt.py    --config /etc/wonderbolt/${recipient}.json    --sasl-username ${sasl_username}``

*main.cfg*

::

    wonderbolt_destination_recipient_limit = 1

*/etc/wonderbolt/list@example.org.json*

.. code:: json

    {
        "envelope_mail_from": "list_bounce@example.org",
        "envelope_rcpt_to": [
            "listadmin@example.org",
            "user1@example.com",
            "user2_lists@example.com"
        ],
        "header_replace": {
            "List-Help": "<mailto:listadmin@example.org>",
            "List-Id": "<test.example.org>",
            "List-Owner": "<mailto:listadmin@example.org>",
            "List-Post": "<mailto:list@example.org>",
            "List-Subscribe:": "<mailto:listadmin@example.org?body=subscribe%20list%20list@example.org>",
            "List-Unsubscribe": "<mailto:listadmin@example.org?body=unsubscribe%20list%20list@example.org>",
            "Precedence": "bulk"
        },
        "require_sasl_username": "envelope_rcpt_to",
        "sasl_recipient_delimiter": "_"
    }

*maps/aliases* (postfix ``virtual_alias_maps``)

::

    list_bounce@example.org listadmin@example.org

*maps/trasport* (postfix ``transport_maps``)

::

    list@example.org wonderbolt:

Dedication
----------

::

                                           ooooooo                
                                       oO0.....00OOOoo            
                                    oO0...........0Oo             
                                  oO000000000000000000o           
                            o00Ooo000000000000000000OoOOo         
                            0....000000000000000000000o           
                            ...........0000000000000000o          
                            0...............000..00000000o        
                     oOoO0OO..................O..0Oo0oooooo       
                     O........0.....0OOooo..O0....O 0O            
                  00OO0.......000....00o  ooO.::.......o          
                  O............000.....00o  O.:.......0           
                   O...........000000......0......00oo            
                    o0.........000000000...........0o             
                      o0........0000000.......0OOoo               
                    OOOO0.......0O0000000......0o       oooo      
                    O............0OO000000.......O    o0....0O    
                     oO...........0OO000000.......00OO........0o  
                        oO.........0OO00.00..............00....0o 
                           o0.......OOO0..0............0oo......0 
                           O........0OO.................o 0......o
                            O0.......00.................0  O0...0 
              ooooooooo        oo0.......................o   ooo  
          oOOOOOOOOOOO000OOOoo  0::......................         
        OOOOOOOOO000000000000000...0.............Oo0....O         
       OOOOOOO000000...........................Oo   oOOo          
      oO oOOO00000.::..00OOoooO00...........0o                    
         0OO00000::.000Oo    0.............0o                     
         0OO0000.:.0000      o............0o                      
         OOO0000.:.0000o      o..........0                        
          OOO0000.:.00OOo      O..........o                       
           OOO0000::.00ooo     o..........0                       
            oOO0000.:.00O      o...........O                      
              OO0000.:.000o     oO0.........O                     
               oO00000.:.OOO        0.......0o                    
                 oO0000.:.ooOo      oO00....0o                    
                   oO000.:.o oO                                   
                     oOO0.:0   o                                  
                       o O.0                                      
                          Oo                                      

GitLab Thumbnail Copyright
`BlackGryph0n <http://blackgryph0n.deviantart.com/art/Rainbow-Dash-204973879>`__
Licensed under `CC BY-NC
3.0 <https://creativecommons.org/licenses/by-nc/3.0/>`__
