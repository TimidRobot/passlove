Archived / Unsupported
======================

This project has been archived and is no longer supported.

A better project: `dropbox/zxcvbn <https://github.com/dropbox/zxcvbn>`_: Low-Budget Password Strength Estimation (especially the `demo <https://lowe.github.io/tryzxcvbn/>`_!)


Word List
=========

The bundled word list (``words.pkl``) uses data from the Part Of Speech Database from `Kevin's Word List Page <http://wordlist.sourceforge.net/>`_.

Help Examples
=============
See the `passlove Wiki <https://github.com/ClockworkNet/passlove/wiki>`_.

Password Strength
=================

Good (72 bits of Entropy)
-------------------------

===========================================  ====================  ==============  ==============
Attack Method                                Guesses per second    Years to Solve  Years to Crack
===========================================  ====================  ==============  ==============
Distributed.net guesses per second (RC5-72)  1,105,696,629,234.00             135              67
ElcomSoft guesses per second (NTLM)              2,800,000,000.00          53,480          26,740
Rate limited to 9 guesses per 3 minutes                      0.05  *over 1 quadrillion*
===========================================  ====================  ==============================

Good passwords should be able to withstand unrestricted brute force attempts by national governments and bot nets.

Moderate (63 bits of Entropy)
-----------------------------

===========================================  ====================  ==============  ==============
Attack Method                                Guesses per second    Years to Solve  Years to Crack
===========================================  ====================  ==============  ==============
Distributed.net guesses per second (RC5-72)  1,105,696,629,234.00            0.26            0.13
ElcomSoft guesses per second (NTLM)              2,800,000,000.00          104.45           52.22
Rate limited to 9 guesses per 3 minutes                      0.05  *over 2 trillion*
===========================================  ====================  ==============================

Moderate passwords should be able to withstand unrestricted brute force attempts by local governments and persistent hackers.

Weak (28 bits of Entropy)
-------------------------

===========================================  ====================  ==============  ==============
Attack Method                                Guesses per second    Years to Solve  Years to Crack
===========================================  ====================  ==============  ==============
Distributed.net guesses per second (RC5-72)  1,105,696,629,234.00  *less than a second*
-------------------------------------------  --------------------  ------------------------------
ElcomSoft guesses per second (NTLM)              2,800,000,000.00  *less than a second*
-------------------------------------------  --------------------  ------------------------------
Rate limited to 9 guesses per 3 minutes                      0.05             170              85
===========================================  ====================  ==============  ==============

Weak passwords are only viable if they are **never** used on multiple systems and the system they are used on has a mechanism for rate limiting guesses.

Unfortunately, systems that rate limit guesses (ex. lockout thresholds) are still rare. Additionally, even systems with lockout thresholds are often compromised, making the passwords hashes available.

Systems that default to having **no** lockout threshold:

- Windows Server 2008 R2 and previous `Account Policies <http://technet.microsoft.com/en-us/library/dd349793%28WS.10%29.aspx>`_

References (retrieved 2012-03-19)
---------------------------------

- `Password_strength - Wikipedia <http://technet.microsoft.com/en-us/library/dd349793%28WS.10%29.aspx>`_
- `A complete suite of ElcomSoft password recovery tools <http://www.elcomsoft.com/eprb.html#gpu>`_

  - `NTLM - Wikipedia <http://en.wikipedia.org/wiki/NTLM>`_

- `stats.distributed.net - RC5-72 Overall Project Stats <http://stats.distributed.net/projects.php?project_id=8>`_

  - 2,425 participants tested 1,105,696,629,234 keys per second
  - 91,027 total participants since beginning of project
  - `RC5 - Wikipedia <http://en.wikipedia.org/wiki/RC5>`_

- *On average, an attacker will have to try half the possible passwords before finding the correct one.* (`Password_strength - Wikipedia <http://en.wikipedia.org/wiki/Password_strength>`_ referencing NIST's `Electronic Authentication Guideline (PDF) <http://csrc.nist.gov/publications/nistpubs/800-63/SP800-63V1_0_2.pdf>`_ and `Law_of_large_numbers - Wikipedia <http://en.wikipedia.org/wiki/Law_of_large_numbers>`_)

- `Password_cracking - Wikipedia <http://en.wikipedia.org/wiki/Password_cracking>`_

License
=======

passlove
--------

- LICENSE_ (`MIT License`_)

.. _LICENSE: LICENSE
.. _`MIT License`: http://www.opensource.org/licenses/MIT

Part of Speech Database - Moby database
---------------------------------------

The Moby database was explicitly placed in the public domain: ::

    The Moby lexicon project is complete and has been place into the public
    domain. Use, sell, rework, excerpt and use in any way on any platform.

    Placing this material on internal or public servers is also encouraged. The
    compiler is not aware of any export restrictions so freely distribute
    world-wide.

    You can verify the public domain status by contacting

    Grady Ward
    3449 Martha Ct.
    Arcata, CA  95521-4884

    grady@netcom.com
    grady@northcoast.com


Part of Speech Database - WordNet database
------------------------------------------

The WordNet database is under the WordNet variant of the MIT license: ::

    This software and database is being provided to you, the LICENSEE, by
    Princeton University under the following license.  By obtaining, using
    and/or copying this software and database, you agree that you have read,
    understood, and will comply with these terms and conditions.:

    Permission to use, copy, modify and distribute this software and database
    and its documentation for any purpose and without fee or royalty is hereby
    granted, provided that you agree to comply with the following copyright
    notice and statements, including the disclaimer, and that the same appear
    on ALL copies of the software, database and documentation, including
    modifications that you make for internal use or for distribution.

    WordNet 1.6 Copyright 1997 by Princeton University.  All rights reserved.

    THIS SOFTWARE AND DATABASE IS PROVIDED "AS IS" AND PRINCETON UNIVERSITY
    MAKES NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED. BY WAY OF
    EXAMPLE, BUT NOT LIMITATION, PRINCETON UNIVERSITY MAKES NO REPRESENTATIONS
    OR WARRANTIES OF MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE OR
    THAT THE USE OF THE LICENSED SOFTWARE, DATABASE OR DOCUMENTATION WILL NOT
    INFRINGE ANY THIRD PARTY PATENTS, COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS.

    The name of Princeton University or Princeton may not be used in
    advertising or publicity pertaining to distribution of the software and/or
    database.  Title to copyright in this software, database and any associated
    documentation shall at all times remain with Princeton University and
    LICENSEE agrees to preserve same.
