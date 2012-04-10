Depends
=======
- Word list or dictionary

  - If no word list is provided on the command line, it defaults to using ``/usr/share/dict/american-english-huge``, which is distributed by the Debian or Ubuntu wamerican-huge package. If you're not using either and your system doesn't have an alternative, it's probably easiest to extract the file from the dpkg.
  - `Ubuntu -- Details of package wamerican-huge in precise <http://packages.ubuntu.com/precise/wamerican-huge>`_
  - `Kevin's Word List Page <http://wordlist.sourceforge.net/>`_ (wamerican-huge is based on SCOWL)

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

Systems that default to having no lockout threshold:

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

passlove is licensed under the `BSD 2-Clause License <http://www.opensource.org/licenses/BSD-2-Clause>`_

    Copyright (c) 2012, Clockwork Active Media Systems
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    - Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    - Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
