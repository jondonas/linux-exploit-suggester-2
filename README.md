
Linux Exploit Suggester 2
=========================

Next-generation exploit suggester based on [Linux_Exploit_Suggester](https://github.com/PenturaLabs/Linux_Exploit_Suggester)

Key Improvements Include:
* More exploits! (Last updated: March 27, 2019)
* Option to download exploit code directly from Exploit DB
* Accurate wildcard matching. This expands the scope of searchable exploits.
* Output colorization for easy viewing.
* And more to come!

This script is extremely useful for quickly finding privilege escalation vulnerabilities both in on-site and exam environments. 

Usage
==============

When run without arguments, the script performs a 'uname -r' to grab the Linux operating system release version, and returns a list of possible exploits. Links to CVEs and applicable exploit POCs are included. Keep in mind that a patched/back-ported patch may fool this script.

```
$ ./linux-exploit-suggester.pl

  Local Kernel: 4.4.0
  Searching among 73 exploits...

  Possible Exploits
  [1] af_packet
      CVE-2016-8655
      Source: http://www.exploit-db.com/exploits/40871
  [2] dirty_cow
      CVE-2016-5195
      Source: http://www.exploit-db.com/exploits/40616
  [3] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [4] get_rekt
      CVE-2017-16695
      Source: http://www.exploit-db.com/exploits/45010
```

Use the **-k** flag to manually enter a wildcard for the kernel/operating system release version.

```
$ ./linux-exploit-suggester.pl -k 3
```

Use the **-d** flag to open a download menu to retrieve exploit code directly from Exploit DB. You can either download all exploits or select them individually by number.

```
$ ./linux-exploit-suggester.pl -d

  Exploit Download
  (Download all: 'a' / Individually: '2,4,5' / Exit: ^c)
  Select exploits to download: a

  Downloading https://www.exploit-db.com/raw/40871 -> exploit_af_packet
  Downloading https://www.exploit-db.com/raw/40616 -> exploit_dirty_cow
  Downloading https://www.exploit-db.com/raw/45697 -> exploit_exploit_x
  Downloading https://www.exploit-db.com/raw/45010 -> exploit_get_rekt
```

Use the **-h** flag to display the help menu

Contributing
============

This project is in active development. Feel free to suggest a new feature or open a pull request!
