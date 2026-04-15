# BlueSAM BOF
A Cobalt Strike Beacon Object File adaptation of BlueSAM that attempts to obtain
a copy of the SAM database through Windows Defender update/VSS behavior and
process offline registry data from Beacon.

Credits to Nightmare-Eclipse's BlueHammer
(https://github.com/Nightmare-Eclipse/BlueHammer) for the original PoC.

## To start
1. Git clone the repo
2. Run `make`

## Usage
1. Import the bluesam.cna script into Cobalt Strike
2. Use the command `bluesam`

```
bluesam
Command         Description
(none)          Runs the BlueSAM BOF with the default target behavior.
any argument    Shows this help menu.
```

Credits:
- https://github.com/Nightmare-Eclipse/BlueHammer
- https://github.com/MEhrn00/boflink
- https://github.com/trustedsec/CS-Situational-Awareness-BOF/tree/master/src/base_template
- https://github.com/CodeXTF2/bof_template
