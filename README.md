# BlueSAM BOF
A Cobalt Strike Beacon Object File adaptation of BlueHammer that attempts to obtain
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
## Sample run
<img width="1165" height="702" alt="image" src="https://github.com/user-attachments/assets/e1eaf4ea-61f0-4752-a023-6f1e027bd6f3" />

## Credits:
- https://github.com/Nightmare-Eclipse/BlueHammer
- https://github.com/MEhrn00/boflink
- https://github.com/trustedsec/CS-Situational-Awareness-BOF/tree/master/src/base_template
- https://github.com/CodeXTF2/bof_template
