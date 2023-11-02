# ActiveMaim

A PoC generator for [this research](https://ttp.report/evasion/2023/11/02/releasing-activemaim-evade-macros-detection.html).

Takes the .mht file macro-enabled document as input.

```
usage: activemaim.py [-h] --infile INFILE --outfile OUTFILE [--inprocedure INPROCEDURE] [--outprocedure OUTPROCEDURE] [--remote REMOTE] [--prependfile PREPENDFILE | --prependrandom]

options:
  -h, --help            show this help message and exit
  --infile INFILE       Input .mht file
  --outfile OUTFILE     Resulting manipulated file with embedded payload
  --remote REMOTE       Address for remote payload
  --prependfile PREPENDFILE
                        File to prepend before MHTML contents
  --prependrandom       Prepend random bytes and OLEVBA bypass

  --inprocedure INPROCEDURE
                        Procedure name to be manipulated
  --outprocedure OUTPROCEDURE
                        Resulting procedure name
```
