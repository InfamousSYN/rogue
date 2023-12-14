Hashcatifier
=======================================

[Hashcatifier](https://github.com/InfamousSYN/rogue/blob/master/tools/hashcatifer.py) is a simple tool used to convert the captured hashes to a format that is consumable by hashcat. 

## Arguments

- `--file` - Used to point to the `freeradius-server-wpe.log` containing the captured credentials from `rogue`, 
- `--output` - Specify the name of the output file, 
- `--format` - Specify the format to output hashes, currently only the supported format is the NET-NTLMv1 (`hashcat -m 5500`)
- `--mode` - Specify the number of hashes to reformat

## Usage

1. Run the hashcatifier utility

```bash
sudo python3 /opt/rogue/tools/hashcatifer.py --file [freeradius-server-wpe.log] -o [output format]
```

2. Launch hashcat with the supplied command

```bash
hashcat -m 5500 [output format] -w [wordlist]
```
