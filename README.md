# mib2template

Simple SNMP MIB -> Zabbix template conversion script.
```
Usage: mib2template.pl <options>

Options:
        -r|--root <OID>                 Root OID to start template generation from. (mandatory)
        -m|--module <MODULE>            MIBs to load. Can be used multiple times, e.g.: -m MIB1 -m MIB2
        -g|--group <Hostgroup>          Zabbix host group this template will belong to. Can be used multiple times, e.g.: -g Templates -g HostGroup1
        -s|--source <filename>          Add generated template to already existing XML file.
        -i|--inplace                    If source file is defined, it will be edited inplace. The output will be send to stdout otherwise.
        -v|--valuemaps                  Use Value Mappings. Will print SQL query for Value Mapping insertion. Should be done via Zabbix API, when it's implemented.
        --interval                      Data collection interval in seconds. Default is 300.
        --history                       History storage period (in days). Default is 7.
        --trends                        Trend storage period (in days). Default is 365.
        --discovery                     Discovery delay (in seconds). Default is 3600.
        -h|--help                       Print this help and exit.
```

#### Examples
The following command will generate template similar to default "Template SNMP Interfaces"
```
./mib2template.pl --module IF-MIB --root .1.3.6.1.2.1.2 --group Templates
```
