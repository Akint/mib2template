# mib2template

Simple SNMP MIB -> Zabbix template conversion script.
```
Usage: mib2template.pl <options>

Options:
        -m|--module <MODULE>            MIBs to load. Can be used multiple times, e.g.: -m IF-MIB -m SW-MIB (mandatory)
        -r|--root <OID>                 Root OID to start template generation from.
        -g|--group <Hostgroup>          Zabbix host group this template will belong to. Can be used multiple times, e.g.: -g Templates -g HostGroup1
        --valuemaps                     Use Value Mappings. You will have to import template as Zabbix Super Admin.
        --interval                      Data collection interval in seconds. Default is 300.
        --history                       History storage period (in days). Default is 7.
        --trends                        Trend storage period (in days). Default is 365.
        --discovery                     Discovery delay (in seconds). Default is 3600.
        -h|--help                       Print this help and exit.
        -v|--verbose                    Increase verbosity level.
        -d|--debug                      Enable debug messaging.
```

#### Examples
The following command will generate template similar to default "Template SNMP Interfaces"
```
./mib2template.pl --module IF-MIB --root .1.3.6.1.2.1.2 --group Templates
```
