#!/usr/bin/perl 
use strict;
use warnings;
use SNMP; # must be 5.0.5 or newer
use XML::LibXML;
use Data::Dumper;
use Getopt::Long qw(GetOptions);
use Date::Format;
use File::Basename;
use utf8;

# from Zabbix sources
#define('ITEM_TYPE_SNMPV1',              1);
#define('ITEM_TYPE_SNMPV2C',             4);
#define('ITEM_TYPE_SNMPV3',              6);
#
#define('ITEM_VALUE_TYPE_FLOAT',         0);
#define('ITEM_VALUE_TYPE_STR',           1); // aka Character
#define('ITEM_VALUE_TYPE_LOG',           2);
#define('ITEM_VALUE_TYPE_UINT64',        3);
#define('ITEM_VALUE_TYPE_TEXT',          4);
#
#define('ITEM_DATA_TYPE_DECIMAL',        0);
#define('ITEM_DATA_TYPE_OCTAL',          1);
#define('ITEM_DATA_TYPE_HEXADECIMAL',    2);
#define('ITEM_DATA_TYPE_BOOLEAN',        3);

# assuming, that integers/counters/gauges go to Zabbix integers
# the rest goes to character type and should be reviewed at frontend (probably, changed or deleted)
my %value_types = (
	BITS		 => 1,
	COUNTER		 => 3,
	COUNTER64	 => 3,
	GAUGE		 => 3,
	INTEGER		 => 3,
	INTEGER32	 => 3,
	IPADDR		 => 1,
	NETADDR		 => 1,
	OBJECTID	 => 1,
	OCTETSTR	 => 1,
	OPAQUE		 => 1,
	TICKS		 => 3,
	UNSIGNED32	 => 3,
);

my $opt = {
	source		=> undef,
	module		=> [],
	group		=> [],
	inplace		=> undef,
	valuemaps	=> undef,
	root		=> undef,
	help		=> undef,
	interval	=> 300,
	history		=> 7,
	trends		=> 365,
	discovery	=> 3600,
};
 
my @valuemaps;
my %value_maps;
my @mappings;
my $vid;
my $mid;
my $doc;
my @applications;

sub print_usage {
	my ($message) = @_;
	my $name = basename($0);
	my $usage = <<EOF
Usage: $name <options>

Options:
\t-r|--root <OID>\t\t\tRoot OID to start template generation from.
\t-m|--module <MODULE>\t\tMIBs to load. Can be used multiple times, e.g.: -m MIB1 -m MIB2
\t-g|--group <Hostgroup>\t\tZabbix host group this template will belong to. Can be used multiple times, e.g.: -g Templates -g HostGroup1
\t-s|--source <filename>\t\tAdd generated template to already existing XML file.
\t-i|--inplace\t\t\tIf source file is defined, it will be edited inplace. The output will be send to stdout otherwise.
\t-v|--valuemaps\t\t\tUse Value Mappings. Will print SQL query for Value Mapping insertion. Should be done via Zabbix API, when it's implemented.
\t--interval\t\t\tData collection interval in seconds. Default is 300.
\t--history\t\t\tHistory storage period (in days). Default is 7.
\t--trends\t\t\tTrend storage period (in days). Default is 365.
\t--discovery\t\t\tDiscovery delay (in seconds). Default is 3600.
\t-h|--help\t\t\tPrint this help and exit.
EOF
;
	if ($message) {
		print (STDERR qq(\033[31;1m$message\033[0m\n\n));
		print (STDERR $usage);
		exit 1;
	} else {
		print $usage;
		exit 0;
	}
}

sub get_options {
	GetOptions($opt,
		q(source=s),
		q(module=s@),
		q(group=s@),
		q(inplace!),
		q(valuemaps!),
		q(help|h!),
		q(root=s),
		q(interval=i),
		q(history=i),
		q(trends=i),
		q(discovery=i),
	);
	
	print_usage() if $opt->{help};
	#print_usage(q(--root is mandatory)) if not defined $opt->{root};
	
	$opt->{root} = qq(.$opt->{root}) if defined $opt->{root} and $opt->{root} !~ m/^\./;
	
	if (defined $opt->{source}){
		my $parser = XML::LibXML->new;
		$doc = $parser->parse_file($opt->{source}) or die qq(can't parse XML file: $@);
	} else {
		create_xml();
	}

	@{$opt->{group}} = qw(Templates) if not @{$opt->{group}};
	my $root = $doc->documentElement();
}

sub hash2xml {
	my ($hash, $name) = @_;
	my $parent = $doc->createElement($name);
	for my $key (keys %$hash){
		my $element = $doc->createElement($key);
		$element->appendText($hash->{$key});
		$parent->appendChild($element);
	}
	return $parent;
}

sub create_xml {
	$doc = XML::LibXML::Document->new('1.0','utf-8');
	my %hash = (
			version => q(3.0),
			#date => time2str('%Y-%m-%dT%H:%M:%S%z', time),
			date => time2str('%Y-%m-%dT%H:%M:%SZ', time),
			groups => qq(),
			templates => qq(),
			value_maps => qq(),
	);
	
	my $zabbix_export = hash2xml(\%hash, q(zabbix_export));
	$doc->addChild($zabbix_export);
}

sub generate_discovery {
	my ($parent) = @_;
	(my $description = $parent->{description}) =~ s/^\s*//gm;
	$description = substr($description, 0, 2048);
	my %hash = (
		name => $parent->{label},
		type => 4,
		snmp_community => q({$SNMP_COMMUNITY}),
		snmp_oid => q(),
		key => $parent->{label},
		delay => $opt->{discovery},
		status => 0,
		allowed_hosts => q(),
		snmpv3_contextname => q(),
		snmpv3_securityname => q(),
		snmpv3_securitylevel => 0,
		snmpv3_authprotocol => 0,
		snmpv3_authpassphrase => q(),
		snmpv3_privprotocol => 0,
		snmpv3_privpassphrase => q(),
		delay_flex => q(),
		params => q(),
		ipmi_sensor => q(),
		authtype => 0,
		username => q(),
		password => q(),
		publickey => q(),
		privatekey => q(),
		port => q(),
		lifetime => 1,
		#description => substr($parent->{description},0,2048),
		description => $description,
		item_prototypes => q(),
		trigger_prototypes => q(),
		graph_prototypes => q(),
		host_prototypes => q(),
	);
	my $discovery_rule = hash2xml(\%hash, q(discovery_rule));

	%hash = (
		evaltype => 0,
		formula => q(),
		conditions => q(),
	);
	$discovery_rule->appendChild(hash2xml(\%hash, q(filter)));
	
	my $application = $parent->{parent}->{label};
	push @applications, $application if not grep {$_ eq $application} @applications;
	
	$parent = $parent->{nextNode}; # Table -> Entry
	for my $child (@{$parent->{children}}){
		my $name = $child->{description} !~ m/^\s*$/m ? $child->{description} : $child->{label};
		$name = (split /\n/, $name )[0];
		$name =~ s/\.\s*$//;
		($description = $child->{description}) =~ s/^\s*//gm;
		$description = substr($description, 0, 2048);
		%hash = (
			name => qq({#SNMPVALUE}: $name),
			type => 4,
			snmp_community => q({$SNMP_COMMUNITY}),
			multiplier => 0,
			snmp_oid => qq($child->{objectID}.{#SNMPINDEX}),
			key => qq($child->{label}\[{#SNMPINDEX}]),
			delay => $opt->{interval},
			history => $opt->{history},
			trends => $opt->{trends},
			status => 0,
			value_type => 0,
			allowed_hosts => q(),
			units => q(),
			delta => 0,
			snmpv3_contextname => q(),
			snmpv3_securityname => q(),
			snmpv3_securitylevel => 0,
			snmpv3_authprotocol => 0,
			snmpv3_authpassphrase => q(),
			snmpv3_privprotocol => 0,
			snmpv3_privpassphrase => q(),
			formula => 1,
			delay_flex => q(),
			params => q(),
			ipmi_sensor => q(),
			data_type => 0,
			authtype => 0,
			username => q(),
			password => q(),
			publickey => q(),
			privatekey => q(),
			port => q(),
			#description => substr($child->{description},0,2048),
			description => $description,
			inventory_link => 0,
			applications => q(),
			valuemap => q(),
			logtimefmt => q(),
			application_prototypes => q(),
		);
		$hash{units} = $child->{units} if defined $child->{units};
		if (defined $value_types{$child->{type}}){
			$hash{value_type} = $value_types{$child->{type}};
		} else {
			print STDERR qq(Could not find value type for OID SYNTAX: $child->{type}\n);
		}
		my $item_prototype = hash2xml(\%hash, q(item_prototype));

		%hash = (
			name => $application,
		);
		${$item_prototype->findnodes(q(applications))}[0]->appendChild(hash2xml(\%hash, q(application)));
			
		${$discovery_rule->getElementsByTagName(q(item_prototypes))}[0]->appendChild($item_prototype);
	
		if (defined $opt->{valuemaps} and keys %{$child->{enums}}){
			$vid++;
			push @valuemaps, qq(INTO valuemaps (valuemapid,name) VALUES (vid+$vid,'$child->{label}'));
			foreach my $key (sort {$child->{enums}->{$a} <=> $child->{enums}->{$b}} keys %{$child->{enums}}){
				$mid++;
				push @mappings, qq(INTO mappings (mappingid,valuemapid,value,newvalue) VALUES (mid+$mid,vid+$vid,'$child->{enums}->{$key}','$key'));
				$value_maps{$child->{label}}{$key} = $child->{enums}->{$key};
			}
			${$item_prototype->findnodes(q(valuemap))}[0]->appendTextChild(qq(name),$child->{label});
		}
	}
	
	${$discovery_rule->findnodes(q(snmp_oid))}[0]->appendText(qq($parent->{objectID}.1));
	return $discovery_rule;
}

sub generate_item {
	my ( $parent ) = @_;

	my $name = $parent->{description} !~ m/^\s*$/m ? $parent->{description} : $parent->{label};
	$name = (split /\n/, $name )[0];
	$name =~ s/\.\s*$//;
	(my $description = $parent->{description}) =~ s/^\s*//gm;
	$description = substr($description, 0, 2048);

	my %hash = (
		name => $name,
		type => 4,
		snmp_community => q({$SNMP_COMMUNITY}),
		multiplier => 0,
		snmp_oid => qq($parent->{objectID}.0),
		key => $parent->{label},
		delay => $opt->{interval},
		history => $opt->{history},
		trends => $opt->{trends},
		status => 0,
		value_type => 0,
		allowed_hosts => q(),
		units => q(),
		delta => 0,
		snmpv3_contextname => q(),
		snmpv3_securityname => q(),
		snmpv3_securitylevel => 0,
		snmpv3_authprotocol => 0,
		snmpv3_authpassphrase => q(),
		snmpv3_privprotocol => 0,
		snmpv3_privpassphrase => q(),
		formula => 1,
		delay_flex => q(),
		params => q(),
		ipmi_sensor => q(),
		data_type => 0,
		authtype => 0,
		username => q(),
		password => q(),
		publickey => q(),
		privatekey => q(),
		port => q(),
		#description => substr($parent->{description},0,2048),
		description => $description,
		inventory_link => 0,
		applications => q(),
		valuemap => q(),
		logtimefmt => q(),
	);
	$hash{units} = $parent->{units} if defined $parent->{units};
	if (defined $value_types{$parent->{type}}){
		$hash{value_type} = $value_types{$parent->{type}};
	} else {
		print STDERR qq(Could not find value type for OID SYNTAX: $parent->{type}\n);
	}
	my $item = hash2xml(\%hash, q(item));

	my $application = $parent->{parent}->{label};
	push @applications, $application if not grep {$_ eq $application} @applications;
	%hash = (
		name => $application,
	);
	${$item->findnodes(q(applications))}[0]->appendChild(hash2xml(\%hash, q(application)));

	if (defined $opt->{valuemaps} and keys %{$parent->{enums}}){
		$vid++;
		push @valuemaps, qq(INTO valuemaps (valuemapid,name) VALUES (vid+$vid,'$parent->{label}'));
		foreach my $key (sort {$parent->{enums}->{$a} <=> $parent->{enums}->{$b}} keys %{$parent->{enums}}){
			$mid++;
			push @mappings, qq(INTO mappings (mappingid,valuemapid,VALUE,newvalue) VALUES (mid+$mid,vid+$vid,'$parent->{enums}->{$key}','$key'));
			$value_maps{$parent->{label}}{$key} = $parent->{enums}->{$key};
		}
		${$item->findnodes(q(valuemap))}[0]->appendTextChild(q(name),$parent->{label});
	}

	return $item;
}

sub generate_template {
	my ($parent) = @_;
	my $name = q(Template MIB ).join(q( ),@{$opt->{module}}).qq( - $parent->{label});
	my %hash = (
		template => $name,
		name => $name,
		description => q(),
		groups => q(),
		applications => q(),
		items => q(),
		discovery_rules => q(),
		macros => q(),
		templates => q(),
		screens => q(),
	);
	my $template = hash2xml(\%hash, q(template));
	
	my $current = $parent;
	my $current_discovery;
	while (defined $current->{nextNode} and $current->{nextNode}->{objectID} =~ /^$parent->{objectID}/){
		$current = $current->{nextNode};
		if (defined $current_discovery){
			if ($current->{objectID} =~ /^$current_discovery->{objectID}/){
				next;
			} else {
				$current_discovery = undef;
			}
		}

		if ($current->{label} =~ m/Table$/){
			$current_discovery = $current;
			my $discovery_rule = generate_discovery($current_discovery);
			${$template->findnodes(q(discovery_rules))}[0]->appendChild($discovery_rule);
		} elsif ( $current->{type} ne q{} ){
			if (defined $value_types{$current->{type}}){
				my $item = generate_item($current);
				${$template->findnodes(q(items))}[0]->appendChild($item);
			}	
		}
	}

	foreach my $application (@applications){
		%hash = (
			name => $application,
		);
		${$template->findnodes(q(applications))}[0]->appendChild(hash2xml(\%hash, q(application)));
	}

	foreach my $group (@{$opt->{group}}){
		%hash = (
			name => $group,
		);
		${$template->findnodes(q(groups))}[0]->appendChild(hash2xml(\%hash, q(group)));
	}
	return $template;
}

sub generate_value_map {
	my ($name) = @_;
	my %hash = (
		name => $name,
		mappings => q(),
	);
	my $value_map = hash2xml(\%hash, q(value_map));
	foreach my $mapping (keys %{$value_maps{$name}}){
		%hash = (
			value => $value_maps{$name}{$mapping},
			newvalue => $mapping,
		);
		${$value_map->findnodes(q(mappings))}[0]->appendChild(hash2xml(\%hash, q(mapping)));
	}
	return $value_map;
}

sub guess_root {
	my ($module) = @_;
	#print qq(Trying to guess root for module $module\n);
	for my $oid (sort keys %SNMP::MIB){
		next if $oid !~ m/.1\./;
		return $oid if $SNMP::MIB{$oid}{moduleID} eq $module; 
	}
	return undef;
}

sub main {
	get_options();
	$SNMP::save_descriptions = 1;
	SNMP::loadModules(@{$opt->{module}});
	SNMP::initMib();

	my @roots = ();

	if (defined $opt->{root}){
		push @roots, $opt->{root};
	} else {
		foreach my $module (@{$opt->{module}}){
			my $oid = guess_root($module);
			if (defined $oid){
				push @roots, $oid;
			} else {
				next;
			}
		}
	}

	foreach my $root (@roots){
		my $parent = $SNMP::MIB{$root};
		if ($parent->{objectID} ne $root){
			print_usage(qq(Parent OID $opt->{root} was not found! Maybe you forgot to load modules using --module=<module_name>?\n));
		}
	
		my $template = generate_template($parent);
		${$doc->findnodes(q(/zabbix_export/templates))}[0]->appendChild($template);
	}

	foreach my $group (@{$opt->{group}}){
		my %hash = (
			name => $group,
		);
		${$doc->findnodes(q(zabbix_export/groups))}[0]->appendChild(hash2xml(\%hash, q(group)));
	}

	foreach my $value_map (keys %value_maps){
		${$doc->findnodes(q(zabbix_export/value_maps))}[0]->appendChild(generate_value_map($value_map));
	}

	my $out = $doc->toString(2);
	utf8::decode($out);
	
	if (defined $opt->{source} and defined $opt->{inplace}){
		open my $fh, q(>), $opt->{source} or die qq(Cannot open $opt->{source} file for write: $!);
		print $fh $doc->toString;
		close $fh;
	} else {
		binmode STDOUT, q(:encoding(UTF-8));
		print $out;
	}
}

main();
