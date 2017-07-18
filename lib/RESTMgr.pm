#!/usr/bin/perl
#
# RESTMgr.pm
# Subroutines for GET/POST/PUT/DELETE requests, response comparison and report generation
#
# Author : Subramani R
# History :
## 08/21/12 (Subramani R) - Created
## 09/03/12 (Subramani R) - Modified to use same session for all the operations in a test execution
## 09/11/12 (Subramani R) - Support is added for POST and PUT to send requests with JSON content-type
## 09/13/12 (Subramani R) - Changed the 'get_reference' subroutine, because now the reference return '/'
##                          instead of '%2F'
## 09/17/12 (Subramani R) - Modified 'compare_response' subroutine in RESTMgr.pm and modified responses in few Test Suites
## 09/20/12 (Subramani R) - Fixed the error when converting '0' integer value from hash to xml/json
## 09/21/12 (Subramani R) - Query String will be generated correctly, when the same field is present more than once
## 09/21/12 (Subramani R) - To handle EA Search cases
## 09/01/13 (Madhu Kumar) - Modified RESTMgr.pm as per NIOS-40963 and WEBAPI-182
## 08/05/13 (Madhu Kumar) - Adds support for urlencoded/json formats, PAPI scripts in setup and _function
## 12/10/14 (Subramani R) - Modified 'create_session' subroutine to validate the response of GET operation

package RESTMgr;

use LWP::UserAgent;
use XML::XSLT;
use XML::Simple;
use REST::Client;
use Data::Dumper 'Dumper';
use JSON;
use FindBin;

my $reason = "";
my $hash_flag = "";
my $objects_flag = 0;

# Creates a Session with given Username/Password
# Input : Grid Master VIP, Username, Password, WAPI Version and Master(1)/Member(0)
# Output : LWP::UserAgent Object to dispatch web requests
sub create_session {
    my ($vip ) = @_;
    my $retry = 15;
    my $ua = LWP::UserAgent->new(timeout => 10000, keep_alive => 1, ssl_opts=>{SSL_verify_mode=>0});
    $ua->cookie_jar( {} );
    #$ua->ssl_opts( {verify_hostname => 0} );
    #$ua->credentials("$vip:443", "InfoBlox ONE Platform", $username, $password);
    my $response = $ua->get("https://jsonplaceholder.typicode.com/posts/1");
    return $ua;
}

# Generates the HTML report from XML file
# Input : Results Directory and XML Report Filename
# Output is an 'index.html' file in Results Directory
sub generate_report {
    my ($results_dir, $report_file) = @_;
    my $xslfile = "$FindBin::Bin/../lib/wapi.xslt"; # Stylesheet Definition for the Report
    my $reportfile = "$results_dir/$report_file";
    
    my $xslt = eval {XML::XSLT->new($xslfile)};
    if ($@) {
	die("Sorry could not create XSLT instance:\n", $@);
    }
    $xslt->transform($reportfile);
    open(REPORT, ">$results_dir/index.html");
    print REPORT $xslt->toString;
    close REPORT;
}

# Generates XML from a HASH
# Input : HASH Reference and Root element for the XML file
# Returns XML String
sub get_xml_from_hash {
    my ($hash, $root) = @_;
    my $xmlout = XML::Simple->new(RootName => $root);
    my $xmlstr = $xmlout->XMLout($hash, KeyAttr => [], noattr => 1);
    return $xmlstr;
}

# Generates XML from a HASH
# Input : HASH Reference
# Returns XML String
sub hash_to_xml {
    my ($hash) = @_;
    my $output = "";
    foreach my $element (keys %$hash) {
	if((ref $hash->{$element} eq "HASH") && $hash->{$element}->{type}) {
	    if($hash->{$element}->{type} eq "int" || $hash->{$element}->{type} eq "boolean") {
		$output = $output . "<$element type=\"$hash->{$element}->{type}\">$hash->{$element}->{content}</$element>\n";
	    }
	    elsif($hash->{$element}->{type} eq "object") {
		my $size = keys %{$hash->{$element}};
		delete $hash->{$element}->{type} || print "Not deleted\n";
		$output = $output . "<$element type=\"object\">" . hash_to_xml($hash->{$element}) . "</$element>";
                my $size = keys %{$hash->{$element}};
	    }
	} elsif(ref $hash->{$element} eq "HASH") {
	    my $size = keys %{$hash->{$element}};
            if($size == 0) {
                $output = $output . "<$element></$element>";
            } else {
                $output = $output . "<$element>" . hash_to_xml($hash->{$element}) . "</$element>";
            }
	} elsif(ref $hash->{$element} eq "ARRAY") {
	    my $array = $hash->{$element};
            $arr_size = scalar @$array;
            my $ref = ref $array->[-$arr_size];
            if ($ref eq "HASH") {
                #Extract Hash values from List field
                $element = "value type='object'" if ($element eq "value");
                $output = $output . "<$element>";
                foreach my $a (@$array) {
		    if (exists $a->{type}){
			$a->{ZZZz} = $a->{type}; #Intentionally added this key 'ZZZz' because to keep 'type=object' at the last position in the HASH $a
			delete $a->{type} || print "Not deleted - the key type\n";
 		    }		
                    $output = $output . hash_to_xml($a);
                }
                $element = "value" if ($element eq "value type='object'");
                $output = $output . "</$element>";
            } else {
                #Extract Array values from List field
                foreach my $m (@$array) {
                    $output = $output . "<value>$m</value>";
                }
            }                                	
	} elsif ($hash->{$element} eq "object") {
	    if ($arr_size > 1) {
                $output = $output . "</value>";
		$output = $output . "<value type='object'>";
	    }
	    $arr_size--;
        } else {    
	    $output = $output . "<$element>$hash->{$element}</$element>\n";
	}
    }
    return $output;
}

# Removes the key 'type' created because of the 'type' attribute in some XML elements.
# It converts string values to integers and booleans, which will be useful when 
# converting this hash to JSON.
# Input : HASH Reference
# Returns a HASH Reference after removing 'type' keys and int/bool conversions
sub remove_type_from_hash {
    my ($hash, $additional_argument) = @_;
    my $output = {};
    foreach my $key (keys %$hash) {
	if(ref $hash->{$key} eq "HASH" && $hash->{$key}->{type}) {
	    my $ref = ref $hash->{$key}->{type};
	    if ($ref eq "ARRAY") {
		my @temp_arr = @{$hash->{$key}->{type}};
		my @new_arr = ();
		my $value_flag = "";
		foreach (@temp_arr) {
		    if ($_ eq "object") {
			$value_flag = "yes";
			next;
		    }
		    push (@new_arr, $_);
		}
		my $arr_size = scalar @new_arr;
		if ($arr_size <= 1) {
		    $hash->{$key}->{type} = $new_arr[0];
		} else {
		    $hash->{$key}->{type} = @new_arr;
		}
		if (($key ne "value") && ($value_flag eq "yes")) {
		    $output->{$key}->{value} = remove_type_from_hash($hash->{$key});
		} else {
		    $output->{$key} = remove_type_from_hash($hash->{$key});
		}
	    } elsif($hash->{$key}->{type} eq 'int') {
		$output->{$key} = int($hash->{$key}->{content});
	    } elsif($hash->{$key}->{type} eq 'boolean') {
		$output->{$key} = $hash->{$key}->{content} eq 'true' ? JSON::true : JSON::false;
	    } elsif($hash->{$key}->{type} eq 'object') {
		delete $hash->{$key}->{type} || print "Not Deleted the type->object\n";
	        if($key eq 'extensible_attributes') {
		   my @ea_keys = keys %{$hash->{$key}};
		   foreach my $m (@ea_keys) {
			$output->{value}->{$key}->{$m} = $hash->{$key}->{$m};
		   }
		} elsif ($key eq 'extattrs') {
		    my @ea_keys = keys %{$hash->{$key}};
		    foreach my $m (@ea_keys) {
                        my $actual_ea = $m;
                        $m =~ s/_/ /g;
                        $output->{value}->{$key}->{$m}->{value}->{val} = $hash->{$key}->{$actual_ea}->{value};
                        #$output->{value}->{$key}->{$m}->{value}->{val} = $hash->{$key}->{$m}->{value};
                   }
		} elsif ($key eq 'cloud_info') {
		    if ($hash->{$key}->{delegated_member}) {
			if ($hash->{$key}->{delegated_member}->{content} eq 'null') {
			    $output->{$key}->{value}->{delegated_member} = JSON::null;
			} else {
			    delete $hash->{$key}->{delegated_member}->{type} || print "Not Deleted the 'delegated_member->type->object'\n";
			    $output->{$key}->{value}->{delegated_member}->{value} = $hash->{$key}->{delegated_member};
			}
		    } else {
		    	$output->{$key}->{value} = $hash->{$key};
		    }
		} else {
		    $output->{$key} =  remove_type_from_hash ($hash->{$key});
		}
	    }
	} elsif(ref $hash->{$key} eq "HASH") {
	    #To remove value type=object present inside _ref - only for arrays of _ref - its mainly used for only v4/v6 shared network objects
	    #Single '_ref' key is handled correctly by outside code and NOT by the below codes
	    if (($additional_argument eq "_ref_key_present") && ($key eq '_ref')) {
		delete $hash->{$key}->{value}->{type} || print "Not Deleted the type->object\n";
		$output->{$key} = $hash->{$key}->{value};
		$additional_argument = "";
	    } else {
	    	$output->{$key} = remove_type_from_hash($hash->{$key});
	    }
	} elsif(ref $hash->{$key} eq "ARRAY") {
	    my $array = $hash->{$key};
	    $arr_size = scalar @$array;
	    for(my $i=0; $i<$arr_size; $i++) {
            	my $ref = ref $array->[$i];
	    	if ($ref eq "HASH") {
		    #To recognise array of '_ref' key presence
		    my $additional_parameter = "_ref_key_present" if (exists $array->[$i]->{'_ref'});
		    $output->{$array}->[$i]= remove_type_from_hash($array->[$i], $additional_parameter);
	    	} else { 
		    $output->{$key} = $hash->{$key};
		}
	    }
	} else {
            if($key eq "type" && $hash->{type} eq "object"){
            } else {
	    	$output->{$key} = $hash->{$key};
	    }
	}
    }
    return $output;
}

# Generates JSON from a HASH
# Input : HASH Reference
# Returns Formatted JSON String
sub hash_to_json {
    my ($json) = @_;
    my $json_obj = JSON->new->allow_nonref;
    my $value = "";
    foreach my $key (keys %$json) {
	my $temp = $json->{$key};
        if(ref $json->{$key} eq "HASH") {
	     if ($key eq "list") {
		$hash_flag="list";
	     	$value = $value . "[" . hash_to_json ($json->{$key}) . "]";
	     } elsif ($key eq "value") {
                $hash_flag="value";
                $value = $value . "{" . hash_to_json ($json->{$key}) . "}";
	     } else {
	        $value.= "\"$key\":" . hash_to_json ($json->{$key}) ;
	     }
        } elsif(ref $temp eq "ARRAY") {
            my $str= $json_obj->pretty->encode (\@$temp);
	    chomp ($str);
	    $value.= $str;
        } else {
            if($key eq "type" && $json->{$key} eq "object"){
print "Need to code\n";
	    } elsif ($key eq "value" && $hash_flag eq "list") {
		my $str= $json_obj->pretty->encode ($temp); #This else if part handles to write only the value part (without key) in [array] field type
                chomp ($str);
		$value.= $str; 
            } else {
	    	my $str= $json_obj->pretty->encode ($temp);
            	chomp ($str);
            	   $value.= "\"$key\":" . $str;
            }
        }
	$value.= ",";	
    }
    chop ($value);
    $value =~ s/,+/,/g;		#Need betterment; instead of =~ substitution statements
    $value =~ s/\[+/\[/g;
    $value =~ s/\]+/\]/g;
    $value =~ s/":,/":"",/g;    #To replace the empty value with double quotes in JSON. This replaces in the begining/middle of the string
    $value =~ s/{"extensible_attributes":/"extensible_attributes":{/; 
    $value =~ s/{"extattrs":/"extattrs":{/;
    $value =~ s/"val":/"value":/g; #For having the keyword value in fields of EA struct

    return $value;
}

# Converts JSON Boolean Object to String values 'true'/'false'
# Input : HASH Reference with JSON Boolean Objects
sub convert_json_boolean_to_str {
    my ($hash) = @_;
    foreach my $key (keys %$hash) {
	next unless ('JSON::XS::Boolean' eq ref $hash->{$key} ||  'JSON::backportPP::Boolean' eq ref $hash->{$key} );
	$hash->{$key} = ( $hash->{$key} ? 'true' : 'false' );
    }
}

# Generates URL-encoded from a HASH
# Input : HASH Reference
# Returns URL-encoded String
sub hash_to_url {
    my ($hash) = @_;
    my $output = "";
    foreach my $element (keys %$hash) {
	if(ref $hash->{$element} eq "HASH"){
	   $output.="$element=$hash->{$element}->{content};";
	} else {
	   $output.="$element=$hash->{$element};";
	}
    }
    chop $output; #to remove the last ';' in the string, which is unwanted
    return $output;
}

# Creats Content-Body for PUT and POST requests based on Content-Type
# Input : HASH Reference of Content, Content Type
# Returns Content-Body in JSON or XML
sub create_content_body {
    my ($content, $content_type) = @_;
    my $content_body;
    $content_body = "<value type='object'>" . hash_to_xml($content) . "</value>" if($content_type eq "xml");
    if ($content_type eq "json") {
	$type_less_content = remove_type_from_hash($content);
	$content_body = hash_to_json($type_less_content);
	$content_body = "{ $content_body }";
	$content_body =~ s/":\s*}/":""}/g;    #To replace the empty value with double quotes in JSON. This replaces in the end of the string
    }
    #field name is any of these keywords like 'value' (or) 'object' (or) 'type' then need to append '_wapi_field' string as suffix to the field name
    $content_body =~ s/_wapi_field//g;    
    $content_body = hash_to_url($content) if($content_type eq "urlencoded");
    return $content_body;
}

# Gets the Reference of an object, which can be used in PUT and DELETE
# Input : Base URL, Log file name, URL, Object type, Field/Values to get the object and Header details
# Returns the object reference
sub get_reference {
    my ($host, $logfile, $url, $object, $ref, %header) = @_;
    my $reference = "";
    my $client = get($host, $logfile, $url, $ref, %header);
    if($client->responseCode eq '200') {
	my $obj = JSON::from_json($client->responseContent(), { allow_nonref => 1 });
        my @list = @{$obj};
        $reference = $list[0]{"_ref"};
	$reference =~ s/^$object\///;
    }
    return $reference;
}

# Generates Query String from the request
# Input : HASH Reference
# Returns array of strings, which can be converted into query string by joining it with '&'
sub generate_query_string {
    my ($request) = @_;
    my @strings;
    foreach $key (keys %$request) {
	if(ref($request->{$key}) eq "ARRAY") {
	    foreach my $value (@{$request->{$key}}) {
		my @array_string = generate_query_string({$key => $value});
		push(@strings, @array_string);
	    }
	} elsif($key =~ /^_8/) {
	    # To handle EA Search cases
	    my $value = $request->{$key};
	    $key =~ s/^_8/*/;
	    my @array_string = generate_query_string({$key => $value});
	    push(@strings, @array_string);
	} elsif($request->{$key} =~ /=/) {
	    #When Modifiers are Used
	    push(@strings, $key . $request->{$key});
	} else {
	    push(@strings, "$key=$request->{$key}");
	}
    }
    return @strings; 
}

# Sends the Request with GET Action
# Input : Base URL, Log file name, URL, Request from Test Data, Header details
# Returns REST Client, which contains the Response details 
sub get {
    my ($host, $ua, $logfile, $url, $request, %header) = @_;
    #my $client = REST::Client->new({ host => $host, useragent => $ua, });
    my $client = REST::Client->new();
    # Generates Query String
    my @strings = generate_query_string($request);
    my $query_string = join('&', @strings);
    # Logs Query String
    open(LOG_FILE, ">>$logfile");
    print LOG_FILE "Query String : $query_string\n";
    print LOG_FILE "="x80 . "\n";
    close LOG_FILE;
    # Sends the request
    $client->GET("$url?$query_string");
    return $client;
}

# Sends the Request with POST Action
# Input : Base URL, Log file name, URL, Request from Test Data, Header details
# Returns REST Client, which contains the Response details
sub post {
    my ($host, $ua, $logfile, $url, $request, $header) = @_;
    #my $client = REST::Client->new({ host => $host, useragent => $ua, });
    my $client = REST::Client->new();
    # Logs the Request Body Content 
    open(LOG_FILE, ">>$logfile");
    print LOG_FILE "Request Content :\n";
    print LOG_FILE "="x80 . "\n";
    print LOG_FILE $request . "\n";   
    close LOG_FILE;
    # Sends the request
    $client->POST($url, $request, $header);
    return $client;
}

# Sends the Request with PUT Action
# Input : Base URL, Log file name, URL, Request from Test Data, Header details
# Returns REST Client, which contains the Response details
sub put {
    my ($host, $ua, $logfile, $url, $request, $header) = @_;
    #my $client = REST::Client->new({ host => $host, useragent => $ua, });
    my $client = REST::Client->new();
    # Logs the Request Body Content
    open(LOG_FILE, ">>$logfile");
    print LOG_FILE "Request Content :\n";
    print LOG_FILE "="x80 . "\n";
    print LOG_FILE $request . "\n";   
    close LOG_FILE;
    # Sends the request
    $client->PUT($url, $request, $header);
    return $client;
}

# Sends the Request with DELETE Action
# Input : Base URL, URL, Header details
# Returns REST Client, which contains the Response details
sub del {
    my ($host, $ua, $url, %header) = @_;
    #my $client = REST::Client->new({ host => $host, useragent => $ua, });
    my $client = REST::Client->new();
    # Sends the request
    $client->DELETE($url);
    return $client;
}

# Compares the Response received with the Expected Response
# Input : Log filename, Expected Response, Actual Response
# Returns 1 if the responses are equal and 0 if they are not
sub compare_responses {
    my ($logfile, $response, $client) = @_;

    my $rcode = $client->responseCode;
    my $rcontent = $client->responseContent;
    my $rctype = $client->responseHeader('Content-Type');
    
    open(LOG_FILE, ">>$logfile");
    print LOG_FILE "Response :\n";
    print LOG_FILE "="x80 . "\n";
    print LOG_FILE "Response Code : $rcode\n";
    print LOG_FILE "Response Content Type : $rctype\n";
    print LOG_FILE "Response Content :\n";
    print LOG_FILE "="x80 . "\n";
    print LOG_FILE "$rcontent\n";
    print LOG_FILE "="x80 . "\n";

    my $obj;
    my $is_content_equal = 1; #To make the content pass
    if($rctype eq "application/xml") {
        if($response->{content}->{value}->{list}) {
            my $xmlobj = XML::Simple->new();
            my $document = $xmlobj->XMLin($rcontent, KeyAttr => [], ForceArray => ['object']);
            if((ref($document->{value}) eq "ARRAY")&&(ref($response->{content}->{value}->{list}->{value}) eq "ARRAY")) {
                $is_content_equal = 1 if(!compare_array($document->{value}, $response->{content}->{value}->{list}->{value}));
            } elsif (ref($document) eq "HASH"){
                my $key_got = keys %{$document};
                my $key_pro = keys %{$response->{content}->{value}->{list}};
                if ($key_pro != $key_got) {
                        $reason = "Objects count mismatch between expected and received data.";
                } elsif(($key_pro == 0)&&($key_got == 0)) {
                    $is_content_equal = 1;
                } elsif($response->{content}->{value}->{list}) {
                     if(!compare_hash_obj($document,$response->{content}->{value}->{list})) {
			 $is_content_equal = 1;
                     } else {
			 $reason = "Either expected or received data is unexpected.";
                     }
                }
            }
            else {
                $reason = "Unexpected Client Response. Check Expected Data.";
            }
        } elsif ($response->{content}->{value}->{value}) {
            my $xmlobj = XML::Simple->new();
            my $document = $xmlobj->XMLin($rcontent, KeyAttr => [], ForceArray => ['object']);
            my @str = $response->{content}->{value}->{value};
            $is_content_equal = 1 if(!compare_hash_obj($document,$str[0]));
        } else {
            if($response->{content}->{value} eq $rcontent) {
                $is_content_equal = 1;
            } elsif($response->{content}->{value} eq "") {
                $reason = "No Value is given for Expected Data.";
            } else {
                $reason = "ERROR: This TestCase has some wrong in response tag definition. Please Re-Confirm it.";
            }
        }
    } elsif($rctype eq "application/json") {

=comment Content validation
        $obj = JSON::from_json($rcontent, { allow_nonref => 1 });
        if(ref($obj) eq "ARRAY") {
            # To convert JSON::XS::Boolean references to true/false
            foreach my $o (@$obj) {
		convert_json_boolean_to_str($o);
            }
	    foreach my $r (@{$response->{content}->{value}->{list}->{object}}) {
		convert_json_boolean_to_str($r);
	    }
            my $size_got = scalar(@$obj);
            my $size_pro = scalar(@{$response->{content}->{value}->{list}->{object}});
            my $size_pro_index = keys (%{$response->{content}->{value}->{list}->{object}[0]});
            if(($size_pro == 1) && ($size_got == 0) && ($size_pro_index == 0)) {
                $is_content_equal =1;
            } elsif (!compare_array($obj, $response->{content}->{value}->{list}->{object})) {
                $is_content_equal =1;
            } else {
                $reason = "Values mismatch between received and expected data.";
            }
        } elsif(ref($obj) eq "HASH") {
	    convert_json_boolean_to_str($obj);
	    convert_json_boolean_to_str($response->{content}->{value}->{list}->{object}[0]);
	    #To handle inconsistent error messages
	    my @inconsistent_err = (
		'Data Conflict Error',            #Inconsistent duplicate value error message
		'Empty values not allowed',	    #Inconsistent empty value error message for name field
		'not in the same network view where this shared network',      #Insconsistent of the numeric value in the v4/v6 shared network error message 
		'Duplicate object .* of type .* already exists in the database.', #Inconsistent duplicate error message for shared TXT record object
		'Required value missing', #Inconsistent error message for Network View object
                'Cannot find 1 available IP address.* in this network.', #As part of NIOS-56321 Design
	    );
            if($obj->{text}) {
                if(($obj->{text} eq $response->{content}->{value}) || ($obj->{text} =~ $inconsistent_err[0]) || ($obj->{text} =~ $inconsistent_err[1]) 
                    || ($obj->{text} =~ $inconsistent_err[2]) || ($obj->{text} =~ $inconsistent_err[3]) || ($obj->{text} =~ $inconsistent_err[4])
                    || ($obj->{text} =~ $inconsistent_err[5])){
                    $is_content_equal = 1;
                } else {
                    $reason = "Received Unexpected Error Message.";
                }
            } else {
                if($response->{content}->{value}->{list}) {
                    $is_content_equal = 1 if(!compare_hash_obj($obj, $response->{content}->{value}->{list}->{object}[0]));
                } elsif($response->{content}->{value}->{object}) {
                    $is_content_equal = 1 if(!compare_hash_obj($obj, $response->{content}->{value}->{object}[0]));
                }
            }
        } else {
            if($rcontent =~ /$response->{content}->{value}/) {
                $is_content_equal = 1;
            } elsif($response->{content}->{value} eq "") {
                $reason = "No Value is given for Expected Data.";
            } else {
                $reason = "ERROR: This TestCase has some wrong in definition. Please Re-Confirm it.";
            }
        }
=cut    
    }
    if(($response->{code} eq $rcode)) {
	if($is_content_equal) {
	    return 1;
	} else {
	    print LOG_FILE "Response Content did not match. \n";
            print LOG_FILE "$reason\n" if ($reason ne "");
            $reason = "";
	    print LOG_FILE "Expected : " . Dumper($response->{content}->{value}->{list}->{value});
	    print LOG_FILE "But Received : " . Dumper($rcontent);
	}
    } else {
	print LOG_FILE "Status did not match. Expected $response->{code};but got $rcode\n";
	print LOG_FILE "Error : $obj->{Error}\n";
	print LOG_FILE "Text  : $obj->{text}\n";
    }
    close LOG_FILE;
    return 0;
}

# Compares two hashes
# Input : Hash Reference 1 and Hash Reference 2
# Returns 0 if both hashes are same and 1 if they are not
sub compare_hash_obj
{ 
    my $read_data = shift;
    my $database_object = shift;
    my $lRead_Data_Temp = "";
    
    my %read_data_hash = %{$read_data};
    my %database_hash = %{$database_object};

    my $mismatch = 0;

    my $debug = 0;

    my $count_read_hash = 0;
    my $count_db_hash = 0;
    
    $count_read_hash = keys %read_data_hash;
    $count_db_hash = keys %database_hash;
    
    if ($count_read_hash != $count_db_hash) {
        $reason = "Values count mismatch between provided and returned data.";
        return 1;
    }
    
    foreach my $key (keys %read_data_hash) {
	if(($key eq "_ref") || ($key eq "status_timestamp") || ($key eq "last_run")) {
	    next;
	}
	$objects_flag++ if($key eq "objects");
	if ((!(ref($read_data_hash{$key}))) && ( !(ref($database_hash{$key}))))	{
	    $lRead_Data_Temp = $read_data_hash{$key};
	    $database_hash{$key} =~ s/\n+//g; 
	    my $rc = compare_scalar($lRead_Data_Temp, $database_hash{$key});
	    $mismatch = $mismatch + $rc;
	    
	    if($rc >= 1) {
		print "<<Mismatch>> key: $key Read: $lRead_Data_Temp DNSone: $database_hash{$key}\n" if($debug == 1);
		$reason = "Expected value for field(s) didnt match with received value";
	    }
	}
	elsif ((ref($read_data_hash{$key}) eq "ARRAY") && ( ref($database_hash{$key}) eq "ARRAY")) {
	    my $rc = compare_array($read_data_hash{$key}, $database_hash{$key});
	    $mismatch = $mismatch + $rc;
	}
	elsif (((ref($read_data_hash{$key}) eq "HASH") || (ref($read_data_hash{$key}) =~ m/^Infoblox*/ )) &&
	       ((ref($database_hash{$key}) eq "HASH") || (ref($database_hash{$key}) =~ m/^Infoblox*/ ))) {
	    my $rc = compare_hash_obj($read_data_hash{$key}, $database_hash{$key});
	    $mismatch = $mismatch + $rc;
	}
	else {
	    $mismatch++;
	}
    }
    return 1 if ($mismatch != 0);
    return 0;
}

# Compares two scalars
# Input : Scalar 1 and Scalar 2
# Returns 0 if both scalars are same and 1 if they are not
sub compare_scalar {
    my $read_data = shift;
    my $database_data = shift;
    return 1 if ((ref($read_data))||(ref($database_data)));
    my $mismatch = 0;
    if (($objects_flag != 0) && (defined($read_data)) && ($read_data =~ /$database_data/)) {
	$objects_flag = 0;
	return 0;
    }
    $mismatch++ if ((defined($read_data)) && ($read_data ne $database_data));
    $mismatch-- if (($mismatch > 0) && ($read_data eq "RESTART_PENDING")); #To handle restart service inconsistent status as 'RESTART_PENDING'
    return 1 if ($mismatch != 0);
    return 0;
}

# Compares two arrays
# Input : Array Reference 1 and Array Reference 2
# Returns 0 if both arrays are same and 1 if they are not
sub compare_array
{
    my $read_data = shift;
    my $database_data = shift;
    return 1 if ((ref($read_data) ne "ARRAY")||(ref($database_data) ne "ARRAY"));
    my $mismatch = 0;
    my @read_data_array = @{$read_data};
    my @database_array = @{$database_data};
    
    my $count_read_array = scalar(@read_data_array);
    my $count_db_array = scalar(@database_array);

    if ($count_read_array != $count_db_array) {
        $reason = "Values count mismatch between provided and returned data.";
        return 1;
    }
    return 1 if (exists($option{c}) && (@read_data_array > @database_array));
    
    return 1 if (exists($option{c}) && (@read_data_array < @database_array) && (@read_data_array == 0));
    
    for (my $i = 0;$i < scalar(@read_data_array);$i++) {
	my $found = 0;
	if (!(ref($read_data_array[$i]))) {
	    if (exists($option{c})) {
		if (!(ref($database_array[$i]))) {
		    my $rc = compare_scalar($read_data_array[$i], $database_array[$i]);
		    $found++ if (!$rc);
		}
	    }
	    else {
		foreach my $database (@database_array) {
		    if (!(ref($database))) {
			my $rc = compare_scalar($read_data_array[$i], $database);
			$found++ if(!$rc);
		    }
		}
	    }
	} elsif (ref($read_data_array[$i]) eq "ARRAY") {
	    foreach my $database (@database_array) {
		if (ref($database) eq "ARRAY") {
		    my $rc = compare_array($read_data_array[$i], $database);
		    $found++ if(!$rc);
		}
	    }
	}
	else {
	    foreach my $database (@database_array) {
		my $rc = compare_hash_obj($read_data_array[$i], $database);
		$found++ if(!$rc);
	    }
	}
	$mismatch++ if ($found != 1);
    }
    
    return 1 if ($mismatch != 0);
    return 0;
}

return 1;
