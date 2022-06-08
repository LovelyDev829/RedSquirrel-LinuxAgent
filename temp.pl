use Tie::File;
use strict;
use warnings;

my $filename = "./outputJsonFiles/IP_addresses.txt";
my @array;
tie @array, 'Tie::File', $filename or die "can't tie file \"$filename\": $!";


my $ip_address1 = $array[0];
my $ip_address2 = $array[1];
position:
print("============================\n");
print("| Red Squirrel Agent UI    |\n");
print("+--------------------------+\n");
print("| 1: Start Agent.          |\n");
print("| 2: Stop Agent.           |\n");
print("| 3: Settings.             |\n");
print("| 4: Save and Exit.        |\n");
print("| 5: Exit without Saving.  |\n");
print("+--------------------------+\n");
print(" Enter Selection: ");

my $name = <STDIN>;
chomp $name;
my $py;

if ($name == 1){
    print("[NOTICE] Starting Agent...\n");
    open($py, "|-", "python3 daemon.py start") or die "Cannot run Python script: $!";
    close($py);
}
elsif ($name == 2){
    print("[NOTICE] Stopping Agent...\n");
    open($py, "|-", "python3 daemon.py stop") or die "Cannot run Python script: $!";
    close($py);
}
elsif ($name == 3){
    position2:
    print("+--------------------------+\n");
    print("| Red Squirrel Agent UI    |\n");
    print("+--------------------------+\n");
    print("| 1: Server's IP address   |\n");
    print("| 2: QA IP address         |\n");
    print("| 3: Return                |\n");
    print("+--------------------------+\n");
    print(" Enter Selection: ");

    my $name2 = <STDIN>;
    chomp $name2;
    if ($name2 == 1){
        print(" Server's IP address : ");
        $ip_address1 = <STDIN>;
        chomp $ip_address1;
    }
    elsif ($name2 == 2){
        print(" QA IP address : ");
        $ip_address2 = <STDIN>;
        chomp $ip_address2;
    }
    elsif ($name2 == 3){
        goto position;
    }
    elsif ($name2 != 1 && $name2 != 2 && $name2 != 3){
        print("\n[ERROR] Invalid input... Try Again...\n");
        goto position2;
    }
    goto position2;
}
elsif ($name == 4){
    print("[NOTICE] Saving and exiting program...\n");
    $array[0] = $ip_address1;
    $array[1] = $ip_address2;
    untie @array;
    goto end;
}
elsif ($name == 5){
    print("[NOTICE] Exiting program without saving...\n");
    goto end;
}
elsif ($name != 1 && $name != 2 && $name != 3 && $name != 4 && $name != 5){
    print("\n[ERROR] Invalid input... Try Again...\n");
    print("ip_address1: $ip_address1, ip_address2: $ip_address2 \n");
    goto position;
}
goto position;
end:



