use strict;
use warnings;

position:
print("=========================\n");
print("| Red Squirrel Agent UI |\n");
print("|-----------------------|\n");
print("| 1: Start Agent.       |\n");
print("| 2: Stop Agent.        |\n");
print("| 3: Exit Program.      |\n");
print("==========================\n");
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
    print("[NOTICE] Exiting program...\n");
    goto end;
}
elsif ($name != 1 && $name != 2 && $name != 3){
    print("\n[ERROR] Invalid input... Try Again...\n");
}
goto position;
end:



