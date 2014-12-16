Extended version of the Cloudstack functional testing.  

These scripts have been tested on Mac.  They should also work on Linux - they will not work on Windows.

They require
vagrant
virtualbox
a checkout of the cloudstack source
maven

You will need a systemvm template for the version you wish to test.
Download this and pop it in the systemvm folder

Update the parameters in runtests.sh to match your system.  Pay particular attention to

-  The location of your cloudstack repo
-  The names of the systemvmA template

Usage

No Parameters

sh ./runtests.sh 
This will start up the virtual machines
Run cloudstack
Create a zone pod and host
Run the simulator
shut down

sh ./runtests.sh -b
Will first build cloudstack and then continue

sh ./runtests.sh -p
Will prepare a running CS environment and leave it running for you to play with.
It will wipe out the database and create a new zone and so on.

These options can be combined.  Eg.

sh ./runtests.sh -b -p
Build CS and prepare a system for you to play with

Debugging in Eclipse

Start with -p to get a clean environment then kill of the jetty run process.

Debug in Eclipse with:

Base: ${project_loc:cloudstack}
Goals: -pl :cloud-client-ui clean package jetty:run
Profiles: systemnvm 

Make sure your maven has sufficient memory to be able to execute cloudstack
