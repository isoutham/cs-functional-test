#!/bin/bash

# --------------------------------------------------------------------------------- #
# Stuff you may well have to change
# --------------------------------------------------------------------------------- #
export CLOUDSTACK=/Users/isoutham/repo/cloudstack
export INSTALL_VM=cloud-install-sys-tmplt
export SCRIPT=${CLOUDSTACK}/scripts/storage/secondary
export XENTEMPLATE=systemvm64template-systemvm-persistent-config-4.5.0.69-xen.vhd.bz2
#export XENTEMPLATE=systemvm64template-4.4-2014-12-02-xen.vhd.bz2
#export XENTEMPLATE=systemvmtemplate-master-4.6.0-xen.vhd.bz2

# --------------------------------------------------------------------------------- #
# The rest
# --------------------------------------------------------------------------------- #
export MAVEN_OPTS="-Xmx2048m -XX:MaxPermSize=512m"
export LINUX_TMPL=ttylinux_pv.vhd
export DEVCLOUD=192.168.56.5
export DEVCLOUD_VBOX=management
export HYPERVISOR=192.168.56.10
export HYPERVISOR_VBOX=xenserver
export SECSTORE=/exports/secondary

args=`getopt npbi $*`
if [ $? != 0 ] 
then
  echo $0 [-p] [-b]
  echo  specify -p to stop after preparing the test environment
  echo  specify -b to build cloudstack before starting the test cycle
  echo  specify -n to activate the noredist profile
  echo  specify -i to install a new systemvm
  exit
fi

SCRIPT_LOCATION=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

set -- $args
for i do
  case $i in
  -p)
    PREPARE=1
    ;;
  -b)
    BUILD=1
    ;;
  -n)
    NOREDIST=" -Dnoredist "
    ;;
  -i)
    INSTALLSVM="1"
    ;;
  esac
done

systemvm() {
	TF=/tmp/$$
	vagrant ssh-config management > ${TF}
	PORT=$(cat ${TF} | grep Port | awk '{print $2;}')
	USER=$(cat ${TF} | grep "User " | awk '{print $2;}')
	HN=$(cat ${TF} | grep HostName | awk '{print $2;}')
	ID=$(cat ${TF} | grep IdentityFile | awk '{print $2;}')
	rm ${TF}
	if [ ! -d ${SCRIPT} ]
	then
		echo "Could not locate ${SCRIPT}"
		exit 2
	fi
	scp -P ${PORT} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ${ID} ${SCRIPT}/* ${SCRIPT_LOCATION}/systemvm/${XENTEMPLATE} ${USER}@${HN}:
	CMD="sudo sh ./${INSTALL_VM} -m ${SECSTORE} -f ${XENTEMPLATE} -h xenserver -o 127.0.0.1 -r cloud -d cloud -t 1 -F"
	vagrant ssh management -c "$CMD"
}

# This does not yet woprk without manual intervention
linuxImage() {
	echo Install Tiny Linux
	cd $OLDDIR
	if [ -f systemvm/${LINUX_TMPL} ]
	then
		echo Installing linux image template 5
		sudo mkdir -p ${SHARED}/secondary/template/tmpl/1/5
		echo sudo mkdir -p ${SHARED}/secondary/template/tmpl/1/5
		sudo cp systemvm/${LINUX_TMPL} ${SHARED}/secondary/template/tmpl/1/5/ce5b212e-215a-3461-94fb-814a635b2215.vhd
		sudo cp systemvm/template.properties ${SHARED}/secondary/template/tmpl/1/5
	fi
	# Workaround for people with spaces in their group name
	sudo chgrp -R nobody ${SHARED}/
}

vagrant up ${DEVCLOUD_VBOX}
if [ $? -ne 0 ]
then
  echo Failed to start ${DEVCLOUD_VBOX}
	exit 1
fi

vagrant up ${HYPERVISOR_VBOX}
if [ $? -ne 0 ]
then
  echo Failed to start ${HYPERVISOR_VBOX}
	exit 1
fi

if [  -n "${INSTALLSVM}" ]
then
	systemvm
fi

#FIXME!!
if [  -n "${INSTALLTINY}" ]
then
	linuxImage
fi

# Kill any old cloudstack instances
ps -ef | grep java|grep systemvm| awk '{print $2;}' | xargs kill

echo Drop old cloud database
sed -i "" -e 's/^DBHOST=.*/DBHOST='${DEVCLOUD}'/' build/replace.properties

echo Update the database

vagrant ssh management -c "mysql -u cloud --password=cloud -e 'drop database cloud;'"
cd ../cloudstack
mvn -P developer ${NOREDIST} -Ddeploydb -pl developer 


cd ../cloudstack
rm -f vmops.log
rm -f jetty-console.out
if [ ! -z "${BUILD}" ]
 then
  echo Building CloudStack
  mvn -T 2C -Psystemvm ${NOREDIST} clean install
fi

echo Start CloudStack
cd ../cloudstack
mvn -P systemvm ${NOREDIST} -pl :cloud-client-ui jetty:run > jetty-console.out 2>&1 &
SERVER_PID=$!

echo Clean the xenserver
sleep 15
python "${SCRIPT_LOCATION}"/xapi_cleanup_xenservers.py http://${HYPERVISOR} root password

# Check for initialization of the management server
COUNTER=0
while [ "$COUNTER" -lt 34 ] ; do
    if grep -q 'Management server node 127.0.0.1 is up' jetty-console.out ; then
        break
    fi
    sleep 5
    COUNTER=$(($COUNTER+1))
done


if grep -q 'Management server node 127.0.0.1 is up' jetty-console.out ; then
   echo Started OK
   sleep 20
   echo Provisioning CloudStack with devcloud zone
   python "${SCRIPT_LOCATION}"/cloudstack_setup_devcloud.py
   python "${SCRIPT_LOCATION}"/cloudstack_checkssvmalive.py

   if [ ! -z "${PREPARE}" ] ; then
      echo "CloudStack running with PID $SERVER_PID"
      exit
   fi

   sleep 30
   python "${SCRIPT_LOCATION}"/cloudstack_test_basic_instance.py
fi


mvn -P systemvm -pl :cloud-client-ui jetty:stop
#sleep 30
#kill -KILL $SERVER_PID

