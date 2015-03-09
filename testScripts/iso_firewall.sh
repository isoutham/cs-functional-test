#!/bin/sh
PUBIP=$2
FW_NAME=FIREWALL_${PUBIP}
PORTNO=$3
EXPECTED=$4
SEARCH=$5

error_exit() {
	echo Returned 1
	exit 1
}

success_exit() {
	echo Returned 0
	exit 0
}

get_counter() {
	o=$1
	c=$(echo ${o} | awk '{print $1;}' | sed -e 's/\[//g' | cut -d':' -f1)
	echo $c
}

CMD="iptables-save -c | grep ${FW_NAME} | grep 'dport $SEARCH'"
out=$(sudo ssh -i /root/.ssh/id_rsa.cloud -o StrictHostKeyChecking=no -p 3922 root@$1 $CMD)
ret=$?

if [ "$ret" -ne "0" -a "$EXPECTED" == "True" ]
then
	echo Rule not there but was expected
	error_exit
fi
if [ "$ret" = "0" -a "$EXPECTED" == "False" ]
then
	echo Rule there but was not expected
	error_exit
fi

counter1=0
if [ "$ret" = "0" ]
then
	counter1=$(get_counter $out)
fi

CMD2="nc -w 1 ${PUBIP} ${PORTNO}"
ncout=$(sudo ssh -i /root/.ssh/id_rsa.cloud -o StrictHostKeyChecking=no -p 3922 root@$1 $CMD2)

# Traffic is blocked by firewall
echo $ncout | grep "Connection timed out"
ret=$?

if [ "$ret" = "0" -a "$EXPECTED" == "True" ]
then
	echo Firewall blocked traffic but should not have
	error_exit
fi

if [ "$ret" -ne "0" -a "$EXPECTED" == "False" ]
then
	echo Firewall blocked traffic as it should have
	success_exit
fi

out=$(sudo ssh -i /root/.ssh/id_rsa.cloud -o StrictHostKeyChecking=no -p 3922 root@$1 $CMD)
counter2=$(get_counter $out)

RULE_HIT=0
if [ "$counter1" -ne  "$counter2" ]
then
	RULE_HIT=1
fi

if [ "$RULE_HIT" == "1" -a "$EXPECTED" == "True" ]
then
	success_exit
fi

echo No good case got hit
error_exit
