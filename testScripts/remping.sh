CMD="sshpass -p password ssh -o StrictHostKeyChecking=no $2 ping -c3 $3"

echo $CMD
sudo ssh -i /root/.ssh/id_rsa.cloud -o StrictHostKeyChecking=no -p 3922 root@$1 $CMD
echo "Returned $?"
