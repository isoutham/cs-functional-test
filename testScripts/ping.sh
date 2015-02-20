CMD="ping -c3 $2 > /dev/null 2>&1"

echo $CMD
sudo ssh -i /root/.ssh/id_rsa.cloud -o StrictHostKeyChecking=no -p 3922 root@$1 $CMD
echo "Returned $?"
