CMD="dpkg -i sshpass_1.05-1_amd64.deb > /dev/null"

sudo scp -i /root/.ssh/id_rsa.cloud -o StrictHostKeyChecking=no -P 3922 /home/vagrant/testScripts/sshpass_1.05-1_amd64.deb root@$1:
sudo ssh -i /root/.ssh/id_rsa.cloud -o StrictHostKeyChecking=no -p 3922 root@$1 $CMD
exit 0
