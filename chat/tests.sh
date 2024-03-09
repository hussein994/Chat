#!/bin/bash

PROG="./client-chat"
PORT=`shuf -i 10000-65000 -n 1`
PORT_C=`shuf -i 10000-65000 -n 1`

echo -n "test 01 - program without arg: "
$PROG > /dev/null 2>&1 && echo "KO -> exit status $? instead of 1" && exit 1 
echo "..................OK"

echo -n "test 02 - program with invalid port number: "
$PROG 65001 > /dev/null 2>&1 && echo "KO -> exit status $? instead of 1" && exit 1 
echo ".....OK"

echo -n "test 03 - program accept /HELO and /QUIT cmd: "
timeout 5 $PROG $PORT > /dev/null 2>&1 &
TO=$!
sleep 2
echo -n "/HELO" | nc -6u -w1 localhost $PORT
echo -n "/QUIT" | nc -6u -w1 localhost $PORT
wait $TO
R=$?
[ "$R" == "124" ] && echo "KO -> program times out"           && exit 1
[ "$R" != "0" ]   && echo "KO -> exit status $R instead of 0" && exit 1
echo "...OK"

echo -n "test 04 - program in client mode: "
echo -n "/QUIT" > cmd.tmp
timeout 5 nc -6ul ::1 $PORT > output & 
TO=$!
sleep 2
timeout 3 $PROG $PORT < cmd.tmp
R=$?
[ "$R" == "124" ] && echo "KO -> programs times out"          && exit 1
[ "$R" != "0" ]   && echo "KO -> exit status $R instead of 0" && exit 1
wait $TO
MES=`cat output`
[ "$MES" != "/HELO/QUIT" ] && echo "KO -> program sent $MES instead /HELO/QUIT" && exit 1
echo "...............OK"

echo -n "test 05 - program accept IPv4 clients: "
timeout 5 $PROG $PORT > output 2> /dev/null &
TO=$!
sleep 2
echo -n "/HELO" | nc -4u -w1 localhost $PORT -p $PORT_C
echo -n "/QUIT" | nc -4u -w1 localhost $PORT -p $PORT_C
wait $TO
R=$?
[ "$R" == "124" ] && echo "KO -> program times out"           && exit 1
[ "$R" != "0" ]   && echo "KO -> exit status $R instead of 0" && exit 1
rm cmd.tmp
echo "..........OK"

echo -n "test 06 - program prints remote IP and port: " 
IP=`cat output | cut -d ' ' -f1`
[ "$IP" != "::ffff:127.0.0.1" ] && echo "KO -> printed IP: $IP | expected: ::ffff:127.0.0.1" && exit 1 
PORT_P=`cat output | cut -d ' ' -f2`
[ "$PORT_P" != "$PORT_C" ] && echo "KO -> printed port: $PORT_P | expected: $PORT_C" && exit 1 
rm output
echo "....OK"

echo -n "test 07 - memory error: "
P=`which valgrind`
[ -z "$P" ] && echo "KO -> please install valgrind" && exit 1
valgrind --leak-check=full --error-exitcode=100 --log-file=valgrind.log $PROG $PORT > /dev/null &
V=$!
sleep 3
echo -n "/HELO" | nc -4u -w1 localhost $PORT
echo -n "/QUIT" | nc -4u -w1 localhost $PORT
wait $V
[ "$?" == "100" ] && echo "KO -> memory pb please check file valgrind.log" && exit 1
rm valgrind.log
echo "..........................OK"
