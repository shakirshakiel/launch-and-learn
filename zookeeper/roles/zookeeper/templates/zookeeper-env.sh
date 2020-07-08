export ZK_SERVER_HEAP=2048
export SERVER_JVMFLAGS="-Xms512m -Djava.rmi.server.hostname={{ hostvars[inventory_hostname]['ansible_host'] }} -Dcom.sun.management.jmxremote.rmi.port=8090 -Dcom.sun.management.jmxremote.local.only=false"
export JMXPORT=8090
#export JMXLOG4J=false