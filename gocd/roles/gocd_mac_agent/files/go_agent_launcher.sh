#!/usr/bin/env sh
set -eo pipefail

function agent_stop {
    /Users/shakirshakiel/ansible_test/go-agent-20.7.0/bin/go-agent stop
}

function agent_start {
    echo "Starting gocd-agent"
    /Users/shakirshakiel/ansible_test/go-agent-20.7.0/bin/go-agent start
}

function agent_status {
    /Users/shakirshakiel/ansible_test/go-agent-20.7.0/bin/go-agent status
}

trap "agent_stop" TERM INT EXIT

set +e
agent_start
set -e

while true; do
  OUTPUT=$(agent_status)

  set +e
  echo $OUTPUT | grep "not running"
  if [ $? = 0 ]; then
    echo "Shutting down launcher"
    break
  fi
  set -e

  echo "Gocd agent is running"
  sleep 10
done

echo "Stopping gocd-agent.."
agent_stop