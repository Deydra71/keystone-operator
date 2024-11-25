#!/bin/sh
set -euxo pipefail

wait_rotation() {
	while [ $seconds -le 30 ]; do
		rotatedat=$(oc get secret keystone -n $NAMESPACE -o jsonpath="{.metadata.annotations['keystone\.openstack\.org/rotatedat']}")
		if [ $rotatedat != "2009-11-10T23:00:00Z" ]; then
			return
		fi
		sleep 1
		seconds=$(( $seconds + 1 ))
	done
}

seconds=1

for i in {1..6}; do
	wait_rotation

	sleep 20 # make sure a rollout started
	oc rollout status deployment/keystone -n $NAMESPACE

	oc annotate secret keystone -n $NAMESPACE rotatedat='2009-11-10T23:00:00Z'
done
