#!/usr/bin/env bash

ssh-keygen -t rsa -b 4096 -C "shakirshakiel@gmail.com" -f id_rsa -N ""

# Copy id_rsa to gocd_agent/files/ and id_rsa.pub to deploy_keys of your github repo
