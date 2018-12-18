#!/bin/bash
#
# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.1
#

jq --version > /dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "Please Install 'jq' https://stedolan.github.io/jq/ to execute this script"
	echo
	exit 1
fi

starttime=$(date +%s)

echo "POST request Enroll on Nxia  ..."
echo
Nxia_TOKEN=$(curl -s -X POST \
  http://192.168.0.233:4000/users \
  -H "content-type: application/x-www-form-urlencoded" \
  -d 'username=ningxia&password=password&orgName=Nxia')
echo $Nxia_TOKEN
Nxia_TOKEN=$(echo $Nxia_TOKEN | jq ".token" | sed "s/\"//g")
echo
echo "ORG1 token is $Nxia_TOKEN"
echo
echo "POST request Enroll on Creator ..."
echo
Nmen_TOKEN=$(curl -s -X POST \
  http://192.168.0.233:4000/users \
  -H "content-type: application/x-www-form-urlencoded" \
  -d 'username=creator&password=password&orgName=Nmen')
echo $Nmen_TOKEN
Nmen_TOKEN=$(echo $Nmen_TOKEN | jq ".token" | sed "s/\"//g")
echo
echo "Creator token is $Nmen_TOKEN"
echo
echo "POST request Enroll on Transfer ..."
echo
Dubai_TOKEN=$(curl -s -X POST \
  http://192.168.0.233:4000/users \
  -H "content-type: application/x-www-form-urlencoded" \
  -d 'username=transfer&password=password&orgName=Dubai')
echo $Dubai_TOKEN
Dubai_TOKEN=$(echo $Dubai_TOKEN | jq ".token" | sed "s/\"//g")
echo
echo "Transfer token is $Dubai_TOKEN"
echo

echo "POST request Enroll on Manager ..."
echo
M_TOKEN=$(curl -s -X POST \
  http://192.168.0.233:4000/users \
  -H "content-type: application/x-www-form-urlencoded" \
  -d 'username=manager&password=password&orgName=Manager')
echo $M_TOKEN
M_TOKEN=$(echo $M_TOKEN | jq ".token" | sed "s/\"//g")
echo
echo "Manager token is $M_TOKEN"
echo



echo "POST Install chaincode on Nxia"
echo
curl -s -X POST \
  http://192.168.0.233:4000/chaincodes \
  -H "authorization: Bearer $Nxia_TOKEN" \
  -H "content-type: application/json" \
  -d '{
	"peers": ["peer1", "peer2"],
	"chaincodeName":"jiakechaincode",
	"chaincodePath":"jiakechaincode",
	"chaincodeVersion":"v2.8"
}'
echo
echo


echo "POST Install chaincode on Nmen"
echo
curl -s -X POST \
  http://192.168.0.233:4000/chaincodes \
  -H "authorization: Bearer $Nmen_TOKEN" \
  -H "content-type: application/json" \
  -d '{
	"peers": ["peer1","peer2"],
	"chaincodeName":"jiakechaincode",
	"chaincodePath":"jiakechaincode",
	"chaincodeVersion":"v2.8"
}'
echo
echo

echo "POST Install chaincode on Dubai"
echo
curl -s -X POST \
  http://192.168.0.233:4000/chaincodes \
  -H "authorization: Bearer $Dubai_TOKEN" \
  -H "content-type: application/json" \
  -d '{
	"peers": ["peer1","peer2"],
	"chaincodeName":"jiakechaincode",
	"chaincodePath":"jiakechaincode",
	"chaincodeVersion":"v2.8"
}'
echo
echo


echo "POST Install chaincode on Manger"
echo
curl -s -X POST \
  http://192.168.0.233:4000/chaincodes \
  -H "authorization: Bearer $M_TOKEN" \
  -H "content-type: application/json" \
  -d '{
	"peers": ["peer1","peer2"],
	"chaincodeName":"jiakechaincode",
	"chaincodePath":"jiakechaincode",
	"chaincodeVersion":"v2.8"
}'
echo
echo

echo "POST upgrade chaincode on peer1 of Jiake"
echo
curl -s -X PUT \
  http://192.168.0.233:4000/channels/chaincodes \
  -H "authorization: Bearer $M_TOKEN" \
  -H "content-type: application/json" \
  -d '{
	"chaincodeName":"jiakechaincode",
	"chaincodeVersion":"v2.8",
  "args":[]
}'
echo
echo

echo "Total execution time : $(($(date +%s)-starttime)) secs ..."