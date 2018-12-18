jq --version > /dev/null 2>&1
		if [ $? -ne 0 ]; then
			echo "Please Install 'jq' https://stedolan.github.io/jq/ to execute this script"
			echo
			exit 1
		fi
A_TOKEN=$(curl -s -X POST http://192.168.0.236:4000/users -H "content-type: application/x-www-form-urlencoded" -d 'username=a&password=password&orgName=a')
A_TOKEN=$(echo $A_TOKEN | jq ".token" | sed "s/\"//g")

B_TOKEN=$(curl -s -X POST http://192.168.0.236:4000/users  -H "content-type: application/x-www-form-urlencoded" -d 'username=b&password=password&orgName=b')
B_TOKEN=$(echo $B_TOKEN | jq ".token" | sed "s/\"//g")
  curl -s -X POST \
		  http://192.168.0.236:4000/channels \
		  -H "authorization: Bearer $a_TOKEN" \
		  -H "content-type: application/json" \
		  -d '{"channelName":"testchannel"}'
 sleep 5
  curl -s -X POST \
				http://192.168.0.236:4000/channels/peers \
				-H "authorization: Bearer $a_TOKEN" \
				-H "content-type: application/json" \
				-d '{"peers": ["peer0","peer1"]}'
 curl -s -X POST \
				http://192.168.0.236:4000/channels/peers \
				-H "authorization: Bearer $b_TOKEN" \
				-H "content-type: application/json" \
				-d '{"peers": ["peer0","peer1"]}'
  curl -s -X POST \
			http://192.168.0.236:4000/chaincodes \
			-H "authorization: Bearer $a_TOKEN" \
			-H "content-type: application/json" \
			-d '{
			  "peers": ["peer0","peer1"],
			  "chaincodeName":"jiakechaincode",
			  "chaincodePath":"jiakechaincode",
			  "chaincodeVersion":"v1.0"
		  }'
 curl -s -X POST \
			http://192.168.0.236:4000/chaincodes \
			-H "authorization: Bearer $b_TOKEN" \
			-H "content-type: application/json" \
			-d '{
			  "peers": ["peer0","peer1"],
			  "chaincodeName":"jiakechaincode",
			  "chaincodePath":"jiakechaincode",
			  "chaincodeVersion":"v1.0"
		  }'
  curl -s -X POST \
		http://192.168.0.236:4000/channels/chaincodes \
		-H "authorization: Bearer $a_TOKEN" \
		-H "content-type: application/json" \
		-d '{
		  "chaincodeName":"jiakechaincode",
		  "chaincodeVersion":"v1.0",
		  "args":[]
	  }'