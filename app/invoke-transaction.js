/**
 * Copyright 2017 IBM All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
'use strict';
var path = require('path');
var fs = require('fs');
var util = require('util');
var hfc = require('fabric-client');
var Peer = require('fabric-client/lib/Peer.js');
var helper = require('./helper.js');
var logger = helper.getLogger('invoke-chaincode');
logger.setLevel('ERROR');
var EventHub = require('fabric-client/lib/EventHub.js');
var ORGS = hfc.getConfigSetting('network-config');

var invokeChaincode = function(peerNames, channelName, chaincodeName, fcn, args, username, org) {
	logger.debug(util.format('\n============ invoke transaction on organization %s ============\n', org));
	var client = helper.getClientForOrg(org);

	var channel = helper.getChannelForOrg(channelName,org);
	if (channel == null){
		logger.error('===============channle is null======================== ' );
		return ;
	}
	var targets = (peerNames) ? helper.newPeers(peerNames, org) : undefined;
	var tx_id = null;
	var returnJsonStr = null;

//  username
	// return helper.getOrgAdmin(org).then((user) => {
	// return helper.getRegisteredUsers(username, org).then((member) => {
	  return client.getUserContext(username, true).then((user) => {
		// logger.debug(user);
		tx_id = client.newTransactionID();
		// logger.debug(util.format('Sending transaction "%j"', tx_id));
		// send proposal to endorser
		var request = {
			chaincodeId: chaincodeName,
			fcn: fcn,
			args: args,
			chainId: channelName,
			txId: tx_id
		};

		if (targets){
			request.targets = targets;
		}
		return channel.sendTransactionProposal(request);
	}, (err) => {
		logger.error('Failed to enroll user \'' + username + '\'. ' + err);
		throw new Error('Failed to enroll user \'' + username + '\'. ' + err);
	}).then((results) => {
		var proposalResponses = results[0];
		var proposal = results[1];
		var all_good = true;
		for (var i in proposalResponses) {
			let one_good = false;
			if (proposalResponses && proposalResponses[i].response &&
				proposalResponses[i].response.status === 200) {
				one_good = true;
				logger.info('transaction proposal was good');
			} else {
				logger.error('transaction proposal was bad');
			}
			all_good = all_good & one_good;
		}
		if (all_good) {
				if (returnJsonStr == null) {
					returnJsonStr = util.format("%s",proposalResponses[0].response.payload);
					// logger.debug("returnJsonStr:"+returnJsonStr);
				}
			var request = {
				proposalResponses: proposalResponses,
				proposal: proposal
			};
			// set the transaction listener and set a timeout of 30sec
			// if the transaction did not get committed within the timeout period,
			// fail the test
			var transactionID = tx_id.getTransactionID();
			var eventPromises = [];

			if (!peerNames) {
				peerNames = channel.getPeers().map(function(peer) {
					return peer.getName();
				});
			}

			var eventhubs = helper.newEventHubs(peerNames, org);
			for (let key in eventhubs) {
				let eh = eventhubs[key];
				eh.connect();

				let txPromise = new Promise((resolve, reject) => {
					let handle = setTimeout(() => {
						eh.disconnect();
						reject();
					}, 50000);

					eh.registerTxEvent(transactionID, (tx, code) => {
						clearTimeout(handle);
						eh.unregisterTxEvent(transactionID);
						eh.disconnect();

						if (code !== 'VALID') {
							logger.error(
								'The balance transfer transaction was invalid, code = ' + code);
							reject();
						} else {
							logger.info(
								'The balance transfer transaction has been committed on peer ' +
								eh._ep._endpoint.addr);
							resolve();
						}
					});
				});
				eventPromises.push(txPromise);
			};
			var sendPromise = channel.sendTransaction(request);
			return Promise.all([sendPromise].concat(eventPromises)).then((results) => {
				logger.debug(' event promise all complete and testing complete');
				return results[0]; // the first returned value is from the 'sendPromise' which is from the 'sendTransaction()' call
			}).catch((err) => {
				logger.error(
					'Failed to send transaction and get notifications within the timeout period.'
				);
				return 'Failed to send transaction and get notifications within the timeout period.';
			});
		} else {
			logger.error(
				'Failed to send Proposal or receive valid response. Response null or status is not 200. exiting...'
			);
			return 'Failed to send Proposal or receive valid response. Response null or status is not 200. exiting...';
		}
	}, (err) => {
		logger.error('Failed to send proposal due to error: ' + err.stack ? err.stack :
			err);
		return 'Failed to send proposal due to error: ' + err.stack ? err.stack :
			err;
	}).then((response) => {
		if (response.status === 'SUCCESS') {
			logger.info(response);
			logger.info('Successfully sent transaction to the orderer.');
			// logger.info(returnJsonStr);
			if (returnJsonStr !== null) {
				return returnJsonStr;
			}
			return response;
		} else {
			logger.error('Failed to order the transaction. Error code: ' + response.status);
			return 'Failed to order the transaction. Error code: ' + response.status;
		}
	}, (err) => {
		logger.error('Failed to send transaction due to error: ' + err.stack ? err
			.stack : err);
		return 'Failed to send transaction due to error: ' + err.stack ? err.stack :
			err;
	});
};

var invokeProposal = async function(peersUrls, channelName, chaincodeName, functionName, args, username, orgName){
    logger.debug(util.format('\n============ invoke transaction on channel %s ============\n', channelName));
    var error_message = null;
    var tx_id_string = null;

    try {
        // first setup the client for this org
        var client =  helper.getClientForOrg(orgName, username);
        logger.debug('Successfully got the fabric client for the organization "%s"', orgName);
        var channel = client.getChannel(channelName);
        if(!channel) {
            let message = util.format('Channel %s was not defined in the connection profile', channelName);
            logger.error(message);
            throw new Error(message);
        }
        var tx_id = client.newTransactionID();
        // will need the transaction ID string for the event registration later
        tx_id_string = tx_id.getTransactionID();
        //args[4] = tx_id_string;
        // send proposal to endorser

        

        var request = {
            targets: peersUrls,
            chaincodeId: chaincodeName,
            fcn: functionName,
            args: args,
            chainId: channelName,
            txId: tx_id
		};
		logger.debug(util.format('\n============ channel: %s ============\n',channel));
		logger.debug(util.format('\n============ request: %s ============\n',request));

        let results = await channel.sendTransactionProposal(request);

        // the returned object has both the endorsement results
        // and the actual proposal, the proposal will be needed
        // later when we send a transaction to the orderer
        var proposalResponses = results[0];
        var proposal = results[1];

        logger.debug(util.format('\n============ proposalResponses %s ============\n', proposalResponses));
        // lets have a look at the responses to see if they are
        // all good, if good they will also include signatures
        // required to be committed
        var all_good = true;
        for (var i in proposalResponses) {
            let one_good = false;
            if (proposalResponses && proposalResponses[i].response &&
                proposalResponses[i].response.status === 200) {
                one_good = true;
                logger.info('invoke chaincode proposal was good');
            } else {
                logger.error('invoke chaincode proposal was bad');
            }
            all_good = all_good & one_good;
        }

        if (all_good) {
            logger.info(util.format(
                'Successfully sent Proposal and received ProposalResponse: Status - %s, message - "%s", metadata - "%s", endorsement signature: %s',
                proposalResponses[0].response.status, proposalResponses[0].response.message,
                proposalResponses[0].response.payload, proposalResponses[0].endorsement.signature));

            // wait for the channel-based event hub to tell us
            // that the commit was good or bad on each peer in our organization
            var promises = [];
            let event_hubs = channel.getChannelEventHubsForOrg();
            event_hubs.forEach((eh) => {
                logger.debug('invokeEventPromise - setting up event');
            let invokeEventPromise = new Promise((resolve, reject) => {
                let event_timeout = setTimeout(() => {
                    let message = 'REQUEST_TIMEOUT:' + eh.getPeerAddr();
            logger.error(message);
            eh.disconnect();
        }, 60000);
            eh.registerTxEvent(tx_id_string, (tx, code, block_num) => {
                logger.info('The chaincode invoke chaincode transaction has been committed on peer %s',eh.getPeerAddr());
            logger.info('Transaction %s has status of %s in blocl %s', tx, code, block_num);
            clearTimeout(event_timeout);

            if (code !== 'VALID') {
                let message = util.format('The invoke chaincode transaction was invalid, code:%s',code);
                logger.error(message);
                reject(new Error(message));
            } else {
                let message = 'The invoke chaincode transaction was valid.';
                logger.info(message);
                resolve(message);
            }
        }, (err) => {
                clearTimeout(event_timeout);
                logger.error(err);
                reject(err);
            },
            // the default for 'unregister' is true for transaction listeners
            // so no real need to set here, however for 'disconnect'
            // the default is false as most event hubs are long running
            // in this use case we are using it only once
            {unregister: true, disconnect: true}
        );
            eh.connect();
        });
            promises.push(invokeEventPromise);
        });

            var orderer_request = {
                txId: tx_id,
                proposalResponses: proposalResponses,
                proposal: proposal
            };
            var sendPromise = channel.sendTransaction(orderer_request);
            // put the send to the orderer last so that the events get registered and
            // are ready for the orderering and committing
            promises.push(sendPromise);
            let results = await Promise.all(promises);
            logger.debug(util.format('------->>> R E S P O N S E : %j', results));
            let response = results.pop(); //  orderer results are last in the results
            if (response.status === 'SUCCESS') {
                logger.info('Successfully sent transaction to the orderer.');
            } else {
                error_message = util.format('Failed to order the transaction. Error code: %s',response.status);
                logger.debug(error_message);
            }

            // now see what each of the event hubs reported
            for(let i in results) {
                let event_hub_result = results[i];
                let event_hub = event_hubs[i];
                logger.debug('Event results for event hub :%s',event_hub.getPeerAddr());
                if(typeof event_hub_result === 'string') {
                    logger.debug(event_hub_result);
                } else {
                    if(!error_message) error_message = event_hub_result.toString();
                    logger.debug(event_hub_result.toString());
                }
            }
        } else {
            error_message = util.format('Failed to send Proposal and receive all good ProposalResponse');
            logger.debug(error_message);
        }
    } catch (error) {
        logger.error('Failed to invoke due to error: ' + error.stack ? error.stack : error);
        error_message = error.toString();
    }

    if (!error_message) {
        let message = util.format(
            'Successfully invoked the chaincode %s to the channel \'%s\' for transaction ID: %s',
            orgName, channelName, tx_id_string);
        logger.info(message);
        let retJson = {};
        retJson.transactionId = tx_id_string;
        return retJson;
    } else {
        let message = util.format('Failed to invoke chaincode. cause:%s',error_message);
        logger.error(message);
        throw new Error(message);
    }
}

exports.invokeChaincode = invokeChaincode;
exports.invokeProposal = invokeProposal;
