'use strict'

var path = require("path");
var fs = require('fs');
var util = require('util');

var helper = require('./helper.js');
var hfc = require('fabric-client');
var logger = helper.getLogger('update-chaincode');
var ORGS = hfc.getConfigSetting('network-config');
var tx_id = null;
var eh = null;
var updateChaincode = function (channelName,chaincodeName,
	chaincodeVersion, username, org) { 
		logger.debug('\n============ update chaincode on organizations ============\n');
		logger.debug('\norg:'+org+'\n');
		logger.debug('\nusername:'+username+'\n');
	var channel = helper.getChannelForOrg(channelName,org);
	if (channel == null){
		logger.error('===============channle is null======================== ' );
		return ;
	}
	var client = helper.getClientForOrg(org);

	return helper.getOrgAdmin(org).then((user) => {
		// read the config block from the orderer for the channel
		// and initialize the verify MSPs based on the participating
		// organizations
		return channel.initialize();
	}, (err) => {
		logger.error('Failed to enroll user \'' + username + '\'. ' + err);
		throw new Error('Failed to enroll user \'' + username + '\'. ' + err);
	}).then((success) => {
		tx_id = client.newTransactionID();
		// send proposal to endorser
		var request = {
			chaincodeId: chaincodeName,
			chaincodeVersion: chaincodeVersion,
			// args: args,
			txId: tx_id
			// "endorsement-policy":{
			// 	identities: [
			// 	  { role: { name: "member", mspId: "JiakeMSP" }},
			// 	  { role: { name: "member", mspId: "CreatorMSP" }},
			// 	  { role: { name: "member", mspId: "TransferMSP" }},
			// 	  { role: { name: "member", mspId: "SellerMSP" }},
			// 	  { role: { name: "admin", mspId: "OrdererMSP" }}
			// 	],
			// 	policy: {
			// 	  "2-of": [
			// 		{ "signed-by": 2},
			// 		{ "1-of": [{ "signed-by": 0 }, { "signed-by": 1 }, { "signed-by": 2 }, { "signed-by": 3 }]}
			// 	  ]
			// 	}
			//   }
		};

		// if (functionName)
		// 	request.fcn = functionName;

		return channel.sendUpgradeProposal(request,120000);
	}, (err) => {
		logger.error('Failed to initialize the channel');
		throw new Error('Failed to initialize the channel');
	}).then((results) => {
		var proposalResponses = results[0];
		var proposal = results[1];
		var all_good = true;
		for (var i in proposalResponses) {
			let one_good = false;
			if (proposalResponses && proposalResponses[i].response &&
				proposalResponses[i].response.status === 200) {
				one_good = true;
				logger.info('instantiate proposal was good');
			} else {
				logger.error('instantiate proposal was bad');
			}
			all_good = all_good & one_good;
		}
		if (all_good) {
			logger.info(util.format(
				'Successfully sent Proposal and received ProposalResponse: Status - %s, message - "%s", metadata - "%s", endorsement signature: %s',
				proposalResponses[0].response.status, proposalResponses[0].response.message,
				proposalResponses[0].response.payload, proposalResponses[0].endorsement
				.signature));
			var request = {
				proposalResponses: proposalResponses,
				proposal: proposal
			};
			// set the transaction listener and set a timeout of 30sec
			// if the transaction did not get committed within the timeout period,
			// fail the test
			var deployId = tx_id.getTransactionID();

			eh = client.newEventHub();
			// let data = fs.readFileSync(path.join(__dirname, ORGS[org].peers['peer1'][
			// 	'tls_cacerts'
			// ]));
			let data = fs.readFileSync( ORGS[org].peers['peer1']['tls_cacerts']);
			eh.setPeerAddr(ORGS[org].peers['peer1']['events'], {
				pem: Buffer.from(data).toString(),
				'ssl-target-name-override': ORGS[org].peers['peer1']['server-hostname']
			});
			eh.connect();

			let txPromise = new Promise((resolve, reject) => {
				let handle = setTimeout(() => {
					eh.disconnect();
					reject();
				}, 30000);

				eh.registerTxEvent(deployId, (tx, code) => {
					logger.info(
						'The chaincode instantiate transaction has been committed on peer ' +
						eh._ep._endpoint.addr);
					clearTimeout(handle);
					eh.unregisterTxEvent(deployId);
					eh.disconnect();

					if (code !== 'VALID') {
						logger.error('The chaincode instantiate transaction was invalid, code = ' + code);
						reject();
					} else {
						logger.info('The chaincode instantiate transaction was valid.');
						resolve();
					}
				});
			});

			var sendPromise = channel.sendTransaction(request);
			return Promise.all([sendPromise].concat([txPromise])).then((results) => {
				logger.debug('Event promise all complete and testing complete');
				return results[0]; // the first returned value is from the 'sendPromise' which is from the 'sendTransaction()' call
			}).catch((err) => {
				logger.error(
					util.format('Failed to send instantiate transaction and get notifications within the timeout period. %s', err)
				);
				return 'Failed to send instantiate transaction and get notifications within the timeout period.';
			});
		} else {
			logger.error(
				'Failed to send instantiate Proposal or receive valid response. Response null or status is not 200. exiting...'
			);
			return 'Failed to send instantiate Proposal or receive valid response. Response null or status is not 200. exiting...';
		}
	}, (err) => {
		logger.error('Failed to send instantiate proposal due to error: ' + err.stack ?
			err.stack : err);
		return 'Failed to send instantiate proposal due to error: ' + err.stack ?
			err.stack : err;
	}).then((response) => {
		if (response.status === 'SUCCESS') {
			logger.info('Successfully sent transaction to the orderer.');
			let response = {
				success: true,
				info: "Chaincode Instantiation is SUCCESS"
			};
			return response;
		} else {
			logger.error('Failed to order the transaction. Error code: ' + response.status);
			return 'Failed to order the transaction. Error code: ' + response.status;
		}
	}, (err) => {
		logger.error('Failed to send instantiate due to error: ' + err.stack ? err
			.stack : err);
		return 'Failed to send instantiate due to error: ' + err.stack ? err.stack :
			err;
	});
        
};
exports.updateChaincode = updateChaincode;