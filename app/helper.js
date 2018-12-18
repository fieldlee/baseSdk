/**
 * Copyright 2017 IBM All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an 'AS IS' BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
'use strict';
var log4js = require('log4js');
var logger = log4js.getLogger('Helper');
logger.setLevel('INFO');

var path = require('path');
var util = require('util');
var fs = require('fs-extra');
var User = require('fabric-client/lib/User.js');
var crypto = require('crypto');
var copService = require('fabric-ca-client');
var async = require('async');


var hfc = require('fabric-client');
hfc.setLogger(logger);
var ORGS = hfc.getConfigSetting('network-config');
var orgList = hfc.getConfigSetting('orgs');
var isManage = hfc.getConfigSetting("manager");
var consensus = hfc.getConfigSetting("consensus");
var ordererList = hfc.getConfigSetting("orderers");
var currentOrgId = hfc.getConfigSetting("curOrgId"); // 当前org id
var chanList = hfc.getConfigSetting("channels");

var eventWaitTime = hfc.getConfigSetting("eventWaitTime");


var clients = {};
var channels = {};
var caClients = {};
var aliasNames = {};
let allEventhubs = [];

for (const chanindex in chanList) {
	var chan = chanList[chanindex];
	// 初始化client channel
	if (isManage) {
		// 设置chan 的channel id和channelTxNum=0
		for (const keyindex in chan.includes) {
			let key = chan.includes[keyindex];
			// client
			var client;
			if (clients[key]) {
				client = clients[key];
			} else {
				client = new hfc();
			}

			logger.debug("======================================org key:" + key);
			let cryptoSuite = hfc.newCryptoSuite();
			cryptoSuite.setCryptoKeyStore(hfc.newCryptoKeyStore({ path: getKeyStoreForOrg(ORGS[key].name) }));
			client.setCryptoSuite(cryptoSuite);

			let channel = client.newChannel(chan.channelId);

			for (let index = 0; index < ordererList.length; index++) {
				const orderid = ordererList[index];
				channel.addOrderer(newOrderer(orderid, client));
			}
			clients[key] = client;

			if (channels[key]) {
				let chans = channels[key];
				chans.push(channel);
				channels[key] = chans;
			} else {
				channels[key] = [channel];
			}

			aliasNames[key] = ORGS[key].aliasName;
			setupPeers(channel, key, client);

			let caUrl = ORGS[key].ca;
			caClients[key] = new copService(caUrl, null, '', cryptoSuite);
		}
	} else {
		let key = currentOrgId;
		var client;
		if (clients[key]) {
			client = clients[key];
		} else {
			client = new hfc();
		}
		// let client = new hfc();
		let cryptoSuite = hfc.newCryptoSuite();
		cryptoSuite.setCryptoKeyStore(hfc.newCryptoKeyStore({ path: getKeyStoreForOrg(ORGS[key].name) }));
		client.setCryptoSuite(cryptoSuite);

		let channel = client.newChannel(chan.channelId);

		for (let index = 0; index < ordererList.length; index++) {
			const orderid = ordererList[index];
			channel.addOrderer(newOrderer(orderid, client));
		}
		clients[key] = client;
		// channels[key] = channel;
		if (channels[key]) {
			let chans = channels[key];
			chans.push(channel);
			channels[key] = chans;
		} else {
			channels[key] = [channel];
		}

		aliasNames[key] = ORGS[key].aliasName;
		setupPeers(channel, key, client);
		let caUrl = ORGS[key].ca;
		caClients[key] = new copService(caUrl, null, '', cryptoSuite);
	}
}

function setupPeers(channel, org, client) {
	for (let key in ORGS[org].peers) {
		// let data = fs.readFileSync(path.join(__dirname, ORGS[org].peers[key]['tls_cacerts']));
		let data = fs.readFileSync(ORGS[org].peers[key]['tls_cacerts']);
		let peer = client.newPeer(
			ORGS[org].peers[key].requests,
			{
				'request-timeout': '100000',
				'pem': Buffer.from(data).toString(),
				'ssl-target-name-override': ORGS[org].peers[key]['server-hostname']
			}
		);
		peer.setName(key);
		channel.addPeer(peer);
	}
}

function newOrderer(orderid, client) {
	var caRootsPath = ORGS[orderid].tls_cacerts;
	let data = fs.readFileSync(caRootsPath);
	let caroots = Buffer.from(data).toString();

	return client.newOrderer(ORGS[orderid].url, {
		'request-timeout': '100000',
		'pem': caroots,
		'ssl-target-name-override': ORGS[orderid]['server-hostname']
	});
}


function readAllFiles(dir) {
	var files = fs.readdirSync(dir);
	var certs = [];
	files.forEach((file_name) => {
		let file_path = path.join(dir, file_name);
		let data = fs.readFileSync(file_path);
		certs.push(data);
	});
	return certs;
}

function getOrgName(org) {
	return ORGS[org]["name"];
}

function getKeyStoreForOrg(org) {
	return hfc.getConfigSetting('keyValueStore') + '_' + org;
}

function newRemotes(names, forPeers, userOrg) {
	let client = getClientForOrg(userOrg);
	let targets = [];
	// find the peer that match the names
	for (let idx in names) {
		let peerName = names[idx];
		// logger.info("peerName:", peerName);
		// logger.info("ORGS:", ORGS);
		if (ORGS[userOrg].peers[peerName]) {
			// found a peer matching the name
			// let data = fs.readFileSync(path.join(__dirname, ORGS[userOrg].peers[peerName]['tls_cacerts']));
			let data = fs.readFileSync(ORGS[userOrg].peers[peerName]['tls_cacerts']);
			let grpcOpts = {
				'request-timeout': '100000',
				'pem': Buffer.from(data).toString(),
				'ssl-target-name-override': ORGS[userOrg].peers[peerName]['server-hostname']
			};

			if (forPeers) {
				targets.push(client.newPeer(ORGS[userOrg].peers[peerName].requests, grpcOpts));
			} else {
				let eh = client.newEventHub();
				eh.setPeerAddr(ORGS[userOrg].peers[peerName].events, grpcOpts);
				targets.push(eh);
			}
		}
	}

	if (targets.length === 0) {
		logger.error(util.format('Failed to find peers matching the names %s', names));
	}

	return targets;
}

//-------------------------------------//
// APIs
//-------------------------------------//
var getChannelForOrg = function (channelName, org) {
	logger.debug("channelName:" + channelName);
	logger.debug("org:" + org);
	let chans = channels[org];
	for (let index = 0; index < chans.length; index++) {
		const chan = chans[index];
		if (chan._name == channelName) {
			return chan;
		}
	}
	return null;
};

var getClientForOrg = function (org) {
	return clients[org];
};

var newPeers = function (names, org) {
	return newRemotes(names, true, org);
};

var newEventHubs = function (names, org) {
	return newRemotes(names, false, org);
};

var getMspID = function (org) {
	return ORGS[org].mspid;
};

var getAdminUser = function (userOrg) {
	var username = hfc.getConfigSetting('caUser');
	var password = hfc.getConfigSetting('caSecret');
	var member;
	var client = getClientForOrg(userOrg);

	return hfc.newDefaultKeyValueStore({
		path: getKeyStoreForOrg(getOrgName(userOrg))
	}).then((store) => {
		client.setStateStore(store);
		// clearing the user context before switching
		client._userContext = null;
		return client.getUserContext(username, true).then((user) => {
			if (user && user.isEnrolled()) {
				logger.info('Successfully loaded member from persistence');
				return user;
			} else {
				let caClient = caClients[userOrg];
				// need to enroll it with CA server
				logger.info(caClient);
				logger.info('no logon caclient and need to enroll it with CA server!');
				return caClient.enroll({
					enrollmentID: username,
					enrollmentSecret: password
				}).then((enrollment) => {
					logger.info('Successfully enrolled user \'' + username + '\'');
					member = new User(username);
					member.setCryptoSuite(client.getCryptoSuite());
					return member.setEnrollment(enrollment.key, enrollment.certificate, getMspID(userOrg));
				}, (err) => {
					logger.error('err:' + err);
					return null;
				}).then(() => {
					return client.setUserContext(member);
				}).then(() => {
					return member;
				}).catch((err) => {
					logger.error('Failed to enroll and persist user. Error: ' + err.stack ?
						err.stack : err);
					return null;
				});
			}
		});
	});
};

var registerUser = function (username, userOrg, isJson) {
	var member;
	var client = getClientForOrg(userOrg);
	var enrollmentSecret = null;
	return hfc.newDefaultKeyValueStore({
		path: getKeyStoreForOrg(getOrgName(userOrg))
	}).then((store) => {
		client.setStateStore(store);
		// clearing the user context before switching
		client._userContext = null;
		return client.getUserContext(username, true).then((user) => {
			if (user && user.isEnrolled()) {
				logger.info('Successfully loaded member from persistence');
				var response = {
					success: false,
					message: "已注册"
				};
				logger.info("1");
				return response;
			} else {
				let caClient = caClients[userOrg];
				return getAdminUser(userOrg).then(function (adminUserObj) {
					member = adminUserObj;
					return caClient.register({
						enrollmentID: username,
						affiliation: aliasNames[userOrg].toLowerCase() + '.department1'
					}, member);
				}).then((secret) => {
					enrollmentSecret = secret;
					logger.debug(username + ' registered successfully');
					return caClient.enroll({
						enrollmentID: username,
						enrollmentSecret: secret
					});
				}, (err) => {
					logger.debug(username + ' failed to register');
					return '' + err;
					//return 'Failed to register '+username+'. Error: ' + err.stack ? err.stack : err;
				}).then((message) => {
					if (message && typeof message === 'string' && message.includes(
						'Error:')) {
						logger.error(username + ' enrollment failed');
						return message;
					}
					logger.debug(username + ' enrolled successfully');
					logger.debug(username + ' key INFO:' + message.key);
					logger.debug(username + ' certificate INFO:' + message.certificate);
					member = new User(username);
					member._enrollmentSecret = enrollmentSecret;
					return member.setEnrollment(message.key, message.certificate, getMspID(userOrg));
				}).then(() => {
					client.setUserContext(member);
					return member;
				}, (err) => {
					logger.error(util.format('%s enroll failed: %s', username, err.stack ? err.stack : err));
					return '' + err;
				});;
			}
		});
	}).then((user) => {
		if (user._identity) {
			// logger.info(user._identity);
			// logger.info(user._identity._certificate);
			var response = {
				success: true,
				secret: user._enrollmentSecret,
				certificate: user._identity._certificate,
				message: username + ' enrolled Successfully',
			};
			return response;
		} else {
			return user;
		}
	}, (err) => {
		logger.error(util.format('Failed to get registered user: %s, error: %s', username, err.stack ? err.stack : err));
		return '' + err;
	});
};

var loginRegisteredUser = function (username, secret, userOrg) {
	var member;
	var client = getClientForOrg(userOrg);
	return hfc.newDefaultKeyValueStore({
		path: getKeyStoreForOrg(getOrgName(userOrg))
	}).then((store) => {
		client.setStateStore(store);
		client._userContext = null;
		return client.getUserContext(username, true).then((user) => {
			if (user && user.isEnrolled()) {
				logger.info('Successfully loaded member from persistence');
				return true;
			} else {
				let caClient = caClients[userOrg];
				return caClient.enroll({
					enrollmentID: username,
					enrollmentSecret: secret
				}).then((message) => {
					if (message && typeof message === 'string' && message.includes(
						'Error:')) {
						logger.error(username + ' enrollment failed');
						return false;
					}
					logger.debug(username + ' enrolled successfully');
					logger.debug(username + ' INFO:' + message);
					member = new User(username);
					member._enrollmentSecret = secret;
					return member.setEnrollment(message.key, message.certificate, getMspID(userOrg));
				}, (err) => {
					logger.error(util.format('%s enroll failed: %s', username, err.stack ? err.stack : err));
					return false;
				}).then((res) => {
					if (res == false) {
						return false;
					}
					client.setUserContext(member).then(() => {
						return true;
					}, (err) => {
						logger.error(util.format('%s setUserContext failed: %s', username, err.stack ? err.stack : err));
						return false;
					})
				});
			}
		}, (err) => {
			logger.error(util.format('%s setUserContext failed: %s', username, err.stack ? err.stack : err));
			return false;
		});
	}).then((result) => {
		if (result == false) {
			return false;
		} else {
			return true;
		}
	}, (err) => {
		logger.error(util.format('Failed to get registered user: %s, error: %s', username, err.stack ? err.stack : err));
		return false;
	});
};

var getRegisteredUsers = function (username, userOrg, isJson) {
	/*** 
		var member;
	var client = getClientForOrg(userOrg);
	var enrollmentSecret = null;
	return hfc.newDefaultKeyValueStore({
		path: getKeyStoreForOrg(getOrgName(userOrg))
	}).then((store) => {
		// console.log(client);
		client.setStateStore(store);
		// clearing the user context before switching
		client._userContext = null;
		return client.getUserContext(username, true).then((user) => {
			if (user && user.isEnrolled()) {
				logger.info('Successfully loaded member from persistence');
				return user;
			} else {
				let caClient = caClients[userOrg];
				return getAdminUser(userOrg).then(function (adminUserObj) {
					member = adminUserObj;
					return caClient.register({
						enrollmentID: username,
						affiliation: aliasNames[userOrg].toLowerCase() + '.department1'
					}, member);
				}).then((secret) => {
					enrollmentSecret = secret;
					logger.debug(username + ' registered successfully');
					return caClient.enroll({
						enrollmentID: username,
						enrollmentSecret: secret
					});
				}, (err) => {
					logger.debug(username + ' failed to register');
					return '' + err;
					//return 'Failed to register '+username+'. Error: ' + err.stack ? err.stack : err;
				}).then((message) => {
					if (message && typeof message === 'string' && message.includes(
						'Error:')) {
						logger.error(username + ' enrollment failed');
						return message;
					}
					logger.debug(username + ' enrolled successfully');
					// logger.debug(username + ' INFO:'+JSON.stringify(message));
					member = new User(username);
					member._enrollmentSecret = enrollmentSecret;
					return member.setEnrollment(message.key, message.certificate, getMspID(userOrg));
				}).then(() => {
					client.setUserContext(member);
					return member;
				}, (err) => {
					logger.error(util.format('%s enroll failed: %s', username, err.stack ? err.stack : err));
					return '' + err;
				});;
			}
		});
	}).then((user) => {
		if (isJson && isJson === true) {
			var response = {
				success: true,
				secret: user._enrollmentSecret,
				message: username + ' enrolled Successfully',
			};
			return response;
		}
		return user;
	}, (err) => {
		logger.error(util.format('Failed to get registered user: %s, error: %s', username, err.stack ? err.stack : err));
		return '' + err;
	});
	*/
	logger.debug("=============start");
	// try {
	logger.debug("=============start1:");
	var client = getClientForOrg(userOrg);
	logger.debug('Successfully initialized the credential stores');
	// client can now act as an agent for organization Org1
	// first check to see if the user is already enrolled
	client.getUserContext(username, true).then(function (user) {
		if (user && user.isEnrolled()) {
			logger.info('Successfully loaded member from persistence');
		} else {
			// user was not enrolled, so we will need an admin user object to register
			logger.debug("=============1");
			client.setUserContext({ username: "admin", password: "adminpw" }).then(function (adminUserObj) {
				logger.debug("=============2");
				let caClient = client.getCertificateAuthority();
				logger.debug("=============3");
				let affiliationService = caClient.newAffiliationService();
				logger.debug("=============4");
				affiliationService.getAll(adminUserObj).then(function (registeredAffiliations) {
					logger.debug("=============5");
					logger.info(registeredAffiliations.result.affiliations);
					// create affiliation for org3/org4/...
					if (!registeredAffiliations.result.affiliations.some(
						x => x.name === userOrg.toLowerCase())) {
						let affiliation = userOrg.toLowerCase() + '.department1';
						logger.debug("=============6");
					   affiliationService.create({
							name: affiliation,
							force: true
						}, adminUserObj).then(function(result){
							logger.debug("result:");
							logger.debug(JSON.stringify(result));
						});
					}
					logger.debug("=============7");
					caClient.register({
						enrollmentID: username,
						affiliation: userOrg.toLowerCase() + '.department1'
					}, adminUserObj).then(function(secret){
						logger.debug("=============8");
						logger.debug('Successfully got the secret for user %s', username);
						client.setUserContext({ username: username, password: secret }).then(function(user){
							if (user && user.isEnrolled) {
								if (isJson && isJson === true) {
									return reqUtils.getResponse(username + ' enrolled Successfully', 200);;
								}
							} else {
								// throw new Error('User was not enrolled ');
							}
							logger.debug('Successfully enrolled username %s  and setUserContext on the client object', username);
						});
						
					});
				});
			});
		}
		
	});


	// } catch(error) {
	//     logger.error('Failed to get registered user: %s with error: %s', username, error.toString());
	//     return 'failed '+error.toString();
	// }
};





var getOrgAdmin = function (userOrg) {
	var admin = ORGS[userOrg].admin;
	var keyPath = admin.key;
	var keyPEM = Buffer.from(readAllFiles(keyPath)[0]).toString();
	// var certPath = path.join(__dirname, admin.cert);
	var certPath = admin.cert;
	var certPEM = readAllFiles(certPath)[0].toString();
	var client = getClientForOrg(userOrg);
	var cryptoSuite = hfc.newCryptoSuite();
	if (userOrg) {
		cryptoSuite.setCryptoKeyStore(hfc.newCryptoKeyStore({ path: getKeyStoreForOrg(getOrgName(userOrg)) }));
		client.setCryptoSuite(cryptoSuite);
	}

	return hfc.newDefaultKeyValueStore({
		path: getKeyStoreForOrg(getOrgName(userOrg))
	}).then((store) => {
		client.setStateStore(store);

		return client.createUser({
			username: 'peer' + userOrg + 'Admin',
			mspid: getMspID(userOrg),
			cryptoContent: {
				privateKeyPEM: keyPEM,
				signedCertPEM: certPEM
			}
		});
	});
};

var setupChaincodeDeploy = function () {
	// process.env.GOPATH = path.join(__dirname, hfc.getConfigSetting('CC_SRC_PATH'));
	process.env.GOPATH = hfc.getConfigSetting('CC_SRC_PATH');
};

var getLogger = function (moduleName) {
	var logger = log4js.getLogger(moduleName);
	logger.setLevel('DEBUG');
	return logger;
};

var buildTarget = function (peer, org) {
	var target = null;
	if (typeof peer !== 'undefined') {
		let targets = newPeers([peer], org);
		if (targets && targets.length > 0) target = targets[0];
	}
	return target;
}


let getChannelInfo = async function (channel, target, org) {
	return getOrgAdmin(org).then((user) => {
		return channel.queryInfo(target);
	}, (err) => {
		logger.info('Failed to get submitter');
		return null;
	}).then((blockinfo) => {
		if (blockinfo) {
			if (blockinfo.height.low) {
				var blockNum = blockinfo.height.low;
				if (typeof (blockNum) == "string") {
					blockNum = parseInt(blockNum);
				}
				return blockNum;
			}
			else {
				return 0;
			}
		} else {
			logger.error('response_payloads is null');
			return null;
		}
	}, (err) => {
		logger.error('Failed to send query due to error: ' + err.stack ? err.stack :
			err);
		return null;
	}).catch((err) => {
		logger.error('Failed to query with error:' + err.stack ? err.stack : err);
		return null;
	});

}

let getBlockTx = async function (channel, index, org) {
	return getOrgAdmin(org).then((user) => {
		return channel.queryBlock(index);
	}, (err) => {
		return null;
	}).then((blockinfo) => {
		if (blockinfo) {
			if (blockinfo.data.data.length) {
				let datalen = blockinfo.data.data.length;
				if (typeof (datalen) == "string") {
					datalen = parseInt(datalen)
				}
				return datalen;
			}
		} else {
			return null;
		}
	}, (err) => {
		logger.error('Failed to send query due to error: ' + err.stack ? err.stack :
			err);
		return null;
	}).catch((err) => {
		logger.error('Failed to query with error:' + err.stack ? err.stack : err);
		return null;
	});

}


let getBlockDateNumber = async function (channel, index, org) {
	return getOrgAdmin(org).then((user) => {
		return channel.queryBlock(index);
	}, (err) => {
		return null;
	}).then((blockinfo) => {
		if (blockinfo) {
			if (blockinfo.data.data[0] && blockinfo.data.data[0].payload.header.channel_header.timestamp) {
				let time = new Date(blockinfo.data.data[0].payload.header.channel_header.timestamp);
				var dateTxBlock = {};
				var strDateFormat = (time.getMonth() + 1).toString() + "-" + time.getDate().toString();
				dateTxBlock[strDateFormat] = {}
				let datalen = blockinfo.data.data.length;
				dateTxBlock[strDateFormat]["block"] = 1;
				dateTxBlock[strDateFormat]["tx"] = datalen;
				return dateTxBlock;
			}
		} else {
			return null;
		}
	}, (err) => {
		logger.error('Failed to send query due to error: ' + err.stack ? err.stack :
			err);
		return null;
	}).catch((err) => {
		logger.error('Failed to query with error:' + err.stack ? err.stack : err);
		return null;
	});

}

exports.getChannelForOrg = getChannelForOrg;
exports.getClientForOrg = getClientForOrg;
exports.getLogger = getLogger;
exports.setupChaincodeDeploy = setupChaincodeDeploy;
exports.getMspID = getMspID;
exports.ORGS = ORGS;
exports.newPeers = newPeers;
exports.newEventHubs = newEventHubs;
exports.registerUser = registerUser;
exports.getRegisteredUsers = getRegisteredUsers;
exports.loginRegisteredUser = loginRegisteredUser;
exports.getOrgAdmin = getOrgAdmin;
exports.getAdminUser = getAdminUser;
exports.eventWaitTime = eventWaitTime;
exports.buildTarget = buildTarget;
exports.getChannelInfo = getChannelInfo;
exports.getBlockTx = getBlockTx;
exports.getBlockDateNumber = getBlockDateNumber;