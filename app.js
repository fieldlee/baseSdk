// log4js
let log4js = require('log4js');
let logger = log4js.getLogger('HyperledgerWebApp');
logger.setLevel('DEBUG');
// express
let express = require('express');
let session = require('express-session');
let cookieParser = require('cookie-parser');
let bodyParser = require('body-parser');
let http = require('http');
let util = require('util');
var fs = require('fs-extra');

let expressJWT = require('express-jwt');
let jwt = require('jsonwebtoken');
let bearerToken = require('express-bearer-token');
let cors = require('cors');
let path = require('path');
let hfc = require('fabric-client');
let app = express();

let secretKey = "thisismysecret";

hfc.addConfigFile(path.join(__dirname, 'config.json'));

var helper = require('./app/helper.js');
var channels = require('./app/create-channel.js');
var join = require('./app/join-channel.js');
var install = require('./app/install-chaincode.js');
var instantiate = require('./app/instantiate-chaincode.js');
var upgrade = require('./app/update-chaincode.js');
var invoke = require('./app/invoke-transaction.js');
var query = require('./app/query.js');
var reqUtils = require('./app/reqUtils.js');
var sdkUtils = require('./app/sdkUtils');

var chanList = hfc.getConfigSetting("channels");
var allChanTx = {};
var getChatBlockHeight = 0;
var allChatBlock = {};
var allChatTx = {};
var defaultChannelId = "channel";
logger.debug('chanList  : ' + chanList);
if (chanList && chanList.length > 0) {
	defaultChannelId = chanList[0]["channelId"];
	// chanList
	for (const index in chanList) {
		logger.debug('chan  : ' + chanList[index]);
		logger.debug('chan.channelId  : ' + chanList[index].channelId);
		allChanTx[chanList[index].channelId] = {}
		allChanTx[chanList[index].channelId]["blockHeight"] = 0;
		allChanTx[chanList[index].channelId]["txNum"] = 0;
		allChanTx[chanList[index].channelId]["hadReadHeight"] = 0;
	}
}

let host = process.env.HOST || hfc.getConfigSetting('host');
let port = process.env.PORT || hfc.getConfigSetting('port');

app.options('*', cors());
app.use(cors());
//support parsing of application/json type post data
app.use(bodyParser.json());
//support parsing of application/x-www-form-urlencoded post data
app.use(bodyParser.urlencoded({
	extended: false
}));
// set secret variable
app.set('secret', secretKey);
// login 
app.use(expressJWT({
    secret: 'thisismysecret'
}).unless({
    path: ['/api/v1/token']
}));
app.use(bearerToken());
app.use(function(req, res, next) {
    logger.info(' ------>>>>>> new request for %s',req.originalUrl);
    logger.info('------->>>>>> request params %s',JSON.stringify(req.body));
    if (req.originalUrl.indexOf('/api/v1/token') >= 0) {
        return next();
    }

    var token = req.token;
    jwt.verify(token, app.get('secret'), function(err, decoded) {
        if (err) {
            res.send({
                success: false,
                message: 'Failed to authenticate token. Make sure to include the ' +
                'token returned from /api/v1/token call in the authorization header ' +
                ' as a Bearer token'
            });
            return;
        } else {
            // add the decoded user name and org name to the request object
            // for the downstream code to use
            req.username = decoded.username;
            req.orgname = decoded.orgName;
            logger.debug(util.format('Decoded from JWT token: username - %s, orgname - %s', decoded.username, decoded.orgName));
            return next();
        }
    });
});

//app.post("/api/v1/save",sdkUtils.save);
app.post("/api/v1/query",sdkUtils.query);
app.post("/api/v1/hashVerify",sdkUtils.hashVerify);
app.post("/api/v1/queryByTransactionId",sdkUtils.queryByTransactionId);
app.post("/api/v1/queryWithPagination",sdkUtils.queryWithPagination);

///////////////////////////////////////////////////////////////////////////////
//////////////////////////////// START SERVER /////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
var server = http.createServer(app).listen(port, function () { });

logger.info('****************** SERVER STARTED ************************');
logger.info('**************  http://' + host + ':' + port + '  ******************');
server.timeout = 240000;
function getErrorMessage(field) {
	var response = {
		success: false,
		info: field + ' field is missing or Invalid in the request'
	};
	return response;
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////// REST ENDPOINTS START HERE ///////////////////////////
///////////////////////////////////////////////////////////////////////////////
// Register and enroll user
app.post('/api/v1/token',  function(req, res) {
    var username = req.body.username;
    var orgName = req.body.orgName || "sureOrg";
    var creatorFlag = req.body.creatorFlag || 0
    logger.debug('End point : /users');
    logger.debug('User name : ' + username);
    logger.debug('Org name  : ' + orgName);
    if (!username) {
        res.json(getErrorMessage('\'username\''));
        return;
    }
    if (!orgName) {
        res.json(getErrorMessage('\'orgName\''));
        return;
    }
    var token = jwt.sign({
        exp: Math.floor(Date.now() / 1000) + parseInt(hfc.getConfigSetting('jwt_expiretime')),
        username: username,
        orgName: orgName
    }, app.get('secret'));

    helper.getRegisteredUsers(username, orgName, true).then(function(response){
		logger.debug('-- returned from registering the username %s for organization %s',username,orgName);
		if (response && typeof response !== 'string') {
			logger.debug('Successfully registered the username %s for organization %s',username,orgName);
			response.token = token;
			if (creatorFlag == 1){
				var file = "/var/fabric-client-kvs_" + orgName + "/" + username
				var result=JSON.parse(fs.readFileSync(file));
				response.certificate = result.enrollment.identity.certificate
			}
			res.json(response);
		} else {
			logger.debug('Failed to register the username %s for organization %s with::%s',username,orgName,response);
			res.json(reqUtils.getErrorMsg(response,500));
		}
	});
});
// Create Channel
app.post('/channels', function (req, res) {
	logger.info('<<<<<<<<<<<<<<<<< C R E A T E  C H A N N E L >>>>>>>>>>>>>>>>>');
	var channelName;
	var channelConfigPath;
	if (req.body.channelName) {
		channelName = req.body.channelName;
	} else {
		channelName = defaultChannelId; //默认第一个Channel
	}

	for (const chanindex in chanList) {
		var chan = chanList[chanindex];
		if (chan["channelId"] == channelName) {
			channelConfigPath = chan["channelConfigPath"];
			break;
		}
	}
	logger.debug('Channel name : ' + channelName);
	logger.debug('channelConfigPath : ' + channelConfigPath); //channelConfigPath
	if (!channelName) {
		res.json(getErrorMessage('\'channelName\''));
		return;
	}
	if (!channelConfigPath) {
		res.json(getErrorMessage('\'channelConfigPath\''));
		return;
	}

	channels.createChannel(channelName, channelConfigPath, req.username, req.orgname)
		.then(function (message) {
			res.json(message);
			// if (message && typeof message !== 'string') {
			// 	res.json(message);
			// } else {
			// 	logger.info(message);
			// 	let jmsg = JSON.parse(message);
			// 	if (jmsg && typeof jmsg !== 'string') {
			// 		res.json(jmsg);
			// 	}
			// 	else {
			// 		res.json({
			// 			success: false,
			// 			info: jmsg
			// 		});
			// 	}
			// }
		});
});
// Join Channel
app.post('/channels/peers', function (req, res) {
	logger.info('<<<<<<<<<<<<<<<<< J O I N  C H A N N E L >>>>>>>>>>>>>>>>>');
	var channelName;
	if (req.body.channelName) {
		channelName = req.body.channelName;
	} else {
		channelName = defaultChannelId; //默认第一个Channel
	}

	var peers = req.body.peers;
	var orgname = req.orgname;
	if (req.body.orgname) {
		orgname = req.body.orgname;
	}

	logger.debug('channelName : ' + channelName);
	logger.debug('peers : ' + peers);
	if (!channelName) {
		res.json(getErrorMessage('\'channelName\''));
		return;
	}
	if (!peers || peers.length == 0) {
		res.json(getErrorMessage('\'peers\''));
		return;
	}

	join.joinChannel(channelName, peers, req.username, orgname)
		.then(function (message) {
			res.json(message);
			// if (message && typeof message !== 'string') {
			// 	res.json(message);
			// } else {
			// 	logger.info(message);
			// 	let jmsg = JSON.parse(message);
			// 	if (jmsg && typeof jmsg !== 'string') {
			// 		res.json(jmsg);
			// 	}
			// 	else {
			// 		res.json({
			// 			success: false,
			// 			info: jmsg
			// 		});
			// 	}
			// }
		});
});
// Install chaincode on target peers
app.post('/chaincodes', function (req, res) {
	logger.debug('==================== INSTALL CHAINCODE ==================');
	var peers = req.body.peers;

	var chaincodeName = req.body.chaincodeName;
	var chaincodePath = req.body.chaincodePath;
	var chaincodeVersion = req.body.chaincodeVersion;
	logger.debug('peers : ' + peers); // target peers list
	logger.debug('chaincodeName : ' + chaincodeName);
	logger.debug('chaincodePath  : ' + chaincodePath);
	logger.debug('chaincodeVersion  : ' + chaincodeVersion);
	if (!peers || peers.length == 0) {
		res.json(getErrorMessage('\'peers\''));
		return;
	}
	if (!chaincodeName) {
		res.json(getErrorMessage('\'chaincodeName\''));
		return;
	}
	if (!chaincodePath) {
		res.json(getErrorMessage('\'chaincodePath\''));
		return;
	}
	if (!chaincodeVersion) {
		res.json(getErrorMessage('\'chaincodeVersion\''));
		return;
	}

	install.installChaincode(peers, chaincodeName, chaincodePath, chaincodeVersion, req.username, req.orgname)
		.then(function (message) {
			res.json(message);
			// if (message && typeof message !== 'string') {
			// 	res.json(message);
			// } else {
			// 	logger.info(message);
			// 	let jmsg = JSON.parse(message);
			// 	if (jmsg && typeof jmsg !== 'string') {
			// 		res.json(jmsg);
			// 	}
			// 	else {
			// 		res.json({
			// 			success: false,
			// 			info: jmsg
			// 		});
			// 	}
			// }
		});
});
// Instantiate chaincode on target peers
app.post('/channels/chaincodes', function (req, res) {
	logger.debug('==================== INSTANTIATE CHAINCODE ==================');
	var chaincodeName = req.body.chaincodeName;
	var chaincodeVersion = req.body.chaincodeVersion;
	var channelName;
	if (req.body.channelName) {
		channelName = req.body.channelName;
	} else {
		channelName = defaultChannelId; //channelName
	}
	var fcn = req.body.fcn;
	var args = req.body.args;
	logger.debug('channelName  : ' + channelName);
	logger.debug('chaincodeName : ' + chaincodeName);
	logger.debug('chaincodeVersion  : ' + chaincodeVersion);
	logger.debug('fcn  : ' + fcn);
	logger.debug('args  : ' + args);
	if (!chaincodeName) {
		res.json(getErrorMessage('\'chaincodeName\''));
		return;
	}
	if (!chaincodeVersion) {
		res.json(getErrorMessage('\'chaincodeVersion\''));
		return;
	}
	if (!channelName) {
		res.json(getErrorMessage('\'channelName\''));
		return;
	}
	if (!args) {
		res.json(getErrorMessage('\'args\''));
		return;
	}
	instantiate.instantiateChaincode(channelName, chaincodeName, chaincodeVersion, fcn, args, req.username, req.orgname)
		.then(function (message) {
			if (message && typeof message !== 'string') {
				res.json(message);
			} else {
				logger.info(message);
				let jmsg = JSON.parse(message);
				if (jmsg && typeof jmsg !== 'string') {
					res.json(jmsg);
				}
				else {
					res.json({
						success: false,
						info: jmsg
					});
				}
			}
		});
});
// UPdate chaincode on target peers
app.put('/channels/chaincodes', function (req, res) {
	logger.debug('==================== UPGRADE CHAINCODE ==================');
	var chaincodeName = req.body.chaincodeName;
	var chaincodeVersion = req.body.chaincodeVersion;
	var channelName;
	if (req.body.channelName) {
		channelName = req.body.channelName;
	} else {
		channelName = defaultChannelId; //channelName
	}

	var fcn = req.body.fcn;
	var args = req.body.args;
	logger.debug('channelName  : ' + channelName);
	logger.debug('chaincodeName : ' + chaincodeName);
	logger.debug('chaincodeVersion  : ' + chaincodeVersion);
	logger.debug('fcn  : ' + fcn);
	logger.debug('args  : ' + args);
	if (!chaincodeName) {
		res.json(getErrorMessage('\'chaincodeName\''));
		return;
	}
	if (!chaincodeVersion) {
		res.json(getErrorMessage('\'chaincodeVersion\''));
		return;
	}
	if (!channelName) {
		res.json(getErrorMessage('\'channelName\''));
		return;
	}
	if (!args) {
		res.json(getErrorMessage('\'args\''));
		return;
	}

	upgrade.updateChaincode(channelName,chaincodeName, chaincodeVersion, req.username, req.orgname)
		.then(function (message) {
			if (message && typeof message !== 'string') {
				res.json(message);
			} else {
				logger.info(message);
				let jmsg = JSON.parse(message);
				if (jmsg && typeof jmsg !== 'string') {
					res.json(jmsg);
				}
				else {
					res.json({
						success: false,
						info: jmsg
					});
				}
			}
		});
});
// Invoke transaction on chaincode on target peers
app.post('/channels/:channelName/chaincodes/:chaincodeName', async function(req, res) {
    logger.debug('==================== INVOKE ON CHAINCODE ==================');
    var peers = req.body.peers;
    var chaincodeName = req.params.chaincodeName;
    var channelName = req.params.channelName;
    var fcn = req.body.fcn;
    var args = req.body.args;
    logger.debug('channelName  : ' + channelName);
    logger.debug('chaincodeName : ' + chaincodeName);
    logger.debug('fcn  : ' + fcn);
    logger.debug('args  : ' + args);
    if (!chaincodeName) {
        res.json(getErrorMessage('\'chaincodeName\''));
        return;
    }
    if (!channelName) {
        res.json(getErrorMessage('\'channelName\''));
        return;
    }
    if (!fcn) {
        res.json(getErrorMessage('\'fcn\''));
        return;
    }
    if (!args) {
        res.json(getErrorMessage('\'args\''));
        return;
    }

    let message = await invoke.invokeChaincode(peers, channelName, chaincodeName, fcn, args, req.username, req.orgname);
    res.send(message);
});
// Query on chaincode on target peers
app.get('/channels/:channelName/chaincodes/:chaincodeName', async function(req, res) {
    logger.debug('==================== QUERY BY CHAINCODE ==================');
    var channelName = req.params.channelName;
    var chaincodeName = req.params.chaincodeName;
    let args = req.query.args;
    let fcn = req.query.fcn;
    let peer = req.query.peer;

    logger.debug('channelName : ' + channelName);
    logger.debug('chaincodeName : ' + chaincodeName);
    logger.debug('fcn : ' + fcn);
    logger.debug('args : ' + args);

    if (!chaincodeName) {
        res.json(getErrorMessage('\'chaincodeName\''));
        return;
    }
    if (!channelName) {
        res.json(getErrorMessage('\'channelName\''));
        return;
    }
    if (!fcn) {
        res.json(getErrorMessage('\'fcn\''));
        return;
    }
    if (!args) {
        res.json(getErrorMessage('\'args\''));
        return;
    }
    args = args.replace(/'/g, '"');
    args = JSON.parse(args);
    logger.debug(args);

    let message = await query.queryChaincode(peer, channelName, chaincodeName, args, fcn, req.username, req.orgname);
    res.send(message);
});
//  Query Get Block by BlockNumber
app.get('/channels/:channelName/blocks/:blockId', async function(req, res) {
    logger.debug('==================== GET BLOCK BY NUMBER ==================');
    let blockId = req.params.blockId;
    let peer = req.query.peer;
    logger.debug('channelName : ' + req.params.channelName);
    logger.debug('BlockID : ' + blockId);
    logger.debug('Peer : ' + peer);
    if (!blockId) {
        res.json(getErrorMessage('\'blockId\''));
        return;
    }

    let message = await query.getBlockByNumber(peer, req.params.channelName, blockId, req.username, req.orgname);
    res.send(message);
});
// Query Get Transaction by Transaction ID
app.get('/channels/:channelName/transactions/:trxnId', async function(req, res) {
    logger.debug('================ GET TRANSACTION BY TRANSACTION_ID ======================');
    logger.debug('channelName : ' + req.params.channelName);
    let trxnId = req.params.trxnId;
    let peer = req.query.peer;
    if (!trxnId) {
        res.json(getErrorMessage('\'trxnId\''));
        return;
    }

    let message = await query.getTransactionByID(peer, req.params.channelName, trxnId, req.username, req.orgname);
    res.send(message);
});
// Query Get Block by Hash
app.get('/channels/:channelName/blocks', async function(req, res) {
    logger.debug('================ GET BLOCK BY HASH ======================');
    logger.debug('channelName : ' + req.params.channelName);
    let hash = req.query.hash;
    let peer = req.query.peer;
    if (!hash) {
        res.json(getErrorMessage('\'hash\''));
        return;
    }

    let message = await query.getBlockByHash(peer, req.params.channelName, hash, req.username, req.orgname);
    res.send(message);
});
//Query for Channel Information
app.get('/channels/:channelName', async function(req, res) {
    logger.debug('================ GET CHANNEL INFORMATION ======================');
    logger.debug('channelName : ' + req.params.channelName);
    let peer = req.query.peer;

    let message = await query.getChainInfo(peer, req.params.channelName, req.username, req.orgname);
    res.send(message);
});
//Query for Channel instantiated chaincodes
app.get('/channels/:channelName/chaincodes', async function(req, res) {
    logger.debug('================ GET INSTANTIATED CHAINCODES ======================');
    logger.debug('channelName : ' + req.params.channelName);
    let peer = req.query.peer;

    let message = await query.getInstalledChaincodes(peer, req.params.channelName, 'instantiated', req.username, req.orgname);
    res.send(message);
});
// Query to fetch all Installed/instantiated chaincodes
app.get('/chaincodes', async function(req, res) {
    var peer = req.query.peer;
    var installType = req.query.type;
    logger.debug('================ GET INSTALLED CHAINCODES ======================');

    let message = await query.getInstalledChaincodes(peer, null, 'installed', req.username, req.orgname)
    res.send(message);
});
// Query to fetch channels
app.get('/channels', async function(req, res) {
    logger.debug('================ GET CHANNELS ======================');
    logger.debug('peer: ' + req.query.peer);
    var peer = req.query.peer;
    if (!peer) {
        res.json(getErrorMessage('\'peer\''));
        return;
    }

    let message = await query.getChannels(peer, req.username, req.orgname);
    res.send(message);
});


app.post('/api/v1/save', async function(req, res) {
    logger.debug("================start post data=================");
    let data = req.body;//JSON.stringify(req.body);
    //通道名称，默认mychannel
    let channelName = req.body.channelName || "mbasechannel";
    //智能合约名称，默认kingland
    let chaincodeName = req.body.chaincodeName || "mbasechain";
    //peer节点url
    let peersUrls = req.body.peersUrls || ["peer0.sureOrg.mbasechain.com"];
    //智能合约方法名
    let functionName = req.body.functionName || "save";
    //用户
    let username = req.username;
    //组织
    let orgName = req.orgname;

    let currentTime = new Date().getTime();
    let args = [];
    data.userName = username;
    args[0] = data.godsCode + "_" + currentTime;
    args[1] = JSON.stringify(data);
    logger.info("---------->args: %s");

    let promises = [];
    let ret = [];


    let invokePromise = invoke.invokeProposal(peersUrls, channelName, chaincodeName, functionName, args, username, orgName).then(message => {
            res.json(reqUtils.getResponse("操作成功",200, message));
        }).catch(err => {
        res.json(reqUtils.getErrorMsg(err.message));
    });
});
