var fs = require("fs");
var net = require("net");
var crypto = require("crypto");
// var Crypt = require("khawn2u-crypt");
var Crypt = require("/home/pi/Desktop/khawn2u-crypt/index.js");
var child_process = require("child_process");
var stream = require("stream");
var os = require("os");
var KryptCoin = function(ops) {
    var self = this;
    this.crypt = new Crypt();
    /*
    this.MultiThreaded = ops.MultiThread;
    if (this.MultiThreaded) {
        this.Threads = os.cpus().length*(ops.ThreadMultiplier || 1);
        this.Workers = [];
        this.OpenWorkers = [];
        this.WorkerCallbacks = {};
        for (var i=0; i<this.Threads; i++) {
            this.OpenWorkers.push(false);
            this.Workers.push(child_process.fork(__dirname+"/worker.js"));
            var id = i;
            this.Workers[i].on('message',function(msg){
                console.log(msg);
                self.OpenWorkers[id] = true;
                if (msg !== "Started") {
                    if (self.WorkerCallbacks[msg.ID] instanceof Function) {
                        self.WorkerCallbacks[msg.ID](msg.Result);
                        delete self.WorkerCallbacks[msg.ID];
                    }
                }
            });
            this.Workers[i].send({Options:ops});
        }
    }
    */
    var PrivateKey = undefined;
    if (ops.PrivateKey) {
        PrivateKey = BigInt(ops.PrivateKey);
        this.PublicKey = this.crypt.secp256k1.getPublicKey(PrivateKey);
        this.Adress = this.crypt.secp256k1.toAdress(this.PublicKey);
    }
    this.parseContract = function(U8array) {
        var Drafter = "0x"+self.crypt.bufferToBigInt(U8array.subarray(0,33)).toString(16);
        var Parties = [];
        for (var i=0; i<U8array[33]; i++) {
            Parties.push("0x"+self.crypt.bufferToBigInt(U8array.subarray(34+(i*33),67+(i*33))).toString(16));
        }
        var idx = 34+(U8array[33]*33);
        var date = new Date(Number(self.crypt.bufferToBigInt(U8array.subarray(idx,idx+16))));
        return {
            Drafter:Drafter,
            Parties:Parties,
            Date:date
        }
    }
    this.contract = function(FulfillmentDate,PartiesAdressList) {
        this.FulfillmentDate = FulfillmentDate;
        this.Fulfilled = false;
        this.isTransaction = false;
        this.Drafter = "0x0";
        this.Parties = PartiesAdressList;
        this.SignedContract = undefined;
        this.UnsignedContract = new Uint8Array(50+(this.Parties.length*33));
        this.UnsignedContract[33] = this.Parties.length;
        for (var i=0; i<this.Parties.length; i++) {
            var adTo = self.crypt.bigIntToBuffer(BigInt(this.Parties[i]));
            this.UnsignedContract.set(adTo,(67+(i*33))-adTo.length);
        }
        var arr = self.crypt.bigIntToBuffer(BigInt(this.FulfillmentDate.valueOf()));
        this.UnsignedContract.set(arr,this.UnsignedContract.length-arr.length);
        this.sign = function(sk) {
            if (sk) {
                this.Drafter = self.crypt.secp256k1.toAdress(self.crypt.secp256k1.getPublicKey(sk));
                var adFrom = self.crypt.bigIntToBuffer(BigInt(this.Drafter));
                this.UnsignedContract.set(adFrom,33-adFrom.length);
                this.SignedContract = self.crypt.SignedMessageToBuffer(self.crypt.secp256k1.sign(this.UnsignedContract,sk));
                return this.SignedContract;
            } else {
                if (PrivateKey) {
                    this.Drafter = self.Adress;
                    var adFrom = self.crypt.bigIntToBuffer(BigInt(this.Drafter));
                    this.UnsignedContract.set(adFrom,33-adFrom.length);
                    this.SignedContract = self.crypt.SignedMessageToBuffer(self.crypt.secp256k1.sign(this.UnsignedContract,PrivateKey));
                    return this.SignedContract;
                } else {
                    throw new Error("No private key supplied, try adding a PrivateKey value in the config for new KryptCoin(config)");
                }
            }
        }
    }
    this.filePath = ops.DataFilePath.endsWith("/") ? ops.DataFilePath : ops.DataFilePath+"/";
    this.UserTransactionTrees = {};
    fs.readdir(this.filePath,function(error,files){
        for (var i=0; i<files.length; i++) {
            var fileName = files[i];
            if (fileName.startsWith("0x")) {
                var TreeFilePath = self.filePath+fileName;
                self.parseAgreementChainStream(fs.createReadStream(TreeFilePath),function(tre){
                    self.UserTransactionTrees[fileName] = tre;
                    console.log(tre);
                });
            } else if (fileName == "AgreementChain") {

            }
        }
    });
    this.Tx = function(sendAdress,Nonce,Amount,Fee,Change) {
		this.To = sendAdress;
		this.From = null;
		this.Amount = Amount;
		this.Fee = Fee;
		this.Change = Change;
		this.Nonce = Nonce;
		var ad = self.crypt.bigIntToBuffer(BigInt(this.To));
		var am = self.crypt.bigIntToBuffer(BigInt(this.Amount));
		var fe = self.crypt.bigIntToBuffer(BigInt(this.Fee));
		var ch = self.crypt.bigIntToBuffer(BigInt(this.Change));
		var id = self.crypt.bigIntToBuffer(BigInt(this.Nonce));
		var Tx = new Uint8Array(id.length+am.length+fe.length+ch.length+37);
		Tx.set(ad,33-ad.length);
		Tx[33] = id.length;
		Tx.set(id,34);
		Tx[34+id.length] = am.length;
		Tx.set(am,35+id.length);
		Tx[35+id.length+am.length] = fe.length;
		Tx.set(fe,36+id.length+am.length);
		Tx[36+id.length+am.length+fe.length] = ch.length;
		Tx.set(ch,37+id.length+am.length+fe.length);
		this.UnsignedTx = Tx;
		this.Signiture = null;
		this.SignedTx = null;
		this.sign = function(sk) {
            if (sk) {
                this.Signiture = self.crypt.secp256k1.sign(this.UnsignedTx,sk);
                this.SignedTx = self.crypt.SignedMessageToBuffer(this.Signiture);
                this.From = self.crypt.secp256k1.toAdress(self.crypt.secp256k1.getPublicKey(sk));
                return this.SignedTx;
            } else {
                if (PrivateKey) {
                    this.Signiture = self.crypt.secp256k1.sign(this.UnsignedTx,PrivateKey);
                    this.SignedTx = self.crypt.SignedMessageToBuffer(this.Signiture);
                    this.From = self.crypt.secp256k1.toAdress(self.crypt.secp256k1.getPublicKey(PrivateKey));
                    return this.SignedTx;
                } else {
                    throw new Error("No private key supplied, try adding a PrivateKey value in the config for new KryptCoin(config)");
                }
            }
		}
	}
	this.parseTx = function(buff) {
		var To = "0x"+self.crypt.bufferToBigInt(buff.subarray(0,33)).toString(16);
		var idx = 34;
		var len = buff[33];
		var Id = self.crypt.bufferToBigInt(buff.subarray(idx,idx+len));
		idx += len+1;
		len = buff[idx-1];
		var Am = self.crypt.bufferToBigInt(buff.subarray(idx,idx+len));
		idx += len+1;
		len = buff[idx-1];
		var Fe = self.crypt.bufferToBigInt(buff.subarray(idx,idx+len));
		idx += len+1;
		len = buff[idx-1];
		var Ch = self.crypt.bufferToBigInt(buff.subarray(idx,idx+len));
		return {
			To:To,
			Fee:{RawTokenAmount:Fe,Value:Number(Fe)/1000000000000000000},
			Amount:{RawTokenAmount:Am,Value:Number(Am)/1000000000000000000},
			Change:{RawTokenAmount:Ch,Value:Number(Ch)/1000000000000000000},
			Nonce:Id
		}
	}
	this.parseSignedTx = function(buff) {
        var SignedTx = self.crypt.BufferToSignedMessage(buff);
        var Tx = self.parseTx(SignedTx.Message);
        Tx.From = self.crypt.secp256k1.toAdress(self.crypt.secp256k1.recoverPublicKey(SignedTx));
        return Tx;
	}
    this.parseAmount = function(a) {
		if (a.constructor === String) {
			var idx = a.indexOf(".");
			if (idx == -1) {
				return BigInt(a)*1000000000000000000n;
			} else {
				var result = BigInt(a.split(".").join(""));
				idx = a.length-idx-1;
				if (idx > 18) {
					return result/(10n**BigInt(idx-18));
				} else {
					return result*(10n**BigInt(18-idx));
				}
			}
		} else if (a.constructor === BigInt) {
			return a;
		} else if (a.constructor === Number) {
			return BigInt(a*1000000000000000000);
		}
	}
	this.Zeros = "0".repeat(256);
	this.amountToString = function(am) {
		if (am >= 0) {
			return (am/1000000000000000000n).toString()+"."+(self.Zeros+(am%1000000000000000000n).toString()).slice(-18);
		} else {
			am = -am;
			return "-"+(am/1000000000000000000n).toString()+"."+(self.Zeros+(am%1000000000000000000n).toString()).slice(-18);
		}
	}
    this.AES256Enc = function(msg,key) {
        var cipher = crypto.createCipheriv('aes-256-ecb', Buffer.from(key), null);
        return Buffer.concat([cipher.update(msg),cipher.final()]);
    }
    this.AES256Dec = function(msg,key) {
        var cipher = crypto.createDecipheriv('aes-256-ecb', Buffer.from(key), null);
        return Buffer.concat([cipher.update(msg),cipher.final()]);
    }
    this.encryptedMessage = function(msg) {
        this.EncryptedMessage = null;
        this.adressEncrypt = function(adres) {
            var keys = self.crypt.secp256k1.encryptWithPublicKey(adres);
            this.EncryptedMessage = {
                Message:self.AES256Enc(msg,keys.SharedKey),
                Key:keys.PublicKey,
                To:adres
            };
        }
        this.arrayBuffer = function() {
            if (this.EncryptedMessage) {
                var key = self.crypt.bigIntToBuffer(BigInt(this.EncryptedMessage.Key));
                var arr = new Uint8Array(34+key.length+this.EncryptedMessage.Message.length);
                var adrs = self.crypt.bigIntToBuffer(BigInt(this.EncryptedMessage.To));
                arr.set(adrs,33-adrs.length);
                arr[33] = key.length;
                arr.set(key,34);
                arr.set(this.EncryptedMessage.Message,34+key.length);
                return arr;
            }
        }
    }
    this.parseEncryptedMessage = function(bfr) {
        var len = bfr[33]+34;
        return {
            Message: bfr.slice(len),
            Key: "0x"+self.crypt.bufferToBigInt(bfr.slice(34,len)).toString(16),
            To: "0x"+self.crypt.bufferToBigInt(bfr.slice(0,33)).toString(16)
        };
    }
    this.decryptMessage = function(msg,sk) {
        if (!sk) {
            sk = PrivateKey;
        }
        var key = self.crypt.secp256k1.decryptWithPrivateKey(msg.Key,sk);
        return self.AES256Dec(msg.Message,key);
    }
    this.getFolderSizeSync = function(path) {
        var size = 0;
        path = path.endsWith("/") ? path : path+"/";
        var files = fs.readdirSync(path);
        for (var i=0; i<files.length; i++) {
            var fileName = files[i];
            var FilePath = path+fileName;
            var stats = fs.statSync(FilePath);
            if (stats.isDirectory()) {
                size += self.getFolderSizeSync(FilePath);
            } else {
                size += stats.size;
            }
        }
        return {
            bytes:size,
            KB:size/1024,
            MB:size/1048576,
            GB:size/1073741824,
            TB:size/1099511627776
        };
    }
    this.parseStorageSize = function(stsize) {
        if (stsize.endsWith("KB")) {
            return parseFloat(stsize)*1024;
        } else if (stsize.endsWith("MB")) {
            return parseFloat(stsize)*1048576;
        } else if (stsize.endsWith("GB")) {
            return parseFloat(stsize)*1073741824;
        } else if (stsize.endsWith("TB")) {
            return parseFloat(stsize)*1099511627776;
        } else {
            return parseInt(stsize);
        }
    }
    this.MaxDataFolderSize = this.parseStorageSize(ops.MaxDataSize || "16GB");
    this.parseAgreementChainStream = function(dataStream,callback) {
        var Tree = [];
        var currentData = Buffer.alloc(0);
        var len = 0;
        var lenlen = 0;
        var step = 0;
        dataStream.on('data',function(data){
            currentData = Buffer.concat([currentData,data]);
            while (true) {
                if (step === 0) {
                    if (currentData.length >= 1) {
                        lenlen = currentData[0];
                        currentData = currentData.subarray(1);
                        step = 1;
                    } else {
                        break;
                    }
                } else if (step === 1) {
                    if (currentData.length >= lenlen) {
                        len = Number(self.crypt.bufferToBigInt(currentData.subarray(0,lenlen)));
                        currentData = currentData.subarray(lenlen);
                        step = 2;
                    } else {
                        break;
                    }
                } else if (step === 2) {
                    if (currentData.length >= len) {
                        if (currentData[0] == 128) {
                            var Txn = self.parseSignedTx(currentData.subarray(1,len));
                            Tree.push(Txn);
                        } else if (currentData[0] == 129) {
                            var Txn = self.parseProofOfAgreement(currentData.subarray(1,len));
                            Tree.push(Txn);
                        } else if (currentData[0] == 130) {
                            var Txn = self.parseEncryptedMessage(currentData.subarray(1,len));
                            Tree.push(Txn);
                        } else if (currentData[0] == 131) {
                            var Txn = self.parseContract(currentData.subarray(1,len));
                            Tree.push(Txn);
                        }
                        currentData = currentData.subarray(len);
                        step = 0;
                    } else {
                        break;
                    }
                }
            }
        });
        dataStream.on('end',function(){
            callback(Tree);
        });
    }
    this.write = function(data,adress) {
        var lenarr = [];
        var len = data.length;
        while (len) {
            lenarr.push(len&255);
            len >>= 8;
        }
        lenarr.unshift(lenarr.length);
        var writeStream = fs.createWriteStream(self.filePath+adress,{flags:'a'});
        writeStream.end(Buffer.concat([Buffer.from(lenarr),data]));
    }
    this.clear = function(data,adress) {
        var lenarr = [];
        var len = data.length;
        while (len) {
            lenarr.push(len&255);
            len >>= 8;
        }
        lenarr.unshift(lenarr.length);
        var writeStream = fs.createWriteStream(self.filePath+adress);
        writeStream.end(Buffer.concat([Buffer.from(lenarr),data]));
    }
    this.proofOfAgreement = function(value,adres,callback) {
        if (!PrivateKey) {
            throw new Error("No private key supplied, add a PrivateKey value in the config for new KryptCoin(config)");
        }
        var path = self.filePath+adres;
        if (!fs.existsSync(path)) {
            callback(Buffer.alloc(0));
            return;
        }
        var hash = new self.crypt.Hash.Keccak(384, [1, 256, 65536, 16777216], 384);
        hash.update(value);
        var dataStream = fs.createReadStream(path);
        dataStream.on('data',function(data){
            hash.update(data);
        });
        dataStream.on('end',function(data){
            var digest = hash.arrayBuffer();
            var sk = self.crypt.bufferToBigInt(digest);
            var TimeArr = self.crypt.bigIntToBuffer(BigInt(new Date().valueOf()));
            var ad = self.crypt.bigIntToBuffer(BigInt(self.Adress));
            var ad2 = self.crypt.bigIntToBuffer(BigInt(adres));
            var msg = new Uint8Array(82+value.length);
            msg.set(ad,33-ad.length);
            msg.set(ad2,66-ad2.length);
            msg.set(TimeArr,82-TimeArr.length);
            msg.set(value,82);
            var PoA = self.crypt.SignedMessageToBuffer(self.crypt.secp384r1.sign(msg,sk));
            callback(PoA);
        });
    }
    this.parseProofOfAgreement = function(data) {
        var s = self.crypt.BufferToSignedMessage(data);
        var adr = "0x"+self.crypt.bufferToBigInt(s.Message.subarray(0,33)).toString(16);
        var adr2 = "0x"+self.crypt.bufferToBigInt(s.Message.subarray(33,66)).toString(16);
        var time = new Date(Number(self.crypt.bufferToBigInt(s.Message.subarray(66,82))));
        var value = s.Message.subarray(82);
        return {
            Message:s.Message,
            Signiture:s.Signiture,
            FromAdress:adr,
            Time:time,
            ValidationAdress:adr2,
            Value:value,
        };
    }
    this.verifyProofOfAgreement = function(ParsedPok,callback) {
        var path = self.filePath+ParsedPok.ValidationAdress;
        if (!fs.existsSync(path) || ParsedPok.Time > new Date()) {
            ParsedPok.Valid = false;
            callback(ParsedPok);
            return;
        }
        var hash = new self.crypt.Hash.Keccak(384, [1, 256, 65536, 16777216], 384);
        hash.update(ParsedPok.Value);
        var dataStream = fs.createReadStream(path);
        dataStream.on('data',function(data){
            hash.update(data);
        });
        dataStream.on('end',function(data){
            var digest = hash.arrayBuffer();
            var pk = self.crypt.secp384r1.getPublicKey(self.crypt.bufferToBigInt(digest));
            ParsedPok.Valid = self.crypt.secp384r1.verify(ParsedPok,pk);
            callback(ParsedPok);
        });
    }
    this.broadcast = function(typ,data) {
        var bdata = Buffer.concat([Buffer.from([(typ&127)+128]),data]);
        var peers = Object.values(this.Peers);
        for (var i=0; i<peers.length; i++) {
            peers[i].send(bdata);
        }
    }
    this.PeerServer = undefined;
    this.Peers = {};
    this.Peer = function(connection,ID,IP) {
        var thisPeer = this;
        this.Connection = connection;
        this.Adress = null;
        this.ID = ID;
        this.IP = IP;
        this.VerifyValue = self.crypt.randomBytes(48);
        this.ProtocallStep = 0;
        this.verifyProofOfAgreementCallback = null;
        this.verifyProofOfAgreement = function(adrs,callback) {
            thisPeer.verifyProofOfAgreementCallback = callback;
            self.proofOfAgreement(thisPeer.VerifyValue,adrs,function(proof){
                thisPeer.Connection.write(Buffer.concat([Buffer.from([2]),proof]));
            })
        }
        this.send = function(data) {
            thisPeer.Connection.write(data);
        }
    }
    this.connectToPeer = function(IPadress,callback) {
        if (!PrivateKey) {
            throw new Error("No private key supplied, add a PrivateKey value in the config for new KryptCoin(config)");
        }
        var callbackcalled = false;
        var PeerID = null;
        var req = net.connect({port: 8343, host: IPadress},function(){
            PeerID = IPadress+":"+req.localPort;
            self.Peers[PeerID] = new self.Peer(req,PeerID,IPadress);
            req.write(Buffer.concat([Buffer.from([0]),self.Peers[PeerID].VerifyValue]));
        });
        req.on('data',function(data){
            var response = self.PeerProtocall(data,self.Peers[PeerID],function(resp){
                req.write(resp);
            });
            if (response) {
                req.write(response);
            } else {
                if (self.Peers[PeerID].ProtocallStep === 2) {
                    if (!callbackcalled) {
                        callbackcalled = true;
                        setTimeout(function(){
                            callback(self.Peers[PeerID]);
                        },1000);
                    }
                }
            }
        });
        req.on('end',function(){
            delete self.Peers[IPadress+":"+req.localPort];
        });
    }
    this.PeerProtocall = function(data,peer,callback) {
        if (data[0] === 0) {
            data = data.slice(1);
            var result = Buffer.concat([Buffer.from([1]),self.crypt.bigIntToBuffer(BigInt(self.crypt.secp256k1.sign(data,PrivateKey).Signiture))]);
            peer.ProtocallStep = 1;
            return result;
        } else if (data[0] === 1) {
            data = data.slice(1);
            var Signiture = {
                Message:peer.VerifyValue,
                Signiture:"0x"+self.crypt.bufferToBigInt(data).toString(16)
            };
            peer.ProtocallStep = 2;
            peer.Adress = self.crypt.secp256k1.toAdress(self.crypt.secp256k1.recoverPublicKey(Signiture));
            console.log("New Peer Identified");
            console.log(peer.ID+" : "+peer.Adress);
        } else if (data[0] === 2) {
            data = data.slice(1);
            peer.ProtocallStep = 3;
            var ProofOfAgreement = self.parseProofOfAgreement(data);
            self.verifyProofOfAgreement(ProofOfAgreement,function(proof){
                if (proof.Valid) {
                    var bfrdata = Buffer.concat([Buffer.from([129]),data]);
                    self.write(bfrdata,proof.FromAdress);
                    self.proofOfAgreement(proof.Value,proof.ValidationAdress,function(proof2){
                        bfrdata = Buffer.concat([Buffer.from([129]),proof2]);
                        self.write(bfrdata,self.Adress);
                        callback(Buffer.concat([Buffer.from([3]),proof2]));
                    });
                } else {
                    callback(Buffer.from([3]));
                }
            })
        } else if (data[0] === 3) {
            data = data.slice(1);
            if (data.length <= 0) {
                console.log("Invalid Proof of Agreement receved");
            } else {
                var ProofOfAgreement = self.parseProofOfAgreement(data);
                if (self.crypt.bufferToBigInt(peer.VerifyValue) !== self.crypt.bufferToBigInt(ProofOfAgreement.Value)) {
                    console.log("Invalid Proof of Agreement receved");
                } else {
                    self.verifyProofOfAgreement(ProofOfAgreement,function(proof){
                        if (proof.Valid && peer.verifyProofOfAgreementCallback instanceof Function) {
                            peer.verifyProofOfAgreementCallback(ProofOfAgreement);
                            peer.verifyProofOfAgreementCallback = undefined;
                        }
                    });
                }
            }
        } else if (data[0] >= 128) {
            if (data[0] == 128) {
                var Txn = self.parseSignedTx(data.slice(1));
                self.write(data,Txn.To);
                self.clear(data,Txn.From);
            }
        }
    }
    this.StartPeerService = function() {
        if (self.PeerServer) {
            throw new Error("Server already started!");
        } else {
            self.PeerServer = net.createServer({allowHalfOpen:true},function(socket){
                var IP = socket.remoteAddress.replaceAll("::ffff:","");
                var PeerID = IP+":"+socket.remotePort;
                self.Peers[PeerID] = new self.Peer(socket,PeerID,IP);
                setTimeout(function(){
                    socket.write(Buffer.concat([Buffer.from([0]),self.Peers[PeerID].VerifyValue]));
                },1000);
                socket.on('data',function(data){
                    var response = self.PeerProtocall(data,self.Peers[PeerID],function(resp){
                        socket.write(resp);
                    });
                    if (response) {
                        socket.write(response);
                    }
                });
                socket.on('end',function(){
                    delete self.Peers[PeerID];
                });
            })
            self.PeerServer.listen(8343,function(err){
                if (err) {
                    throw new Error("Error starting Server");
                }
            })
        }
    }
    this.scanInternetForPeers = function(noScanIPs,callback) {
        var found = [];
        var count = 0;
        var tried = 0;
        var callbackNotFired = true;
        var loop = setInterval(function(){
            count++;
            if (count >= 65535) {
                console.log("Done pinging! waiting for pending pings to come back...");
                clearInterval(loop);
            }
            // var ip = [70,92,count&255,(count>>8)&255].join(".");
            var ip = [70,92,(count>>8)&255,count&255].join(".");
            var connected = false;
            var req = net.connect({port: 8343, host: ip},function(){
                found.push(ip);
                connected = true;
                tried++;
                req.end();
                delete req;
            });
            req.on('error',function(){});
            setTimeout(function(){
                if (!connected) {
                    req.end();
                    delete req;
                    tried++;
                }
                if (tried%500 === 0) {
                    // console.log((tried/4294967296).toFixed(3)+"%");
                    console.clear();
                    console.log((tried/655.35).toFixed(3)+"%");
                    console.log("Count: "+count.toString());
                    console.log("Tries: "+tried.toString());
                    console.log("Sucsesses: "+found.length.toString());
                    console.log("Sucsess Ratio: "+((found.length*100)/tried).toFixed(3)+"%");
                    console.log("Current IP: "+ip);
                }
                // if (tried >= 4294967296) {
                if (tried >= 65535 && callbackNotFired) {
                    callbackNotFired = false;
                    callback(found);
                }
            },500);
        },2);
    }
    this.StopPeerService = function() {
        if (self.PeerServer) {
            self.PeerServer.close();
            self.PeerServer = undefined;
        } else {
            throw new Error("Server already closed!");
        }
    }
}
if (typeof window === 'undefined') {
	module.exports = KryptCoin;
}