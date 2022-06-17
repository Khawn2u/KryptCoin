var fs = require("fs");
var net = require("net");
// var Crypt = require("/home/pi/Desktop/khawn2u-crypt/index.js");
var Crypt = require("khawn2u-crypt");
var KryptCoin = function(ops) {
    var self = this;
    this.crypt = new Crypt();
    var PrivateKey = undefined;
    if (ops.PrivateKey) {
        PrivateKey = BigInt(ops.PrivateKey);
        this.PublicKey = this.crypt.PublicPrameters.getPublicKey(PrivateKey);
        this.Adress = this.crypt.PublicPrameters.toAdress(this.PublicKey);
    }
    /*
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
                this.Drafter = self.crypt.PublicPrameters.toAdress(self.crypt.PublicPrameters.getPublicKey(sk));
                var adFrom = self.crypt.bigIntToBuffer(BigInt(this.Drafter));
                this.UnsignedContract.set(adFrom,33-adFrom.length);
                this.SignedContract = self.crypt.SignedMessageToBuffer(self.crypt.PublicPrameters.sign(this.UnsignedContract,sk));
                return this.SignedContract;
            } else {
                if (PrivateKey) {
                    this.Drafter = self.Adress;
                    var adFrom = self.crypt.bigIntToBuffer(BigInt(this.Drafter));
                    this.UnsignedContract.set(adFrom,33-adFrom.length);
                    this.SignedContract = self.crypt.SignedMessageToBuffer(self.crypt.PublicPrameters.sign(this.UnsignedContract,PrivateKey));
                    return this.SignedContract;
                } else {
                    throw new Error("No private key supplied, try adding a PrivateKey value in the config for new KryptCoin(config)");
                }
            }
        }
    }
    */
    this.filePath = ops.DataFilePath.endsWith("/") ? ops.DataFilePath : ops.DataFilePath+"/";
    this.UserTransactionTrees = {};
    fs.readdir(this.filePath,function(error,files){
        for (var i=0; i<files.length; i++) {
            var fileName = files[i];
            if (fileName.startsWith("0x")) {
                var TreeFilePath = self.filePath+fileName;
                self.parseTransactionTreeStream(fs.createReadStream(TreeFilePath),function(tre){
                    self.UserTransactionTrees[fileName] = tre;
                });
            } else if (fileName.startsWith("_0x")) {
                
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
                this.Signiture = self.crypt.PublicPrameters.sign(this.UnsignedTx,sk);
                this.SignedTx = self.crypt.SignedMessageToBuffer(this.Signiture);
                this.From = self.crypt.PublicPrameters.toAdress(self.crypt.PublicPrameters.getPublicKey(sk));
                return this.SignedTx;
            } else {
                if (PrivateKey) {
                    this.Signiture = self.crypt.PublicPrameters.sign(this.UnsignedTx,PrivateKey);
                    this.SignedTx = self.crypt.SignedMessageToBuffer(this.Signiture);
                    this.From = self.crypt.PublicPrameters.toAdress(self.crypt.PublicPrameters.getPublicKey(PrivateKey));
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
		Tx.From = self.crypt.PublicPrameters.toAdress(self.crypt.PublicPrameters.recoverPublicKey(SignedTx));
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
        return size;
    }
    this.parseTransactionTreeStream = function(dataStream,callback) {
        var Tree = [];
        var currentData = Buffer.alloc(0);
        var len = 0;
        var step = true;
        dataStream.on('data',function(data){
            currentData = Buffer.concat([currentData,data]);
            while (true) {
                if (step) {
                    if (currentData.length >= 2) {
                        len = currentData[0]+(currentData[1]*256);
                        currentData = currentData.subarray(2);
                        step = false;
                    } else {
                        break;
                    }
                } else {
                    if (currentData.length >= len) {
                        var Txn = self.parseSignedTx(currentData.subarray(0,len));
                        Tree.push(Txn);
                        currentData = currentData.subarray(len);
                        step = true;
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
    this.proofOfKnowledge = function(value,adres,callback) {
        if (!PrivateKey) {
            throw new Error("No private key supplied, add a PrivateKey value in the config for new KryptCoin(config)");
        }
        var path = self.filePath+adres;
        if (!fs.existsSync(path)) {
            callback(Buffer.alloc(0));
            return;
        }
        var hash = new self.crypt.Hash.Keccak(256, [1, 256, 65536, 16777216], 256);
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
            var PoK = self.crypt.SignedMessageToBuffer(self.crypt.PublicPrameters.sign(msg,sk));
            callback(PoK);
        });
    }
    this.parseProofOfKnowledge = function(data) {
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
    this.verifyProofOfKnowledge = function(ParsedPok,callback) {
        var path = self.filePath+ParsedPok.ValidationAdress;
        if (!fs.existsSync(path) || ParsedPok.Time > new Date()) {
            ParsedPok.Valid = false;
            callback(ParsedPok);
            return;
        }
        var hash = new self.crypt.Hash.Keccak(256, [1, 256, 65536, 16777216], 256);
        hash.update(ParsedPok.Value);
        var dataStream = fs.createReadStream(path);
        dataStream.on('data',function(data){
            hash.update(data);
        });
        dataStream.on('end',function(data){
            var digest = hash.arrayBuffer();
            var pk = self.crypt.PublicPrameters.getPublicKey(self.crypt.bufferToBigInt(digest));
            ParsedPok.Valid = self.crypt.PublicPrameters.verify(ParsedPok,pk);
            callback(ParsedPok);
        });
    }






    /*
    this.PeerServer = undefined;
    this.Peers = {};
    this.StartPeerService = function() {
        if (self.PeerServer) {
            throw new Error("Server already started!");
        } else {
            self.PeerServer = net.createServer(function(socket){
                self.Peers[socket.remoteAddress+":"+socket.remotePort] = socket;
                socket.on('data',function(data){
                    console.log(data);
                });
                socket.on('end',function(){
                    delete self.Peers[socket.remoteAddress+":"+socket.remotePort];
                });
            })
            self.PeerServer.listen(8343,function(err){
                if (err) {
                    throw new Error("Error starting Server");
                }
                var adress = self.PeerServer.address();
                console.log("Lisining at: "+adress.address+":"+adress.port);
            })
        }
    }
    this.StopPeerService = function() {
        if (self.PeerServer) {
            self.PeerServer.close();
            self.PeerServer = undefined;
        } else {
            throw new Error("Server already closed!");
        }
    }
    */
}
if (typeof window === 'undefined') {
	module.exports = KryptCoin;
}