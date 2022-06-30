var os = require("os");
var fs = require("fs");
var net = require("net");
var http = require("http");
var dgram = require("dgram");
var crypto = require("crypto");
var cluster = require("cluster");
var Crypt = require("khawn2u-crypt");
var child_process = require("child_process");
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
        var data = U8array;
        var Signed = [];
        while (data[0]) {
            var signiture = self.crypt.BufferToSignedMessage(data);
            var Addr = self.crypt.secp256k1.toAdress(self.crypt.secp256k1.recoverPublicKey(signiture));
            Signed.push(Addr);
            data = signiture.Message;
        }
        data = data.subarray(1);
        var len = data[0]+1;
        var date = new Date(Number(self.crypt.bufferToBigInt(data.subarray(1,len))));
        data = data.subarray(len);
        var Terms = [];
        while (data.length) {
            var Addr = "0x"+self.crypt.bufferToBigInt(data.subarray(0,33)).toString(16);
            data = data.subarray(33);
            len = data[0]+1;
            var am = self.crypt.bufferToBigInt(data.subarray(1,len));
            if (am&1n) {
                am = -(am>>1n);
            } else {
                am >>= 1n;
            }
            data = data.subarray(len);
            len = data[0]+1;
            var st = Number(self.crypt.bufferToBigInt(data.subarray(1,len)));
            data = data.subarray(len);
            Terms.push({
                Adress: Addr,
                Payment: am,
                Storage: st,
                Signed: Signed.includes(Addr),
            });
        }
        return {
            Date:date,
            Terms:Terms,
            arrayBuffer:U8array,
            Standard:"KC-131"
        }
    }
    this.contract = function(FulfillmentDate,Terms) {
        this.FulfillmentDate = FulfillmentDate;
        this.Fulfilled = false;
        this.Terms = Terms;
        this.SignedContract = undefined;
        var arr = self.crypt.bigIntToBuffer(BigInt(this.FulfillmentDate.valueOf()));
        this.UnsignedContract = [0,arr.length,Array.from(arr)];
        for (var i=0; i<this.Terms.length; i++) {
            var adBfr = new Uint8Array(33);
            var adTo = self.crypt.bigIntToBuffer(BigInt(this.Terms[i].Adress));
            adBfr.set(adTo,33-adTo.length);
            this.UnsignedContract.push(Array.from(adBfr));
            if (this.Terms[i].Payment < 0) {
                var Amount = ((-this.Terms[i].Payment)<<1n)|1n;
                var am = self.crypt.bigIntToBuffer(Amount);
                this.UnsignedContract.push(am.length);
                this.UnsignedContract.push(Array.from(am));
            } else {
                var Amount = this.Terms[i].Payment<<1n;
                var am = self.crypt.bigIntToBuffer(Amount);
                this.UnsignedContract.push(am.length);
                this.UnsignedContract.push(Array.from(am));
            }
            var st = self.crypt.bigIntToBuffer(BigInt(this.Terms[i].Storage));
            this.UnsignedContract.push(st.length);
            this.UnsignedContract.push(Array.from(st));
        }
        this.UnsignedContract = new Uint8Array(this.UnsignedContract.flat());
        this.sign = function(sk) {
            if (sk) {
                this.SignedContract = self.crypt.SignedMessageToBuffer(self.crypt.secp256k1.sign(this.UnsignedContract,sk));
                return this.SignedContract;
            } else {
                if (PrivateKey) {
                    this.SignedContract = self.crypt.SignedMessageToBuffer(self.crypt.secp256k1.sign(this.UnsignedContract,PrivateKey));
                    return this.SignedContract;
                } else {
                    throw new Error("No private key supplied, try adding a PrivateKey value in the config for new KryptCoin(config)");
                }
            }
        }
    }
    this.signBuffer = function(msg,sk) {
        if (sk) {
            return self.crypt.SignedMessageToBuffer(self.crypt.secp256k1.sign(msg,sk));
        } else {
            if (PrivateKey) {
                return self.crypt.SignedMessageToBuffer(self.crypt.secp256k1.sign(msg,PrivateKey));
            } else {
                throw new Error("No private key supplied, try adding a PrivateKey value in the config for new KryptCoin(config)");
            }
        }
    }
    this.filePath = ops.DataFilePath.endsWith("/") ? ops.DataFilePath : ops.DataFilePath+"/";
    this.Tx = function(sendAdress,Nonce,Amount,Fee,Change) {
		this.To = sendAdress;
		this.From = null;
		this.Amount = Amount;
		this.Fee = Fee;
		this.Change = Change;
		this.Nonce = BigInt(Nonce);
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
		var Id = Number(self.crypt.bufferToBigInt(buff.subarray(idx,idx+len)));
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
            arrayBuffer:buff,
			To:To,
			Fee:{RawTokenAmount:Fe,Value:Number(Fe)/1000000000000000000},
			Amount:{RawTokenAmount:Am,Value:Number(Am)/1000000000000000000},
			Change:{RawTokenAmount:Ch,Value:Number(Ch)/1000000000000000000},
			Nonce:Id,
            Standard:"KC-128"
		}
	}
	this.parseSignedTx = function(buff) {
        var SignedTx = self.crypt.BufferToSignedMessage(buff);
        var Tx = self.parseTx(SignedTx.Message);
        Tx.From = self.crypt.secp256k1.toAdress(self.crypt.secp256k1.recoverPublicKey(SignedTx));
        Tx.arrayBuffer = buff;
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
    this.findBalence = function(adrs,callback) {
        var Bal = 0n;
        var Bal2 = 0n;
        var lastDate = false;
        self.readData(adrs,function(bl){
            if (bl.Standard == "KC-128") {
                if (bl.To == adrs) {
                    Bal += bl.Amount.RawTokenAmount;
                }
                if (bl.From == adrs) {
                    Bal -= bl.Amount.RawTokenAmount+bl.Fee.RawTokenAmount;
                }
            } else if (bl.Standard == "KC-130") {
                if (!lastDate || bl.Time == lastDate) {
                    lastDate = bl.Time;
                } else {
                    Bal += BigInt(bl.Time-lastDate)*2500000000000n;
                    lastDate = bl.Time;
                }
            }
        },function(){
            if (lastDate) {
                Bal2 = Bal+BigInt((new Date())-lastDate)*2500000000000n;
            }
            callback(Bal,Bal2,lastDate);
        },["KC-128","KC-130"]);
    }
    this.verifyTx = function(Txn,callback) {
        var path = self.filePath+Txn.From;
        if (!fs.existsSync(path)) {
            callback(false);
            return;
        }
        self.parseStream(fs.createReadStream(path),function(block){
            console.log(block);
        });
    }
    this.AES256Enc = function(msg,key) {
        var cipher = crypto.createCipheriv('aes-256-ecb', Buffer.from(key), null);
        return Buffer.concat([cipher.update(msg),cipher.final()]);
    }
    this.AES256Dec = function(msg,key) {
        var cipher = crypto.createDecipheriv('aes-256-ecb', Buffer.from(key), null);
        return Buffer.concat([cipher.update(msg),cipher.final()]);
    }
    this.AES256EncStream = function(strm,key) {
        var cipher = crypto.createCipheriv('aes-256-ecb', Buffer.from(key), null);
        strm.pipe(cipher);
        return cipher;
    }
    this.AES256DecStream = function(strm,key) {
        var cipher = crypto.createDecipheriv('aes-256-ecb', Buffer.from(key), null);
        strm.pipe(cipher);
        return cipher;
    }
    this.encryptedMessage = function(msg) {
        this.EncryptedMessage = null;
        this.encryptWithAdress = function(adres) {
            var keys = self.crypt.secp256k1.encryptWithPublicKey(adres);
            this.EncryptedMessage = {
                Message:self.AES256Enc(msg,keys.SharedKey),
                Key:keys.PublicKey,
                To:adres,
                Standard: "KC-129"
            };
            return this;
        }
        this.sign = function(sk) {
            if (this.EncryptedMessage) {
                var key = self.crypt.bigIntToBuffer(BigInt(this.EncryptedMessage.Key));
                var arr = new Uint8Array(34+key.length+this.EncryptedMessage.Message.length);
                var adrs = self.crypt.bigIntToBuffer(BigInt(this.EncryptedMessage.To));
                arr.set(adrs,33-adrs.length);
                arr[33] = key.length;
                arr.set(key,34);
                arr.set(this.EncryptedMessage.Message,34+key.length);
                if (!sk) {
                    sk = PrivateKey;
                }
                this.EncryptedMessage.arrayBuffer = self.signBuffer(arr,sk);
                return this.EncryptedMessage;
            }
        }
    }
    this.parseEncryptedMessage = function(msgbfr) {
        var signiture = self.crypt.BufferToSignedMessage(msgbfr);
        var from = self.crypt.secp256k1.toAdress(self.crypt.secp256k1.recoverPublicKey(signiture));
        var bfr = signiture.Message;
        var len = bfr[33]+34;
        return {
            arrayBuffer:msgbfr,
            Message: bfr.slice(len),
            Key: "0x"+self.crypt.bufferToBigInt(bfr.slice(34,len)).toString(16),
            To: "0x"+self.crypt.bufferToBigInt(bfr.slice(0,33)).toString(16),
            From: from,
            Standard:"KC-129"
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
                size += self.getFolderSizeSync(FilePath).bytes;
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
    this.parseAny = function(type,data) {
        type = ((type&127)|128);
        if (type == 128) {
            var Txn = self.parseSignedTx(data);
            return Txn;
        } else if (type == 129) {
            var Message = self.parseEncryptedMessage(data);
            // if (Message.To == self.Adress) {
            //     Message.DecrypedMessage = self.decryptMessage(Message).toString('utf-8');
            // }
            return Message;
        } else if (type == 130) {
            return self.parseProofOfAgreement(data);
        } else if (type == 131) {
            return self.parseContract(data);
        }
    }
    this.getDataSync = function(addrs,type,ID) {
        var path = self.filePath+addrs+"/KC-"+((type&127)|128).toString()+"/#"+ID;
        if (fs.existsSync(path)) {
            return fs.readFileSync(path);
        } else {
            return null;
        }
    }
    this.readData = function(adrs,BlockCallback,EndCallback,limitStandard) {
        var path = self.filePath+adrs+"/index";
        if (!fs.existsSync(path)) {
            if (EndCallback) {
                EndCallback();
            }
            return;
        }
        var fstream = fs.createReadStream(path);
        var leftover = Buffer.alloc(0);
        fstream.on('data',function(data){
            leftover = Buffer.concat([leftover,data]);
            if (limitStandard) {
                while (leftover.length > 33) {
                    if (limitStandard.includes("KC-"+leftover[0].toString())) {
                        var d = self.getDataSync(adrs,leftover[0]&127,self.crypt.toHex(leftover.subarray(1,33)));
                        if (d) {
                            BlockCallback(self.parseAny(leftover[0]&127,d));
                        } else {
                            throw new Error("ERROR Missing Data");
                        }
                    }
                    leftover = leftover.subarray(33);
                }
            } else {
                while (leftover.length > 33) {
                    var d = self.getDataSync(adrs,leftover[0]&127,self.crypt.toHex(leftover.subarray(1,33)));
                    if (d) {
                        BlockCallback(self.parseAny(leftover[0]&127,d));
                    } else {
                        throw new Error("ERROR Missing Data");
                    }
                    leftover = leftover.subarray(33);
                }
            }
        });
        fstream.on('end',function(){
            if (EndCallback) {
                EndCallback();
            }
        });
    }
    this.write = function(type,data,adress) {
        var Hash = self.crypt.Keccak256(data);
        var ID = self.crypt.toHex(Hash);
        var path = self.filePath+adress;
        if (!fs.existsSync(path)) {
            fs.mkdirSync(path);
        }
        fs.appendFile(path+"/index",Buffer.concat([Buffer.from([((type&127)|128)]),Hash]),function(err){
            if (err) {
                console.log(err);
            }
        });
        path += "/KC-"+((type&127)|128).toString();
        if (!fs.existsSync(path)) {
            fs.mkdirSync(path);
        }
        path += "/#"+ID;
        if (fs.existsSync(path)) {
            return ID;
        }
        fs.writeFile(path,data,function(err){
            if (err) {
                console.log(err);
            }
        });
    }
    this.delete = function(type,ID,adress) {
        var path = self.filePath+adress+"/KC-"+((type&127)|128).toString()+"/"+ID;
        fs.unlink(path,function(err){
            if (err) {
                console.log(err);
            }
        });
    }
    this.addAdress = function(adress) {
        var path = self.filePath+adress;
        if (!fs.existsSync(path)) {
            fs.mkdirSync(path);
        }
    }
    this.proofOfAgreement = function(value,adres,callback) {
        if (!PrivateKey) {
            throw new Error("No private key supplied, add a PrivateKey value in the config for new KryptCoin(config)");
        }
        var path = self.filePath+adres+"/index";
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
            ArrayBuffer: data,
            Message:s.Message,
            Signiture:s.Signiture,
            FromAdress:adr,
            Time:time,
            ValidationAdress:adr2,
            Value:value,
            Standard:"KC-130"
        };
    }
    this.verifyProofOfAgreement = function(ParsedPok,callback) {
        var path = self.filePath+ParsedPok.ValidationAdress+"/index";
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
        var d = Buffer.concat([Buffer.from([(typ&127)+128]),data]);
        var bdata = self.padBuffer(d);
        var peers = Object.values(this.Peers);
        for (var i=0; i<peers.length; i++) {
            peers[i].Connection.write(bdata);
        }
    }
    this.broadcastStream = function(type,addr,stream,adder) {
        var RandID = self.crypt.randomBytes(32);
        var header = Buffer.alloc(68);
        header[0] = 4;
        var ad = self.crypt.bigIntToBuffer(BigInt(addr));
        header.set(ad,34-ad.length);
        header[35] = (type&127)|128;
        header.set(RandID,36);
        header = self.padBuffer(Buffer.concat([header,adder]));
        var peers = Object.values(self.Peers);
        for (var i=0; i<peers.length; i++) {
            peers[i].Connection.write(header);
        }
        header = Buffer.alloc(33);
        header[0] = 5;
        header.set(RandID,1);
        stream.on('data',function(data){
            data = self.padBuffer(Buffer.concat([header,data]));
            for (var i=0; i<peers.length; i++) {
                peers[i].Connection.write(data);
            }
        });
        stream.on('end',function(){
            var data = self.padBuffer(header);
            for (var i=0; i<peers.length; i++) {
                peers[i].Connection.write(data);
            }
        });
    }
    this.PeerServer = undefined;
    this.Peers = {};
    this.Peer = function(connection,ID,IP) {
        var thisPeer = this;
        this.Connection = connection;
        this.Adress = null;
        this.ID = ID;
        this.IP = IP;
        this.VerifyValue = self.crypt.randomBytes(32);
        this.ProtocallStep = 0;
        this.verifyProofOfAgreementCallback = null;
        this.verifyProofOfAgreement = function(adrs,callback) {
            thisPeer.verifyProofOfAgreementCallback = callback;
            self.proofOfAgreement(thisPeer.VerifyValue,adrs,function(proof){
                thisPeer.Connection.write(self.padBuffer(Buffer.concat([Buffer.from([2]),proof])));
            });
        }
        this.send = function(data) {
            thisPeer.Connection.write(self.padBuffer(data));
        }
    }
    this.padBuffer = function(bfr) {
        var len = self.crypt.bigIntToBuffer(BigInt(bfr.length));
        return Buffer.concat([Buffer.from([len.length]),len,bfr]);
    }
    this.unpadArray = function(bfr) {
        var arr = [];
        var data = bfr;
        while (data.length) {
            var lenlen = data[0]+1;
            var len = Number(self.crypt.bufferToBigInt(data.subarray(1,lenlen)));
            arr.push(data.subarray(lenlen,lenlen+len));
            data = data.subarray(lenlen+len);
        }
        return arr;
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
            req.write(self.padBuffer(Buffer.concat([Buffer.from([0]),self.Peers[PeerID].VerifyValue])));
        });
        req.on('data',function(data){
            var response = self.PeerProtocall(data,self.Peers[PeerID],function(resp){
                req.write(self.padBuffer(resp));
            });
            if (response) {
                req.write(self.padBuffer(response));
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
    this.WritingFiles = {};
    this.PeerProtocall = function(dataa,peer,callback) {
        var arr = self.unpadArray(dataa);
        var result = undefined;
        for (var i=0; i<arr.length; i++) {
            var data = arr[i];
            if (data[0] === 0) {
                if (peer.ProtocallStep === 0) {
                    data = data.subarray(1);
                    var signval = self.crypt.secp256k1.sign(data,PrivateKey);
                    result = Buffer.concat([Buffer.from([1]),self.crypt.bigIntToBuffer(BigInt(signval.Signiture))]);
                    peer.ProtocallStep = 1;
                }
            } else if (data[0] === 1) {
                if (peer.ProtocallStep === 1) {
                    data = data.subarray(1);
                    var Signiture = {
                        Message:Buffer.from(peer.VerifyValue),
                        Signiture:"0x"+self.crypt.bufferToBigInt(data).toString(16)
                    };
                    peer.ProtocallStep = 2;
                    peer.Adress = self.crypt.secp256k1.toAdress(self.crypt.secp256k1.recoverPublicKey(Signiture));
                    console.log("New Peer Identified");
                    console.log(peer.ID+" : "+peer.Adress);
                }
            } else if (data[0] === 2) {
                data = data.subarray(1);
                peer.ProtocallStep = 3;
                var ProofOfAgreement = self.parseProofOfAgreement(data);
                self.verifyProofOfAgreement(ProofOfAgreement,function(proof){
                    if (proof.Valid) {
                        self.write(2,data,proof.ValidationAdress);
                        self.proofOfAgreement(proof.Value,proof.ValidationAdress,function(proof2){
                            callback(Buffer.concat([Buffer.from([3]),proof2]));
                        });
                    } else {
                        callback(Buffer.from([3]));
                    }
                })
            } else if (data[0] === 3) {
                data = data.subarray(1);
                if (data.length <= 0) {
                    console.log("Invalid Proof of Agreement receved");
                } else {
                    var ProofOfAgreement = self.parseProofOfAgreement(data);
                    if (self.crypt.bufferToBigInt(peer.VerifyValue) !== self.crypt.bufferToBigInt(ProofOfAgreement.Value)) {
                        console.log("Invalid Proof of Agreement receved");
                    } else {
                        self.verifyProofOfAgreement(ProofOfAgreement,function(proof){
                            if (proof.Valid && peer.verifyProofOfAgreementCallback instanceof Function) {
                                self.write(2,data,proof.FromAdress);
                                peer.verifyProofOfAgreementCallback(ProofOfAgreement);
                                peer.verifyProofOfAgreementCallback = undefined;
                            }
                        });
                    }
                }
            } else if (data[0] === 4) {
                data = data.subarray(1);
                var addr = "0x"+self.crypt.bufferToBigInt(data.subarray(0,33)).toString(16);
                var type = data[34]&127;
                var RandID = self.crypt.toHex(data.subarray(35,67));
                data = data.subarray(67);
                var path = self.filePath+addr;
                if (!fs.existsSync(path)) {
                    fs.mkdirSync(path);
                }
                path += "/KC-"+((type&127)|128).toString();
                if (!fs.existsSync(path)) {
                    fs.mkdirSync(path);
                }
                path += "/"+RandID;
                self.WritingFiles[RandID] = {
                    Hash:new self.crypt.Hash.Keccak(256, [1, 256, 65536, 16777216], 256),
                    Stream: fs.createWriteStream(path),
                    Path:path
                }
                self.WritingFiles[RandID].Stream.write(data);
                self.WritingFiles[RandID].Hash.update(data);
            } else if (data[0] === 5) {
                data = data.subarray(1);
                var RandID = self.crypt.toHex(data.subarray(0,32));
                data = data.subarray(32);
                // console.log(RandID);
                if (data.length <= 0) {
                    var Name = "#"+self.crypt.toHex(self.WritingFiles[RandID].Hash.arrayBuffer());
                    self.WritingFiles[RandID].Stream.end();
                    var newPath = self.WritingFiles[RandID].Path.replaceAll(RandID,Name);
                    fs.rename(self.WritingFiles[RandID].Path,newPath,function(err){
                        if (err) {
                            console.log(err);
                        }
                    });
                } else {
                    if (self.WritingFiles[RandID]) {
                        self.WritingFiles[RandID].Stream.write(data);
                        self.WritingFiles[RandID].Hash.update(data);
                    }
                }
            } else if (data[0] >= 128) {
                if (data[0] == 128) {
                    data = data.subarray(1);
                    var Txn = self.parseSignedTx(data);
                    console.log("Transaction Receved");
                    console.log(Txn);
                    self.write(0,data,Txn.To);
                    if (Txn.From !== Txn.To) {
                        self.write(0,data,Txn.From);
                    }
                    var webTxn = {};
                    Object.assign(webTxn,Txn);
                    webTxn.Fee = self.amountToString(webTxn.Fee.RawTokenAmount);
                    webTxn.Change = self.amountToString(webTxn.Change.RawTokenAmount);
                    webTxn.Amount = self.amountToString(webTxn.Amount.RawTokenAmount);
                    self.WebQue.push(Txn);
                } else if (data[0] == 129) {
                    data = data.subarray(1);
                    var Message = self.parseEncryptedMessage(data);
                    if (Message.To == self.Adress) {
                        Message.DecrypedMessage = self.decryptMessage(Message).toString('utf-8');
                        if (self.WebGUIServer) {
                            self.WebQue.push(Message);
                        }
                    }
                    self.write(1,data,Message.To);
                    // self.clear(data,Txn.From);
                } else if (data[0] == 130) {
                    data = data.subarray(1);
                    // var Txn = self.parse?(data.slice(1));
                    // self.write(data,Txn.To);
                    // self.clear(data,Txn.From);
                } else if (data[0] == 131) {
                    data = data.subarray(1);
                    var Contract = self.parseContract(data);
                    console.log("Contract Receved");
                    console.log(Contract);
                    var valid = Contract.Terms.map(function(term){return term.Signed}).reduce(function(a,b){return a && b});
                    console.log(valid ? "Fully Signed Contract Receved" : "Non-fully Signed Contract Receved");
                    if (valid) {
                        for (var i=0; i<Contract.Terms.length; i++) {
                            self.write(3,data,Contract.Terms[i].Adress);
                        }
                    }
                }
            }
        }
        return result;
    }
    this.UDPsocket = null;
    this.discoveredPeers = [];
    this.PublicIP = null;
    this.StartPeerService = function() {
        if (self.PeerServer) {
            throw new Error("Server already started!");
        } else {
            self.UDPsocket = dgram.createSocket("udp4");
            self.UDPsocket.on("message", function (msg, rinfo) {
                console.log("New Peer Discovered: "+rinfo.address+":"+rinfo.port);
                if (!self.discoveredPeers.includes(rinfo.address)) {
                    self.discoveredPeers.push(rinfo.address+":"+rinfo.port);
                }
            });
            self.UDPsocket.bind(8344,"224.0.32.151",function(){
                self.UDPsocket.setBroadcast(true);
                self.UDPsocket.addMembership("224.0.32.151",'0.0.0.0');
            });
            self.PeerServer = net.createServer({allowHalfOpen:true},function(socket){
                var IP = socket.remoteAddress.replaceAll("::ffff:","");
                var PeerID = IP+":"+socket.remotePort;
                self.Peers[PeerID] = new self.Peer(socket,PeerID,IP);
                socket.write(self.padBuffer(Buffer.concat([Buffer.from([0]),self.Peers[PeerID].VerifyValue])));
                socket.on('data',function(data){
                    var response = self.PeerProtocall(data,self.Peers[PeerID],function(resp){
                        socket.write(self.padBuffer(resp));
                    });
                    if (response) {
                        socket.write(self.padBuffer(response));
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
    this.comeOutToPeers = function() {
        var message = Buffer.alloc(0);
        self.UDPsocket.send(message, 0, message.length, 8344, "224.0.32.151",function(err){
            if (err) {
                console.log(err)
            }
        });
    }
    this.StopPeerService = function() {
        if (self.PeerServer) {
            self.PeerServer.close();
            self.PeerServer = undefined;
        } else {
            throw new Error("Server already closed!");
        }
    }
    this.WebGUIServer = null;
    this.WebQue = [];
    this.startWebGUI = function(port) {
        if (self.WebGUIServer) {
            throw new Error("Server already started!");
        } else {
            self.WebGUIServer = http.createServer(function(req,res){
                if (req.url.startsWith("/api/")) {
                    if (req.url.startsWith("/api/getData")) {
                        res.writeHead(200);
                        self.getData(self.Adress,function(bl){
                            if (bl.Standard == "KC-128") {
                                bl.Amount = self.amountToString(bl.Amount.RawTokenAmount);
                                bl.Fee = self.amountToString(bl.Fee.RawTokenAmount);
                                bl.Change = self.amountToString(bl.Change.RawTokenAmount);
                                bl.Nonce = Number(bl.Nonce);
                            } else if (bl.Standard == "KC-130") {
                                bl = false;
                            } else if (bl.Standard == "KC-131") {
                                for (var i=0; i<bl.Terms.length; i++) {
                                    bl.Terms[i].Payment = self.amountToString(bl.Terms[i].Payment);
                                }
                            } else if (bl.Standard == "KC-129" && bl.To == self.Adress) {
                                bl.DecrypedMessage = self.decryptMessage(bl).toString('utf-8');
                            }
                            if (bl) {
                                res.write(JSON.stringify(bl)+"\n");
                            }
                        },function(){
                            res.end();
                        });
                    } else if (req.url.startsWith("/api/getMessages")) {
                        res.writeHead(200);
                        self.getData(self.Adress,function(bl){
                            if (bl.To == self.Adress) {
                                bl.DecrypedMessage = self.decryptMessage(bl).toString('utf-8');
                            }
                            res.write(JSON.stringify(bl)+"\n");
                        },function(){
                            res.end();
                        },["KC-129"]);
                    } else if (req.url.startsWith("/api/sendMessage/0x")) {
                        var message = "";
                        req.on('data',function(data){
                            message += data;
                        });
                        req.on('end',function(){
                            var Message = new self.encryptedMessage(message);
                            var msg = Message.encryptWithAdress(req.url.slice(17)).sign().arrayBuffer;
                            self.broadcast(1,msg);
                            self.write(1,msg,req.url.slice(17));
                            res.writeHead(200);
                            res.end();
                        });
                    } else if (req.url.startsWith("/api/update")) {
                        for (var i=0; i<self.WebQue.length; i++) {
                            res.write(JSON.stringify(self.WebQue[i])+"\n");
                        }
                        self.WebQue = [];
                        res.end();
                    } else if (req.url.startsWith("/api/getUsers")) {
                        fs.readdir(self.filePath,function(err,stuff){
                            stuff = stuff.filter(function(val){return val.startsWith("0x") && val !== self.Adress});
                            res.end(JSON.stringify(stuff)+"\n");
                        });
                    } else if (req.url.startsWith("/api/addUser/0x")) {
                        self.addAdress(req.url.slice(13));
                        res.writeHead(200);
                        res.end();
                    } else if (req.url.startsWith("/api/files")) {
                        if (req.url.length <= 11) {
                            res.writeHead(200);
                            res.end(os.homedir());
                        } else {
                            var path = decodeURI(req.url.slice(11));
                            if (fs.existsSync(path)) {
                                path = path.endsWith("/") ? path : path+"/";
                                fs.readdir(path,function(err,paths){
                                    var result = "";
                                    for (var i=0; i<paths.length; i++) {
                                        // paths[i] = {Name:paths[i],File:fs.statSync(FilePath).isFile()};
                                        result += JSON.stringify({Name:paths[i],File:fs.statSync(path+paths[i]).isFile()})+"\n";
                                    }
                                    res.writeHead(200);
                                    res.end(result);
                                });
                            } else {
                                res.writeHead(404);
                                res.end();
                            }
                        }
                    } else if (req.url.startsWith("/api/uploadFile/")) {
                        var path = decodeURI(req.url.slice(16));
                        if (fs.existsSync(path)) {
                            var keys = self.crypt.secp256k1.encryptWithPublicKey(self.Adress);
                            var key = self.crypt.bigIntToBuffer(BigInt(keys.PublicKey));
                            var header = Buffer.alloc(key.length+1);
                            header[0] = key.length;
                            header.set(key,1);
                            var Stream = fs.createReadStream(path);
                            self.broadcastStream(1,self.Adress,self.AES256EncStream(Stream,keys.SharedKey),header);
                            res.writeHead(200);
                            res.end();
                        } else {
                            res.writeHead(404);
                            res.end();
                        }
                    } else {
                        res.writeHead(404);
                        res.end();
                    }
                } else {
                    var path = __dirname+"/WebGUI"+req.url;
                    if (fs.existsSync(path)) {
                        res.writeHead(200);
                        var stream = fs.createReadStream(path);
                        stream.pipe(res);
                    } else {
                        res.writeHead(404);
                        res.end();
                    }
                }
            });
            self.WebGUIServer.listen(port || 8080,'127.0.0.1');
        }
    }
    this.stopWebGUI = function() {
        if (self.WebGUIServer) {
            self.WebGUIServer.close();
            self.WebGUIServer = undefined;
        } else {
            throw new Error("Server already closed!");
        }
    }
}
if (typeof window === 'undefined') {
	module.exports = KryptCoin;
}