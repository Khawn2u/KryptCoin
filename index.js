var os = require("os");
var fs = require("fs");
var net = require("net");
var http = require("http");
var util = require('util');
var dgram = require("dgram");
var stream = require('stream');
var crypto = require("crypto");
var events = require('events');
var readline = require('readline');
var Crypt = require("khawn2u-crypt");
var DC = null;
try {
    DC = require('discovery-channel');
} catch (err) {
    console.log("Peer discovery package failed to load, although this is okay because that package is really old and I know how crappy old packages are. So I have made this package not required and KryptCoin will continue to function, just without peers, your welcome");
}
var child_process = require("child_process");
const { Stream } = require("stream");
var KryptCoin = function(ops) {
    var self = this;
    this.crypt = new Crypt();
    this.Threads = os.cpus().length*(ops.ThreadMultiplier || 1);
    this.Workers = [];
    this.WorkerCallbacks = {};
    var PrivateKey = null;
    if (ops.PrivateKey) {
        PrivateKey = BigInt(ops.PrivateKey);
        this.PublicKey = self.crypt.secp256k1.getPublicKey(PrivateKey);
        this.Adress = self.crypt.secp256k1.toAdress(this.PublicKey);
    }
    var OpsTmp = {};
    Object.assign(OpsTmp,ops);
    OpsTmp.Adress = this.Adress;
    this.CurrentWorker = 0;
    this.WorkerStreamCallbacks = {};
    for (var i=0; i<this.Threads; i++) {
        this.Workers.push(child_process.spawn("node",[__dirname+"/worker.js"],{stdio:[process.stdin, process.stdout, process.stderr, 'pipe']}));
        this.Workers[i].ioStream = this.Workers[i].stdio[3];
        this.Workers[i].ioStream.write(Buffer.from(JSON.stringify(OpsTmp),'utf-8'));
        this.Workers[i].ioStream.on('data',function(data){
            var RandID = data.subarray(0,32).toString('hex');
            // console.log(RandID)
            if (self.WorkerStreamCallbacks[RandID]) {
                if (data.length > 32) {
                    self.WorkerStreamCallbacks[RandID].push(data.slice(32));
                    // if (data.slice(-32).toString('hex') == RandID) {
                    //     self.WorkerStreamCallbacks[RandID].push(data.slice(32,-32));
                    //     self.WorkerStreamCallbacks[RandID].destroy();
                    //     delete self.WorkerStreamCallbacks[RandID];
                    // } else {
                    //     self.WorkerStreamCallbacks[RandID].push(data.slice(32));
                    // }
                } else {
                    self.WorkerStreamCallbacks[RandID].destroy();
                    delete self.WorkerStreamCallbacks[RandID];
                }
            }
        })
    }
    this.streamToWorker = function(InStream) {
        var Worker = self.Workers[self.CurrentWorker];
        self.CurrentWorker++;
        if (self.CurrentWorker >= self.Workers.length) {
            self.CurrentWorker = 0;
        }
        var RandIDBuff = crypto.randomBytes(32);
        var RandID = RandIDBuff.toString('hex');
        InStream.on('data',function(chunk) {
            Worker.ioStream.write(Buffer.concat([RandIDBuff,chunk]));
        });
        InStream.on('end',function() {
            Worker.ioStream.write(RandIDBuff);
        });
        var OutStream = new stream.Readable({read() {}});
        self.WorkerStreamCallbacks[RandID] = OutStream;
        return OutStream;
    }
    this.newWorkerStream = function() {
        var Worker = self.Workers[self.CurrentWorker];
        self.CurrentWorker++;
        if (self.CurrentWorker >= self.Workers.length) {
            self.CurrentWorker = 0;
        }
        var RandIDBuff = crypto.randomBytes(32);
        var RandID = RandIDBuff.toString('hex');
        var InStream = new stream.Writable({
            write: function(chunk, encoding, next) {
                Worker.ioStream.write(Buffer.concat([RandIDBuff,chunk]));
                next();
            },
            final: function() {
                Worker.ioStream.write(RandIDBuff);
            }
        });
        var OutStream = new stream.Readable({read() {}});
        self.WorkerStreamCallbacks[RandID] = OutStream;
        return {
            Output: OutStream,
            Input: InStream
        };
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
    this.signContractBuffer = function(msg,sk) {
        if (sk) {
            var t1 = self.crypt.SignedMessageToBuffer(self.crypt.secp256k1.sign(msg.subarray(1),sk));
            var t2 = new Uint8Array(t1.length+1);
            t2.set(t1,1);
            t2[0] = 131;
            return t2;
        } else {
            if (PrivateKey) {
                var t1 = self.crypt.SignedMessageToBuffer(self.crypt.secp256k1.sign(msg.subarray(1),PrivateKey));
                var t2 = new Uint8Array(t1.length+1);
                t2.set(t1,1);
                t2[0] = 131;
                return t2;
            } else {
                throw new Error("No private key supplied, try adding a PrivateKey value in the config for new KryptCoin(config)");
            }
        }
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
                var t = new Uint8Array(this.SignedTx.length+1);
                t[0] = 128;
                t.set(this.SignedTx,1);
                this.SignedTx = t;
                this.From = self.crypt.secp256k1.toAdress(self.crypt.secp256k1.getPublicKey(sk));
                return this.SignedTx;
            } else {
                if (PrivateKey) {
                    this.Signiture = self.crypt.secp256k1.sign(this.UnsignedTx,PrivateKey);
                    this.SignedTx = self.crypt.SignedMessageToBuffer(this.Signiture);
                    var t = new Uint8Array(this.SignedTx.length+1);
                    t[0] = 128;
                    t.set(this.SignedTx,1);
                    this.SignedTx = t;
                    this.From = self.crypt.secp256k1.toAdress(self.crypt.secp256k1.getPublicKey(PrivateKey));
                    return this.SignedTx;
                } else {
                    throw new Error("No private key supplied, try adding a PrivateKey value in the config for new KryptCoin(config)");
                }
            }
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
                var t = new Uint8Array(this.EncryptedMessage.arrayBuffer.length+1);
                t.set(this.EncryptedMessage.arrayBuffer,1);
                t[0] = 129;
                this.EncryptedMessage.arrayBuffer = t;
                return this.EncryptedMessage.arrayBuffer;
            }
        }
    }
    this.Contract = function(FulfillmentDate,Terms) {
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
                var t = new Uint8Array(this.SignedContract.length+1);
                t.set(this.SignedContract,1);
                t[0] = 131;
                this.SignedContract = t;
                return this.SignedContract;
            } else {
                if (PrivateKey) {
                    this.SignedContract = self.crypt.SignedMessageToBuffer(self.crypt.secp256k1.sign(this.UnsignedContract,PrivateKey));
                    var t = new Uint8Array(this.SignedContract.length+1);
                    t.set(this.SignedContract,1);
                    t[0] = 131;
                    this.SignedContract = t;
                    return this.SignedContract;
                } else {
                    throw new Error("No private key supplied, try adding a PrivateKey value in the config for new KryptCoin(config)");
                }
            }
        }
    }
    this.parse = function(bffr,callback) {
        var Streams = self.newWorkerStream();
        Streams.Input.end(bffr);
        var body = "";
        Streams.Output.on('data',function(data){
            body += data;
        });
        Streams.Output.on('close',function(){
            callback(JSON.parse(body));
        });
    }
    this.socket = dgram.createSocket("udp4");
    this.socket.MTU = 65507;
    this.Peers = {};
    if (DC) {
        this.DiscoveryChannel = DC();
        this.DiscoveryChannel.on('peer',function(ch,info){
            self.connectToPeer(info);
        });
    }
    this.broadcast = function(bffr) {
        var prs = Object.values(self.Peers);
        for (var i=0; i<prs.length; i++) {
            if (prs[i].send instanceof Function && prs[i].Identified) {
                prs[i].send(bffr);
            }
        }
    }
    this.bufferEqual = function(a,b) {
        if (a.length !== b.length) {
            return false;
        }
        for (var i=0; i<a.length; i++) {
            if (a[i] !== b[i]) {
                return false;
            }
        }
        return true;
    }
    this.connectToPeer = function(info) {
        self.dataProtocall(Buffer.alloc(0),{address:info.host,port:info.port});
    }
    this.dataProtocall = function(data,info) {
        var PeerID = info.address+":"+info.port;
        if (!self.Peers[PeerID]) {
            self.Peers[PeerID] = {
                IP: info.address,
                Port: info.port,
                ID: PeerID,
                Adress: null,
                TimeLastSeen: new Date(),
                ValidationValue: crypto.randomBytes(32),
                Identified: false,
                send: function(b) {
                    self.socket.send(b,0,b.length,self.Peers[PeerID].Port,self.Peers[PeerID].IP,function(err){
                        if (err) {
                            console.log(err);
                        }
                    });
                },
                Timeout:setTimeout(function(){
                    if (!self.Peers[PeerID].Identified) {
                        delete self.Peers[PeerID];
                    }
                },10000)
            };
            var b = Buffer.concat([Buffer.alloc(1),self.Peers[PeerID].ValidationValue]);
            self.Peers[PeerID].send(b);
        } else {
            // if (data.length <= 0) {
            //     return;
            // }
            // console.log(self.Peers[PeerID]);
            if (!self.Peers[PeerID].Identified && (data[0] !== 0 && data[0] !== 1)) {
                self.Peers[PeerID].ValidationValue = crypto.randomBytes(32);
                self.Peers[PeerID].send(Buffer.concat([Buffer.alloc(1),self.Peers[PeerID].ValidationValue]));
                return;
            }
            self.Peers[PeerID].TimeLastSeen = new Date();
            if (data[0] == 0) {
                data = data.slice(1);
                var head = Buffer.alloc(1);
                head[0] = 1;
                self.Peers[PeerID].send(Buffer.concat([head,self.signBuffer(data,PrivateKey)]));
            } else if (data[0] == 1) {
                data = data.slice(1);
                var signiture = self.crypt.BufferToSignedMessage(data);
                if (self.bufferEqual(signiture.Message,self.Peers[PeerID].ValidationValue)) {
                    self.Peers[PeerID].Adress = self.crypt.secp256k1.toAdress(self.crypt.secp256k1.recoverPublicKey(signiture));
                    var tf = !self.Peers[PeerID].Identified;
                    self.Peers[PeerID].Identified = true;
                    if (tf) {
                        self.emit('peer',self.Peers[PeerID]);
                    }
                } else {
                    delete self.Peers[PeerID];
                }
            } else if (data[0] == 128) {
                self.parse(data,function(Txn){
                    self.emit('txn',Txn);
                });
            } else if (data[0] == 129) {
                self.parse(data,function(msg){
                    if (msg.Dec) {
                        self.emit('message',msg);
                        self.emit('message-receved',msg);
                    } else {
                        self.emit('message',msg);
                    }
                });
            } else if (data[0] == 131) {
                self.parse(data,function(con){
                    self.emit('contract',con);
                });
            }
        }
    }
    this.socket.on('message',self.dataProtocall);
    this.startPeerService = function(port,callback) {
        if (this.DiscoveryChannel) {
            this.DiscoveryChannel.join("KryptCoin",port || 8343);
        }
        self.socket.bind(port || 8343,"0.0.0.0",function(){
            if (callback instanceof Function) {
                callback();
            }
        });
    }
    this.stopPeerService = function(callback) {
        if (this.DiscoveryChannel) {
            this.DiscoveryChannel.leave("KryptCoin");
        }
        self.socket.close(function(){
            if (callback instanceof Function) {
                callback();
            }
        });
    }
    this.startTerminalInterface = function() {
        var rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout,
            completer:function(line) {
                return ['1','2'];
            }
        });
    }
}
util.inherits(KryptCoin, events.EventEmitter);
if (typeof window === 'undefined') {
    module.exports = KryptCoin;
}
