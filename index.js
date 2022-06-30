var os = require("os");
var fs = require("fs");
var net = require("net");
var http = require("http");
var util = require('util');
var dgram = require("dgram");
var stream = require('stream');
var crypto = require("crypto");
var events = require('events');
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
    OpsTmp.DataFilePath = OpsTmp.DataFilePath.endsWith("/") ? OpsTmp.DataFilePath : OpsTmp.DataFilePath+"/";
    this.filePath = OpsTmp.DataFilePath;
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
                    // self.WorkerStreamCallbacks[RandID].push(data.slice(32));
                    if (data.slice(-32).toString('hex') == RandID) {
                        self.WorkerStreamCallbacks[RandID].push(data.slice(32,-32));
                        self.WorkerStreamCallbacks[RandID].destroy();
                        delete self.WorkerStreamCallbacks[RandID];
                    } else {
                        self.WorkerStreamCallbacks[RandID].push(data.slice(32));
                    }
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
    this.addAdress = function(addr) {
        if (!fs.existsSync(self.filePath+addr)) {
            fs.mkdirSync(self.filePath+addr);
        }
    }
    this.encryptedMessage = function(msg) {
        this.EncryptedMessage = null;
        this.SignedMessage = null;
        this.sign = function(sk) {
            var arr = Buffer.from(msg,'utf-8');
            if (!sk) {
                sk = PrivateKey;
            }
            this.SignedMessage = self.signBuffer(arr,sk);
            return this;
        }
        this.encryptWithAdress = function(adres) {
            if (this.SignedMessage) {
                var keys = self.crypt.secp256k1.encryptWithPublicKey(adres);
                var enc = self.AES256Enc(this.SignedMessage,keys.SharedKey);
                var keyBfr = self.crypt.bigIntToBuffer(BigInt(keys.PublicKey));
                var adrsArr = Buffer.alloc(35);
                var adrs = self.crypt.bigIntToBuffer(BigInt(adres));
                adrsArr.set(adrs,34-adrs.length);
                adrsArr[0] = 129;
                adrsArr[34] = keyBfr.length;
                this.EncryptedMessage = Buffer.concat([adrsArr,keyBfr,enc]);
                return this.EncryptedMessage;
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
        var body = "";
        Streams.Output.on('data',function(data){
            body += data;
        });
        Streams.Output.on('close',function(){
            callback(JSON.parse(body));
        });
        Streams.Input.end(bffr);
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
                Timeout:setInterval(function(){
                    if ((new Date())-self.Peers[PeerID].TimeLastSeen >= 10000 && !self.Peers[PeerID].Identified) {
                        clearInterval(self.Peers[PeerID].Timeout);
                        self.emit('peer-fail',self.Peers[PeerID]);
                        delete self.Peers[PeerID];
                        return;
                    }
                    if (self.Peers[PeerID].Identified) {
                        clearInterval(self.Peers[PeerID].Timeout);
                    } else {
                        self.Peers[PeerID].send(Buffer.concat([Buffer.alloc(1),self.Peers[PeerID].ValidationValue]));
                    }
                },1000)
            };
            var b = Buffer.concat([Buffer.alloc(1),self.Peers[PeerID].ValidationValue]);
            self.Peers[PeerID].send(b);
        } else {
            if (data.length <= 0) {
                return;
            }
            // console.log(self.Peers[PeerID]);
            if (!self.Peers[PeerID].Identified && (data[0] !== 0 && data[0] !== 1)) {
                // self.Peers[PeerID].ValidationValue = crypto.randomBytes(32);
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
                    self.addAdress(self.Peers[PeerID].Adress);
                    self.Peers[PeerID].Identified = true;
                    if (tf) {
                        self.emit('peer',self.Peers[PeerID]);
                    }
                }/* else {
                    clearInterval(self.Peers[PeerID].Timeout);
                    delete self.Peers[PeerID];
                }*/
            } else if (data[0] == 128) {
                self.parse(data,function(Txn){
                    self.emit('txn',Txn);
                });
            } else if (data[0] == 129) {
                // console.log("Message");
                self.parse(data,function(msg){
                    if (msg.DecryptedMessage) {
                        self.emit('message-receved',msg);
                        if (self.WebGUIServer) {
                            self.WebQue.push(msg);
                        }
                    }
                    self.emit('message',msg);
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
    process.on('exit',function(){
        self.stopPeerService();
    })
    this.startTerminalInterface = function() {
        var UP = Buffer.from("1b5b41",'hex');
        var DOWN = Buffer.from("1b5b42",'hex');
        var LEFT = Buffer.from("1b5b44",'hex');
        var RIGHT = Buffer.from("1b5b43",'hex');
        var ENTER = Buffer.from("0d",'hex');
        process.stdin.setRawMode(true);
        var Colors = {
            Reset:"\x1b[0m",
            Bright:"\x1b[1m",
            Dim:"\x1b[2m",
            Underscore:"\x1b[4m",
            Blink:"\x1b[5m",
            Reverse:"\x1b[7m",
            Hidden:"\x1b[8m",
            FgBlack:"\x1b[30m",
            FgRed:"\x1b[31m",
            FgGreen:"\x1b[32m",
            FgYellow:"\x1b[33m",
            FgBlue:"\x1b[34m",
            FgMagenta:"\x1b[35m",
            FgCyan:"\x1b[36m",
            FgWhite:"\x1b[37m",
            BgBlack:"\x1b[40m",
            BgRed:"\x1b[41m",
            BgGreen:"\x1b[42m",
            BgYellow:"\x1b[43m",
            BgBlue:"\x1b[44m",
            BgMagenta:"\x1b[45m",
            BgCyan:"\x1b[46m",
            BgWhite:"\x1b[47m"
        }
        var State = {
            SelectionIndex:0,
            SelectionList:["Test 1","Test 2","Test 3","Test 4"]
        };
        function reDraw() {
            console.clear();
            console.log("KryptCoin\n\n\n\n\n");
            for (var i=0; i<State.SelectionList.length; i++) {
                if (i == State.SelectionIndex) {
                    console.log(Colors.Underscore+State.SelectionList[i]+Colors.Reset);
                } else {
                    console.log(State.SelectionList[i]);
                }
            }
        }
        process.stdin.on('data',function(key){
            if (key[0] == 3) {
                process.exit();
                return;
            }
            if (self.bufferEqual(UP,key)) {
                // console.log("UP");
                // State.SelectionIndex = (State.SelectionIndex+State.SelectionList.length-1)%State.SelectionList.length;
            } else if (self.bufferEqual(DOWN,key)) {
                // console.log("DOWN");
                // State.SelectionIndex = (State.SelectionIndex+1)%State.SelectionList.length;
            } else if (self.bufferEqual(LEFT,key)) {
                // console.log("LEFT");
                State.SelectionIndex = Math.max(State.SelectionIndex-1,0);
                reDraw();
            } else if (self.bufferEqual(RIGHT,key)) {
                // console.log("RIGHT");
                State.SelectionIndex = Math.min(State.SelectionIndex+1,State.SelectionList.length-1);
                reDraw();
            } else if (self.bufferEqual(ENTER,key)) {
                // console.log("ENTER");
            } else {
                // console.log(key);
            }
        });
        console.clear();
        console.log("KryptCoin Terminal");
    }
    this.WebGUIServer = null;
    this.WebQue = [];
    this.startWebGUI = function(port) {
        if (self.WebGUIServer) {
            throw new Error("Server already started!");
        } else {
            self.WebGUIServer = http.createServer(function(req,res){
                if (req.url.startsWith("/api/")) {
                    if (req.url.startsWith("/api/getMessages")) {
                        res.writeHead(200);
                        res.end();
                    } else if (req.url.startsWith("/api/sendMessage/0x")) {
                        var message = "";
                        req.on('data',function(data){
                            message += data;
                        });
                        req.on('end',function(){
                            var Message = new self.encryptedMessage(message);
                            var msg = Message.sign().encryptWithAdress(req.url.slice(17));
                            self.broadcast(msg);
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
                            // var Stream = fs.createReadStream(path);
                            // self.broadcastStream(self.Adress,self.AES256EncStream(Stream,keys.SharedKey),header);
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
                    if (req.url == "/") {
                        path = __dirname+"/WebGUI/index.html";
                    }
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
util.inherits(KryptCoin, events.EventEmitter);
if (typeof window === 'undefined') {
    module.exports = KryptCoin;
}